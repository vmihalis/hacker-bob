#include <CommonCrypto/CommonDigest.h>
#include <CommonCrypto/CommonHMAC.h>
#include <libproc.h>
#include <mach-o/dyld.h>
#include <sys/event.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/wait.h>

#include <cerrno>
#include <climits>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>

#include <fcntl.h>
#include <poll.h>
#include <pthread.h>
#include <signal.h>
#include <time.h>
#include <unistd.h>

extern char** environ;

namespace {

constexpr int kControlFd = 3;
constexpr int kJournalFd = 4;
constexpr int kKeyFd = 5;
constexpr int kCustodyEventFd = 6;
constexpr size_t kDigestBytes = CC_SHA256_DIGEST_LENGTH;
constexpr size_t kMaximumLineBytes = 4096;
constexpr size_t kMaximumJournalBytes = 64 * 1024;
constexpr uint64_t kNanosecondsPerMillisecond = 1000000ULL;
constexpr uint64_t kMaximumDeadmanMs = 5000;
constexpr uint64_t kMaximumCleanupMs = 2000;
constexpr uint64_t kStartupCustodyMs = 10000;
constexpr uint64_t kInjectedBlockedStartupCustodyMs = 1000;
constexpr uint64_t kInjectedExpiredStartupCustodyMs = 300;
constexpr const char* kSemanticDomain =
    "hacker-bob/darwin-safety-semantic-cleanup/v1";
constexpr const char* kJournalDomain =
    "hacker-bob/darwin-safety-deadman-journal/v1";
constexpr const char* kReceiptDomain =
    "hacker-bob/darwin-safety-cleanup-receipt/v1";
constexpr const char* kProcessDomain =
    "hacker-bob/darwin-safety-worker-process-observation/v1";
constexpr const char* kChildProcessDomain =
    "hacker-bob/darwin-safety-child-process-start/v1";
constexpr const char* kProcessGroupDomain =
    "hacker-bob/darwin-safety-process-group/v1";
constexpr const char* kCustodyCommandKeyDomain =
    "hacker-bob/darwin-safety-custody-command-key/v1";
constexpr const char* kCustodyEvidenceKeyDomain =
    "hacker-bob/darwin-safety-custody-evidence-key/v1";
constexpr const char* kCustodyActionDomain =
    "hacker-bob/darwin-safety-custody-action/v1";
constexpr size_t kCustodyEnvelopeOffset = 2;
constexpr size_t kCustodyEnvelopeFieldCount = 14;
constexpr size_t kCustodyEnvelopeEnd =
    kCustodyEnvelopeOffset + kCustodyEnvelopeFieldCount;
constexpr size_t kCustodyBindingFieldCount = 8;
constexpr size_t kCustodyAcceptanceFieldCount =
    kCustodyEnvelopeEnd + 5 + kCustodyBindingFieldCount + 1;

void SecureZero(void* value, size_t length) {
  volatile unsigned char* cursor = static_cast<volatile unsigned char*>(value);
  while (length > 0) {
    *cursor = 0;
    ++cursor;
    --length;
  }
}

void ZeroString(std::string* value) {
  if (value != nullptr && !value->empty()) {
    SecureZero(value->data(), value->size());
    value->clear();
  }
}

class SecretVectorGuard {
 public:
  explicit SecretVectorGuard(std::vector<unsigned char>* value) : value_(value) {}
  ~SecretVectorGuard() {
    if (value_ != nullptr && !value_->empty()) {
      SecureZero(value_->data(), value_->size());
    }
  }

  SecretVectorGuard(const SecretVectorGuard&) = delete;
  SecretVectorGuard& operator=(const SecretVectorGuard&) = delete;

 private:
  std::vector<unsigned char>* value_;
};

uint64_t MonotonicNanoseconds() {
  struct timespec value = {};
  if (clock_gettime(CLOCK_MONOTONIC, &value) != 0 || value.tv_sec < 0) return 0;
  return static_cast<uint64_t>(value.tv_sec) * 1000000000ULL +
         static_cast<uint64_t>(value.tv_nsec);
}

struct AbsoluteDeadline {
  uint64_t expires = 0;
  bool valid = false;
};

bool BuildAbsoluteDeadlineAt(uint64_t now, uint64_t timeout_ms,
                             AbsoluteDeadline* output) {
  output->expires = 0;
  output->valid = false;
  if (now == 0 || timeout_ms == 0 ||
      timeout_ms > UINT64_MAX / kNanosecondsPerMillisecond) {
    return false;
  }
  const uint64_t window = timeout_ms * kNanosecondsPerMillisecond;
  if (now > UINT64_MAX - window) return false;
  output->expires = now + window;
  output->valid = true;
  return true;
}

bool BuildAbsoluteDeadline(uint64_t timeout_ms, AbsoluteDeadline* output) {
  return BuildAbsoluteDeadlineAt(MonotonicNanoseconds(), timeout_ms, output);
}

bool RemainingAt(const AbsoluteDeadline& deadline, uint64_t now,
                 uint64_t* remaining_ns) {
  *remaining_ns = 0;
  if (!deadline.valid || now == 0 || now >= deadline.expires) return false;
  *remaining_ns = deadline.expires - now;
  return true;
}

bool Remaining(const AbsoluteDeadline& deadline, uint64_t* remaining_ns) {
  return RemainingAt(deadline, MonotonicNanoseconds(), remaining_ns);
}

bool DeadlineExpired(const AbsoluteDeadline& deadline) {
  uint64_t remaining = 0;
  return !Remaining(deadline, &remaining);
}

int DeadlineHelperSelftest() {
  AbsoluteDeadline deadline;
  uint64_t remaining = 1;
  if (BuildAbsoluteDeadlineAt(0, 1, &deadline) || deadline.valid ||
      BuildAbsoluteDeadlineAt(UINT64_MAX - 10, 1, &deadline) ||
      !BuildAbsoluteDeadlineAt(100, 2, &deadline) || !deadline.valid ||
      deadline.expires != 2000100ULL ||
      !RemainingAt(deadline, 100, &remaining) || remaining != 2000000ULL ||
      RemainingAt(deadline, 0, &remaining) || remaining != 0 ||
      RemainingAt(deadline, deadline.expires, &remaining) || remaining != 0) {
    return 66;
  }
  return 0;
}

void CleanupDeadlineSignal(int) {
  _exit(124);
}

volatile sig_atomic_t g_watcher_deadline_fired = 0;

void WatchdogDeadlineSignal(int) {
  g_watcher_deadline_fired = 1;
  _exit(125);
}

bool ArmWatcherDeadline(const AbsoluteDeadline& deadline) {
  uint64_t remaining_ns = 0;
  if (!Remaining(deadline, &remaining_ns)) return false;
  struct sigaction action = {};
  action.sa_handler = WatchdogDeadlineSignal;
  sigemptyset(&action.sa_mask);
  if (sigaction(SIGALRM, &action, nullptr) != 0) return false;
  const uint64_t microseconds = (remaining_ns + 999ULL) / 1000ULL;
  struct itimerval timer = {};
  timer.it_value.tv_sec = static_cast<time_t>(microseconds / 1000000ULL);
  timer.it_value.tv_usec = static_cast<suseconds_t>(microseconds % 1000000ULL);
  if (timer.it_value.tv_sec == 0 && timer.it_value.tv_usec == 0) {
    timer.it_value.tv_usec = 1;
  }
  g_watcher_deadline_fired = 0;
  return setitimer(ITIMER_REAL, &timer, nullptr) == 0;
}

void DisarmProcessDeadline() {
  struct itimerval timer = {};
  setitimer(ITIMER_REAL, &timer, nullptr);
}

bool BuildChildDeadline(const AbsoluteDeadline& outer,
                        AbsoluteDeadline* child) {
  uint64_t remaining_ns = 0;
  if (!Remaining(outer, &remaining_ns)) return false;
  // Every nested custodian must finish early enough for its parent to reap it,
  // persist and read back evidence, and publish the terminal receipt inside the
  // signed outer bound. A fixed 10 ms reserve made that hierarchy scheduler-
  // dependent on hosted ARM runners.
  uint64_t reserve = remaining_ns / 3;
  if (reserve > 100000000ULL) reserve = 100000000ULL;
  if (reserve < 1000000ULL && remaining_ns > 1000000ULL) reserve = 1000000ULL;
  if (reserve == 0 || reserve >= remaining_ns) return false;
  child->expires = outer.expires - reserve;
  child->valid = true;
  return true;
}

bool BuildHandoffStallFixtureDeadlines(
    const AbsoluteDeadline& outer, AbsoluteDeadline* child,
    AbsoluteDeadline* observation) {
  const uint64_t now = MonotonicNanoseconds();
  uint64_t remaining_ns = 0;
  if (!RemainingAt(outer, now, &remaining_ns) || remaining_ns < 6) {
    return false;
  }
  // This injected fixture needs three strictly ordered failure boundaries:
  // cleanup-child self-deadline, custodian observation/exit, then the watcher's
  // signed terminal deadline. Sharing the final boundary made the two parent
  // processes race to SIGALRM (both exit 125) and did not deterministically
  // exercise the cleanup child's independent deadline.
  const uint64_t child_reserve = remaining_ns / 2;
  const uint64_t observation_reserve = remaining_ns / 3;
  if (child_reserve <= observation_reserve || observation_reserve == 0) {
    return false;
  }
  child->expires = outer.expires - child_reserve;
  child->valid = true;
  observation->expires = outer.expires - observation_reserve;
  observation->valid = true;
  return child->expires > now && observation->expires > child->expires &&
         observation->expires < outer.expires;
}

bool ArmProcessDeadline(const AbsoluteDeadline& deadline) {
  uint64_t remaining_ns = 0;
  if (!Remaining(deadline, &remaining_ns)) return false;
  struct sigaction action = {};
  action.sa_handler = CleanupDeadlineSignal;
  sigemptyset(&action.sa_mask);
  if (sigaction(SIGALRM, &action, nullptr) != 0) return false;
  const uint64_t microseconds = (remaining_ns + 999ULL) / 1000ULL;
  struct itimerval timer = {};
  timer.it_value.tv_sec = static_cast<time_t>(microseconds / 1000000ULL);
  timer.it_value.tv_usec = static_cast<suseconds_t>(microseconds % 1000000ULL);
  if (timer.it_value.tv_sec == 0 && timer.it_value.tv_usec == 0) {
    timer.it_value.tv_usec = 1;
  }
  return setitimer(ITIMER_REAL, &timer, nullptr) == 0;
}

int g_cleanup_guard_queue = -1;

void* CleanupCustodyGuardThread(void*) {
  struct kevent event = {};
  for (;;) {
    const int count = kevent(g_cleanup_guard_queue, nullptr, 0, &event, 1, nullptr);
    if (count < 0 && errno == EINTR) continue;
    _exit(124);
  }
}

bool StartCleanupCustodyGuard(pid_t expected_parent,
                              const AbsoluteDeadline& deadline) {
  uint64_t remaining_ns = 0;
  if (expected_parent < 2 || getppid() != expected_parent ||
      !Remaining(deadline, &remaining_ns) || remaining_ns > INT64_MAX) {
    return false;
  }
  const int queue = kqueue();
  if (queue < 0) return false;
  struct kevent changes[3];
  EV_SET(&changes[0], static_cast<uintptr_t>(expected_parent), EVFILT_PROC,
         EV_ADD | EV_ENABLE | EV_CLEAR, NOTE_EXIT, 0, nullptr);
  EV_SET(&changes[1], 1, EVFILT_TIMER, EV_ADD | EV_ENABLE | EV_ONESHOT,
         NOTE_NSECONDS, static_cast<intptr_t>(remaining_ns), nullptr);
  if (kevent(queue, changes, 2, nullptr, 0, nullptr) != 0 ||
      getppid() != expected_parent) {
    close(queue);
    return false;
  }
  g_cleanup_guard_queue = queue;
  pthread_attr_t attributes;
  if (pthread_attr_init(&attributes) != 0) {
    close(queue);
    g_cleanup_guard_queue = -1;
    return false;
  }
  bool accepted = pthread_attr_setdetachstate(
      &attributes, PTHREAD_CREATE_DETACHED) == 0;
  pthread_t thread;
  if (accepted) {
    accepted = pthread_create(&thread, &attributes,
                              CleanupCustodyGuardThread, nullptr) == 0;
  }
  pthread_attr_destroy(&attributes);
  if (!accepted) {
    close(queue);
    g_cleanup_guard_queue = -1;
  }
  return accepted;
}

std::string Hex(const unsigned char* bytes, size_t length) {
  static constexpr char kHex[] = "0123456789abcdef";
  std::string output(length * 2, '0');
  for (size_t index = 0; index < length; ++index) {
    output[index * 2] = kHex[bytes[index] >> 4];
    output[index * 2 + 1] = kHex[bytes[index] & 0x0f];
  }
  return output;
}

int HexNibble(unsigned char value) {
  if (value >= '0' && value <= '9') return value - '0';
  if (value >= 'a' && value <= 'f') return value - 'a' + 10;
  return -1;
}

bool IsDigest(const std::string& value) {
  if (value.size() != kDigestBytes * 2) return false;
  for (size_t index = 0; index < value.size(); ++index) {
    if (HexNibble(static_cast<unsigned char>(value[index])) < 0) return false;
  }
  return true;
}

std::string Sha256(const unsigned char* bytes, size_t length) {
  unsigned char digest[kDigestBytes];
  CC_SHA256(bytes, static_cast<CC_LONG>(length), digest);
  std::string output = Hex(digest, sizeof(digest));
  SecureZero(digest, sizeof(digest));
  return output;
}

std::string HmacSha256(const std::vector<unsigned char>& key,
                       const std::string& value) {
  unsigned char digest[kDigestBytes];
  CCHmac(kCCHmacAlgSHA256, key.data(), key.size(), value.data(), value.size(),
         digest);
  std::string output = Hex(digest, sizeof(digest));
  SecureZero(digest, sizeof(digest));
  return output;
}

std::vector<unsigned char> DeriveCustodyKey(
    const std::vector<unsigned char>& launch_key, const char* domain,
    const std::string& contract_digest) {
  std::string material(domain);
  material.push_back('\t');
  material.append(contract_digest);
  unsigned char digest[kDigestBytes];
  CCHmac(kCCHmacAlgSHA256, launch_key.data(), launch_key.size(), material.data(),
         material.size(), digest);
  std::vector<unsigned char> output(digest, digest + sizeof(digest));
  SecureZero(digest, sizeof(digest));
  ZeroString(&material);
  return output;
}

bool ConstantTimeEqual(const std::string& left, const std::string& right) {
  if (left.size() != right.size()) return false;
  unsigned char difference = 0;
  for (size_t index = 0; index < left.size(); ++index) {
    difference |= static_cast<unsigned char>(left[index] ^ right[index]);
  }
  return difference == 0;
}

std::string FramedDigest(const char* domain,
                         const std::vector<std::string>& fields) {
  CC_SHA256_CTX context;
  CC_SHA256_Init(&context);
  CC_SHA256_Update(&context, domain, static_cast<CC_LONG>(std::strlen(domain)));
  for (size_t field_index = 0; field_index < fields.size(); ++field_index) {
    uint64_t length = fields[field_index].size();
    unsigned char encoded[8];
    for (size_t index = 0; index < sizeof(encoded); ++index) {
      encoded[7 - index] = static_cast<unsigned char>(length & 0xff);
      length >>= 8;
    }
    CC_SHA256_Update(&context, encoded, sizeof(encoded));
    if (!fields[field_index].empty()) {
      CC_SHA256_Update(&context, fields[field_index].data(),
                       static_cast<CC_LONG>(fields[field_index].size()));
    }
    SecureZero(encoded, sizeof(encoded));
  }
  unsigned char digest[kDigestBytes];
  CC_SHA256_Final(digest, &context);
  std::string output = Hex(digest, sizeof(digest));
  SecureZero(digest, sizeof(digest));
  SecureZero(&context, sizeof(context));
  return output;
}

std::string Join(const std::vector<std::string>& fields, size_t count) {
  std::string output;
  for (size_t index = 0; index < count; ++index) {
    if (index != 0) output.push_back('\t');
    output.append(fields[index]);
  }
  return output;
}

std::vector<std::string> Split(const std::string& value) {
  std::vector<std::string> output;
  size_t start = 0;
  for (size_t index = 0; index <= value.size(); ++index) {
    if (index == value.size() || value[index] == '\t') {
      output.emplace_back(value.substr(start, index - start));
      start = index + 1;
    }
  }
  return output;
}

bool ParseUint64(const std::string& value, uint64_t minimum, uint64_t maximum,
                 uint64_t* output) {
  if (value.empty() || (value.size() > 1 && value[0] == '0')) return false;
  uint64_t parsed = 0;
  for (size_t index = 0; index < value.size(); ++index) {
    const unsigned char byte = static_cast<unsigned char>(value[index]);
    if (byte < '0' || byte > '9') return false;
    const uint64_t digit = byte - '0';
    if (parsed > (UINT64_MAX - digit) / 10) return false;
    parsed = parsed * 10 + digit;
  }
  if (parsed < minimum || parsed > maximum) return false;
  *output = parsed;
  return true;
}

bool IsReasonCode(const std::string& value) {
  if (value.empty() || value.size() > 128 || value[0] < 'a' || value[0] > 'z') {
    return false;
  }
  for (size_t index = 1; index < value.size(); ++index) {
    const unsigned char byte = static_cast<unsigned char>(value[index]);
    if (!((byte >= 'a' && byte <= 'z') || (byte >= '0' && byte <= '9') ||
          byte == '_')) {
      return false;
    }
  }
  return true;
}

bool WriteAll(int fd, const std::string& value) {
  size_t offset = 0;
  while (offset < value.size()) {
    const ssize_t written = write(fd, value.data() + offset, value.size() - offset);
    if (written < 0 && errno == EINTR) {
      if (g_watcher_deadline_fired != 0) return false;
      continue;
    }
    if (written <= 0) return false;
    offset += static_cast<size_t>(written);
  }
  return true;
}

bool WriteLine(int fd, const std::vector<std::string>& fields) {
  std::string line = Join(fields, fields.size());
  line.push_back('\n');
  const bool written = WriteAll(fd, line);
  ZeroString(&line);
  return written;
}

bool ReadLineBlocking(int fd, std::string* output) {
  output->clear();
  while (output->size() <= kMaximumLineBytes) {
    char byte = 0;
    const ssize_t count = read(fd, &byte, 1);
    if (count < 0 && errno == EINTR) continue;
    if (count != 1) return false;
    if (byte == '\n') return !output->empty();
    if (byte == '\r' || byte == '\0') return false;
    output->push_back(byte);
  }
  return false;
}

bool ReadKeyCapability(int fd, std::vector<unsigned char>* key) {
  unsigned char capability[36];
  size_t offset = 0;
  while (offset < sizeof(capability)) {
    const ssize_t count = read(fd, capability + offset, sizeof(capability) - offset);
    if (count < 0 && errno == EINTR) continue;
    if (count <= 0) {
      SecureZero(capability, sizeof(capability));
      return false;
    }
    offset += static_cast<size_t>(count);
  }
  const bool accepted = std::memcmp(capability, "KEY1", 4) == 0;
  if (accepted) key->assign(capability + 4, capability + sizeof(capability));
  SecureZero(capability, sizeof(capability));
  return accepted && key->size() == 32;
}

bool VerifySignedFields(const std::vector<std::string>& fields,
                        size_t expected_count,
                        const std::vector<unsigned char>& key) {
  if (fields.size() != expected_count || !IsDigest(fields.back())) return false;
  std::string payload = Join(fields, fields.size() - 1);
  std::string expected = HmacSha256(key, payload);
  const bool accepted = ConstantTimeEqual(expected, fields.back());
  ZeroString(&payload);
  ZeroString(&expected);
  return accepted;
}

std::string SemanticDigest(const std::string& profile) {
  std::vector<std::string> fields = {
      "rf_release",
      "future_cleanup_provider",
      "chameleon_reviewed_family_2101",
      "first",
      "emission_unknown_without_external_observer",
  };
  if (profile == "rf_off_only") {
    fields.emplace_back("mf1_field_off_reset_restore_not_applicable");
  } else if (profile == "rf_off_restore_mf1_false" ||
             profile == "rf_off_restore_mf1_true") {
    fields.emplace_back("mf1_field_off_reset_restore");
    fields.emplace_back("chameleon_reviewed_family_4038");
    fields.emplace_back(profile == "rf_off_restore_mf1_true" ? "true" : "false");
    fields.emplace_back("readback");
    fields.emplace_back("chameleon_reviewed_family_4039");
  } else {
    return std::string();
  }
  return FramedDigest(kSemanticDomain, fields);
}

struct FileIdentity {
  dev_t device = 0;
  ino_t inode = 0;
  off_t size = 0;
  uid_t uid = 0;
  gid_t gid = 0;
  mode_t mode = 0;
  time_t mtime_sec = 0;
  long mtime_nsec = 0;
  time_t ctime_sec = 0;
  long ctime_nsec = 0;
};

bool SameFileIdentity(const FileIdentity& left, const FileIdentity& right) {
  return left.device == right.device && left.inode == right.inode &&
         left.size == right.size && left.uid == right.uid &&
         left.gid == right.gid && left.mode == right.mode &&
         left.mtime_sec == right.mtime_sec &&
         left.mtime_nsec == right.mtime_nsec &&
         left.ctime_sec == right.ctime_sec &&
         left.ctime_nsec == right.ctime_nsec;
}

bool SelfExecutable(std::string* path, std::string* digest,
                    FileIdentity* identity) {
  uint32_t capacity = PATH_MAX;
  char unresolved[PATH_MAX];
  if (_NSGetExecutablePath(unresolved, &capacity) != 0) return false;
  char resolved[PATH_MAX];
  if (realpath(unresolved, resolved) == nullptr) return false;
  const int fd = open(resolved, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
  if (fd < 0) return false;
  struct stat before = {};
  bool accepted = fstat(fd, &before) == 0 && S_ISREG(before.st_mode) &&
                  before.st_nlink == 1 && before.st_uid == geteuid() &&
                  (before.st_mode & 0022) == 0 && before.st_size > 0 &&
                  before.st_size <= 16 * 1024 * 1024;
  std::vector<unsigned char> bytes;
  if (accepted) {
    bytes.resize(static_cast<size_t>(before.st_size));
    size_t offset = 0;
    while (offset < bytes.size()) {
      const ssize_t count = pread(fd, bytes.data() + offset, bytes.size() - offset,
                                  static_cast<off_t>(offset));
      if (count < 0 && errno == EINTR) continue;
      if (count <= 0) {
        accepted = false;
        break;
      }
      offset += static_cast<size_t>(count);
    }
  }
  struct stat after = {};
  if (!accepted || fstat(fd, &after) != 0 || before.st_dev != after.st_dev ||
      before.st_ino != after.st_ino || before.st_size != after.st_size ||
      before.st_mtimespec.tv_sec != after.st_mtimespec.tv_sec ||
      before.st_mtimespec.tv_nsec != after.st_mtimespec.tv_nsec ||
      before.st_ctimespec.tv_sec != after.st_ctimespec.tv_sec ||
      before.st_ctimespec.tv_nsec != after.st_ctimespec.tv_nsec) {
    accepted = false;
  }
  if (accepted) {
    *path = resolved;
    *digest = Sha256(bytes.data(), bytes.size());
    identity->device = before.st_dev;
    identity->inode = before.st_ino;
    identity->size = before.st_size;
    identity->uid = before.st_uid;
    identity->gid = before.st_gid;
    identity->mode = before.st_mode;
    identity->mtime_sec = before.st_mtimespec.tv_sec;
    identity->mtime_nsec = before.st_mtimespec.tv_nsec;
    identity->ctime_sec = before.st_ctimespec.tv_sec;
    identity->ctime_nsec = before.st_ctimespec.tv_nsec;
  }
  if (!bytes.empty()) SecureZero(bytes.data(), bytes.size());
  close(fd);
  return accepted;
}

struct ProcessIdentity {
  pid_t pid = -1;
  uid_t uid = 0;
  gid_t gid = 0;
  uid_t ruid = 0;
  gid_t rgid = 0;
  uint64_t start_sec = 0;
  uint64_t start_usec = 0;
  std::string command;
};

bool ReadProcessIdentity(pid_t pid, ProcessIdentity* output) {
  struct proc_bsdinfo info = {};
  const int count = proc_pidinfo(pid, PROC_PIDTBSDINFO, 0, &info, sizeof(info));
  if (count != sizeof(info) || info.pbi_pid != static_cast<uint32_t>(pid)) {
    return false;
  }
  output->pid = pid;
  output->uid = info.pbi_uid;
  output->gid = info.pbi_gid;
  output->ruid = info.pbi_ruid;
  output->rgid = info.pbi_rgid;
  output->start_sec = info.pbi_start_tvsec;
  output->start_usec = info.pbi_start_tvusec;
  output->command.assign(info.pbi_comm, strnlen(info.pbi_comm, sizeof(info.pbi_comm)));
  return !output->command.empty();
}

bool SameProcessIdentity(const ProcessIdentity& left,
                         const ProcessIdentity& right) {
  return left.pid == right.pid && left.uid == right.uid &&
         left.gid == right.gid && left.ruid == right.ruid &&
         left.rgid == right.rgid && left.start_sec == right.start_sec &&
         left.start_usec == right.start_usec && left.command == right.command;
}

bool SameProcessStartIdentity(const ProcessIdentity& left,
                              const ProcessIdentity& right) {
  return left.pid == right.pid && left.uid == right.uid &&
         left.gid == right.gid && left.ruid == right.ruid &&
         left.rgid == right.rgid && left.start_sec == right.start_sec &&
         left.start_usec == right.start_usec;
}

std::string ProcessIdentityDigest(const ProcessIdentity& value) {
  return FramedDigest(kProcessDomain,
                      {std::to_string(value.pid), std::to_string(value.uid),
                       std::to_string(value.gid), std::to_string(value.ruid),
                       std::to_string(value.rgid),
                       std::to_string(value.start_sec),
                       std::to_string(value.start_usec), value.command});
}

std::string ProcessStartIdentityDigest(const ProcessIdentity& value) {
  return FramedDigest(
      kChildProcessDomain,
      {std::to_string(value.pid), std::to_string(value.uid),
       std::to_string(value.gid), std::to_string(value.ruid),
       std::to_string(value.rgid), std::to_string(value.start_sec),
       std::to_string(value.start_usec)});
}

std::string ProcessGroupIdentityDigest(const std::string& role, pid_t pid,
                                       pid_t pgid, pid_t session_id,
                                       const std::string& start_digest) {
  return FramedDigest(kProcessGroupDomain,
                      {role, std::to_string(pid), std::to_string(pgid),
                       std::to_string(session_id), start_digest});
}

struct ChildLifecycle {
  pid_t pid = -1;
  pid_t pgid = -1;
  pid_t session_id = -1;
  ProcessIdentity start_identity;
  std::string role;
  std::string start_identity_digest;
  std::string group_identity_digest;
  bool identity_bound = false;
  bool group_bound = false;
  bool terminal = false;
  bool reaped = false;
  bool signal_sent = false;
  bool ownership_lost = false;
  int status = 0;
};

bool EstablishIsolatedSession() {
  const pid_t pid = getpid();
  return pid >= 2 && setsid() == pid && getpgrp() == pid && getsid(0) == pid;
}

bool BindCurrentIsolatedGroup(
    const std::string& role, ProcessIdentity* identity,
    std::string* start_identity_digest, pid_t* pgid, pid_t* session_id,
    std::string* group_identity_digest) {
  const pid_t pid = getpid();
  ProcessIdentity before;
  ProcessIdentity after;
  const pid_t observed_pgid = getpgrp();
  const pid_t observed_session = getsid(0);
  if (pid < 2 || observed_pgid != pid || observed_session != pid ||
      !ReadProcessIdentity(pid, &before) ||
      !ReadProcessIdentity(pid, &after) ||
      !SameProcessStartIdentity(before, after)) {
    return false;
  }
  *identity = after;
  *start_identity_digest = ProcessStartIdentityDigest(after);
  *pgid = observed_pgid;
  *session_id = observed_session;
  *group_identity_digest = ProcessGroupIdentityDigest(
      role, pid, observed_pgid, observed_session, *start_identity_digest);
  return true;
}

void MarkChildReaped(ChildLifecycle* child, int status) {
  child->status = status;
  child->terminal = true;
  child->reaped = true;
}

bool BindDirectChildLifecycle(pid_t pid, const std::string& role,
                              const AbsoluteDeadline& deadline,
                              ChildLifecycle* child) {
  child->pid = pid;
  child->role = role;
  if (pid < 2) return false;
  for (;;) {
    int status = 0;
    pid_t waited;
    do {
      waited = waitpid(pid, &status, WNOHANG);
    } while (waited < 0 && errno == EINTR);
    if (waited == pid) {
      MarkChildReaped(child, status);
      return false;
    }
    if (waited < 0) {
      child->terminal = true;
      child->ownership_lost = errno == ECHILD;
      return false;
    }

    ProcessIdentity before;
    ProcessIdentity after;
    const bool before_read = ReadProcessIdentity(pid, &before);
    if (before_read && !child->identity_bound) {
      child->start_identity = before;
      child->start_identity_digest = ProcessStartIdentityDigest(before);
      child->identity_bound = true;
    }
    const pid_t observed_pgid = getpgid(pid);
    const pid_t observed_session = getsid(pid);
    const bool after_read = ReadProcessIdentity(pid, &after);
    if (before_read && after_read && SameProcessStartIdentity(before, after) &&
        observed_pgid == pid && observed_session == pid) {
      child->start_identity = after;
      child->start_identity_digest = ProcessStartIdentityDigest(after);
      child->identity_bound = true;
      child->pgid = observed_pgid;
      child->session_id = observed_session;
      child->group_identity_digest = ProcessGroupIdentityDigest(
          role, pid, observed_pgid, observed_session,
          child->start_identity_digest);
      child->group_bound = true;
      return true;
    }

    uint64_t remaining_ns = 0;
    if (!Remaining(deadline, &remaining_ns)) return false;
    const uint64_t pause_ns =
        remaining_ns < 1000000ULL ? remaining_ns : 1000000ULL;
    struct timespec pause = {
        static_cast<time_t>(pause_ns / 1000000000ULL),
        static_cast<long>(pause_ns % 1000000000ULL)};
    if (nanosleep(&pause, nullptr) != 0 && errno != EINTR) return false;
  }
}

bool VerifyChildTargetIdentity(const ChildLifecycle& child) {
  if (!child.identity_bound || child.pid < 2) return false;
  ProcessIdentity current;
  if (!ReadProcessIdentity(child.pid, &current) ||
      !SameProcessStartIdentity(child.start_identity, current) ||
      ProcessStartIdentityDigest(current) != child.start_identity_digest) {
    return false;
  }
  if (!child.group_bound) return true;
  const pid_t current_pgid = getpgid(child.pid);
  const pid_t current_session = getsid(child.pid);
  return current_pgid == child.pgid && current_session == child.session_id &&
         child.pgid == child.pid && child.session_id == child.pid &&
         ProcessGroupIdentityDigest(
             child.role, child.pid, current_pgid, current_session,
             child.start_identity_digest) == child.group_identity_digest;
}

bool WaitForChildExitUntil(ChildLifecycle* child,
                           const AbsoluteDeadline& deadline) {
  if (child->terminal) return child->reaped;
  for (;;) {
    int status = 0;
    pid_t result;
    do {
      result = waitpid(child->pid, &status, WNOHANG);
    } while (result < 0 && errno == EINTR);
    if (result == child->pid) {
      MarkChildReaped(child, status);
      return true;
    }
    if (result < 0) {
      child->terminal = true;
      child->ownership_lost = errno == ECHILD;
      return false;
    }
    uint64_t remaining_ns = 0;
    if (!Remaining(deadline, &remaining_ns)) return false;
    const uint64_t pause_ns =
        remaining_ns < 1000000ULL ? remaining_ns : 1000000ULL;
    struct timespec pause = {
        static_cast<time_t>(pause_ns / 1000000000ULL),
        static_cast<long>(pause_ns % 1000000000ULL)};
    if (nanosleep(&pause, nullptr) != 0 && errno != EINTR) return false;
  }
}

bool KillAndReapChild(ChildLifecycle* child) {
  if (child->terminal) return child->reaped;
  if (child->pid < 2) return false;

  int status = 0;
  pid_t observed;
  do {
    observed = waitpid(child->pid, &status, WNOHANG);
  } while (observed < 0 && errno == EINTR);
  if (observed == child->pid) {
    MarkChildReaped(child, status);
    return true;
  }
  if (observed < 0) {
    child->terminal = true;
    child->ownership_lost = errno == ECHILD;
    return false;
  }
  // A zero WNOHANG result proves this process still owns an unreaped direct
  // child. Only after that proof do start/session/group identities authorize a
  // signal, preventing a stale PID or PGID from becoming a kill target.
  if (!VerifyChildTargetIdentity(*child)) {
    do {
      observed = waitpid(child->pid, &status, WNOHANG);
    } while (observed < 0 && errno == EINTR);
    if (observed == child->pid) {
      MarkChildReaped(child, status);
      return true;
    }
    if (observed < 0) {
      child->terminal = true;
      child->ownership_lost = errno == ECHILD;
    }
    return false;
  }

  const pid_t target = child->group_bound ? -child->pgid : child->pid;
  if (kill(target, SIGKILL) != 0) {
    if (errno != ESRCH) return false;
  } else {
    child->signal_sent = true;
  }
  for (;;) {
    observed = waitpid(child->pid, &status, 0);
    if (observed == child->pid) {
      MarkChildReaped(child, status);
      return true;
    }
    if (observed < 0 && errno == EINTR) continue;
    child->terminal = true;
    child->ownership_lost = observed < 0 && errno == ECHILD;
    return false;
  }
}

struct WatchdogConfig {
  std::string contract_digest;
  std::string executable_digest;
  std::string instrument_digest;
  std::string lease_digest;
  std::string fencing_token_digest;
  uint64_t fencing_generation = 0;
  pid_t worker_pid = -1;
  std::string worker_identity_digest;
  std::string cleanup_capability_digest;
  std::string restore_digest;
  std::string semantic_digest;
  std::string provider_manifest_digest;
  std::string journal_id_digest;
  std::string profile;
  uint64_t deadman_ms = 0;
  uint64_t maximum_extension_ms = 0;
  uint64_t cleanup_timeout_ms = 0;
  std::string fixture_behavior;
};

bool IsFixtureBehavior(const std::string& value) {
  return value == "ack" || value == "stuck" || value == "partial_stuck" ||
         value == "wrong_receipt" || value == "journal_trigger_fail" ||
         value == "watchdog_stall_after_ready" ||
         value == "watchdog_stall_after_cleanup_handoff" ||
         value == "watchdog_exit_before_cleanup_guard" ||
         value == "watchdog_exit_after_cleanup_guard" ||
         value == "watchdog_block_first_journal_fsync" ||
         value == "watchdog_block_ready_output" ||
         value == "custody_late_arm_after_expiry" ||
         value == "custody_delay_arm_ack" ||
         value == "custody_expired_arm_ack" ||
         value == "custody_forged_arm_ack" ||
         value == "custody_pipe_only_arm" ||
         value == "custody_late_extend_ack" ||
         value == "custody_forged_extend_ack" ||
         value == "custody_replayed_extend_ack" ||
         value == "custody_reordered_extend_ack";
}

bool ParseWatchdogConfig(const std::vector<std::string>& fields,
                         const std::vector<unsigned char>& key,
                         WatchdogConfig* output) {
  uint64_t worker_pid = 0;
  if (!VerifySignedFields(fields, 21, key) || fields[0] != "CFG1" ||
      fields[1] != "1" || !IsDigest(fields[2]) || !IsDigest(fields[3]) ||
      !IsDigest(fields[4]) || !IsDigest(fields[5]) || !IsDigest(fields[6]) ||
      !ParseUint64(fields[7], 1, UINT32_MAX, &output->fencing_generation) ||
      !ParseUint64(fields[8], 2, INT_MAX, &worker_pid) ||
      !IsDigest(fields[9]) || !IsDigest(fields[10]) || !IsDigest(fields[11]) ||
      !IsDigest(fields[12]) || !IsDigest(fields[13]) || !IsDigest(fields[14]) ||
      !ParseUint64(fields[16], 1, kMaximumDeadmanMs, &output->deadman_ms) ||
      !ParseUint64(fields[17], 1, kMaximumDeadmanMs,
                   &output->maximum_extension_ms) ||
      !ParseUint64(fields[18], 1, kMaximumCleanupMs,
                   &output->cleanup_timeout_ms) ||
      !IsFixtureBehavior(fields[19])) {
    return false;
  }
  const std::string semantic = SemanticDigest(fields[15]);
  if (semantic.empty() || !ConstantTimeEqual(semantic, fields[12])) return false;
  output->contract_digest = fields[2];
  output->executable_digest = fields[3];
  output->instrument_digest = fields[4];
  output->lease_digest = fields[5];
  output->fencing_token_digest = fields[6];
  output->worker_pid = static_cast<pid_t>(worker_pid);
  output->worker_identity_digest = fields[9];
  output->cleanup_capability_digest = fields[10];
  output->restore_digest = fields[11];
  output->semantic_digest = fields[12];
  output->provider_manifest_digest = fields[13];
  output->journal_id_digest = fields[14];
  output->profile = fields[15];
  output->fixture_behavior = fields[19];
  return output->maximum_extension_ms >= output->deadman_ms;
}

std::string CustodyActionDigest(const WatchdogConfig& config) {
  return FramedDigest(
      kCustodyActionDomain,
      {config.contract_digest, config.executable_digest,
       config.instrument_digest, config.lease_digest,
       config.fencing_token_digest, std::to_string(config.fencing_generation),
       config.worker_identity_digest, config.cleanup_capability_digest,
       config.restore_digest, config.semantic_digest,
       config.provider_manifest_digest, config.journal_id_digest,
       config.profile});
}

class Journal {
 public:
  bool Initialize(int fd, const std::string& contract_digest) {
    struct stat status = {};
    const int flags = fcntl(fd, F_GETFL);
    if (fd != kJournalFd || fstat(fd, &status) != 0 ||
        !S_ISREG(status.st_mode) || status.st_nlink != 1 ||
        status.st_uid != geteuid() || status.st_gid != getegid() ||
        (status.st_mode & 0077) != 0 || status.st_size != 0 || flags < 0 ||
        (flags & O_ACCMODE) != O_RDWR || (flags & O_APPEND) == 0 ||
        flock(fd, LOCK_EX | LOCK_NB) != 0) {
      return false;
    }
    fd_ = fd;
    contract_digest_ = contract_digest;
    previous_digest_.assign(kDigestBytes * 2, '0');
    return true;
  }

  bool Append(const std::string& event, const std::string& reason,
              bool block_before_fsync = false) {
    if (fd_ < 0 || event.empty() || reason.empty()) return false;
    ++sequence_;
    const uint64_t now = MonotonicNanoseconds();
    if (now == 0) return false;
    const std::vector<std::string> digest_fields = {
        std::to_string(sequence_), std::to_string(now), event, reason,
        contract_digest_, previous_digest_};
    const std::string digest = FramedDigest(kJournalDomain, digest_fields);
    const std::vector<std::string> line_fields = {
        "J1", std::to_string(sequence_), std::to_string(now), event, reason,
        contract_digest_, previous_digest_, digest};
    std::string line = Join(line_fields, line_fields.size());
    line.push_back('\n');
    const bool appended = WriteAll(fd_, line);
    if (appended && block_before_fsync) {
      // Fixture-only deterministic model of an indefinitely blocked first
      // durability syscall. The independent custodian must not share this FD.
      for (;;) pause();
    }
    const bool accepted = appended && fsync(fd_) == 0;
    ZeroString(&line);
    if (!accepted) return false;
    previous_digest_ = digest;
    return true;
  }

  bool AppendWithin(const std::string& event, const std::string& reason,
                    const AbsoluteDeadline& deadline,
                    bool fail_for_fixture = false) {
    if (DeadlineExpired(deadline)) return false;
    if (fail_for_fixture) {
      // Model an append/fsync failure after sequence redemption. Later records
      // cannot accidentally form a complete, success-claiming evidence chain.
      ++sequence_;
      return false;
    }
    return Append(event, reason) && !DeadlineExpired(deadline);
  }

  bool Readback() const {
    if (fd_ < 0) return false;
    struct stat status = {};
    if (fstat(fd_, &status) != 0 || status.st_size <= 0 ||
        status.st_size > static_cast<off_t>(kMaximumJournalBytes)) {
      return false;
    }
    std::string bytes(static_cast<size_t>(status.st_size), '\0');
    size_t offset = 0;
    while (offset < bytes.size()) {
      const ssize_t count = pread(fd_, bytes.data() + offset, bytes.size() - offset,
                                  static_cast<off_t>(offset));
      if (count < 0 && errno == EINTR) continue;
      if (count <= 0) return false;
      offset += static_cast<size_t>(count);
    }
    uint64_t expected_sequence = 1;
    std::string previous(kDigestBytes * 2, '0');
    size_t start = 0;
    while (start < bytes.size()) {
      const size_t end = bytes.find('\n', start);
      if (end == std::string::npos || end == start) return false;
      const std::vector<std::string> fields = Split(bytes.substr(start, end - start));
      uint64_t sequence = 0;
      uint64_t monotonic = 0;
      if (fields.size() != 8 || fields[0] != "J1" ||
          !ParseUint64(fields[1], 1, UINT64_MAX, &sequence) ||
          !ParseUint64(fields[2], 1, UINT64_MAX, &monotonic) ||
          sequence != expected_sequence || fields[5] != contract_digest_ ||
          fields[6] != previous || !IsDigest(fields[7])) {
        return false;
      }
      const std::string digest = FramedDigest(
          kJournalDomain,
          {fields[1], fields[2], fields[3], fields[4], fields[5], fields[6]});
      if (!ConstantTimeEqual(digest, fields[7])) return false;
      previous = fields[7];
      ++expected_sequence;
      start = end + 1;
    }
    return expected_sequence - 1 == sequence_ && previous == previous_digest_;
  }

  uint64_t sequence() const { return sequence_; }
  const std::string& head_digest() const { return previous_digest_; }
  bool initialized() const { return fd_ >= 0; }

 private:
  int fd_ = -1;
  uint64_t sequence_ = 0;
  std::string contract_digest_;
  std::string previous_digest_;
};

void CloseAllExcept(const std::vector<int>& keep) {
  const int maximum = getdtablesize();
  for (int fd = 0; fd < maximum; ++fd) {
    bool retained = false;
    for (size_t index = 0; index < keep.size(); ++index) {
      if (keep[index] == fd) retained = true;
    }
    if (!retained) close(fd);
  }
}

bool SetCloseOnExec(int fd, bool enabled) {
  const int flags = fcntl(fd, F_GETFD);
  if (flags < 0) return false;
  const int next = enabled ? flags | FD_CLOEXEC : flags & ~FD_CLOEXEC;
  return fcntl(fd, F_SETFD, next) == 0;
}

void ClosePipe(int descriptors[2]) {
  for (size_t index = 0; index < 2; ++index) {
    if (descriptors[index] >= 0) {
      close(descriptors[index]);
      descriptors[index] = -1;
    }
  }
}

bool CreatePipe(int descriptors[2]) {
  descriptors[0] = -1;
  descriptors[1] = -1;
  if (pipe(descriptors) != 0) return false;
  if (!SetCloseOnExec(descriptors[0], true) ||
      !SetCloseOnExec(descriptors[1], true)) {
    ClosePipe(descriptors);
    return false;
  }
  return true;
}

struct CleanupOutcome {
  std::string outcome = "cleanup_unavailable";
  pid_t cleanup_pid = -1;
  pid_t cleanup_pgid = -1;
  pid_t cleanup_session_id = -1;
  std::string cleanup_start_identity_digest = std::string(kDigestBytes * 2, '0');
  std::string cleanup_group_identity_digest = std::string(kDigestBytes * 2, '0');
  bool separate_exec = false;
};

enum class BoundedLineResult {
  kAccepted,
  kTimeout,
  kRejected,
};

BoundedLineResult ReadLineBounded(int fd, const AbsoluteDeadline& deadline,
                                  std::string* output) {
  output->clear();
  const int flags = fcntl(fd, F_GETFL);
  if (flags < 0 || fcntl(fd, F_SETFL, flags | O_NONBLOCK) != 0) {
    return BoundedLineResult::kRejected;
  }
  for (;;) {
    char byte = 0;
    for (;;) {
      const ssize_t count = read(fd, &byte, 1);
      if (count > 0) {
        output->push_back(byte);
        if (output->size() > kMaximumLineBytes) {
          return BoundedLineResult::kRejected;
        }
        const size_t newline = output->find('\n');
        if (newline != std::string::npos) {
          output->resize(newline);
          return BoundedLineResult::kAccepted;
        }
        continue;
      }
      if (count == 0) return BoundedLineResult::kRejected;
      if (errno == EINTR) continue;
      if (errno != EAGAIN && errno != EWOULDBLOCK) {
        return BoundedLineResult::kRejected;
      }
      break;
    }

    uint64_t remaining_ns = 0;
    if (!Remaining(deadline, &remaining_ns)) return BoundedLineResult::kTimeout;
    const uint64_t remaining_ms =
        (remaining_ns + kNanosecondsPerMillisecond - 1) /
        kNanosecondsPerMillisecond;
    struct pollfd descriptor = {fd, POLLIN | POLLHUP, 0};
    const int polled = poll(&descriptor, 1, static_cast<int>(remaining_ms));
    if (polled < 0 && errno == EINTR) continue;
    if (polled < 0 ||
        (polled > 0 && (descriptor.revents & (POLLERR | POLLNVAL)) != 0)) {
      return BoundedLineResult::kRejected;
    }
    if (polled == 0) continue;
    // POLLIN and POLLHUP both return to the nonblocking read loop. This drains
    // any final bytes before classifying an EOF without a newline as rejected.
  }
}

bool WriteBytesUntil(int fd, const unsigned char* value, size_t length,
                     const AbsoluteDeadline& deadline) {
  const int flags = fcntl(fd, F_GETFL);
  if (flags < 0 || fcntl(fd, F_SETFL, flags | O_NONBLOCK) != 0) return false;
  size_t offset = 0;
  while (offset < length) {
    const ssize_t written = write(fd, value + offset, length - offset);
    if (written > 0) {
      offset += static_cast<size_t>(written);
      continue;
    }
    if (written < 0 && errno == EINTR) continue;
    if (written >= 0 || (errno != EAGAIN && errno != EWOULDBLOCK)) return false;
    uint64_t remaining_ns = 0;
    if (!Remaining(deadline, &remaining_ns)) return false;
    const uint64_t remaining_ms =
        (remaining_ns + kNanosecondsPerMillisecond - 1) /
        kNanosecondsPerMillisecond;
    struct pollfd descriptor = {fd, POLLOUT | POLLHUP, 0};
    const int polled = poll(&descriptor, 1, static_cast<int>(remaining_ms));
    if (polled < 0 && errno == EINTR) continue;
    if (polled <= 0 ||
        (descriptor.revents & (POLLERR | POLLHUP | POLLNVAL)) != 0) {
      return false;
    }
  }
  return !DeadlineExpired(deadline);
}

bool WriteLineUntil(int fd, const std::vector<std::string>& fields,
                    const AbsoluteDeadline& deadline) {
  std::string line = Join(fields, fields.size());
  line.push_back('\n');
  const bool accepted = WriteBytesUntil(
      fd, reinterpret_cast<const unsigned char*>(line.data()), line.size(), deadline);
  ZeroString(&line);
  return accepted;
}

bool WriteLineImmediate(int fd, const std::vector<std::string>& fields) {
  const int flags = fcntl(fd, F_GETFL);
  if (flags < 0 || fcntl(fd, F_SETFL, flags | O_NONBLOCK) != 0) return false;
  std::string line = Join(fields, fields.size());
  line.push_back('\n');
  size_t offset = 0;
  while (offset < line.size()) {
    const ssize_t written = write(fd, line.data() + offset, line.size() - offset);
    if (written > 0) {
      offset += static_cast<size_t>(written);
      continue;
    }
    if (written < 0 && errno == EINTR) continue;
    ZeroString(&line);
    return false;
  }
  ZeroString(&line);
  return true;
}

CleanupOutcome LaunchCleanup(const WatchdogConfig& config,
                             const std::string& executable_path,
                             const FileIdentity& executable_identity,
                             const AbsoluteDeadline& deadline,
                             std::vector<unsigned char>* command_key,
                             std::vector<unsigned char>* evidence_key) {
  CleanupOutcome output;
  int handoff[2] = {-1, -1};
  int receipt[2] = {-1, -1};
  int key_pipe[2] = {-1, -1};
  std::vector<unsigned char> cleanup_key;
  AbsoluteDeadline child_deadline;
  AbsoluteDeadline stall_observation_deadline;
  ChildLifecycle cleanup_child;
  bool terminate_child = false;
  bool handoff_stall_fixture = false;
  bool child_deadline_built = false;

  if (DeadlineExpired(deadline)) {
    output.outcome = "cleanup_timeout";
    return output;
  }
  if (!CreatePipe(handoff) || !CreatePipe(receipt) || !CreatePipe(key_pipe)) {
    output.outcome = DeadlineExpired(deadline)
        ? "cleanup_timeout" : "cleanup_pipe_rejected";
    ClosePipe(handoff);
    ClosePipe(receipt);
    ClosePipe(key_pipe);
    return output;
  }
  unsigned char cleanup_key_bytes[32];
  arc4random_buf(cleanup_key_bytes, sizeof(cleanup_key_bytes));
  cleanup_key.assign(cleanup_key_bytes,
                     cleanup_key_bytes + sizeof(cleanup_key_bytes));
  SecureZero(cleanup_key_bytes, sizeof(cleanup_key_bytes));

  std::string current_path;
  std::string current_digest;
  FileIdentity current_identity;
  if (DeadlineExpired(deadline) ||
      !SelfExecutable(&current_path, &current_digest, &current_identity) ||
      current_path != executable_path ||
      !SameFileIdentity(current_identity, executable_identity) ||
      current_digest != config.executable_digest) {
    output.outcome = DeadlineExpired(deadline)
        ? "cleanup_timeout" : "cleanup_executable_rejected";
    goto cleanup_pipes;
  }

  handoff_stall_fixture =
      config.fixture_behavior == "watchdog_stall_after_cleanup_handoff";
  child_deadline_built = handoff_stall_fixture
      ? BuildHandoffStallFixtureDeadlines(
          deadline, &child_deadline, &stall_observation_deadline)
      : BuildChildDeadline(deadline, &child_deadline);
  if (DeadlineExpired(deadline) || !child_deadline_built) {
    output.outcome = "cleanup_timeout";
    goto cleanup_pipes;
  }
  output.cleanup_pid = fork();
  if (output.cleanup_pid < 0) {
    output.outcome = DeadlineExpired(deadline)
        ? "cleanup_timeout" : "cleanup_fork_rejected";
    goto cleanup_pipes;
  }
  if (output.cleanup_pid == 0) {
    if (!EstablishIsolatedSession()) _exit(119);
    if (!cleanup_key.empty()) SecureZero(cleanup_key.data(), cleanup_key.size());
    if (command_key != nullptr && !command_key->empty()) {
      SecureZero(command_key->data(), command_key->size());
    }
    if (evidence_key != nullptr && !evidence_key->empty()) {
      SecureZero(evidence_key->data(), evidence_key->size());
    }
    if (!ArmProcessDeadline(child_deadline) ||
        dup2(handoff[0], kControlFd) != kControlFd ||
        dup2(receipt[1], kJournalFd) != kJournalFd ||
        dup2(key_pipe[0], kKeyFd) != kKeyFd ||
        !SetCloseOnExec(kControlFd, false) || !SetCloseOnExec(kJournalFd, false) ||
        !SetCloseOnExec(kKeyFd, false)) {
      _exit(120);
    }
    CloseAllExcept({kControlFd, kJournalFd, kKeyFd});
    char* const argv[] = {const_cast<char*>(executable_path.c_str()),
                          const_cast<char*>("--cleanup-worker-fixture"), nullptr};
    char* const empty_environment[] = {nullptr};
    execve(executable_path.c_str(), argv, empty_environment);
    _exit(121);
  }

  if (!BindDirectChildLifecycle(output.cleanup_pid, "cleanup_worker",
                                child_deadline, &cleanup_child)) {
    output.outcome = DeadlineExpired(deadline)
        ? "cleanup_timeout" : "cleanup_identity_rejected";
    goto cleanup_pipes;
  }
  output.cleanup_pgid = cleanup_child.pgid;
  output.cleanup_session_id = cleanup_child.session_id;
  output.cleanup_start_identity_digest = cleanup_child.start_identity_digest;
  output.cleanup_group_identity_digest = cleanup_child.group_identity_digest;

  close(handoff[0]);
  handoff[0] = -1;
  close(receipt[1]);
  receipt[1] = -1;
  close(key_pipe[0]);
  key_pipe[0] = -1;
  {
    unsigned char capability[36];
    std::memcpy(capability, "KEY1", 4);
    std::memcpy(capability + 4, cleanup_key.data(), cleanup_key.size());
    if (!WriteBytesUntil(key_pipe[1], capability, sizeof(capability), deadline)) {
      output.outcome = "cleanup_handoff_failed";
    }
    SecureZero(capability, sizeof(capability));
    close(key_pipe[1]);
    key_pipe[1] = -1;
  }
  {
    std::vector<std::string> fields = {
        "CLEAN1", "1", config.contract_digest, config.executable_digest,
        config.instrument_digest, config.lease_digest,
        config.fencing_token_digest, std::to_string(config.fencing_generation),
        config.worker_identity_digest, config.cleanup_capability_digest,
        config.restore_digest, config.semantic_digest,
        config.provider_manifest_digest, config.journal_id_digest, config.profile,
        std::to_string(child_deadline.expires), std::to_string(getpid()),
        config.fixture_behavior};
    std::string payload = Join(fields, fields.size());
    fields.emplace_back(HmacSha256(cleanup_key, payload));
    ZeroString(&payload);
    if (!WriteLineUntil(handoff[1], fields, deadline)) {
      output.outcome = "cleanup_handoff_failed";
    }
    close(handoff[1]);
    handoff[1] = -1;
  }
  // The cleanup-only child has its signed handoff and can act independently
  // before any receipt/evidence write. Reporting must never suppress safety.
  if (config.fixture_behavior == "watchdog_exit_before_cleanup_guard") {
    WriteLineUntil(kCustodyEventFd,
                   {"ORPHAN1", std::to_string(output.cleanup_pid),
                    "parent_exit_before_guard"}, deadline);
    _exit(112);
  }
  if (config.fixture_behavior == "watchdog_stall_after_cleanup_handoff") {
    WriteLineUntil(kCustodyEventFd,
                   {"ORPHAN1", std::to_string(output.cleanup_pid),
                    "parent_stall_after_handoff"}, deadline);
    const bool child_exited = WaitForChildExitUntil(
        &cleanup_child, stall_observation_deadline);
    const bool child_self_deadline_observed = child_exited &&
        ((WIFEXITED(cleanup_child.status) &&
          WEXITSTATUS(cleanup_child.status) == 124) ||
         (WIFSIGNALED(cleanup_child.status) &&
          WTERMSIG(cleanup_child.status) == SIGALRM));
    const bool observation_sent = WriteLineUntil(
        kCustodyEventFd,
        {"ORPHAN1", std::to_string(output.cleanup_pid),
         child_self_deadline_observed
             ? "cleanup_self_deadline_observed"
             : "cleanup_self_deadline_failed"},
        deadline);
    _exit(child_self_deadline_observed && observation_sent ? 114 : 115);
  }
  if (output.outcome == "cleanup_handoff_failed") {
    terminate_child = true;
  } else {
    std::string line;
    const BoundedLineResult read_result =
        ReadLineBounded(receipt[0], deadline, &line);
    if (read_result == BoundedLineResult::kTimeout) {
      output.outcome = "cleanup_timeout";
      terminate_child = true;
    } else if (read_result != BoundedLineResult::kAccepted) {
      output.outcome = "cleanup_receipt_rejected";
    } else {
      const std::vector<std::string> fields = Split(line);
      if (config.fixture_behavior == "watchdog_exit_after_cleanup_guard" &&
          VerifySignedFields(fields, 5, cleanup_key) && fields[0] == "GUARD1" &&
          fields[1] == "1" && fields[2] == config.contract_digest &&
          fields[3] == std::to_string(output.cleanup_pid)) {
        WriteLineUntil(kCustodyEventFd,
                       {"ORPHAN1", std::to_string(output.cleanup_pid),
                        "parent_exit_after_guard"}, deadline);
        _exit(113);
      }
      uint64_t cleanup_pid = 0;
      if (!VerifySignedFields(fields, 12, cleanup_key) || fields[0] != "DONE1" ||
          fields[1] != "1" || fields[2] != config.contract_digest ||
          fields[3] != config.instrument_digest ||
          fields[4] != config.lease_digest ||
          fields[5] != config.cleanup_capability_digest ||
          fields[6] != config.restore_digest || fields[7] != config.semantic_digest ||
          fields[8] != "fixture_acknowledged_rf_unknown" ||
          !ParseUint64(fields[9], 2, INT_MAX, &cleanup_pid) ||
          cleanup_pid != static_cast<uint64_t>(output.cleanup_pid) ||
          !IsDigest(fields[10])) {
        output.outcome = "cleanup_receipt_rejected";
      } else {
        const std::string receipt_digest = FramedDigest(
            kReceiptDomain,
            {fields[2], fields[5], fields[6], fields[7], fields[8], fields[9]});
        if (!ConstantTimeEqual(receipt_digest, fields[10])) {
          output.outcome = "cleanup_receipt_rejected";
        } else {
          output.outcome = "fixture_acknowledged_rf_unknown";
          output.separate_exec = true;
        }
      }
    }
    ZeroString(&line);
  }
  {
    const bool exited = !terminate_child &&
        WaitForChildExitUntil(&cleanup_child, deadline);
    bool reaped = exited;
    if (!exited) {
      reaped = KillAndReapChild(&cleanup_child);
      if (output.outcome == "fixture_acknowledged_rf_unknown") {
        output.outcome = "cleanup_timeout";
        output.separate_exec = false;
      }
      if (!reaped) output.separate_exec = false;
    } else if ((WIFEXITED(cleanup_child.status) &&
                WEXITSTATUS(cleanup_child.status) == 124) ||
               (WIFSIGNALED(cleanup_child.status) &&
                WTERMSIG(cleanup_child.status) == SIGALRM)) {
      output.outcome = "cleanup_timeout";
      output.separate_exec = false;
    } else if (!WIFEXITED(cleanup_child.status) ||
               WEXITSTATUS(cleanup_child.status) != 0) {
      if (output.outcome == "fixture_acknowledged_rf_unknown" ||
          output.outcome == "cleanup_receipt_rejected") {
        output.outcome = "cleanup_worker_failed";
        output.separate_exec = false;
      }
    }
  }

cleanup_pipes:
  ClosePipe(handoff);
  ClosePipe(receipt);
  ClosePipe(key_pipe);
  if (!cleanup_key.empty()) SecureZero(cleanup_key.data(), cleanup_key.size());
  if (cleanup_child.pid >= 2 && !cleanup_child.terminal) {
    if (!KillAndReapChild(&cleanup_child)) output.separate_exec = false;
  }
  if (DeadlineExpired(deadline)) {
    output.outcome = "cleanup_timeout";
    output.separate_exec = false;
  }
  return output;
}

struct CustodyChannels {
  pid_t pid = -1;
  int command_fd = -1;
  int receipt_fd = -1;
  std::string action_digest;
  std::string nonce;
  AbsoluteDeadline startup_deadline;
  ProcessIdentity watcher_start_identity;
  std::string watcher_start_identity_digest;
  pid_t watcher_pgid = -1;
  pid_t watcher_session_id = -1;
  std::string watcher_group_identity_digest;
  ChildLifecycle child;
};

void AppendCustodyEnvelope(std::vector<std::string>* fields,
                           const WatchdogConfig& config,
                           const CustodyChannels& channels,
                           pid_t watcher_pid) {
  fields->emplace_back(config.contract_digest);
  fields->emplace_back(channels.action_digest);
  fields->emplace_back(channels.nonce);
  fields->emplace_back(std::to_string(watcher_pid));
  fields->emplace_back(std::to_string(channels.pid));
  fields->emplace_back(std::to_string(channels.startup_deadline.expires));
  fields->emplace_back(channels.watcher_start_identity_digest);
  fields->emplace_back(std::to_string(channels.watcher_pgid));
  fields->emplace_back(std::to_string(channels.watcher_session_id));
  fields->emplace_back(channels.watcher_group_identity_digest);
  fields->emplace_back(channels.child.start_identity_digest);
  fields->emplace_back(std::to_string(channels.child.pgid));
  fields->emplace_back(std::to_string(channels.child.session_id));
  fields->emplace_back(channels.child.group_identity_digest);
}

bool ExactCustodyEnvelope(const std::vector<std::string>& fields,
                          const WatchdogConfig& config,
                          const CustodyChannels& channels,
                          pid_t watcher_pid) {
  return fields[2] == config.contract_digest &&
         fields[3] == channels.action_digest && fields[4] == channels.nonce &&
         fields[5] == std::to_string(watcher_pid) &&
         fields[6] == std::to_string(channels.pid) &&
         fields[7] == std::to_string(channels.startup_deadline.expires) &&
         fields[8] == channels.watcher_start_identity_digest &&
         fields[9] == std::to_string(channels.watcher_pgid) &&
         fields[10] == std::to_string(channels.watcher_session_id) &&
         fields[11] == channels.watcher_group_identity_digest &&
         fields[12] == channels.child.start_identity_digest &&
         fields[13] == std::to_string(channels.child.pgid) &&
         fields[14] == std::to_string(channels.child.session_id) &&
         fields[15] == channels.child.group_identity_digest;
}

void AppendCustodyBindings(std::vector<std::string>* fields,
                           const WatchdogConfig& config) {
  fields->emplace_back(config.instrument_digest);
  fields->emplace_back(config.lease_digest);
  fields->emplace_back(config.fencing_token_digest);
  fields->emplace_back(std::to_string(config.fencing_generation));
  fields->emplace_back(config.worker_identity_digest);
  fields->emplace_back(config.cleanup_capability_digest);
  fields->emplace_back(config.restore_digest);
  fields->emplace_back(config.semantic_digest);
}

bool ExactCustodyBindings(const std::vector<std::string>& fields,
                          size_t offset, const WatchdogConfig& config) {
  return fields[offset] == config.instrument_digest &&
         fields[offset + 1] == config.lease_digest &&
         fields[offset + 2] == config.fencing_token_digest &&
         fields[offset + 3] == std::to_string(config.fencing_generation) &&
         fields[offset + 4] == config.worker_identity_digest &&
         fields[offset + 5] == config.cleanup_capability_digest &&
         fields[offset + 6] == config.restore_digest &&
         fields[offset + 7] == config.semantic_digest;
}

void SignFields(std::vector<std::string>* fields,
                const std::vector<unsigned char>& key) {
  std::string payload = Join(*fields, fields->size());
  fields->emplace_back(HmacSha256(key, payload));
  ZeroString(&payload);
}

bool SetCustodyQueueDeadline(int queue, const AbsoluteDeadline& deadline) {
  uint64_t remaining_ns = 0;
  if (!Remaining(deadline, &remaining_ns) || remaining_ns > INT64_MAX) {
    return false;
  }
  struct kevent change;
  EV_SET(&change, 1, EVFILT_TIMER, EV_ADD | EV_ENABLE | EV_ONESHOT,
         NOTE_NSECONDS, static_cast<intptr_t>(remaining_ns), nullptr);
  return kevent(queue, &change, 1, nullptr, 0, nullptr) == 0;
}

bool ValidCustodyWindow(uint64_t issued, uint64_t valid_until,
                        uint64_t maximum_ms) {
  const uint64_t now = MonotonicNanoseconds();
  const uint64_t maximum = maximum_ms * kNanosecondsPerMillisecond;
  return now != 0 && issued <= now && valid_until >= now &&
         valid_until >= issued && valid_until - issued <= maximum &&
         now - issued <= maximum && valid_until - now <= maximum;
}

void DelayMilliseconds(uint64_t milliseconds) {
  struct timespec delay = {
      static_cast<time_t>(milliseconds / 1000ULL),
      static_cast<long>((milliseconds % 1000ULL) * 1000000ULL)};
  while (nanosleep(&delay, &delay) != 0 && errno == EINTR) {}
}

void DelayPast(uint64_t monotonic_deadline) {
  for (;;) {
    const uint64_t now = MonotonicNanoseconds();
    if (now == 0 || now > monotonic_deadline) return;
    uint64_t remaining = monotonic_deadline - now;
    if (remaining < UINT64_MAX - 2000000ULL) remaining += 2000000ULL;
    struct timespec delay = {
        static_cast<time_t>(remaining / 1000000000ULL),
        static_cast<long>(remaining % 1000000000ULL)};
    if (nanosleep(&delay, nullptr) == 0) return;
    if (errno != EINTR) return;
  }
}

bool EmitCustodyAcceptance(
    const WatchdogConfig& config, const CustodyChannels& channels,
    pid_t watcher_pid, int receipt_fd,
    const std::vector<unsigned char>& evidence_key, bool arm,
    uint64_t sequence, uint64_t issued, uint64_t valid_until) {
  const uint64_t accepted_at = MonotonicNanoseconds();
  if (accepted_at == 0) return false;
  if (arm && config.fixture_behavior == "custody_delay_arm_ack") {
    DelayMilliseconds(75);
  }
  if (!arm && config.fixture_behavior == "custody_late_extend_ack") {
    DelayPast(valid_until);
  }
  if (arm && config.fixture_behavior == "custody_pipe_only_arm") {
    return true;
  }

  uint64_t evidence_sequence = sequence;
  uint64_t evidence_valid_until = valid_until;
  if (arm && config.fixture_behavior == "custody_expired_arm_ack") {
    evidence_valid_until = issued > 1 ? issued - 1 : 1;
  }
  if (!arm && config.fixture_behavior == "custody_replayed_extend_ack") {
    evidence_sequence = sequence > 0 ? sequence - 1 : 0;
  }
  if (!arm && config.fixture_behavior == "custody_reordered_extend_ack") {
    evidence_sequence = sequence == UINT64_MAX ? 0 : sequence + 1;
  }

  std::vector<std::string> fields = {
      arm ? "CUSTODY_ARMED1" : "CUSTODY_EXTENDED1", "1"};
  AppendCustodyEnvelope(&fields, config, channels, watcher_pid);
  fields.emplace_back(std::to_string(evidence_sequence));
  fields.emplace_back(std::to_string(issued));
  fields.emplace_back(std::to_string(evidence_valid_until));
  fields.emplace_back(std::to_string(accepted_at));
  fields.emplace_back(std::to_string(evidence_valid_until));
  AppendCustodyBindings(&fields, config);
  SignFields(&fields, evidence_key);
  if ((arm && config.fixture_behavior == "custody_forged_arm_ack") ||
      (!arm && config.fixture_behavior == "custody_forged_extend_ack")) {
    std::string& signature = fields.back();
    signature[0] = signature[0] == '0' ? '1' : '0';
  }
  const AbsoluteDeadline write_deadline = {valid_until, true};
  if (!arm && config.fixture_behavior == "custody_late_extend_ack") {
    return WriteLineImmediate(receipt_fd, fields);
  }
  return WriteLineUntil(receipt_fd, fields, write_deadline);
}

bool ReceiveCustodyAcceptance(
    const WatchdogConfig& config, const CustodyChannels& channels,
    const std::vector<unsigned char>& evidence_key, bool arm,
    uint64_t sequence, uint64_t issued, uint64_t valid_until,
    const AbsoluteDeadline& deadline,
    std::vector<std::string>* acceptance) {
  std::string line;
  const BoundedLineResult read_result =
      ReadLineBounded(channels.receipt_fd, deadline, &line);
  const std::vector<std::string> fields = Split(line);
  uint64_t parsed_sequence = 0;
  uint64_t parsed_issued = 0;
  uint64_t parsed_valid_until = 0;
  uint64_t accepted_at = 0;
  uint64_t accepted_deadline = 0;
  const uint64_t now = MonotonicNanoseconds();
  const bool accepted = read_result == BoundedLineResult::kAccepted &&
      fields.size() == kCustodyAcceptanceFieldCount &&
      VerifySignedFields(fields, kCustodyAcceptanceFieldCount, evidence_key) &&
      fields[0] == (arm ? "CUSTODY_ARMED1" : "CUSTODY_EXTENDED1") &&
      fields[1] == "1" &&
      ExactCustodyEnvelope(fields, config, channels, getpid()) &&
      ParseUint64(fields[kCustodyEnvelopeEnd], 0, UINT64_MAX,
                  &parsed_sequence) &&
      ParseUint64(fields[kCustodyEnvelopeEnd + 1], 1, UINT64_MAX,
                  &parsed_issued) &&
      ParseUint64(fields[kCustodyEnvelopeEnd + 2], 1, UINT64_MAX,
                  &parsed_valid_until) &&
      ParseUint64(fields[kCustodyEnvelopeEnd + 3], 1, UINT64_MAX,
                  &accepted_at) &&
      ParseUint64(fields[kCustodyEnvelopeEnd + 4], 1, UINT64_MAX,
                  &accepted_deadline) &&
      parsed_sequence == sequence && parsed_issued == issued &&
      parsed_valid_until == valid_until && accepted_deadline == valid_until &&
      accepted_at >= issued && accepted_at <= valid_until &&
      now != 0 && accepted_at <= now && now <= valid_until &&
      ExactCustodyBindings(fields, kCustodyEnvelopeEnd + 5, config) &&
      !DeadlineExpired(deadline);
  ZeroString(&line);
  if (!accepted) return false;
  *acceptance = fields;
  return true;
}

int CompleteCustodyRedemption(
    const WatchdogConfig& config, const CustodyChannels& channels,
    pid_t watcher_pid, int receipt_fd,
    std::vector<unsigned char>* command_key,
    std::vector<unsigned char>* evidence_key, const std::string& trigger_reason,
    uint64_t last_sequence, const AbsoluteDeadline& deadline) {
  bool deadline_healthy = deadline.valid && ArmWatcherDeadline(deadline);
  CleanupOutcome cleanup;
  std::string executable_path;
  std::string executable_digest;
  FileIdentity executable_identity;
  if (!deadline.valid || DeadlineExpired(deadline)) {
    cleanup.outcome = "cleanup_timeout";
    deadline_healthy = false;
  } else if (!SelfExecutable(&executable_path, &executable_digest,
                             &executable_identity) ||
             executable_digest != config.executable_digest) {
    cleanup.outcome = DeadlineExpired(deadline)
        ? "cleanup_timeout" : "cleanup_executable_rejected";
  } else {
    cleanup = LaunchCleanup(config, executable_path, executable_identity,
                            deadline, command_key, evidence_key);
  }
  if (DeadlineExpired(deadline)) {
    cleanup.outcome = "cleanup_timeout";
    cleanup.separate_exec = false;
    deadline_healthy = false;
  }

  std::vector<std::string> evidence = {"CUSTODY1", "1"};
  AppendCustodyEnvelope(&evidence, config, channels, watcher_pid);
  evidence.emplace_back(trigger_reason);
  evidence.emplace_back(std::to_string(last_sequence));
  evidence.emplace_back(cleanup.outcome);
  evidence.emplace_back("unknown");
  evidence.emplace_back("quarantined");
  evidence.emplace_back(std::to_string(cleanup.cleanup_pid));
  evidence.emplace_back(cleanup.separate_exec ? "true" : "false");
  evidence.emplace_back(cleanup.cleanup_start_identity_digest);
  evidence.emplace_back(std::to_string(cleanup.cleanup_pgid));
  evidence.emplace_back(std::to_string(cleanup.cleanup_session_id));
  evidence.emplace_back(cleanup.cleanup_group_identity_digest);
  SignFields(&evidence, *evidence_key);
  const bool event_sent = deadline.valid && !DeadlineExpired(deadline) &&
      WriteLineUntil(kCustodyEventFd, evidence, deadline);
  const bool receipt_sent = deadline.valid && !DeadlineExpired(deadline) &&
      WriteLineUntil(receipt_fd, evidence, deadline);
  const bool within_deadline = deadline.valid && !DeadlineExpired(deadline);
  DisarmProcessDeadline();
  return event_sent && receipt_sent && deadline_healthy && within_deadline
      ? 0 : 85;
}

int CleanupCustodianMain(
    const WatchdogConfig& config, const CustodyChannels& channels,
    pid_t watcher_pid, int command_fd,
    int receipt_fd, std::vector<unsigned char>* command_key,
    std::vector<unsigned char>* evidence_key,
    const AbsoluteDeadline& startup_deadline) {
  close(STDIN_FILENO);
  close(STDOUT_FILENO);
  close(STDERR_FILENO);
  close(kJournalFd);
  const int command_flags = fcntl(command_fd, F_GETFL);
  if (command_flags < 0 ||
      fcntl(command_fd, F_SETFL, command_flags | O_NONBLOCK) != 0) {
    return 88;
  }

  const int queue = kqueue();
  bool registered = queue >= 0 && getppid() == watcher_pid;
  if (registered) {
    struct kevent changes[3];
    EV_SET(&changes[0], static_cast<uintptr_t>(watcher_pid), EVFILT_PROC,
           EV_ADD | EV_ENABLE | EV_CLEAR, NOTE_EXIT, 0, nullptr);
    EV_SET(&changes[1], static_cast<uintptr_t>(kControlFd), EVFILT_READ,
           EV_ADD | EV_ENABLE | EV_CLEAR, 0, 0, nullptr);
    EV_SET(&changes[2], static_cast<uintptr_t>(command_fd), EVFILT_READ,
           EV_ADD | EV_ENABLE | EV_CLEAR, 0, 0, nullptr);
    registered = kevent(queue, changes, 3, nullptr, 0, nullptr) == 0 &&
                 getppid() == watcher_pid &&
                 SetCustodyQueueDeadline(queue, startup_deadline);
  }
  if (!registered) {
    if (queue >= 0) close(queue);
    return 89;
  }

  std::vector<std::string> ready = {"CUSTODY_READY1", "1"};
  AppendCustodyEnvelope(&ready, config, channels, watcher_pid);
  SignFields(&ready, *command_key);
  if (!WriteLineUntil(receipt_fd, ready, startup_deadline)) {
    close(queue);
    return 90;
  }

  bool armed = false;
  uint64_t last_sequence = 0;
  AbsoluteDeadline custody_deadline = startup_deadline;
  std::string receive_buffer;
  std::string trigger_reason;
  AbsoluteDeadline trigger_deadline;
  for (;;) {
    if (DeadlineExpired(custody_deadline)) {
      trigger_reason = armed ? "deadman_timeout" : "startup_timeout";
      break;
    }
    struct kevent events[4];
    const int count = kevent(queue, nullptr, 0, events, 4, nullptr);
    if (count < 0 && errno == EINTR) continue;
    if (count < 0) {
      trigger_reason = "custody_observation_failed";
      break;
    }
    for (int index = 0; index < count && trigger_reason.empty(); ++index) {
      const struct kevent& event = events[index];
      if (event.filter == EVFILT_PROC) {
        trigger_reason = "watchdog_process_exit";
        break;
      }
      if (event.filter == EVFILT_TIMER) {
        trigger_reason = armed ? "deadman_timeout" : "startup_timeout";
        break;
      }
      if (event.filter != EVFILT_READ) continue;
      if (event.ident == static_cast<uintptr_t>(kControlFd)) {
        // The custodian shares only the read-side lifecycle capability. It must
        // never consume configuration or heartbeat bytes.
        if ((event.flags & EV_EOF) != 0) {
          trigger_reason = "control_channel_closed";
        }
        continue;
      }
      if (event.ident != static_cast<uintptr_t>(command_fd)) continue;
      char bytes[1024];
      for (;;) {
        const ssize_t read_count = read(command_fd, bytes, sizeof(bytes));
        if (read_count < 0 && errno == EINTR) continue;
        if (read_count < 0 &&
            (errno == EAGAIN || errno == EWOULDBLOCK)) break;
        if (read_count == 0) {
          trigger_reason = "custody_channel_closed";
          break;
        }
        if (read_count < 0) {
          trigger_reason = "custody_channel_failed";
          break;
        }
        receive_buffer.append(bytes, static_cast<size_t>(read_count));
        if (receive_buffer.size() > kMaximumLineBytes) {
          trigger_reason = "custody_protocol_rejected";
          break;
        }
        size_t newline;
        while (trigger_reason.empty() &&
               (newline = receive_buffer.find('\n')) != std::string::npos) {
          std::string line = receive_buffer.substr(0, newline);
          receive_buffer.erase(0, newline + 1);
          const std::vector<std::string> fields = Split(line);
          ZeroString(&line);
          if (DeadlineExpired(custody_deadline)) {
            trigger_reason = armed ? "deadman_timeout" : "startup_timeout";
            break;
          }
          const bool arm = !fields.empty() && fields[0] == "CUSTODY_ARM1";
          const bool extend = !fields.empty() &&
                              fields[0] == "CUSTODY_EXTEND1";
          const bool trigger = !fields.empty() &&
                               fields[0] == "CUSTODY_TRIGGER1";
          if (arm) {
            uint64_t issued = 0;
            uint64_t valid_until = 0;
            if (armed ||
                !VerifySignedFields(
                    fields,
                    kCustodyEnvelopeEnd + 2 + kCustodyBindingFieldCount + 1,
                    *command_key) ||
                fields[1] != "1" ||
                !ExactCustodyEnvelope(fields, config, channels, watcher_pid) ||
                !ParseUint64(fields[kCustodyEnvelopeEnd], 1, UINT64_MAX,
                             &issued) ||
                !ParseUint64(fields[kCustodyEnvelopeEnd + 1], 1, UINT64_MAX,
                             &valid_until) ||
                !ExactCustodyBindings(fields, kCustodyEnvelopeEnd + 2,
                                      config) ||
                !ValidCustodyWindow(issued, valid_until, config.deadman_ms)) {
              trigger_reason = "custody_protocol_rejected";
              break;
            }
            const AbsoluteDeadline runtime_deadline = {valid_until, true};
            if (!SetCustodyQueueDeadline(queue, runtime_deadline)) {
              trigger_reason = "custody_deadline_rejected";
              break;
            }
            custody_deadline = runtime_deadline;
            armed = true;
            if (!EmitCustodyAcceptance(
                    config, channels, watcher_pid, receipt_fd, *evidence_key,
                    true, 0, issued, valid_until)) {
              trigger_reason = "custody_ack_delivery_failed";
              break;
            }
          } else if (extend) {
            uint64_t sequence = 0;
            uint64_t issued = 0;
            uint64_t valid_until = 0;
            if (!armed ||
                !VerifySignedFields(
                    fields,
                    kCustodyEnvelopeEnd + 3 + kCustodyBindingFieldCount + 1,
                    *command_key) ||
                fields[1] != "1" ||
                !ExactCustodyEnvelope(fields, config, channels, watcher_pid) ||
                !ParseUint64(fields[kCustodyEnvelopeEnd], 1, UINT64_MAX,
                             &sequence) ||
                sequence != last_sequence + 1 ||
                !ParseUint64(fields[kCustodyEnvelopeEnd + 1], 1, UINT64_MAX,
                             &issued) ||
                !ParseUint64(fields[kCustodyEnvelopeEnd + 2], 1, UINT64_MAX,
                             &valid_until) ||
                !ExactCustodyBindings(fields, kCustodyEnvelopeEnd + 3,
                                      config) ||
                !ValidCustodyWindow(issued, valid_until,
                                    config.maximum_extension_ms)) {
              trigger_reason = "custody_protocol_rejected";
              break;
            }
            const AbsoluteDeadline runtime_deadline = {valid_until, true};
            if (!SetCustodyQueueDeadline(queue, runtime_deadline)) {
              trigger_reason = "custody_deadline_rejected";
              break;
            }
            custody_deadline = runtime_deadline;
            last_sequence = sequence;
            if (!EmitCustodyAcceptance(
                    config, channels, watcher_pid, receipt_fd, *evidence_key,
                    false, sequence, issued, valid_until)) {
              trigger_reason = "custody_ack_delivery_failed";
              break;
            }
          } else if (trigger) {
            uint64_t sequence = 0;
            uint64_t deadline_value = 0;
            uint64_t remaining_ns = 0;
            if (!VerifySignedFields(
                    fields,
                    kCustodyEnvelopeEnd + 3 + kCustodyBindingFieldCount + 1,
                    *command_key) ||
                fields[1] != "1" ||
                !ExactCustodyEnvelope(fields, config, channels, watcher_pid) ||
                !IsReasonCode(fields[kCustodyEnvelopeEnd]) ||
                !ParseUint64(fields[kCustodyEnvelopeEnd + 1], 0, UINT64_MAX,
                             &sequence) ||
                !ParseUint64(fields[kCustodyEnvelopeEnd + 2], 1, UINT64_MAX,
                             &deadline_value) ||
                !ExactCustodyBindings(fields, kCustodyEnvelopeEnd + 3,
                                      config)) {
              trigger_reason = "custody_protocol_rejected";
              break;
            }
            trigger_deadline = {deadline_value, true};
            if (!Remaining(trigger_deadline, &remaining_ns) ||
                remaining_ns >
                    config.cleanup_timeout_ms * kNanosecondsPerMillisecond) {
              trigger_reason = "custody_deadline_rejected";
              trigger_deadline = {};
              break;
            }
            last_sequence = sequence;
            trigger_reason = fields[kCustodyEnvelopeEnd];
          } else {
            trigger_reason = "custody_protocol_rejected";
          }
        }
        if (!trigger_reason.empty() ||
            static_cast<size_t>(read_count) < sizeof(bytes)) break;
      }
    }
    if (!trigger_reason.empty()) break;
  }
  close(queue);
  if (!trigger_deadline.valid) {
    BuildAbsoluteDeadline(config.cleanup_timeout_ms, &trigger_deadline);
  }
  return CompleteCustodyRedemption(
      config, channels, watcher_pid, receipt_fd, command_key, evidence_key,
      trigger_reason.empty() ? "custody_unknown_trigger" : trigger_reason,
      last_sequence, trigger_deadline);
}

bool StartCleanupCustodian(
    const WatchdogConfig& config, std::vector<unsigned char>* watcher_key,
    std::vector<unsigned char>* command_key,
    std::vector<unsigned char>* evidence_key, CustodyChannels* channels) {
  int command[2] = {-1, -1};
  int receipt[2] = {-1, -1};
  AbsoluteDeadline startup_deadline;
  const bool injected_block =
      config.fixture_behavior == "watchdog_block_first_journal_fsync" ||
      config.fixture_behavior == "watchdog_block_ready_output";
  const bool injected_expiry =
      config.fixture_behavior == "custody_late_arm_after_expiry";
  const uint64_t startup_custody_ms = injected_block
      ? kInjectedBlockedStartupCustodyMs
      : injected_expiry ? kInjectedExpiredStartupCustodyMs : kStartupCustodyMs;
  if (!BuildAbsoluteDeadline(
          startup_custody_ms, &startup_deadline) ||
      !CreatePipe(command) || !CreatePipe(receipt)) {
    ClosePipe(command);
    ClosePipe(receipt);
    return false;
  }
  channels->startup_deadline = startup_deadline;
  channels->action_digest = CustodyActionDigest(config);
  if (!BindCurrentIsolatedGroup(
          "watchdog_control", &channels->watcher_start_identity,
          &channels->watcher_start_identity_digest, &channels->watcher_pgid,
          &channels->watcher_session_id,
          &channels->watcher_group_identity_digest)) {
    ClosePipe(command);
    ClosePipe(receipt);
    return false;
  }
  unsigned char nonce_bytes[16];
  arc4random_buf(nonce_bytes, sizeof(nonce_bytes));
  channels->nonce = Hex(nonce_bytes, sizeof(nonce_bytes));
  SecureZero(nonce_bytes, sizeof(nonce_bytes));
  *command_key = DeriveCustodyKey(
      *watcher_key, kCustodyCommandKeyDomain, config.contract_digest);
  *evidence_key = DeriveCustodyKey(
      *watcher_key, kCustodyEvidenceKeyDomain, config.contract_digest);
  channels->pid = fork();
  if (channels->pid < 0) {
    ClosePipe(command);
    ClosePipe(receipt);
    return false;
  }
  if (channels->pid == 0) {
    if (!EstablishIsolatedSession()) _exit(91);
    CustodyChannels child_channels = *channels;
    child_channels.pid = getpid();
    child_channels.child = {};
    child_channels.child.pid = getpid();
    child_channels.child.role = "cleanup_custodian";
    if (!BindCurrentIsolatedGroup(
            child_channels.child.role, &child_channels.child.start_identity,
            &child_channels.child.start_identity_digest,
            &child_channels.child.pgid, &child_channels.child.session_id,
            &child_channels.child.group_identity_digest)) {
      _exit(92);
    }
    child_channels.child.identity_bound = true;
    child_channels.child.group_bound = true;
    close(command[1]);
    close(receipt[0]);
    if (watcher_key != nullptr && !watcher_key->empty()) {
      SecureZero(watcher_key->data(), watcher_key->size());
    }
    const int result = CleanupCustodianMain(
        config, child_channels, getppid(), command[0], receipt[1], command_key,
        evidence_key, startup_deadline);
    if (!command_key->empty()) {
      SecureZero(command_key->data(), command_key->size());
    }
    if (!evidence_key->empty()) {
      SecureZero(evidence_key->data(), evidence_key->size());
    }
    _exit(result);
  }
  if (!BindDirectChildLifecycle(channels->pid, "cleanup_custodian",
                                startup_deadline, &channels->child)) {
    ClosePipe(command);
    ClosePipe(receipt);
    if (!channels->child.terminal) KillAndReapChild(&channels->child);
    channels->pid = -1;
    return false;
  }
  close(command[0]);
  close(receipt[1]);
  close(kCustodyEventFd);
  channels->command_fd = command[1];
  channels->receipt_fd = receipt[0];
  std::string line;
  const BoundedLineResult read_result =
      ReadLineBounded(channels->receipt_fd, startup_deadline, &line);
  const std::vector<std::string> fields = Split(line);
  const bool ready = read_result == BoundedLineResult::kAccepted &&
      VerifySignedFields(fields, kCustodyEnvelopeEnd + 1, *command_key) &&
      fields[0] == "CUSTODY_READY1" && fields[1] == "1" &&
      ExactCustodyEnvelope(fields, config, *channels, getpid());
  ZeroString(&line);
  if (!ready) {
    close(channels->command_fd);
    close(channels->receipt_fd);
    channels->command_fd = -1;
    channels->receipt_fd = -1;
    if (channels->pid >= 2) {
      KillAndReapChild(&channels->child);
      channels->pid = -1;
    }
    return false;
  }
  return true;
}

bool SendCustodyArm(const WatchdogConfig& config,
                    const CustodyChannels& channels,
                    const std::vector<unsigned char>& command_key,
                    const std::vector<unsigned char>& evidence_key,
                    uint64_t issued, uint64_t valid_until,
                    const AbsoluteDeadline& write_deadline,
                    std::vector<std::string>* acceptance) {
  std::vector<std::string> fields = {
      "CUSTODY_ARM1", "1"};
  AppendCustodyEnvelope(&fields, config, channels, getpid());
  fields.emplace_back(std::to_string(issued));
  fields.emplace_back(std::to_string(valid_until));
  AppendCustodyBindings(&fields, config);
  SignFields(&fields, command_key);
  return WriteLineUntil(channels.command_fd, fields, write_deadline) &&
      ReceiveCustodyAcceptance(config, channels, evidence_key, true, 0,
                               issued, valid_until, write_deadline,
                               acceptance);
}

bool SendCustodyExtend(const WatchdogConfig& config,
                       const CustodyChannels& channels,
                       const std::vector<unsigned char>& command_key,
                       const std::vector<unsigned char>& evidence_key,
                       uint64_t sequence, uint64_t issued,
                       uint64_t valid_until,
                       std::vector<std::string>* acceptance) {
  const AbsoluteDeadline write_deadline = {valid_until, true};
  std::vector<std::string> fields = {
      "CUSTODY_EXTEND1", "1"};
  AppendCustodyEnvelope(&fields, config, channels, getpid());
  fields.emplace_back(std::to_string(sequence));
  fields.emplace_back(std::to_string(issued));
  fields.emplace_back(std::to_string(valid_until));
  AppendCustodyBindings(&fields, config);
  SignFields(&fields, command_key);
  return WriteLineUntil(channels.command_fd, fields, write_deadline) &&
      ReceiveCustodyAcceptance(config, channels, evidence_key, false,
                               sequence, issued, valid_until, write_deadline,
                               acceptance);
}

int RedeemCleanupAfterContract(
    const WatchdogConfig& config, std::vector<unsigned char>* watcher_key,
    const std::vector<unsigned char>& command_key,
    const std::vector<unsigned char>& evidence_key, CustodyChannels* channels,
    Journal* journal, const std::string& trigger_reason,
    uint64_t last_sequence) {
  AbsoluteDeadline deadline;
  const bool deadline_valid =
      BuildAbsoluteDeadline(config.cleanup_timeout_ms, &deadline);
  AbsoluteDeadline custody_deadline;
  const bool custody_deadline_valid =
      deadline_valid && BuildChildDeadline(deadline, &custody_deadline);
  bool evidence_healthy = journal != nullptr && journal->initialized();
  if (deadline_valid && !ArmWatcherDeadline(deadline)) evidence_healthy = false;
  if (!custody_deadline_valid) evidence_healthy = false;

  bool trigger_sent = false;
  if (custody_deadline_valid && channels != nullptr &&
      channels->command_fd >= 0) {
    std::vector<std::string> fields = {
        "CUSTODY_TRIGGER1", "1"};
    AppendCustodyEnvelope(&fields, config, *channels, getpid());
    fields.emplace_back(trigger_reason);
    fields.emplace_back(std::to_string(last_sequence));
    fields.emplace_back(std::to_string(custody_deadline.expires));
    AppendCustodyBindings(&fields, config);
    SignFields(&fields, command_key);
    trigger_sent = WriteLineUntil(
        channels->command_fd, fields, custody_deadline);
    if (!trigger_sent) {
      close(channels->command_fd);
      channels->command_fd = -1;
    }
  }
  if (watcher_key != nullptr && !watcher_key->empty()) {
    SecureZero(watcher_key->data(), watcher_key->size());
  }

  const bool injected_failure =
      config.fixture_behavior == "journal_trigger_fail";
  if (journal == nullptr || !journal->initialized() || !deadline_valid ||
      !journal->AppendWithin("cleanup_triggered", trigger_reason, deadline,
                             injected_failure)) {
    evidence_healthy = false;
  }

  CleanupOutcome cleanup;
  std::string custody_reason = trigger_reason;
  pid_t custody_pid = channels == nullptr ? -1 : channels->pid;
  bool custody_receipt = false;
  if (deadline_valid && channels != nullptr && channels->receipt_fd >= 0) {
    std::string line;
    const BoundedLineResult read_result =
        ReadLineBounded(channels->receipt_fd, deadline, &line);
    const std::vector<std::string> fields = Split(line);
    uint64_t receipt_sequence = 0;
    uint64_t parsed_custody_pid = 0;
    uint64_t parsed_watcher_pid = 0;
    uint64_t parsed_cleanup_pid = 0;
    uint64_t parsed_cleanup_pgid = 0;
    uint64_t parsed_cleanup_session = 0;
    if (read_result == BoundedLineResult::kAccepted &&
        VerifySignedFields(fields,
                           kCustodyEnvelopeEnd + 12,
                           evidence_key) &&
        fields[0] == "CUSTODY1" && fields[1] == "1" &&
        ExactCustodyEnvelope(fields, config, *channels, getpid()) &&
        IsReasonCode(fields[kCustodyEnvelopeEnd]) &&
        ParseUint64(fields[kCustodyEnvelopeEnd + 1], 0, UINT64_MAX,
                    &receipt_sequence) &&
        IsReasonCode(fields[kCustodyEnvelopeEnd + 2]) &&
        fields[kCustodyEnvelopeEnd + 3] == "unknown" &&
        fields[kCustodyEnvelopeEnd + 4] == "quarantined" &&
        ParseUint64(fields[6], 2, INT_MAX, &parsed_custody_pid) &&
        ParseUint64(fields[5], 2, INT_MAX, &parsed_watcher_pid) &&
        (fields[kCustodyEnvelopeEnd + 5] == "-1" ||
         ParseUint64(fields[kCustodyEnvelopeEnd + 5], 2, INT_MAX,
                     &parsed_cleanup_pid)) &&
        (fields[kCustodyEnvelopeEnd + 6] == "true" ||
         fields[kCustodyEnvelopeEnd + 6] == "false") &&
        IsDigest(fields[kCustodyEnvelopeEnd + 7]) &&
        (fields[kCustodyEnvelopeEnd + 8] == "-1" ||
         ParseUint64(fields[kCustodyEnvelopeEnd + 8], 2, INT_MAX,
                     &parsed_cleanup_pgid)) &&
        (fields[kCustodyEnvelopeEnd + 9] == "-1" ||
         ParseUint64(fields[kCustodyEnvelopeEnd + 9], 2, INT_MAX,
                     &parsed_cleanup_session)) &&
        IsDigest(fields[kCustodyEnvelopeEnd + 10]) &&
        parsed_custody_pid == static_cast<uint64_t>(channels->pid) &&
        parsed_watcher_pid == static_cast<uint64_t>(getpid()) &&
        receipt_sequence == last_sequence &&
        ((parsed_cleanup_pid == 0 && parsed_cleanup_pgid == 0 &&
          parsed_cleanup_session == 0) ||
         (parsed_cleanup_pid == parsed_cleanup_pgid &&
          parsed_cleanup_pid == parsed_cleanup_session))) {
      custody_receipt = true;
      custody_reason = fields[kCustodyEnvelopeEnd];
      cleanup.outcome = fields[kCustodyEnvelopeEnd + 2];
      cleanup.cleanup_pid = fields[kCustodyEnvelopeEnd + 5] == "-1"
          ? -1 : static_cast<pid_t>(parsed_cleanup_pid);
      cleanup.separate_exec = fields[kCustodyEnvelopeEnd + 6] == "true";
      cleanup.cleanup_start_identity_digest =
          fields[kCustodyEnvelopeEnd + 7];
      cleanup.cleanup_pgid = parsed_cleanup_pgid == 0
          ? -1 : static_cast<pid_t>(parsed_cleanup_pgid);
      cleanup.cleanup_session_id = parsed_cleanup_session == 0
          ? -1 : static_cast<pid_t>(parsed_cleanup_session);
      cleanup.cleanup_group_identity_digest =
          fields[kCustodyEnvelopeEnd + 10];
    } else {
      cleanup.outcome = read_result == BoundedLineResult::kTimeout
          ? "cleanup_timeout" : "custody_receipt_rejected";
    }
    ZeroString(&line);
  } else {
    cleanup.outcome = "cleanup_custodian_unavailable";
  }
  if (!trigger_sent && !custody_receipt) evidence_healthy = false;

  int custody_status = 0;
  bool custody_reaped = false;
  if (channels != nullptr && channels->pid >= 2 && deadline_valid) {
    custody_reaped = WaitForChildExitUntil(&channels->child, deadline);
    if (!custody_reaped) {
      KillAndReapChild(&channels->child);
    }
    custody_status = channels->child.status;
    channels->pid = -1;
  }
  if (!custody_reaped || !WIFEXITED(custody_status) ||
      WEXITSTATUS(custody_status) != 0) {
    if (cleanup.outcome == "fixture_acknowledged_rf_unknown") {
      cleanup.outcome = "cleanup_custodian_failed";
      cleanup.separate_exec = false;
    }
    evidence_healthy = false;
  }
  if (!deadline_valid || DeadlineExpired(deadline)) {
    cleanup.outcome = "cleanup_timeout";
    cleanup.separate_exec = false;
    evidence_healthy = false;
  }
  if (journal == nullptr || !journal->initialized() || !deadline_valid ||
      !journal->AppendWithin("cleanup_finished", cleanup.outcome, deadline)) {
    evidence_healthy = false;
  }

  std::string terminal_reason =
      cleanup.outcome == "fixture_acknowledged_rf_unknown"
          ? custody_reason : cleanup.outcome;
  if (journal == nullptr || !journal->initialized() || !deadline_valid ||
      !journal->AppendWithin("terminal_quarantine", terminal_reason, deadline)) {
    evidence_healthy = false;
  }
  if (deadline_valid && DeadlineExpired(deadline)) {
    cleanup.outcome = "cleanup_timeout";
    cleanup.separate_exec = false;
    terminal_reason = "cleanup_timeout";
    evidence_healthy = false;
  }

  bool readback = false;
  if (evidence_healthy && deadline_valid && !DeadlineExpired(deadline)) {
    readback = journal->Readback() && !DeadlineExpired(deadline);
  }
  if (!readback) evidence_healthy = false;

  const uint64_t journal_sequence =
      journal != nullptr && journal->initialized() ? journal->sequence() : 0;
  const std::string journal_head =
      journal != nullptr && journal->initialized() &&
              IsDigest(journal->head_digest())
          ? journal->head_digest() : std::string(kDigestBytes * 2, '0');
  const std::vector<std::string> terminal = {
      "TERM1", "quarantined", terminal_reason, std::to_string(last_sequence),
      cleanup.outcome, "unknown", "true", std::to_string(journal_sequence),
      journal_head, readback ? "true" : "false", std::to_string(getpid()),
      std::to_string(cleanup.cleanup_pid), cleanup.separate_exec ? "true" : "false",
      std::to_string(custody_pid), channels->watcher_start_identity_digest,
      std::to_string(channels->watcher_pgid),
      std::to_string(channels->watcher_session_id),
      channels->watcher_group_identity_digest,
      channels->child.start_identity_digest,
      std::to_string(channels->child.pgid),
      std::to_string(channels->child.session_id),
      channels->child.group_identity_digest,
      cleanup.cleanup_start_identity_digest,
      std::to_string(cleanup.cleanup_pgid),
      std::to_string(cleanup.cleanup_session_id),
      cleanup.cleanup_group_identity_digest};
  const bool sent = deadline_valid && !DeadlineExpired(deadline)
      ? WriteLineUntil(STDOUT_FILENO, terminal, deadline)
      : WriteLineImmediate(STDOUT_FILENO, terminal);
  const bool within_deadline = deadline_valid && !DeadlineExpired(deadline);
  DisarmProcessDeadline();
  return sent && evidence_healthy && readback && custody_receipt &&
      within_deadline ? 0 : 85;
}

bool ExactProtocolBindings(const std::vector<std::string>& fields,
                           size_t binding_offset,
                           const WatchdogConfig& config,
                           const std::string& challenge) {
  return fields[binding_offset] == challenge &&
         fields[binding_offset + 1] == config.contract_digest &&
         fields[binding_offset + 2] == config.instrument_digest &&
         fields[binding_offset + 3] == config.lease_digest &&
         fields[binding_offset + 4] == config.fencing_token_digest &&
         fields[binding_offset + 5] == std::to_string(config.fencing_generation) &&
         fields[binding_offset + 6] == config.worker_identity_digest &&
         fields[binding_offset + 7] == config.cleanup_capability_digest &&
         fields[binding_offset + 8] == config.restore_digest &&
         fields[binding_offset + 9] == config.semantic_digest;
}

struct ProtocolDecision {
  bool accepted = false;
  bool stop = false;
  uint64_t sequence = 0;
  uint64_t issued = 0;
  uint64_t deadline = 0;
  std::string reason = "protocol_rejected";
};

ProtocolDecision EvaluateProtocol(const std::string& line,
                                  const WatchdogConfig& config,
                                  const std::vector<unsigned char>& key,
                                  const std::string& challenge,
                                  uint64_t last_sequence) {
  ProtocolDecision output;
  const std::vector<std::string> fields = Split(line);
  const bool heartbeat = !fields.empty() && fields[0] == "HB1";
  const bool stop = !fields.empty() && fields[0] == "STOP1";
  const size_t expected = heartbeat ? 16 : (stop ? 17 : 0);
  if (expected == 0) {
    output.reason = "protocol_type_rejected";
    return output;
  }
  if (fields.size() != expected) {
    output.reason = stop ? "cleanup_operation_widening_rejected"
                         : "protocol_shape_rejected";
    return output;
  }
  if (!VerifySignedFields(fields, expected, key) || fields[1] != "1") {
    output.reason = heartbeat ? "heartbeat_authentication_invalid"
                              : "stop_authentication_invalid";
    return output;
  }
  uint64_t sequence = 0;
  uint64_t issued = 0;
  uint64_t valid_until = 0;
  const size_t issued_index = heartbeat ? 3 : 4;
  const size_t valid_index = heartbeat ? 4 : 5;
  const size_t binding_offset = heartbeat ? 5 : 6;
  if (!ParseUint64(fields[2], 1, UINT64_MAX, &sequence) ||
      !ParseUint64(fields[issued_index], 1, UINT64_MAX, &issued) ||
      !ParseUint64(fields[valid_index], 1, UINT64_MAX, &valid_until)) {
    output.reason = "protocol_integer_rejected";
    return output;
  }
  output.sequence = sequence;
  if (sequence <= last_sequence) {
    output.reason = heartbeat ? "heartbeat_replay" : "stop_replay";
    return output;
  }
  if (sequence != last_sequence + 1) {
    output.reason = heartbeat ? "heartbeat_sequence_gap" : "stop_sequence_gap";
    return output;
  }
  if (!ExactProtocolBindings(fields, binding_offset, config, challenge)) {
    output.reason = "protocol_binding_mismatch";
    return output;
  }
  const uint64_t now = MonotonicNanoseconds();
  const uint64_t maximum_window =
      config.maximum_extension_ms * kNanosecondsPerMillisecond;
  if (now == 0 || issued > now || valid_until < now || valid_until < issued ||
      valid_until - issued > maximum_window || now - issued > maximum_window ||
      valid_until - now > maximum_window) {
    output.reason = heartbeat ? "heartbeat_stale" : "stop_stale";
    return output;
  }
  if (stop && fields[3] != "operator_stop" && fields[3] != "lease_revoked" &&
      fields[3] != "worker_disconnect") {
    output.reason = "stop_reason_rejected";
    return output;
  }
  output.accepted = true;
  output.stop = stop;
  output.issued = issued;
  output.deadline = valid_until;
  output.reason = stop ? fields[3] : "heartbeat_accepted";
  return output;
}

int CleanupWorkerMain() {
  if (environ != nullptr && environ[0] != nullptr) return 91;
  if (getpid() < 2 || getpgrp() != getpid() || getsid(0) != getpid()) {
    return 90;
  }
  std::vector<unsigned char> key;
  SecretVectorGuard key_guard(&key);
  if (!ReadKeyCapability(kKeyFd, &key)) return 92;
  close(kKeyFd);
  std::string line;
  if (!ReadLineBlocking(kControlFd, &line)) return 93;
  close(kControlFd);
  std::vector<std::string> fields = Split(line);
  if (!VerifySignedFields(fields, 19, key) || fields[0] != "CLEAN1" ||
      fields[1] != "1" || !IsDigest(fields[2]) || !IsDigest(fields[3]) ||
      !IsDigest(fields[4]) || !IsDigest(fields[5]) || !IsDigest(fields[6]) ||
      !IsDigest(fields[8]) || !IsDigest(fields[9]) || !IsDigest(fields[10]) ||
      !IsDigest(fields[11]) || !IsDigest(fields[12]) || !IsDigest(fields[13]) ||
      !IsFixtureBehavior(fields[17])) {
    return 94;
  }
  uint64_t generation = 0;
  uint64_t deadline_value = 0;
  uint64_t expected_parent_value = 0;
  if (!ParseUint64(fields[7], 1, UINT32_MAX, &generation) ||
      !ParseUint64(fields[15], 1, UINT64_MAX, &deadline_value) ||
      !ParseUint64(fields[16], 2, INT_MAX, &expected_parent_value) ||
      SemanticDigest(fields[14]) != fields[11]) {
    return 95;
  }
  const AbsoluteDeadline deadline = {deadline_value, true};
  if (fields[17] == "watchdog_exit_before_cleanup_guard") {
    struct timespec delay = {0, 25000000};
    nanosleep(&delay, nullptr);
  }
  if (!StartCleanupCustodyGuard(
          static_cast<pid_t>(expected_parent_value), deadline)) {
    return 99;
  }
  std::string executable_path;
  std::string executable_digest;
  FileIdentity executable_identity;
  if (!SelfExecutable(&executable_path, &executable_digest, &executable_identity) ||
      executable_digest != fields[3]) {
    return 96;
  }
  if (fields[17] == "watchdog_exit_after_cleanup_guard") {
    const std::string pid = std::to_string(getpid());
    std::vector<std::string> guarded = {"GUARD1", "1", fields[2], pid};
    std::string guarded_payload = Join(guarded, guarded.size());
    guarded.emplace_back(HmacSha256(key, guarded_payload));
    ZeroString(&guarded_payload);
    const bool announced = WriteLineUntil(kJournalFd, guarded, deadline);
    if (!key.empty()) SecureZero(key.data(), key.size());
    if (!announced) return 100;
    for (;;) pause();
  }
  if (fields[17] == "stuck" ||
      fields[17] == "watchdog_stall_after_cleanup_handoff") {
    if (!key.empty()) SecureZero(key.data(), key.size());
    for (;;) pause();
  }
  if (fields[17] == "partial_stuck") {
    const unsigned char partial[] = "DONE1\t";
    const bool partial_written = WriteBytesUntil(
        kJournalFd, partial, sizeof(partial) - 1, deadline);
    if (!key.empty()) SecureZero(key.data(), key.size());
    if (!partial_written) return 98;
    for (;;) pause();
  }
  if (fields[17] == "wrong_receipt") fields[10].assign(64, '0');
  const std::string pid = std::to_string(getpid());
  const std::string outcome = "fixture_acknowledged_rf_unknown";
  const std::string receipt_digest = FramedDigest(
      kReceiptDomain, {fields[2], fields[9], fields[10], fields[11], outcome, pid});
  std::vector<std::string> receipt = {
      "DONE1", "1", fields[2], fields[4], fields[5], fields[9], fields[10],
      fields[11], outcome, pid, receipt_digest};
  std::string payload = Join(receipt, receipt.size());
  receipt.emplace_back(HmacSha256(key, payload));
  ZeroString(&payload);
  const bool written = WriteLineUntil(kJournalFd, receipt, deadline);
  if (!key.empty()) SecureZero(key.data(), key.size());
  close(kJournalFd);
  return written ? 0 : 97;
}

[[noreturn]] void BlockReadyOutputForFixture() {
  unsigned char bytes[4096];
  std::memset(bytes, 'R', sizeof(bytes));
  for (;;) {
    size_t offset = 0;
    while (offset < sizeof(bytes)) {
      const ssize_t written =
          write(STDOUT_FILENO, bytes + offset, sizeof(bytes) - offset);
      if (written > 0) {
        offset += static_cast<size_t>(written);
        continue;
      }
      if (written < 0 && errno == EINTR) continue;
      for (;;) pause();
    }
  }
}

int WatchdogMain() {
  std::vector<unsigned char> key;
  SecretVectorGuard key_guard(&key);
  if (!ReadKeyCapability(kKeyFd, &key)) {
    WriteLine(STDOUT_FILENO, {"ERROR1", "key_capability_rejected"});
    return 70;
  }
  close(kKeyFd);
  std::string config_line;
  if (!ReadLineBlocking(kControlFd, &config_line)) {
    WriteLine(STDOUT_FILENO, {"ERROR1", "launch_contract_rejected"});
    return 71;
  }
  const std::vector<std::string> config_fields = Split(config_line);
  WatchdogConfig config;
  if (!ParseWatchdogConfig(config_fields, key, &config)) {
    WriteLine(STDOUT_FILENO, {"ERROR1", "launch_contract_rejected"});
    return 72;
  }
  ZeroString(&config_line);

  // A valid, signed CFG1 record redeems the launch contract. From this point
  // no startup effect is admitted until the independent cleanup custodian has
  // registered parent/control/deadline custody and returned CUSTODY_READY1.
  std::vector<unsigned char> custody_command_key;
  std::vector<unsigned char> custody_evidence_key;
  SecretVectorGuard custody_command_key_guard(&custody_command_key);
  SecretVectorGuard custody_evidence_key_guard(&custody_evidence_key);
  CustodyChannels custody;
  if (!StartCleanupCustodian(config, &key, &custody_command_key,
                             &custody_evidence_key, &custody)) {
    // Pipe/fork/READY failure cannot claim cleanup and cannot enter any
    // executable, journal, worker-observation, or READY side effect.
    WriteLineImmediate(STDOUT_FILENO,
                       {"ERROR1", "cleanup_custody_admission_rejected"});
    close(kCustodyEventFd);
    close(kControlFd);
    close(kJournalFd);
    return 87;
  }

  std::string executable_path;
  std::string executable_digest;
  FileIdentity executable_identity;
  Journal journal;
  int queue = -1;
  const auto redeem = [&](const std::string& reason,
                          uint64_t last_sequence) {
    const int result = RedeemCleanupAfterContract(
        config, &key, custody_command_key, custody_evidence_key, &custody,
        &journal, reason, last_sequence);
    if (queue >= 0) close(queue);
    if (custody.command_fd >= 0) close(custody.command_fd);
    if (custody.receipt_fd >= 0) close(custody.receipt_fd);
    close(kControlFd);
    close(kJournalFd);
    return result;
  };
  const auto startup_failure = [&](const std::string& reason) {
    const int result = redeem(reason, 0);
    // A cleanup receipt cannot turn an armed-startup failure into a successful
    // watchdog launch. The nonzero exit also rejects a caller still waiting for
    // READY when the terminal record itself was deliverable.
    return result == 0 ? 86 : result;
  };

  if (!SelfExecutable(&executable_path, &executable_digest, &executable_identity) ||
      executable_digest != config.executable_digest) {
    return startup_failure("executable_identity_rejected");
  }

  if (!journal.Initialize(kJournalFd, config.contract_digest)) {
    return startup_failure("journal_capability_rejected");
  }

  ProcessIdentity process_before;
  ProcessIdentity process_after;
  if (!ReadProcessIdentity(config.worker_pid, &process_before)) {
    return startup_failure("worker_identity_rejected");
  }
  queue = kqueue();
  if (queue < 0) {
    return startup_failure("watchdog_registration_rejected");
  }
  struct kevent changes[3];
  EV_SET(&changes[0], static_cast<uintptr_t>(config.worker_pid), EVFILT_PROC,
         EV_ADD | EV_ENABLE | EV_CLEAR, NOTE_EXIT, 0, nullptr);
  EV_SET(&changes[1], static_cast<uintptr_t>(kControlFd), EVFILT_READ,
         EV_ADD | EV_ENABLE | EV_CLEAR, 0, 0, nullptr);
  EV_SET(&changes[2], static_cast<uintptr_t>(custody.pid), EVFILT_PROC,
         EV_ADD | EV_ENABLE | EV_CLEAR, NOTE_EXIT, 0, nullptr);
  if (kevent(queue, changes, 3, nullptr, 0, nullptr) != 0) {
    return startup_failure("watchdog_registration_rejected");
  }
  if (!ReadProcessIdentity(config.worker_pid, &process_after) ||
      !SameProcessIdentity(process_before, process_after)) {
    return startup_failure("worker_identity_race_rejected");
  }
  const std::string process_digest = ProcessIdentityDigest(process_after);
  if (process_after.uid != geteuid() || process_after.ruid != getuid()) {
    return startup_failure("worker_principal_rejected");
  }
  unsigned char challenge_bytes[16];
  arc4random_buf(challenge_bytes, sizeof(challenge_bytes));
  const std::string challenge = Hex(challenge_bytes, sizeof(challenge_bytes));
  SecureZero(challenge_bytes, sizeof(challenge_bytes));
  uint64_t now = MonotonicNanoseconds();
  const bool block_first_fsync =
      config.fixture_behavior == "watchdog_block_first_journal_fsync";
  if (now == 0 ||
      !journal.Append("watchdog_started", "armed", block_first_fsync)) {
    return startup_failure("watchdog_start_evidence_failed");
  }
  if (config.fixture_behavior == "watchdog_block_ready_output") {
    BlockReadyOutputForFixture();
  }
  const int control_flags = fcntl(kControlFd, F_GETFL);
  if (control_flags < 0 || fcntl(kControlFd, F_SETFL, control_flags | O_NONBLOCK) != 0) {
    return startup_failure("control_channel_configuration_failed");
  }
  if (config.fixture_behavior == "custody_late_arm_after_expiry") {
    struct timespec delay = {0, 400000000};
    while (nanosleep(&delay, &delay) != 0 && errno == EINTR) {}
  }
  const uint64_t arm_issued = MonotonicNanoseconds();
  if (arm_issued == 0 ||
      arm_issued > UINT64_MAX -
          config.deadman_ms * kNanosecondsPerMillisecond) {
    return startup_failure("custody_deadline_rejected");
  }
  uint64_t deadline =
      arm_issued + config.deadman_ms * kNanosecondsPerMillisecond;
  const AbsoluteDeadline arm_write_deadline = {deadline, true};
  std::vector<std::string> arm_acceptance;
  if (!SendCustodyArm(config, custody, custody_command_key,
                      custody_evidence_key, arm_issued, deadline,
                      arm_write_deadline, &arm_acceptance)) {
    return startup_failure("custody_arm_rejected");
  }
  now = MonotonicNanoseconds();
  if (now == 0 || now > deadline) {
    return startup_failure("custody_arm_rejected");
  }
  std::vector<std::string> ready = {
      "READY1", challenge, std::to_string(now), process_digest,
      std::to_string(getpid())};
  ready.insert(ready.end(), arm_acceptance.begin(), arm_acceptance.end());
  if (!WriteLine(STDOUT_FILENO, ready)) {
    return startup_failure("ready_delivery_failed");
  }
  if (config.fixture_behavior == "watchdog_stall_after_ready") {
    for (;;) pause();
  }

  uint64_t last_sequence = 0;
  std::string receive_buffer;
  std::string trigger_reason;
  bool triggered = false;
  while (!triggered) {
    now = MonotonicNanoseconds();
    if (now == 0 || now >= deadline) {
      trigger_reason = "deadman_timeout";
      triggered = true;
      break;
    }
    const uint64_t remaining = deadline - now;
    struct timespec timeout = {
        static_cast<time_t>(remaining / 1000000000ULL),
        static_cast<long>(remaining % 1000000000ULL)};
    struct kevent events[4];
    const int count = kevent(queue, nullptr, 0, events, 4, &timeout);
    if (count < 0 && errno == EINTR) continue;
    if (count < 0) {
      trigger_reason = "watchdog_observation_failed";
      triggered = true;
      break;
    }
    if (count == 0) continue;
    for (int event_index = 0; event_index < count && !triggered; ++event_index) {
      if (events[event_index].filter == EVFILT_PROC) {
        trigger_reason =
            events[event_index].ident == static_cast<uintptr_t>(custody.pid)
                ? "cleanup_custodian_exit" : "worker_process_exit";
        triggered = true;
        break;
      }
      if (events[event_index].filter != EVFILT_READ) continue;
      char bytes[1024];
      for (;;) {
        const ssize_t read_count = read(kControlFd, bytes, sizeof(bytes));
        if (read_count < 0 && errno == EINTR) continue;
        if (read_count < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) break;
        if (read_count == 0) {
          trigger_reason = "control_channel_closed";
          triggered = true;
          break;
        }
        if (read_count < 0) {
          trigger_reason = "control_channel_failed";
          triggered = true;
          break;
        }
        receive_buffer.append(bytes, static_cast<size_t>(read_count));
        if (receive_buffer.size() > kMaximumLineBytes) {
          trigger_reason = "protocol_oversize_rejected";
          triggered = true;
          break;
        }
        size_t newline = std::string::npos;
        while (!triggered && (newline = receive_buffer.find('\n')) != std::string::npos) {
          std::string line = receive_buffer.substr(0, newline);
          receive_buffer.erase(0, newline + 1);
          const ProtocolDecision decision = EvaluateProtocol(
              line, config, key, challenge, last_sequence);
          ZeroString(&line);
          if (!decision.accepted) {
            trigger_reason = decision.reason;
            last_sequence = decision.sequence;
            triggered = true;
          } else {
            last_sequence = decision.sequence;
            if (decision.stop) {
              trigger_reason = decision.reason;
              triggered = true;
            } else {
              std::vector<std::string> extend_acceptance;
              if (!SendCustodyExtend(
                      config, custody, custody_command_key,
                      custody_evidence_key, last_sequence, decision.issued,
                      decision.deadline, &extend_acceptance)) {
                trigger_reason = "custody_extension_failed";
                triggered = true;
              } else {
                deadline = decision.deadline;
              }
              if (!triggered) {
                std::vector<std::string> ack = {
                    "ACK1", std::to_string(last_sequence),
                    std::to_string(deadline)};
                ack.insert(ack.end(), extend_acceptance.begin(),
                           extend_acceptance.end());
                if (!WriteLine(STDOUT_FILENO, ack)) {
                  trigger_reason = "control_ack_failed";
                  triggered = true;
                }
              }
            }
          }
        }
        if (static_cast<size_t>(read_count) < sizeof(bytes)) break;
      }
    }
    if (!triggered) {
      ProcessIdentity current;
      if (!ReadProcessIdentity(config.worker_pid, &current) ||
          !SameProcessIdentity(process_after, current)) {
        trigger_reason = "worker_process_identity_changed";
        triggered = true;
      }
    }
  }

  if (trigger_reason.empty()) trigger_reason = "watchdog_unknown_trigger";
  return redeem(trigger_reason, last_sequence);
}

bool ReadExactBlocking(int fd, void* output, size_t length) {
  size_t offset = 0;
  unsigned char* bytes = static_cast<unsigned char*>(output);
  while (offset < length) {
    const ssize_t count = read(fd, bytes + offset, length - offset);
    if (count > 0) {
      offset += static_cast<size_t>(count);
      continue;
    }
    if (count < 0 && errno == EINTR) continue;
    return false;
  }
  return true;
}

bool WriteExactBlocking(int fd, const void* input, size_t length) {
  size_t offset = 0;
  const unsigned char* bytes = static_cast<const unsigned char*>(input);
  while (offset < length) {
    const ssize_t count = write(fd, bytes + offset, length - offset);
    if (count > 0) {
      offset += static_cast<size_t>(count);
      continue;
    }
    if (count < 0 && errno == EINTR) continue;
    return false;
  }
  return true;
}

int ChildLifecycleSelftest() {
  int ready[2] = {-1, -1};
  int release[2] = {-1, -1};
  if (!CreatePipe(ready) || !CreatePipe(release)) {
    ClosePipe(ready);
    ClosePipe(release);
    return 101;
  }
  const pid_t first_pid = fork();
  if (first_pid < 0) {
    ClosePipe(ready);
    ClosePipe(release);
    return 102;
  }
  if (first_pid == 0) {
    close(ready[0]);
    close(release[1]);
    unsigned char value = 1;
    const bool prepared = EstablishIsolatedSession() &&
        WriteExactBlocking(ready[1], &value, sizeof(value)) &&
        ReadExactBlocking(release[0], &value, sizeof(value));
    _exit(prepared ? 0 : 103);
  }
  close(ready[1]);
  ready[1] = -1;
  close(release[0]);
  release[0] = -1;
  unsigned char value = 0;
  AbsoluteDeadline deadline;
  ChildLifecycle first;
  if (!ReadExactBlocking(ready[0], &value, sizeof(value)) || value != 1 ||
      !BuildAbsoluteDeadline(1000, &deadline) ||
      !BindDirectChildLifecycle(first_pid, "selftest_reaped_child", deadline,
                                &first) ||
      !WriteExactBlocking(release[1], &value, sizeof(value))) {
    if (!first.terminal) KillAndReapChild(&first);
    ClosePipe(ready);
    ClosePipe(release);
    return 104;
  }
  ClosePipe(ready);
  ClosePipe(release);
  if (!BuildAbsoluteDeadline(1000, &deadline) ||
      !WaitForChildExitUntil(&first, deadline) || !first.reaped ||
      first.signal_sent || !KillAndReapChild(&first) || first.signal_sent) {
    return 105;
  }

  // Re-presenting an already reaped child as a stale target deterministically
  // exercises the ECHILD/PID-reuse boundary: the helper must terminalize it
  // without issuing any signal.
  ChildLifecycle stale = first;
  stale.terminal = false;
  stale.reaped = false;
  stale.signal_sent = false;
  stale.ownership_lost = false;
  if (KillAndReapChild(&stale) || !stale.terminal || stale.reaped ||
      stale.signal_sent || !stale.ownership_lost) {
    return 106;
  }

  int descendants[2] = {-1, -1};
  if (!CreatePipe(descendants)) return 107;
  const pid_t group_pid = fork();
  if (group_pid < 0) {
    ClosePipe(descendants);
    return 108;
  }
  if (group_pid == 0) {
    close(descendants[0]);
    if (!EstablishIsolatedSession()) _exit(109);
    const pid_t descendant_pid = fork();
    if (descendant_pid < 0) _exit(110);
    if (descendant_pid == 0) {
      for (;;) pause();
    }
    if (!WriteExactBlocking(descendants[1], &descendant_pid,
                            sizeof(descendant_pid))) {
      _exit(111);
    }
    for (;;) pause();
  }
  close(descendants[1]);
  descendants[1] = -1;
  pid_t descendant_pid = -1;
  ChildLifecycle group;
  if (!ReadExactBlocking(descendants[0], &descendant_pid,
                         sizeof(descendant_pid)) ||
      descendant_pid < 2 || !BuildAbsoluteDeadline(1000, &deadline) ||
      !BindDirectChildLifecycle(group_pid, "selftest_descendant_group",
                                deadline, &group) ||
      !KillAndReapChild(&group) || !group.reaped || !group.signal_sent ||
      !KillAndReapChild(&group)) {
    if (!group.terminal) KillAndReapChild(&group);
    ClosePipe(descendants);
    return 112;
  }
  ClosePipe(descendants);
  if (!BuildAbsoluteDeadline(2000, &deadline)) return 113;
  while (kill(-group.pgid, 0) == 0 || errno == EPERM) {
    uint64_t remaining_ns = 0;
    if (!Remaining(deadline, &remaining_ns)) return 114;
    struct timespec pause = {0, 1000000};
    nanosleep(&pause, nullptr);
  }
  if (errno != ESRCH) return 115;
  return 0;
}

}  // namespace

int main(int argc, char** argv) {
  if (argc != 2 || argv == nullptr || argv[1] == nullptr) return 64;
  if (signal(SIGPIPE, SIG_IGN) == SIG_ERR) return 65;
  if (std::strcmp(argv[1], "--watchdog-fixture") == 0) return WatchdogMain();
  if (std::strcmp(argv[1], "--cleanup-worker-fixture") == 0) {
    return CleanupWorkerMain();
  }
  if (std::strcmp(argv[1], "--deadline-helper-selftest") == 0) {
    return DeadlineHelperSelftest();
  }
  if (std::strcmp(argv[1], "--child-lifecycle-selftest") == 0) {
    return ChildLifecycleSelftest();
  }
  return 64;
}
