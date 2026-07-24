#include <node_api.h>

#include <CommonCrypto/CommonDigest.h>
#include <fcntl.h>
#include <poll.h>
#include <sys/acl.h>
#include <sys/file.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/ttycom.h>
#include <termios.h>
#include <unistd.h>

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cerrno>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <memory>
#include <mutex>
#include <string>
#include <vector>

namespace {

constexpr uint32_t kVersion = 1;
constexpr const char* kPrimitive =
    "darwin_openat_tiocexcl_termios_exact_frame_v1";
constexpr const char* kRejected = "darwin_native_serial_custody_rejected";
constexpr const char* kOpenRejected = "darwin_native_serial_open_rejected";
constexpr const char* kTransactionAmbiguous =
    "darwin_native_serial_transaction_ambiguous";
constexpr const char* kDtrBlocker =
    "darwin_tty_preopen_dtr_history_unprovable";
constexpr const char* kAclDigestDomain =
    "hacker-bob/chameleon-darwin-device-acl-profile/v1";
constexpr const char* kWorkerDigestDomain =
    "hacker-bob/chameleon-darwin-worker-device-authority/v1";
constexpr size_t kMaxPathBytes = 4096;
constexpr size_t kMaxComponentBytes = 255;
constexpr size_t kMaxAclBytes = 64 * 1024;
constexpr size_t kMinimumFrameBytes = 10;
constexpr size_t kMaximumFrameBytes = 16 * 1024;
constexpr int kMaximumTimeoutMs = 1000;
constexpr unsigned char kSof = 0x11;
constexpr unsigned char kSofLrc = 0xef;

void SecureZero(void* value, size_t length) {
  volatile unsigned char* cursor = static_cast<volatile unsigned char*>(value);
  while (length > 0) {
    *cursor = 0;
    ++cursor;
    --length;
  }
}

void ZeroVector(std::vector<unsigned char>* value) {
  if (value != nullptr && !value->empty()) {
    SecureZero(value->data(), value->size());
    value->clear();
    value->shrink_to_fit();
  }
}

void ZeroString(std::string* value) {
  if (value != nullptr && !value->empty()) {
    SecureZero(value->data(), value->size());
    value->clear();
  }
}

class ScopedFd {
 public:
  explicit ScopedFd(int fd = -1) : fd_(fd) {}
  ScopedFd(const ScopedFd&) = delete;
  ScopedFd& operator=(const ScopedFd&) = delete;
  ~ScopedFd() { Reset(); }
  int get() const { return fd_; }
  int Release() {
    const int value = fd_;
    fd_ = -1;
    return value;
  }
  void Reset(int next = -1) {
    if (fd_ >= 0) close(fd_);
    fd_ = next;
  }

 private:
  int fd_;
};

struct ExpectedStat {
  uint64_t ctime_ns = 0;
  int64_t dev = 0;
  uint64_t gid = 0;
  uint64_t ino = 0;
  uint64_t mode = 0;
  uint64_t nlink = 0;
  int64_t rdev = 0;
  uint64_t uid = 0;
};

struct OpenConfig {
  std::string directory_path;
  std::string final_component;
  ExpectedStat expected_directory;
  ExpectedStat expected_device;
  std::string directory_stat_digest;
  std::string device_stat_digest;
  std::string operator_device_identity_digest;
  uint32_t worker_uid = 0;
  uint32_t worker_gid = 0;
  std::string worker_identity_digest;
  std::string acl_profile_state;
  std::vector<unsigned char> acl_profile_bytes;
  std::string acl_profile_digest;
  uint32_t connection_generation = 0;

  ~OpenConfig() {
    ZeroString(&directory_path);
    ZeroString(&final_component);
    ZeroString(&operator_device_identity_digest);
    ZeroString(&worker_identity_digest);
    ZeroString(&acl_profile_state);
    ZeroVector(&acl_profile_bytes);
    ZeroString(&acl_profile_digest);
  }
};

struct SerialState {
  std::mutex mutex;
  int fd = -1;
  uint32_t generation = 0;
  uint32_t next_sequence = 1;
  uint32_t active_sequence = 0;
  bool busy = false;
  bool closed = false;
  std::atomic<bool> abort_requested{false};

  ~SerialState() {
    abort_requested.store(true, std::memory_order_release);
    std::lock_guard<std::mutex> lock(mutex);
    if (fd >= 0) {
      close(fd);
      fd = -1;
    }
    closed = true;
  }
};

struct HandleBox {
  std::shared_ptr<SerialState> state;
};

struct TransactionWork {
  napi_env env = nullptr;
  napi_async_work work = nullptr;
  napi_deferred deferred = nullptr;
  std::shared_ptr<SerialState> state;
  uint32_t generation = 0;
  uint32_t sequence = 0;
  uint32_t maximum_response_bytes = 0;
  uint32_t timeout_ms = 0;
  std::vector<unsigned char> request;
  std::vector<unsigned char> response;
  bool succeeded = false;

  ~TransactionWork() {
    ZeroVector(&request);
    ZeroVector(&response);
  }
};

bool DefineProperty(napi_env env, napi_value object, const char* name,
                    napi_value value) {
  const napi_property_descriptor descriptor = {
      name, nullptr, nullptr, nullptr, nullptr, value, napi_enumerable, nullptr};
  return napi_define_properties(env, object, 1, &descriptor) == napi_ok;
}

void ThrowCode(napi_env env, const char* code) {
  napi_value message;
  napi_value error;
  napi_value code_value;
  if (napi_create_string_utf8(env, "Darwin native serial custody was rejected",
                              NAPI_AUTO_LENGTH, &message) != napi_ok ||
      napi_create_error(env, nullptr, message, &error) != napi_ok ||
      napi_create_string_utf8(env, code, NAPI_AUTO_LENGTH, &code_value) != napi_ok ||
      !DefineProperty(env, error, "code", code_value)) {
    napi_throw_error(env, code, "Darwin native serial custody was rejected");
    return;
  }
  napi_throw(env, error);
}

bool IsObject(napi_env env, napi_value value) {
  napi_valuetype type = napi_undefined;
  // The public Node 20 N-API does not expose V8's proxy predicate. The CommonJS
  // capability wrapper rejects proxies before this boundary; native still
  // insists on an exact own enumerable string-key set and primitive values.
  return napi_typeof(env, value, &type) == napi_ok && type == napi_object;
}

bool HasExactKeys(napi_env env, napi_value value,
                  const std::vector<const char*>& expected) {
  if (!IsObject(env, value)) return false;
  napi_value keys;
  if (napi_get_all_property_names(
          env, value, napi_key_own_only, napi_key_enumerable,
          napi_key_numbers_to_strings, &keys) != napi_ok) {
    return false;
  }
  uint32_t length = 0;
  if (napi_get_array_length(env, keys, &length) != napi_ok ||
      length != expected.size()) {
    return false;
  }
  std::vector<bool> found(expected.size(), false);
  for (uint32_t index = 0; index < length; ++index) {
    napi_value key;
    if (napi_get_element(env, keys, index, &key) != napi_ok) return false;
    size_t bytes = 0;
    if (napi_get_value_string_utf8(env, key, nullptr, 0, &bytes) != napi_ok ||
        bytes == 0 || bytes > 128) {
      return false;
    }
    std::string name(bytes + 1, '\0');
    size_t copied = 0;
    if (napi_get_value_string_utf8(env, key, name.data(), bytes + 1, &copied) !=
            napi_ok ||
        copied != bytes) {
      ZeroString(&name);
      return false;
    }
    name.resize(bytes);
    bool matched = false;
    for (size_t expected_index = 0; expected_index < expected.size(); ++expected_index) {
      if (!found[expected_index] && name == expected[expected_index]) {
        found[expected_index] = true;
        matched = true;
        break;
      }
    }
    ZeroString(&name);
    if (!matched) return false;
  }
  return std::all_of(found.begin(), found.end(), [](bool value) { return value; });
}

bool GetNamed(napi_env env, napi_value object, const char* name, napi_value* output) {
  return napi_get_named_property(env, object, name, output) == napi_ok;
}

bool ReadBool(napi_env env, napi_value object, const char* name, bool* output) {
  napi_value value;
  return GetNamed(env, object, name, &value) &&
         napi_get_value_bool(env, value, output) == napi_ok;
}

bool ReadUint32(napi_env env, napi_value object, const char* name, uint32_t* output) {
  napi_value value;
  return GetNamed(env, object, name, &value) &&
         napi_get_value_uint32(env, value, output) == napi_ok;
}

bool ReadString(napi_env env, napi_value object, const char* name, size_t maximum,
                std::string* output) {
  napi_value value;
  size_t bytes = 0;
  if (!GetNamed(env, object, name, &value) ||
      napi_get_value_string_utf8(env, value, nullptr, 0, &bytes) != napi_ok ||
      bytes == 0 || bytes > maximum) {
    return false;
  }
  std::string result(bytes + 1, '\0');
  size_t copied = 0;
  if (napi_get_value_string_utf8(env, value, result.data(), bytes + 1, &copied) !=
          napi_ok || copied != bytes) {
    ZeroString(&result);
    return false;
  }
  result.resize(bytes);
  if (std::find(result.begin(), result.end(), '\0') != result.end()) {
    ZeroString(&result);
    return false;
  }
  *output = std::move(result);
  return true;
}

bool IsDigest(const std::string& value) {
  if (value.size() != 64) return false;
  return std::all_of(value.begin(), value.end(), [](char character) {
    return (character >= '0' && character <= '9') ||
           (character >= 'a' && character <= 'f');
  });
}

bool ReadDigest(napi_env env, napi_value object, const char* name,
                std::string* output) {
  return ReadString(env, object, name, 64, output) && IsDigest(*output);
}

bool ReadDecimal(napi_env env, napi_value object, const char* name, uint64_t* output) {
  std::string encoded;
  if (!ReadString(env, object, name, 40, &encoded) ||
      (encoded.size() > 1 && encoded[0] == '0')) {
    ZeroString(&encoded);
    return false;
  }
  uint64_t result = 0;
  for (char character : encoded) {
    if (character < '0' || character > '9') {
      ZeroString(&encoded);
      return false;
    }
    const uint64_t digit = static_cast<uint64_t>(character - '0');
    if (result > (UINT64_MAX - digit) / 10) {
      ZeroString(&encoded);
      return false;
    }
    result = result * 10 + digit;
  }
  ZeroString(&encoded);
  *output = result;
  return true;
}

bool ReadSignedDecimal(napi_env env, napi_value object, const char* name,
                       int64_t* output) {
  std::string encoded;
  if (!ReadString(env, object, name, 40, &encoded)) return false;
  const bool negative = encoded[0] == '-';
  const size_t start = negative ? 1 : 0;
  if (start == encoded.size() || (encoded.size() - start > 1 && encoded[start] == '0') ||
      (negative && encoded == "-0")) {
    ZeroString(&encoded);
    return false;
  }
  uint64_t magnitude = 0;
  const uint64_t maximum = negative ? (static_cast<uint64_t>(INT64_MAX) + 1)
                                    : static_cast<uint64_t>(INT64_MAX);
  for (size_t index = start; index < encoded.size(); ++index) {
    const char character = encoded[index];
    if (character < '0' || character > '9') {
      ZeroString(&encoded);
      return false;
    }
    const uint64_t digit = static_cast<uint64_t>(character - '0');
    if (magnitude > (maximum - digit) / 10) {
      ZeroString(&encoded);
      return false;
    }
    magnitude = magnitude * 10 + digit;
  }
  ZeroString(&encoded);
  if (negative) {
    *output = magnitude == static_cast<uint64_t>(INT64_MAX) + 1
                  ? INT64_MIN
                  : -static_cast<int64_t>(magnitude);
  } else {
    *output = static_cast<int64_t>(magnitude);
  }
  return true;
}

bool ReadBuffer(napi_env env, napi_value object, const char* name,
                size_t maximum, std::vector<unsigned char>* output) {
  napi_value value;
  bool is_buffer = false;
  void* bytes = nullptr;
  size_t length = 0;
  if (!GetNamed(env, object, name, &value) ||
      napi_is_buffer(env, value, &is_buffer) != napi_ok || !is_buffer ||
      napi_get_buffer_info(env, value, &bytes, &length) != napi_ok ||
      length > maximum) {
    return false;
  }
  output->assign(static_cast<unsigned char*>(bytes),
                 static_cast<unsigned char*>(bytes) + length);
  return true;
}

bool ReadExpectedStat(napi_env env, napi_value parent, const char* name,
                      bool device, ExpectedStat* output) {
  napi_value object;
  if (!GetNamed(env, parent, name, &object)) return false;
  const std::vector<const char*> directory_fields = {
      "ctime_ns", "dev", "gid", "ino", "mode", "nlink", "uid"};
  const std::vector<const char*> device_fields = {
      "ctime_ns", "dev", "gid", "ino", "mode", "nlink", "rdev", "uid"};
  if (!HasExactKeys(env, object, device ? device_fields : directory_fields) ||
      !ReadDecimal(env, object, "ctime_ns", &output->ctime_ns) ||
      !ReadSignedDecimal(env, object, "dev", &output->dev) ||
      !ReadDecimal(env, object, "gid", &output->gid) ||
      !ReadDecimal(env, object, "ino", &output->ino) ||
      !ReadDecimal(env, object, "mode", &output->mode) ||
      !ReadDecimal(env, object, "nlink", &output->nlink) ||
      !ReadDecimal(env, object, "uid", &output->uid)) {
    return false;
  }
  return !device || ReadSignedDecimal(env, object, "rdev", &output->rdev);
}

bool IsFixtureComponent(const std::string& value) {
  if (value.size() < 5 || value.rfind("ttys", 0) != 0 || value == "." ||
      value == "..") {
    return false;
  }
  return std::all_of(value.begin(), value.end(), [](char character) {
    return (character >= 'a' && character <= 'z') ||
           (character >= 'A' && character <= 'Z') ||
           (character >= '0' && character <= '9') || character == '.' ||
           character == '_' || character == '-';
  });
}

bool ReadOpenConfig(napi_env env, napi_value input, OpenConfig* output) {
  const std::vector<const char*> fields = {
      "acl_profile_bytes",
      "acl_profile_digest",
      "acl_profile_state",
      "connection_generation",
      "device_stat_digest",
      "directory_path",
      "directory_stat_digest",
      "expected_device",
      "expected_directory",
      "final_component",
      "fixture_only",
      "operator_device_identity_digest",
      "version",
      "worker_gid",
      "worker_identity_digest",
      "worker_uid",
  };
  uint32_t version = 0;
  bool fixture_only = false;
  if (!HasExactKeys(env, input, fields) ||
      !ReadUint32(env, input, "version", &version) || version != kVersion ||
      !ReadBool(env, input, "fixture_only", &fixture_only)) {
    return false;
  }
  if (!fixture_only) {
    ThrowCode(env, kDtrBlocker);
    return false;
  }
  const char* fixture_environment =
      std::getenv("BOB_CHAMELEON_DARWIN_PTY_FIXTURE");
  if (fixture_environment == nullptr || std::strcmp(fixture_environment, "1") != 0 ||
      !ReadString(env, input, "directory_path", kMaxPathBytes,
                  &output->directory_path) ||
      output->directory_path.empty() || output->directory_path[0] != '/' ||
      !ReadString(env, input, "final_component", kMaxComponentBytes,
                  &output->final_component) ||
      !IsFixtureComponent(output->final_component) ||
      output->final_component.find('/') != std::string::npos ||
      !ReadExpectedStat(env, input, "expected_directory", false,
                        &output->expected_directory) ||
      !ReadExpectedStat(env, input, "expected_device", true,
                        &output->expected_device) ||
      !ReadDigest(env, input, "directory_stat_digest",
                  &output->directory_stat_digest) ||
      !ReadDigest(env, input, "device_stat_digest", &output->device_stat_digest) ||
      !ReadDigest(env, input, "operator_device_identity_digest",
                  &output->operator_device_identity_digest) ||
      !ReadUint32(env, input, "worker_uid", &output->worker_uid) ||
      !ReadUint32(env, input, "worker_gid", &output->worker_gid) ||
      !ReadDigest(env, input, "worker_identity_digest",
                  &output->worker_identity_digest) ||
      !ReadString(env, input, "acl_profile_state", 16,
                  &output->acl_profile_state) ||
      (output->acl_profile_state != "absent" &&
       output->acl_profile_state != "present") ||
      !ReadBuffer(env, input, "acl_profile_bytes", kMaxAclBytes,
                  &output->acl_profile_bytes) ||
      !ReadDigest(env, input, "acl_profile_digest", &output->acl_profile_digest) ||
      !ReadUint32(env, input, "connection_generation",
                  &output->connection_generation) ||
      output->connection_generation == 0) {
    return false;
  }
  if ((output->acl_profile_state == "absent" &&
       !output->acl_profile_bytes.empty()) ||
      (output->acl_profile_state == "present" &&
       output->acl_profile_bytes.empty())) {
    return false;
  }
  return true;
}

uint64_t CtimeNanoseconds(const struct stat& value) {
  if (value.st_ctimespec.tv_sec < 0 || value.st_ctimespec.tv_nsec < 0) return UINT64_MAX;
  const uint64_t seconds = static_cast<uint64_t>(value.st_ctimespec.tv_sec);
  const uint64_t nanoseconds = static_cast<uint64_t>(value.st_ctimespec.tv_nsec);
  if (seconds > (UINT64_MAX - nanoseconds) / 1000000000ULL) return UINT64_MAX;
  return seconds * 1000000000ULL + nanoseconds;
}

bool MatchesExpected(const struct stat& actual, const ExpectedStat& expected,
                     bool device) {
  return CtimeNanoseconds(actual) == expected.ctime_ns &&
         static_cast<int64_t>(actual.st_dev) == expected.dev &&
         static_cast<uint64_t>(actual.st_gid) == expected.gid &&
         static_cast<uint64_t>(actual.st_ino) == expected.ino &&
         static_cast<uint64_t>(actual.st_mode) == expected.mode &&
         static_cast<uint64_t>(actual.st_nlink) == expected.nlink &&
         static_cast<uint64_t>(actual.st_uid) == expected.uid &&
         (!device || static_cast<int64_t>(actual.st_rdev) == expected.rdev);
}

bool SameStat(const struct stat& left, const struct stat& right, bool device) {
  return left.st_dev == right.st_dev && left.st_gid == right.st_gid &&
         left.st_ino == right.st_ino && left.st_mode == right.st_mode &&
         left.st_nlink == right.st_nlink && left.st_uid == right.st_uid &&
         left.st_ctimespec.tv_sec == right.st_ctimespec.tv_sec &&
         left.st_ctimespec.tv_nsec == right.st_ctimespec.tv_nsec &&
         (!device || left.st_rdev == right.st_rdev);
}

std::string FramedDigest(const char* domain, const std::string& state,
                         const std::vector<unsigned char>& bytes) {
  CC_SHA256_CTX context;
  CC_SHA256_Init(&context);
  CC_SHA256_Update(&context, domain, static_cast<CC_LONG>(std::strlen(domain)));
  const auto append = [&context](const void* value, size_t length) {
    unsigned char encoded[8];
    uint64_t remaining = static_cast<uint64_t>(length);
    for (int index = 7; index >= 0; --index) {
      encoded[index] = static_cast<unsigned char>(remaining & 0xff);
      remaining >>= 8;
    }
    CC_SHA256_Update(&context, encoded, sizeof(encoded));
    if (length > 0) {
      CC_SHA256_Update(&context, value, static_cast<CC_LONG>(length));
    }
    SecureZero(encoded, sizeof(encoded));
  };
  append(state.data(), state.size());
  append(bytes.data(), bytes.size());
  unsigned char digest[CC_SHA256_DIGEST_LENGTH];
  CC_SHA256_Final(digest, &context);
  static constexpr char kHex[] = "0123456789abcdef";
  std::string output(CC_SHA256_DIGEST_LENGTH * 2, '0');
  for (size_t index = 0; index < CC_SHA256_DIGEST_LENGTH; ++index) {
    output[index * 2] = kHex[digest[index] >> 4];
    output[index * 2 + 1] = kHex[digest[index] & 0x0f];
  }
  SecureZero(digest, sizeof(digest));
  SecureZero(&context, sizeof(context));
  return output;
}

std::string WorkerIdentityDigest(uint32_t uid, uint32_t gid,
                                 const std::string& acl_digest) {
  const std::string uid_value = std::to_string(uid);
  const std::string gid_value = std::to_string(gid);
  CC_SHA256_CTX context;
  CC_SHA256_Init(&context);
  CC_SHA256_Update(&context, kWorkerDigestDomain,
                   static_cast<CC_LONG>(std::strlen(kWorkerDigestDomain)));
  const auto append = [&context](const std::string& value) {
    unsigned char encoded[8];
    uint64_t remaining = static_cast<uint64_t>(value.size());
    for (int index = 7; index >= 0; --index) {
      encoded[index] = static_cast<unsigned char>(remaining & 0xff);
      remaining >>= 8;
    }
    CC_SHA256_Update(&context, encoded, sizeof(encoded));
    if (!value.empty()) {
      CC_SHA256_Update(&context, value.data(), static_cast<CC_LONG>(value.size()));
    }
    SecureZero(encoded, sizeof(encoded));
  };
  append(uid_value);
  append(gid_value);
  append(acl_digest);
  unsigned char digest[CC_SHA256_DIGEST_LENGTH];
  CC_SHA256_Final(digest, &context);
  static constexpr char kHex[] = "0123456789abcdef";
  std::string output(CC_SHA256_DIGEST_LENGTH * 2, '0');
  for (size_t index = 0; index < CC_SHA256_DIGEST_LENGTH; ++index) {
    output[index * 2] = kHex[digest[index] >> 4];
    output[index * 2 + 1] = kHex[digest[index] & 0x0f];
  }
  SecureZero(digest, sizeof(digest));
  SecureZero(&context, sizeof(context));
  return output;
}

bool ConstantTimeEqual(const std::vector<unsigned char>& left,
                       const std::vector<unsigned char>& right) {
  size_t difference = left.size() ^ right.size();
  const size_t maximum = std::max(left.size(), right.size());
  for (size_t index = 0; index < maximum; ++index) {
    const unsigned char left_byte = index < left.size() ? left[index] : 0;
    const unsigned char right_byte = index < right.size() ? right[index] : 0;
    difference |= static_cast<size_t>(left_byte ^ right_byte);
  }
  return difference == 0;
}

bool ReadAclProfile(int fd, std::string* state,
                    std::vector<unsigned char>* external) {
  errno = 0;
  acl_t acl = acl_get_fd_np(fd, ACL_TYPE_EXTENDED);
  if (acl == nullptr) {
    if (errno == ENOENT || errno == ENOTSUP || errno == EOPNOTSUPP) {
      *state = "absent";
      return true;
    }
    return false;
  }
  acl_entry_t entry;
  const int entry_result = acl_get_entry(acl, ACL_FIRST_ENTRY, &entry);
  if (entry_result < 0) {
    acl_free(acl);
    return false;
  }
  if (entry_result == 0) {
    *state = "absent";
    acl_free(acl);
    return true;
  }
  const ssize_t size = acl_size(acl);
  if (size <= 0 || size > static_cast<ssize_t>(kMaxAclBytes)) {
    acl_free(acl);
    return false;
  }
  external->resize(static_cast<size_t>(size));
  const ssize_t copied = acl_copy_ext(external->data(), acl, size);
  acl_free(acl);
  if (copied != size) {
    ZeroVector(external);
    return false;
  }
  *state = "present";
  return true;
}

bool ConfigureRaw115200(int fd) {
  struct termios value;
  if (tcgetattr(fd, &value) != 0) return false;
  cfmakeraw(&value);
  value.c_cflag &= ~(CSIZE | PARENB | PARODD | CSTOPB | CRTSCTS);
  value.c_cflag |= (CS8 | CLOCAL | CREAD);
  value.c_iflag &= ~(IXON | IXOFF | IXANY);
  value.c_cc[VMIN] = 0;
  value.c_cc[VTIME] = 0;
  if (cfsetispeed(&value, B115200) != 0 ||
      cfsetospeed(&value, B115200) != 0 ||
      tcsetattr(fd, TCSANOW, &value) != 0 || tcflush(fd, TCIOFLUSH) != 0) {
    SecureZero(&value, sizeof(value));
    return false;
  }
  struct termios verified;
  if (tcgetattr(fd, &verified) != 0) {
    SecureZero(&value, sizeof(value));
    return false;
  }
  const bool exact = cfgetispeed(&verified) == B115200 &&
                     cfgetospeed(&verified) == B115200 &&
                     (verified.c_cflag & CSIZE) == CS8 &&
                     (verified.c_cflag & (PARENB | PARODD | CSTOPB | CRTSCTS)) == 0 &&
                     (verified.c_iflag & (IXON | IXOFF | IXANY)) == 0 &&
                     verified.c_cc[VMIN] == 0 && verified.c_cc[VTIME] == 0;
  SecureZero(&value, sizeof(value));
  SecureZero(&verified, sizeof(verified));
  return exact;
}

bool ClearAndObserveModemLines(int fd, std::string* dtr_state,
                              std::string* rts_state) {
  errno = 0;
  const bool dtr_clear_called = ioctl(fd, TIOCCDTR) == 0;
  const int dtr_clear_errno = dtr_clear_called ? 0 : errno;
  int clear_bits = TIOCM_DTR | TIOCM_RTS;
  errno = 0;
  const bool mask_clear_called = ioctl(fd, TIOCMBIC, &clear_bits) == 0;
  const int mask_clear_errno = mask_clear_called ? 0 : errno;
  int modem_bits = 0;
  errno = 0;
  const bool modem_bits_observed = ioctl(fd, TIOCMGET, &modem_bits) == 0;
  const int modem_bits_errno = modem_bits_observed ? 0 : errno;
  if (modem_bits_observed) {
    if (!dtr_clear_called || !mask_clear_called) return false;
    if ((modem_bits & (TIOCM_DTR | TIOCM_RTS)) != 0) return false;
    *dtr_state = "deasserted_observed_after_open";
    *rts_state = "deasserted_observed_after_open";
    return true;
  }
  // Darwin pseudo-terminals commonly do not implement modem-control ioctls.
  // That is acceptable only in this fixture-only addon path and is reported
  // explicitly; it is never treated as physical line-state evidence.
  if ((!dtr_clear_called && dtr_clear_errno != ENOTTY && dtr_clear_errno != EINVAL) ||
      (!mask_clear_called && mask_clear_errno != ENOTTY && mask_clear_errno != EINVAL) ||
      (modem_bits_errno != ENOTTY && modem_bits_errno != EINVAL)) {
    return false;
  }
  *dtr_state = "unobservable_pseudo_terminal";
  *rts_state = "unobservable_pseudo_terminal";
  return true;
}

bool IsExactPtySlave(int fd) {
  char path_buffer[PATH_MAX];
  SecureZero(path_buffer, sizeof(path_buffer));
  const int result = ttyname_r(fd, path_buffer, sizeof(path_buffer));
  if (result != 0) {
    SecureZero(path_buffer, sizeof(path_buffer));
    return false;
  }
  const std::string path_value(path_buffer);
  const bool accepted = path_value.rfind("/dev/ttys", 0) == 0;
  SecureZero(path_buffer, sizeof(path_buffer));
  return accepted;
}

bool SetString(napi_env env, napi_value object, const char* name,
               const std::string& value) {
  napi_value encoded;
  return napi_create_string_utf8(env, value.data(), value.size(), &encoded) == napi_ok &&
         DefineProperty(env, object, name, encoded);
}

bool SetCString(napi_env env, napi_value object, const char* name,
                const char* value) {
  napi_value encoded;
  return napi_create_string_utf8(env, value, NAPI_AUTO_LENGTH, &encoded) == napi_ok &&
         DefineProperty(env, object, name, encoded);
}

bool SetBool(napi_env env, napi_value object, const char* name, bool value) {
  napi_value encoded;
  return napi_get_boolean(env, value, &encoded) == napi_ok &&
         DefineProperty(env, object, name, encoded);
}

bool SetUint32(napi_env env, napi_value object, const char* name, uint32_t value) {
  napi_value encoded;
  return napi_create_uint32(env, value, &encoded) == napi_ok &&
         DefineProperty(env, object, name, encoded);
}

void FinalizeHandle(napi_env, void* data, void*) {
  auto* box = static_cast<HandleBox*>(data);
  if (box == nullptr) return;
  if (box->state) {
    box->state->abort_requested.store(true, std::memory_order_release);
    std::lock_guard<std::mutex> lock(box->state->mutex);
    if (!box->state->busy && box->state->fd >= 0) {
      close(box->state->fd);
      box->state->fd = -1;
      box->state->closed = true;
    }
  }
  delete box;
}

bool GetHandle(napi_env env, napi_value value, std::shared_ptr<SerialState>* output) {
  napi_valuetype type = napi_undefined;
  void* raw = nullptr;
  if (napi_typeof(env, value, &type) != napi_ok || type != napi_external ||
      napi_get_value_external(env, value, &raw) != napi_ok || raw == nullptr) {
    return false;
  }
  auto* box = static_cast<HandleBox*>(raw);
  if (!box->state) return false;
  *output = box->state;
  return true;
}

napi_value OpenExact(napi_env env, napi_callback_info info) {
  size_t argc = 1;
  napi_value args[1];
  if (napi_get_cb_info(env, info, &argc, args, nullptr, nullptr) != napi_ok ||
      argc != 1) {
    ThrowCode(env, kOpenRejected);
    return nullptr;
  }
  OpenConfig config;
  if (!ReadOpenConfig(env, args[0], &config)) {
    bool pending = false;
    napi_is_exception_pending(env, &pending);
    if (!pending) ThrowCode(env, kOpenRejected);
    return nullptr;
  }
  const uid_t real_uid = getuid();
  const uid_t effective_uid = geteuid();
  const gid_t real_gid = getgid();
  const gid_t effective_gid = getegid();
  if (real_uid != effective_uid || real_gid != effective_gid ||
      config.worker_uid != static_cast<uint32_t>(real_uid) ||
      config.worker_uid != static_cast<uint32_t>(effective_uid) ||
      config.worker_gid != static_cast<uint32_t>(real_gid) ||
      config.worker_gid != static_cast<uint32_t>(effective_gid) ||
      (config.expected_device.mode & S_IFMT) != S_IFCHR ||
      config.expected_device.nlink != 1) {
    ThrowCode(env, kOpenRejected);
    return nullptr;
  }

  int directory_flags = O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW;
  ScopedFd directory_fd(open(config.directory_path.c_str(), directory_flags));
  struct stat directory_before;
  struct stat device_before;
  SecureZero(&directory_before, sizeof(directory_before));
  SecureZero(&device_before, sizeof(device_before));
  if (directory_fd.get() < 0 || fstat(directory_fd.get(), &directory_before) != 0 ||
      !S_ISDIR(directory_before.st_mode) ||
      !MatchesExpected(directory_before, config.expected_directory, false) ||
      fstatat(directory_fd.get(), config.final_component.c_str(), &device_before,
              AT_SYMLINK_NOFOLLOW) != 0 ||
      !S_ISCHR(device_before.st_mode) || device_before.st_nlink != 1 ||
      !MatchesExpected(device_before, config.expected_device, true)) {
    SecureZero(&directory_before, sizeof(directory_before));
    SecureZero(&device_before, sizeof(device_before));
    ThrowCode(env, kOpenRejected);
    return nullptr;
  }

  const int device_flags =
      O_RDWR | O_NONBLOCK | O_CLOEXEC | O_NOCTTY | O_NOFOLLOW;
  ScopedFd device_fd(openat(directory_fd.get(), config.final_component.c_str(),
                            device_flags));
  struct stat device_opened;
  struct stat device_after;
  struct stat directory_after;
  SecureZero(&device_opened, sizeof(device_opened));
  SecureZero(&device_after, sizeof(device_after));
  SecureZero(&directory_after, sizeof(directory_after));
  int descriptor_flags = -1;
  if (device_fd.get() < 0 || fstat(device_fd.get(), &device_opened) != 0 ||
      !S_ISCHR(device_opened.st_mode) || device_opened.st_nlink != 1 ||
      !SameStat(device_before, device_opened, true) ||
      !MatchesExpected(device_opened, config.expected_device, true) ||
      !IsExactPtySlave(device_fd.get()) ||
      (descriptor_flags = fcntl(device_fd.get(), F_GETFD)) < 0 ||
      (descriptor_flags & FD_CLOEXEC) == 0 ||
      flock(device_fd.get(), LOCK_EX | LOCK_NB) != 0 ||
      ioctl(device_fd.get(), TIOCEXCL) != 0) {
    SecureZero(&directory_before, sizeof(directory_before));
    SecureZero(&device_before, sizeof(device_before));
    SecureZero(&device_opened, sizeof(device_opened));
    SecureZero(&device_after, sizeof(device_after));
    SecureZero(&directory_after, sizeof(directory_after));
    ThrowCode(env, kOpenRejected);
    return nullptr;
  }

  std::string dtr_state;
  std::string rts_state;
  std::string actual_acl_state;
  std::vector<unsigned char> actual_acl_bytes;
  bool configured = ConfigureRaw115200(device_fd.get()) &&
                    ClearAndObserveModemLines(device_fd.get(), &dtr_state, &rts_state) &&
                    ReadAclProfile(device_fd.get(), &actual_acl_state, &actual_acl_bytes);
  const std::string actual_acl_digest =
      configured ? FramedDigest(kAclDigestDomain, actual_acl_state, actual_acl_bytes)
                 : std::string();
  const std::string actual_worker_identity_digest = configured
      ? WorkerIdentityDigest(config.worker_uid, config.worker_gid, actual_acl_digest)
      : std::string();
  if (!configured || actual_acl_state != config.acl_profile_state ||
      actual_acl_digest != config.acl_profile_digest ||
      actual_worker_identity_digest != config.worker_identity_digest ||
      !ConstantTimeEqual(actual_acl_bytes, config.acl_profile_bytes) ||
      fstat(device_fd.get(), &device_after) != 0 ||
      fstatat(directory_fd.get(), config.final_component.c_str(), &device_opened,
              AT_SYMLINK_NOFOLLOW) != 0 ||
      fstat(directory_fd.get(), &directory_after) != 0 ||
      !SameStat(device_before, device_after, true) ||
      !SameStat(device_before, device_opened, true) ||
      !SameStat(directory_before, directory_after, false)) {
    ZeroVector(&actual_acl_bytes);
    ZeroString(&actual_acl_state);
    ZeroString(&dtr_state);
    ZeroString(&rts_state);
    SecureZero(&directory_before, sizeof(directory_before));
    SecureZero(&device_before, sizeof(device_before));
    SecureZero(&device_opened, sizeof(device_opened));
    SecureZero(&device_after, sizeof(device_after));
    SecureZero(&directory_after, sizeof(directory_after));
    ThrowCode(env, kOpenRejected);
    return nullptr;
  }
  ZeroVector(&actual_acl_bytes);
  ZeroString(&actual_acl_state);

  auto state = std::make_shared<SerialState>();
  state->fd = device_fd.Release();
  state->generation = config.connection_generation;
  auto* box = new HandleBox{state};
  napi_value output;
  napi_value attestation;
  if (napi_create_object(env, &output) != napi_ok ||
      napi_create_object(env, &attestation) != napi_ok ||
      !SetUint32(env, attestation, "version", kVersion) ||
      !SetCString(env, attestation, "primitive", kPrimitive) ||
      !SetBool(env, attestation, "fixture_only", true) ||
      !SetString(env, attestation, "operator_device_identity_digest",
                 config.operator_device_identity_digest) ||
      !SetString(env, attestation, "directory_stat_digest",
                 config.directory_stat_digest) ||
      !SetString(env, attestation, "device_stat_digest", config.device_stat_digest) ||
      !SetString(env, attestation, "worker_identity_digest",
                 config.worker_identity_digest) ||
      !SetString(env, attestation, "acl_profile_digest", config.acl_profile_digest) ||
      !SetUint32(env, attestation, "connection_generation",
                 config.connection_generation) ||
      !SetBool(env, attestation, "exclusive_open", true) ||
      !SetBool(env, attestation, "close_on_exec", true) ||
      !SetBool(env, attestation, "no_controlling_tty", true) ||
      !SetBool(env, attestation, "no_follow", true) ||
      !SetBool(env, attestation, "raw_115200_8n1", true) ||
      !SetBool(env, attestation, "dtr_preopen_guaranteed", false) ||
      !SetBool(env, attestation, "dtr_transient_guaranteed", false) ||
      !SetString(env, attestation, "post_open_dtr_state", dtr_state) ||
      !SetString(env, attestation, "post_open_rts_state", rts_state) ||
      !SetBool(env, attestation, "production_ready", false)) {
    delete box;
    ZeroString(&dtr_state);
    ZeroString(&rts_state);
    SecureZero(&directory_before, sizeof(directory_before));
    SecureZero(&device_before, sizeof(device_before));
    SecureZero(&device_opened, sizeof(device_opened));
    SecureZero(&device_after, sizeof(device_after));
    SecureZero(&directory_after, sizeof(directory_after));
    ThrowCode(env, kOpenRejected);
    return nullptr;
  }
  napi_value external;
  if (napi_create_external(env, box, FinalizeHandle, nullptr, &external) != napi_ok) {
    delete box;
    ZeroString(&dtr_state);
    ZeroString(&rts_state);
    SecureZero(&directory_before, sizeof(directory_before));
    SecureZero(&device_before, sizeof(device_before));
    SecureZero(&device_opened, sizeof(device_opened));
    SecureZero(&device_after, sizeof(device_after));
    SecureZero(&directory_after, sizeof(directory_after));
    ThrowCode(env, kOpenRejected);
    return nullptr;
  }
  if (!DefineProperty(env, output, "handle", external) ||
      !DefineProperty(env, output, "attestation", attestation)) {
    // `external` now owns `box`; close immediately but leave deletion to its
    // finalizer so a property-definition failure cannot double free it.
    std::lock_guard<std::mutex> lock(state->mutex);
    if (state->fd >= 0) close(state->fd);
    state->fd = -1;
    state->closed = true;
    ZeroString(&dtr_state);
    ZeroString(&rts_state);
    SecureZero(&directory_before, sizeof(directory_before));
    SecureZero(&device_before, sizeof(device_before));
    SecureZero(&device_opened, sizeof(device_opened));
    SecureZero(&device_after, sizeof(device_after));
    SecureZero(&directory_after, sizeof(directory_after));
    ThrowCode(env, kOpenRejected);
    return nullptr;
  }
  ZeroString(&dtr_state);
  ZeroString(&rts_state);
  SecureZero(&directory_before, sizeof(directory_before));
  SecureZero(&device_before, sizeof(device_before));
  SecureZero(&device_opened, sizeof(device_opened));
  SecureZero(&device_after, sizeof(device_after));
  SecureZero(&directory_after, sizeof(directory_after));
  return output;
}

unsigned char CalculateLrc(const unsigned char* bytes, size_t length) {
  unsigned int sum = 0;
  for (size_t index = 0; index < length; ++index) sum = (sum + bytes[index]) & 0xff;
  return static_cast<unsigned char>((0U - sum) & 0xff);
}

uint16_t ReadBigEndian16(const unsigned char* bytes) {
  return static_cast<uint16_t>((static_cast<uint16_t>(bytes[0]) << 8) | bytes[1]);
}

bool ValidRequestFrame(const std::vector<unsigned char>& frame) {
  if (frame.size() < kMinimumFrameBytes || frame.size() > kMaximumFrameBytes ||
      frame[0] != kSof || frame[1] != kSofLrc || ReadBigEndian16(&frame[4]) != 0 ||
      CalculateLrc(&frame[2], 6) != frame[8] ||
      static_cast<size_t>(ReadBigEndian16(&frame[6])) + kMinimumFrameBytes !=
          frame.size()) {
    return false;
  }
  return CalculateLrc(&frame[9], frame.size() - kMinimumFrameBytes) == frame.back();
}

bool ValidResponseFrame(const std::vector<unsigned char>& frame, uint16_t command) {
  return frame.size() >= kMinimumFrameBytes && frame.size() <= kMaximumFrameBytes &&
         frame[0] == kSof && frame[1] == kSofLrc &&
         ReadBigEndian16(&frame[2]) == command &&
         CalculateLrc(&frame[2], 6) == frame[8] &&
         static_cast<size_t>(ReadBigEndian16(&frame[6])) + kMinimumFrameBytes ==
             frame.size() &&
         CalculateLrc(&frame[9], frame.size() - kMinimumFrameBytes) == frame.back();
}

bool WaitForFd(int fd, short events,
               const std::chrono::steady_clock::time_point& deadline,
               const std::atomic<bool>& aborted) {
  while (!aborted.load(std::memory_order_acquire)) {
    const auto now = std::chrono::steady_clock::now();
    if (now >= deadline) return false;
    const auto remaining =
        std::chrono::duration_cast<std::chrono::milliseconds>(deadline - now).count();
    const int timeout = static_cast<int>(std::max<int64_t>(1, std::min<int64_t>(10, remaining)));
    struct pollfd descriptor = {fd, events, 0};
    const int result = poll(&descriptor, 1, timeout);
    if (result < 0 && errno == EINTR) continue;
    if (result < 0) return false;
    if (result == 0) continue;
    if ((descriptor.revents & (POLLERR | POLLHUP | POLLNVAL)) != 0) return false;
    if ((descriptor.revents & events) != 0) return true;
  }
  return false;
}

bool PerformTransaction(TransactionWork* work) {
  int fd = -1;
  {
    std::lock_guard<std::mutex> lock(work->state->mutex);
    if (work->state->closed || work->state->fd < 0 ||
        work->state->generation != work->generation || !work->state->busy ||
        work->state->active_sequence != work->sequence) {
      return false;
    }
    fd = work->state->fd;
  }
  if (!ValidRequestFrame(work->request)) return false;
  int pending = 0;
  if (ioctl(fd, FIONREAD, &pending) != 0 || pending != 0) return false;
  const auto deadline = std::chrono::steady_clock::now() +
                        std::chrono::milliseconds(work->timeout_ms);
  size_t written = 0;
  while (written < work->request.size()) {
    if (!WaitForFd(fd, POLLOUT, deadline, work->state->abort_requested)) return false;
    const ssize_t result =
        write(fd, work->request.data() + written, work->request.size() - written);
    if (result < 0 && (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK)) continue;
    if (result <= 0) return false;
    written += static_cast<size_t>(result);
  }
  // A partial or completed write is never retried as a command. Waiting on the
  // existing fd only finishes this exact write operation.
  while (true) {
    int output_bytes = 0;
    if (ioctl(fd, TIOCOUTQ, &output_bytes) != 0) return false;
    if (output_bytes == 0) break;
    if (!WaitForFd(fd, POLLOUT, deadline, work->state->abort_requested)) return false;
  }

  const uint16_t request_command = ReadBigEndian16(&work->request[2]);
  size_t expected_length = 0;
  work->response.reserve(work->maximum_response_bytes);
  while (expected_length == 0 || work->response.size() < expected_length) {
    if (!WaitForFd(fd, POLLIN, deadline, work->state->abort_requested)) return false;
    unsigned char chunk[1024];
    const size_t remaining =
        work->maximum_response_bytes - work->response.size();
    const ssize_t result = read(fd, chunk, std::min(sizeof(chunk), remaining));
    if (result < 0 && (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK)) {
      SecureZero(chunk, sizeof(chunk));
      continue;
    }
    if (result <= 0) {
      SecureZero(chunk, sizeof(chunk));
      return false;
    }
    work->response.insert(work->response.end(), chunk, chunk + result);
    SecureZero(chunk, sizeof(chunk));
    if (work->response.size() >= 1 && work->response[0] != kSof) return false;
    if (work->response.size() >= 2 && work->response[1] != kSofLrc) return false;
    if (work->response.size() >= 9) {
      if (ReadBigEndian16(&work->response[2]) != request_command ||
          CalculateLrc(&work->response[2], 6) != work->response[8]) {
        return false;
      }
      expected_length =
          static_cast<size_t>(ReadBigEndian16(&work->response[6])) + kMinimumFrameBytes;
      if (expected_length > work->maximum_response_bytes ||
          expected_length > kMaximumFrameBytes) {
        return false;
      }
    }
    if (expected_length > 0 && work->response.size() > expected_length) return false;
  }
  if (!ValidResponseFrame(work->response, request_command)) return false;
  if (ioctl(fd, FIONREAD, &pending) != 0 || pending != 0) return false;
  // Retain a small bounded quiescence window to catch an already-split trailing
  // frame. Later bytes remain fail-closed because the next transaction requires
  // an empty input queue before writing.
  const auto trailing_now = std::chrono::steady_clock::now();
  if (trailing_now >= deadline) return false;
  const auto trailing_remaining =
      std::chrono::duration_cast<std::chrono::milliseconds>(deadline - trailing_now).count();
  const int trailing_timeout =
      static_cast<int>(std::max<int64_t>(0, std::min<int64_t>(2, trailing_remaining)));
  struct pollfd trailing = {fd, POLLIN, 0};
  const int trailing_result = poll(&trailing, 1, trailing_timeout);
  if (trailing_result < 0 ||
      (trailing_result > 0 && (trailing.revents & (POLLIN | POLLERR | POLLHUP | POLLNVAL)))) {
    return false;
  }
  return !work->state->abort_requested.load(std::memory_order_acquire);
}

void ExecuteTransaction(napi_env, void* data) {
  auto* work = static_cast<TransactionWork*>(data);
  work->succeeded = PerformTransaction(work);
  std::lock_guard<std::mutex> lock(work->state->mutex);
  if (!work->succeeded && work->state->fd >= 0) {
    close(work->state->fd);
    work->state->fd = -1;
    work->state->closed = true;
  }
  work->state->busy = false;
  work->state->active_sequence = 0;
}

void CompleteTransaction(napi_env env, napi_status status, void* data) {
  auto* work = static_cast<TransactionWork*>(data);
  if (status == napi_ok && work->succeeded) {
    napi_value response;
    if (napi_create_buffer_copy(env, work->response.size(), work->response.data(),
                                nullptr, &response) == napi_ok) {
      napi_resolve_deferred(env, work->deferred, response);
    } else {
      napi_value message;
      napi_value error;
      napi_create_string_utf8(env, "Darwin native serial transaction was ambiguous",
                              NAPI_AUTO_LENGTH, &message);
      napi_create_error(env, nullptr, message, &error);
      napi_reject_deferred(env, work->deferred, error);
    }
  } else {
    napi_value message;
    napi_value error;
    napi_value code;
    napi_create_string_utf8(env, "Darwin native serial transaction was ambiguous",
                            NAPI_AUTO_LENGTH, &message);
    napi_create_error(env, nullptr, message, &error);
    napi_create_string_utf8(env, kTransactionAmbiguous, NAPI_AUTO_LENGTH, &code);
    DefineProperty(env, error, "code", code);
    napi_reject_deferred(env, work->deferred, error);
  }
  napi_delete_async_work(env, work->work);
  delete work;
}

napi_value TransactExact(napi_env env, napi_callback_info info) {
  size_t argc = 6;
  napi_value args[6];
  if (napi_get_cb_info(env, info, &argc, args, nullptr, nullptr) != napi_ok ||
      argc != 6) {
    ThrowCode(env, kTransactionAmbiguous);
    return nullptr;
  }
  std::shared_ptr<SerialState> state;
  uint32_t generation = 0;
  uint32_t sequence = 0;
  uint32_t maximum_response_bytes = 0;
  uint32_t timeout_ms = 0;
  bool is_buffer = false;
  void* bytes = nullptr;
  size_t length = 0;
  if (!GetHandle(env, args[0], &state) ||
      napi_get_value_uint32(env, args[1], &generation) != napi_ok || generation == 0 ||
      napi_get_value_uint32(env, args[2], &sequence) != napi_ok || sequence == 0 ||
      napi_is_buffer(env, args[3], &is_buffer) != napi_ok || !is_buffer ||
      napi_get_buffer_info(env, args[3], &bytes, &length) != napi_ok ||
      length < kMinimumFrameBytes || length > kMaximumFrameBytes ||
      napi_get_value_uint32(env, args[4], &maximum_response_bytes) != napi_ok ||
      maximum_response_bytes < kMinimumFrameBytes ||
      maximum_response_bytes > kMaximumFrameBytes ||
      napi_get_value_uint32(env, args[5], &timeout_ms) != napi_ok || timeout_ms == 0 ||
      timeout_ms > kMaximumTimeoutMs) {
    ThrowCode(env, kTransactionAmbiguous);
    return nullptr;
  }
  auto* work = new TransactionWork();
  work->env = env;
  work->state = state;
  work->generation = generation;
  work->sequence = sequence;
  work->maximum_response_bytes = maximum_response_bytes;
  work->timeout_ms = timeout_ms;
  work->request.assign(static_cast<unsigned char*>(bytes),
                       static_cast<unsigned char*>(bytes) + length);
  if (!ValidRequestFrame(work->request)) {
    delete work;
    ThrowCode(env, kTransactionAmbiguous);
    return nullptr;
  }
  {
    std::lock_guard<std::mutex> lock(state->mutex);
    if (state->closed || state->fd < 0 || state->busy ||
        state->generation != generation || state->next_sequence != sequence) {
      delete work;
      ThrowCode(env, kTransactionAmbiguous);
      return nullptr;
    }
    state->busy = true;
    state->active_sequence = sequence;
    state->next_sequence += 1;
    state->abort_requested.store(false, std::memory_order_release);
  }
  napi_value promise;
  napi_value resource_name;
  if (napi_create_promise(env, &work->deferred, &promise) != napi_ok ||
      napi_create_string_utf8(env, "bobDarwinSerialExactTransaction",
                              NAPI_AUTO_LENGTH, &resource_name) != napi_ok ||
      napi_create_async_work(env, nullptr, resource_name, ExecuteTransaction,
                             CompleteTransaction, work, &work->work) != napi_ok ||
      napi_queue_async_work(env, work->work) != napi_ok) {
    std::lock_guard<std::mutex> lock(state->mutex);
    state->busy = false;
    state->active_sequence = 0;
    if (state->fd >= 0) {
      close(state->fd);
      state->fd = -1;
      state->closed = true;
    }
    if (work->work != nullptr) napi_delete_async_work(env, work->work);
    delete work;
    ThrowCode(env, kTransactionAmbiguous);
    return nullptr;
  }
  return promise;
}

napi_value AbortExact(napi_env env, napi_callback_info info) {
  size_t argc = 3;
  napi_value args[3];
  std::shared_ptr<SerialState> state;
  uint32_t generation = 0;
  uint32_t sequence = 0;
  bool aborted = false;
  if (napi_get_cb_info(env, info, &argc, args, nullptr, nullptr) != napi_ok || argc != 3 ||
      !GetHandle(env, args[0], &state) ||
      napi_get_value_uint32(env, args[1], &generation) != napi_ok ||
      napi_get_value_uint32(env, args[2], &sequence) != napi_ok) {
    ThrowCode(env, kRejected);
    return nullptr;
  }
  {
    std::lock_guard<std::mutex> lock(state->mutex);
    if (!state->closed && state->busy && state->generation == generation &&
        state->active_sequence == sequence) {
      state->abort_requested.store(true, std::memory_order_release);
      aborted = true;
    }
  }
  napi_value output;
  napi_get_boolean(env, aborted, &output);
  return output;
}

napi_value CloseExact(napi_env env, napi_callback_info info) {
  size_t argc = 1;
  napi_value args[1];
  std::shared_ptr<SerialState> state;
  if (napi_get_cb_info(env, info, &argc, args, nullptr, nullptr) != napi_ok || argc != 1 ||
      !GetHandle(env, args[0], &state)) {
    ThrowCode(env, kRejected);
    return nullptr;
  }
  bool closed = false;
  {
    std::lock_guard<std::mutex> lock(state->mutex);
    if (state->closed) {
      closed = true;
    } else if (state->busy) {
      state->abort_requested.store(true, std::memory_order_release);
    } else {
      if (state->fd >= 0) close(state->fd);
      state->fd = -1;
      state->closed = true;
      closed = true;
    }
  }
  napi_value output;
  napi_get_boolean(env, closed, &output);
  return output;
}

napi_value Init(napi_env env, napi_value exports) {
  const napi_property_descriptor descriptors[] = {
      {"openExact", nullptr, OpenExact, nullptr, nullptr, nullptr, napi_enumerable,
       nullptr},
      {"transactExact", nullptr, TransactExact, nullptr, nullptr, nullptr,
       napi_enumerable, nullptr},
      {"abortExact", nullptr, AbortExact, nullptr, nullptr, nullptr, napi_enumerable,
       nullptr},
      {"closeExact", nullptr, CloseExact, nullptr, nullptr, nullptr, napi_enumerable,
       nullptr},
  };
  if (napi_define_properties(env, exports,
                             sizeof(descriptors) / sizeof(descriptors[0]),
                             descriptors) != napi_ok) {
    return nullptr;
  }
  return exports;
}

}  // namespace

NAPI_MODULE(NODE_GYP_MODULE_NAME, Init)
