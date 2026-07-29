#include <node_api.h>

#include <CommonCrypto/CommonDigest.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <mach/mach_time.h>
#include <openssl/evp.h>
#include <poll.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#include <algorithm>
#include <array>
#include <atomic>
#include <cerrno>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <limits>
#include <memory>
#include <mutex>
#include <string>
#include <vector>

#include "generated_bootstrap_semantics.h"

namespace {

constexpr int kLauncherContextFd = 3;
constexpr int kDelegatedDeviceFd = 4;
constexpr int kDispatchInputFd = 5;
constexpr int kTerminalResultFd = 6;
constexpr int kResponseVaultSinkFd = 7;
constexpr uint16_t kVersion = 1;
constexpr uint16_t kAlgorithmEd25519 = 1;
constexpr size_t kDigestBytes = 32;
constexpr size_t kSignatureBytes = 64;
constexpr size_t kSpkiBytes = 44;
constexpr size_t kEnvelopeHeaderBytes = 50;
constexpr size_t kInputHeaderBytes = 18;
constexpr size_t kResultBytes = 196;
constexpr size_t kResponseSinkHeaderBytes = 280;
constexpr size_t kMaximumContextBytes = 16 * 1024;
constexpr size_t kMaximumEnvelopeBytes = 40 * 1024;
constexpr size_t kMaximumCommandBytes = 64 * 1024;
constexpr size_t kMaximumInputBytes = 112 * 1024;
constexpr size_t kMaximumResponseBytes = 1024 * 1024;
constexpr uint64_t kMaximumEffectWindowNs = 10ULL * 60ULL * 1000000000ULL;
constexpr uint64_t kStartupWindowNs = 10ULL * 1000000000ULL;
constexpr uint64_t kResultWriteWindowNs = 2ULL * 1000000000ULL;
constexpr uint64_t kFixturePostPollStallNs = 600ULL * 1000000ULL;
constexpr uint32_t kExpectedDeviceStatusFlags = O_RDWR | O_NONBLOCK;
// Darwin exposes the kernel-private FWASWRITTEN bit through F_GETFL after a
// successful regular-file write. It is not caller-selectable open authority;
// mask only this exact post-write state bit during final sink revalidation.
constexpr int kDarwinKernelWasWrittenFlag = 0x00010000;

constexpr unsigned char kContextEnvelopeMagic[8] = {
    'H', 'B', 'P', 'H', 'D', 'L', 'C', '1'};
constexpr unsigned char kContextBodyMagic[8] = {
    'H', 'B', 'P', 'H', 'D', 'L', 'B', '1'};
constexpr unsigned char kDispatchEnvelopeMagic[8] = {
    'H', 'B', 'P', 'H', 'D', 'S', 'E', '1'};
constexpr unsigned char kDispatchPayloadMagic[8] = {
    'H', 'B', 'P', 'H', 'D', 'S', 'P', '1'};
constexpr unsigned char kDispatchInputMagic[8] = {
    'H', 'B', 'P', 'H', 'D', 'I', 'N', '1'};
constexpr unsigned char kDescriptorIdentityMagic[8] = {
    'H', 'B', 'P', 'H', 'D', 'I', 'D', '1'};
constexpr unsigned char kTerminalResultMagic[8] = {
    'H', 'B', 'P', 'H', 'D', 'R', 'S', '1'};
constexpr unsigned char kResponseSinkIdentityMagic[8] = {
    'H', 'B', 'P', 'H', 'D', 'V', 'S', '1'};
constexpr unsigned char kResponseSinkRecordMagic[8] = {
    'H', 'B', 'P', 'H', 'V', 'S', 'R', '1'};
constexpr unsigned char kEd25519SpkiPrefix[12] = {
    0x30, 0x2a, 0x30, 0x05, 0x06, 0x03,
    0x2b, 0x65, 0x70, 0x03, 0x21, 0x00};
constexpr char kContextSignatureDomain[] =
    "hacker-bob/physical-native-launcher-context-signature/v1\0";
constexpr char kDispatchSignatureDomain[] =
    "hacker-bob/physical-native-dispatch-ticket-signature/v1\0";
constexpr char kDescriptorRole[] = "launcher_delegated_device_transport";
constexpr char kDescriptorPurpose[] = "physical_native_dispatch_transport";
constexpr char kResponseSinkRole[] = "vault_reserved_provider_response_sink";
constexpr char kResponseSinkPurpose[] = "physical_native_response_vault_ingest";
constexpr char kProtocol[] = "hacker-bob/physical-native-dispatch/v1";
std::atomic<bool> g_started{false};

void SecureZero(void* pointer, size_t length) {
  volatile unsigned char* cursor = static_cast<volatile unsigned char*>(pointer);
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

class ScopedFd {
 public:
  explicit ScopedFd(int fd = -1) : fd_(fd) {}
  ScopedFd(const ScopedFd&) = delete;
  ScopedFd& operator=(const ScopedFd&) = delete;
  ~ScopedFd() { Reset(); }
  int get() const { return fd_; }
  void Reset(int next = -1) {
    if (fd_ >= 0) close(fd_);
    fd_ = next;
  }

 private:
  int fd_;
};

struct FieldView {
  const unsigned char* data = nullptr;
  size_t length = 0;
};

struct EnvelopeView {
  std::string key_id;
  std::array<unsigned char, kDigestBytes> public_key_digest{};
  const unsigned char* payload = nullptr;
  size_t payload_length = 0;
  const unsigned char* signature = nullptr;
  const unsigned char* prefix = nullptr;
  size_t prefix_length = 0;
};

struct KernelIdentity {
  dev_t dev = 0;
  ino_t ino = 0;
  mode_t mode = 0;
  dev_t rdev = 0;
  nlink_t nlink = 0;
  uid_t uid = 0;
  gid_t gid = 0;
};

struct DeviceWriteBoundary {
  KernelIdentity identity;
  uid_t uid = 0;
  gid_t gid = 0;
};

struct ResponseSinkBoundary {
  KernelIdentity identity;
  off_t initial_size = 0;
};

enum class TerminalStatus : uint16_t {
  kRejectedNoEffect = 1,
  kAmbiguousQuarantined = 2,
  kFixtureCompleteNonAuthorizing = 3,
};

struct DispatchWork {
  napi_env env = nullptr;
  napi_async_work work = nullptr;
  napi_deferred deferred = nullptr;
  bool terminal_result_written = false;
  TerminalStatus status = TerminalStatus::kRejectedNoEffect;
  uint32_t flags = 0;
  uint32_t response_length = 0;
  uint64_t ticket_sequence = 0;
  uint64_t settled_ns = 0;
  std::array<unsigned char, kDigestBytes> envelope_digest{};
  std::array<unsigned char, kDigestBytes> descriptor_digest{};
  std::array<unsigned char, kDigestBytes> response_digest{};
  std::array<unsigned char, kDigestBytes> sink_descriptor_digest{};
  std::array<unsigned char, kDigestBytes> sink_record_digest{};
  std::vector<unsigned char> context;
  std::vector<unsigned char> input;
  std::vector<unsigned char> command;
  std::vector<unsigned char> response;

  ~DispatchWork() {
    ZeroVector(&context);
    ZeroVector(&input);
    ZeroVector(&command);
    ZeroVector(&response);
    SecureZero(envelope_digest.data(), envelope_digest.size());
    SecureZero(descriptor_digest.data(), descriptor_digest.size());
    SecureZero(response_digest.data(), response_digest.size());
    SecureZero(sink_descriptor_digest.data(), sink_descriptor_digest.size());
    SecureZero(sink_record_digest.data(), sink_record_digest.size());
  }
};

uint16_t ReadU16(const unsigned char* bytes) {
  return static_cast<uint16_t>((static_cast<uint16_t>(bytes[0]) << 8U) |
                               static_cast<uint16_t>(bytes[1]));
}

uint32_t ReadU32(const unsigned char* bytes) {
  return (static_cast<uint32_t>(bytes[0]) << 24U) |
         (static_cast<uint32_t>(bytes[1]) << 16U) |
         (static_cast<uint32_t>(bytes[2]) << 8U) |
         static_cast<uint32_t>(bytes[3]);
}

uint64_t ReadU64(const unsigned char* bytes) {
  uint64_t value = 0;
  for (size_t index = 0; index < 8; ++index) {
    value = (value << 8U) | static_cast<uint64_t>(bytes[index]);
  }
  return value;
}

void WriteU16(unsigned char* bytes, uint16_t value) {
  bytes[0] = static_cast<unsigned char>((value >> 8U) & 0xffU);
  bytes[1] = static_cast<unsigned char>(value & 0xffU);
}

void WriteU32(unsigned char* bytes, uint32_t value) {
  bytes[0] = static_cast<unsigned char>((value >> 24U) & 0xffU);
  bytes[1] = static_cast<unsigned char>((value >> 16U) & 0xffU);
  bytes[2] = static_cast<unsigned char>((value >> 8U) & 0xffU);
  bytes[3] = static_cast<unsigned char>(value & 0xffU);
}

void WriteU64(unsigned char* bytes, uint64_t value) {
  for (size_t index = 0; index < 8; ++index) {
    bytes[7 - index] = static_cast<unsigned char>(value & 0xffU);
    value >>= 8U;
  }
}

bool ConstantEqual(const unsigned char* left, const unsigned char* right,
                   size_t length) {
  unsigned char difference = 0;
  for (size_t index = 0; index < length; ++index) {
    difference |= static_cast<unsigned char>(left[index] ^ right[index]);
  }
  return difference == 0;
}

bool Sha256(const unsigned char* bytes, size_t length,
            std::array<unsigned char, kDigestBytes>* output) {
  if (output == nullptr || length > std::numeric_limits<CC_LONG>::max()) return false;
  return CC_SHA256(bytes, static_cast<CC_LONG>(length), output->data()) != nullptr;
}

bool ContinuousNs(uint64_t* output) {
  if (output == nullptr) return false;
  mach_timebase_info_data_t timebase{};
  if (mach_timebase_info(&timebase) != KERN_SUCCESS || timebase.denom == 0) return false;
  const __uint128_t scaled =
      static_cast<__uint128_t>(mach_continuous_time()) * timebase.numer;
  const __uint128_t nanoseconds = scaled / timebase.denom;
  if (nanoseconds > std::numeric_limits<uint64_t>::max()) return false;
  *output = static_cast<uint64_t>(nanoseconds);
  return true;
}

int PollTimeoutMs(uint64_t deadline_ns) {
  uint64_t now = 0;
  if (!ContinuousNs(&now) || now >= deadline_ns) return 0;
  const uint64_t remaining = deadline_ns - now;
  const uint64_t rounded = (remaining + 999999ULL) / 1000000ULL;
  return static_cast<int>(std::min<uint64_t>(rounded,
      static_cast<uint64_t>(std::numeric_limits<int>::max())));
}

bool WaitFd(int fd, short events, uint64_t deadline_ns) {
  while (true) {
    const int timeout = PollTimeoutMs(deadline_ns);
    if (timeout <= 0) return false;
    pollfd descriptor{fd, events, 0};
    const int result = poll(&descriptor, 1, timeout);
    if (result > 0) {
      if ((descriptor.revents & (POLLERR | POLLNVAL)) != 0) return false;
      if ((descriptor.revents & events) != 0) return true;
      if ((descriptor.revents & POLLHUP) != 0) return events == POLLIN;
      continue;
    }
    if (result == 0) return false;
    if (errno != EINTR) return false;
  }
}

bool SetNonblocking(int fd) {
  const int flags = fcntl(fd, F_GETFL);
  return flags >= 0 && fcntl(fd, F_SETFL, flags | O_NONBLOCK) == 0;
}

bool ReadToEof(int fd, size_t maximum, uint64_t deadline_ns,
               std::vector<unsigned char>* output) {
  if (output == nullptr || !SetNonblocking(fd)) return false;
  std::array<unsigned char, 4096> buffer{};
  while (true) {
    const ssize_t count = read(fd, buffer.data(), buffer.size());
    if (count > 0) {
      const size_t amount = static_cast<size_t>(count);
      if (output->size() > maximum - amount) {
        SecureZero(buffer.data(), buffer.size());
        return false;
      }
      output->insert(output->end(), buffer.data(), buffer.data() + amount);
      SecureZero(buffer.data(), amount);
      continue;
    }
    if (count == 0) {
      SecureZero(buffer.data(), buffer.size());
      return !output->empty();
    }
    if (errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR) {
      SecureZero(buffer.data(), buffer.size());
      return false;
    }
    if (errno == EINTR) continue;
    if (!WaitFd(fd, POLLIN, deadline_ns)) {
      SecureZero(buffer.data(), buffer.size());
      return false;
    }
  }
}

bool ValidateDeviceWriteBoundary(int fd, uint64_t deadline_ns,
                                 const DeviceWriteBoundary& boundary);

void ApplyFixturePostPollStall(size_t write_ordinal) {
  const char* selected =
      std::getenv("BOB_CHAMELEON_DARWIN_NATIVE_DISPATCH_FIXTURE_POST_POLL_STALL");
  const bool requested =
      (write_ordinal == 1U && selected != nullptr && std::strcmp(selected, "first") == 0) ||
      (write_ordinal == 2U && selected != nullptr &&
       std::strcmp(selected, "continuation") == 0);
  if (!requested) return;
  timespec remaining{
      static_cast<time_t>(kFixturePostPollStallNs / 1000000000ULL),
      static_cast<long>(kFixturePostPollStallNs % 1000000000ULL)};
  while (nanosleep(&remaining, &remaining) != 0 && errno == EINTR) {
  }
}

bool WriteAll(int fd, const unsigned char* bytes, size_t length,
              uint64_t deadline_ns, bool* wrote_any,
              const DeviceWriteBoundary* device_boundary = nullptr) {
  size_t offset = 0;
  size_t write_ordinal = 0;
  while (offset < length) {
    if (!WaitFd(fd, POLLOUT, deadline_ns)) return false;
    ++write_ordinal;
    if (device_boundary != nullptr) {
      ApplyFixturePostPollStall(write_ordinal);
      if (!ValidateDeviceWriteBoundary(fd, deadline_ns, *device_boundary)) return false;
    }
    const ssize_t count = write(fd, bytes + offset, length - offset);
    if (count > 0) {
      offset += static_cast<size_t>(count);
      if (wrote_any != nullptr) *wrote_any = true;
      continue;
    }
    if (count < 0 && (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK)) {
      continue;
    }
    return false;
  }
  return true;
}

bool IsToken(const FieldView& field, bool identifier) {
  if (field.data == nullptr || field.length == 0 ||
      field.length > (identifier ? 128U : 191U)) return false;
  for (size_t index = 0; index < field.length; ++index) {
    const unsigned char value = field.data[index];
    if (value == 0 || value > 0x7fU) return false;
    if (index == 0) {
      if (identifier) {
        if (value < 'a' || value > 'z') return false;
      } else if (!((value >= 'A' && value <= 'Z') ||
                   (value >= 'a' && value <= 'z') ||
                   (value >= '0' && value <= '9'))) {
        return false;
      }
      continue;
    }
    const bool allowed = (value >= 'A' && value <= 'Z') ||
                         (value >= 'a' && value <= 'z') ||
                         (value >= '0' && value <= '9') || value == '.' ||
                         value == '_' || value == ':' || value == '@' || value == '-';
    if (!allowed || (identifier && (value == ':' || value == '@' ||
                                    (value >= 'A' && value <= 'Z')))) return false;
  }
  return true;
}

bool FieldEquals(const FieldView& field, const char* expected) {
  const size_t length = std::strlen(expected);
  return field.length == length && ConstantEqual(field.data,
      reinterpret_cast<const unsigned char*>(expected), length);
}

bool SameField(const FieldView& left, const FieldView& right) {
  return left.length == right.length &&
         ConstantEqual(left.data, right.data, left.length);
}

bool ParseTlv(const unsigned char* bytes, size_t length,
              const unsigned char magic[8], uint16_t field_count,
              std::vector<FieldView>* fields) {
  if (bytes == nullptr || fields == nullptr || length < 12 ||
      !ConstantEqual(bytes, magic, 8) || ReadU16(bytes + 8) != kVersion ||
      ReadU16(bytes + 10) != field_count) return false;
  fields->assign(static_cast<size_t>(field_count) + 1U, FieldView{});
  size_t offset = 12;
  for (uint16_t expected = 1; expected <= field_count; ++expected) {
    if (offset > length || length - offset < 6) return false;
    const uint16_t tag = ReadU16(bytes + offset);
    const uint32_t field_length = ReadU32(bytes + offset + 2);
    offset += 6;
    if (tag != expected || static_cast<size_t>(field_length) > length - offset) {
      return false;
    }
    (*fields)[expected] = {bytes + offset, static_cast<size_t>(field_length)};
    offset += static_cast<size_t>(field_length);
  }
  return offset == length;
}

bool ParseEnvelope(const unsigned char* bytes, size_t length,
                   const unsigned char magic[8], EnvelopeView* output) {
  if (bytes == nullptr || output == nullptr || length < kEnvelopeHeaderBytes + 1 + 12 +
      kSignatureBytes || length > kMaximumEnvelopeBytes ||
      !ConstantEqual(bytes, magic, 8) || ReadU16(bytes + 8) != kVersion ||
      ReadU16(bytes + 10) != kAlgorithmEd25519) return false;
  const uint16_t key_length = ReadU16(bytes + 12);
  const uint32_t payload_length = ReadU32(bytes + 14);
  const size_t payload_offset = kEnvelopeHeaderBytes + key_length;
  if (key_length == 0 || key_length > 191 || payload_length < 12 ||
      payload_offset > length || static_cast<size_t>(payload_length) > length - payload_offset ||
      payload_offset + static_cast<size_t>(payload_length) + kSignatureBytes != length) {
    return false;
  }
  const FieldView key_view{bytes + kEnvelopeHeaderBytes, key_length};
  if (!IsToken(key_view, false)) return false;
  output->key_id.assign(reinterpret_cast<const char*>(key_view.data), key_view.length);
  std::copy(bytes + 18, bytes + 50, output->public_key_digest.begin());
  output->payload = bytes + payload_offset;
  output->payload_length = payload_length;
  output->signature = bytes + payload_offset + payload_length;
  output->prefix = bytes;
  output->prefix_length = payload_offset + payload_length;
  return true;
}

bool ValidSpki(const FieldView& field) {
  return field.length == kSpkiBytes &&
         ConstantEqual(field.data, kEd25519SpkiPrefix, sizeof(kEd25519SpkiPrefix));
}

bool VerifyEd25519(const EnvelopeView& envelope, const FieldView& spki,
                   const char* domain, size_t domain_length) {
  if (!ValidSpki(spki) || domain == nullptr || domain_length == 0) return false;
  std::array<unsigned char, kDigestBytes> digest{};
  if (!Sha256(spki.data, spki.length, &digest) ||
      !ConstantEqual(digest.data(), envelope.public_key_digest.data(), digest.size())) {
    SecureZero(digest.data(), digest.size());
    return false;
  }
  SecureZero(digest.data(), digest.size());
  std::vector<unsigned char> message;
  if (domain_length > std::numeric_limits<size_t>::max() - 8 - envelope.prefix_length) {
    return false;
  }
  message.reserve(domain_length + 8 + envelope.prefix_length);
  message.insert(message.end(), reinterpret_cast<const unsigned char*>(domain),
                 reinterpret_cast<const unsigned char*>(domain) + domain_length);
  std::array<unsigned char, 8> encoded_length{};
  WriteU64(encoded_length.data(), envelope.prefix_length);
  message.insert(message.end(), encoded_length.begin(), encoded_length.end());
  message.insert(message.end(), envelope.prefix,
                 envelope.prefix + envelope.prefix_length);
  SecureZero(encoded_length.data(), encoded_length.size());

  EVP_PKEY* raw_key = EVP_PKEY_new_raw_public_key(
      EVP_PKEY_ED25519, nullptr, spki.data + sizeof(kEd25519SpkiPrefix), 32);
  EVP_MD_CTX* context = raw_key == nullptr ? nullptr : EVP_MD_CTX_new();
  bool verified = false;
  if (context != nullptr && EVP_DigestVerifyInit(context, nullptr, nullptr, nullptr,
                                                 raw_key) == 1) {
    verified = EVP_DigestVerify(context, envelope.signature, kSignatureBytes,
                                message.data(), message.size()) == 1;
  }
  if (context != nullptr) EVP_MD_CTX_free(context);
  if (raw_key != nullptr) EVP_PKEY_free(raw_key);
  ZeroVector(&message);
  return verified;
}

bool ValidateContextFields(const std::vector<FieldView>& fields) {
  if (fields.size() != 36 || fields[1].length != 4 || ReadU32(fields[1].data) != 1 ||
      fields[2].length != 1 || fields[2].data[0] != 1 ||
      fields[3].length != 4 || fields[4].length != 4 ||
      !IsToken(fields[5], false) || !IsToken(fields[9], true) ||
      fields[15].length != 8 || ReadU64(fields[15].data) == 0 ||
      !IsToken(fields[20], false) || !ValidSpki(fields[22]) ||
      !ValidSpki(fields[23]) || fields[24].length < 16 || fields[24].length > 64 ||
      fields[29].length != 4 || ReadU32(fields[29].data) == 0 ||
      ReadU32(fields[29].data) > kMaximumResponseBytes) {
    return false;
  }
  constexpr uint16_t digest_tags[] = {
      6, 7, 8, 10, 11, 12, 13, 14, 16, 17, 18, 19, 21,
      25, 26, 27, 28, 30, 31, 32, 33, 34, 35};
  for (uint16_t tag : digest_tags) {
    if (fields[tag].length != kDigestBytes) return false;
  }
  std::array<unsigned char, kDigestBytes> dispatch_spki_digest{};
  const bool digest_ok = Sha256(fields[23].data, fields[23].length,
                                &dispatch_spki_digest) &&
      ConstantEqual(dispatch_spki_digest.data(), fields[21].data, kDigestBytes);
  SecureZero(dispatch_spki_digest.data(), dispatch_spki_digest.size());
  return digest_ok;
}

bool ValidateDispatchFields(const std::vector<FieldView>& fields) {
  if (fields.size() != 65 || fields[1].length != 4 || ReadU32(fields[1].data) != 1 ||
      !FieldEquals(fields[2], kProtocol) || !IsToken(fields[7], false) ||
      fields[8].length < 16 || fields[8].length > 64 || fields[9].length != 8 ||
      ReadU64(fields[9].data) == 0 || !IsToken(fields[10], true) ||
      fields[16].length != 8 || ReadU64(fields[16].data) == 0 ||
      !IsToken(fields[17], false) || !IsToken(fields[25], false) ||
      !IsToken(fields[27], false) || fields[31].length != 8 ||
      ReadU64(fields[31].data) == 0 || fields[32].length != 8 ||
      !IsToken(fields[33], false) || fields[50].length != 8 ||
      ReadU64(fields[50].data) == 0 || fields[52].length != 4 ||
      ReadU32(fields[52].data) == 0 || fields[53].length != 4 ||
      ReadU32(fields[53].data) == 0 || fields[55].length != 8 ||
      fields[56].length != 8 || ReadU64(fields[56].data) == 0 ||
      fields[57].length != 1 || fields[57].data[0] != 1 ||
      fields[63].length != 4 || ReadU32(fields[63].data) == 0) return false;
  constexpr uint16_t digest_tags[] = {
      11, 12, 13, 14, 15, 18, 19, 20, 21, 22, 23, 24, 26, 28, 29, 30,
      34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49,
      51, 54, 58, 59, 60, 61, 62, 64};
  for (uint16_t tag : digest_tags) {
    if (fields[tag].length != kDigestBytes) return false;
  }
  const uint32_t command_length = ReadU32(fields[52].data);
  const uint32_t response_maximum = ReadU32(fields[53].data);
  const uint64_t not_before = ReadU64(fields[55].data);
  const uint64_t deadline = ReadU64(fields[56].data);
  const uint32_t vault_byte_ceiling = ReadU32(fields[63].data);
  if (command_length > kMaximumCommandBytes || response_maximum > kMaximumResponseBytes ||
      vault_byte_ceiling > kMaximumResponseBytes ||
      response_maximum > vault_byte_ceiling ||
      deadline <= not_before || deadline - not_before > kMaximumEffectWindowNs) return false;
  const bool grant_kind = FieldEquals(fields[3], "bootstrap") ||
                          FieldEquals(fields[3], "preparation") ||
                          FieldEquals(fields[3], "active") ||
                          FieldEquals(fields[3], "maintenance") ||
                          FieldEquals(fields[3], "cleanup");
  const bool command_kind = FieldEquals(fields[4], "observe") ||
                            FieldEquals(fields[4], "command") ||
                            FieldEquals(fields[4], "cleanup") ||
                            FieldEquals(fields[4], "fence") ||
                            FieldEquals(fields[4], "quarantine");
  const bool effect_class = FieldEquals(fields[5], "none") ||
                            FieldEquals(fields[5], "target") ||
                            FieldEquals(fields[5], "environment") ||
                            FieldEquals(fields[5], "device_admin");
  const bool rf_constraint = FieldEquals(fields[6], "rf_off") ||
                             FieldEquals(fields[6], "bounded") ||
                             FieldEquals(fields[6], "not_applicable");
  if (!grant_kind || !command_kind || !effect_class || !rf_constraint) return false;
  if (FieldEquals(fields[3], "bootstrap") &&
      (!FieldEquals(fields[4], "observe") || !FieldEquals(fields[5], "none") ||
       !FieldEquals(fields[6], "rf_off"))) return false;
  return !FieldEquals(fields[3], "cleanup") || FieldEquals(fields[4], "cleanup");
}

bool SameKernelIdentity(const KernelIdentity& left, const KernelIdentity& right) {
  return left.dev == right.dev && left.ino == right.ino && left.mode == right.mode &&
         left.rdev == right.rdev && left.nlink == right.nlink && left.uid == right.uid &&
         left.gid == right.gid;
}

bool SameSocketKernelObject(const KernelIdentity& left, const KernelIdentity& right) {
  // Darwin reflects local and peer shutdown directions in socket permission
  // bits. Those bits are mutable state of the same socket, not object identity.
  return left.dev == right.dev && left.ino == right.ino &&
         (left.mode & S_IFMT) == (right.mode & S_IFMT) &&
         left.rdev == right.rdev && left.nlink == right.nlink &&
         left.uid == right.uid && left.gid == right.gid;
}

bool ReadKernelIdentity(int fd, KernelIdentity* output) {
  struct stat status{};
  if (output == nullptr || fstat(fd, &status) != 0) return false;
  output->dev = status.st_dev;
  output->ino = status.st_ino;
  output->mode = status.st_mode;
  output->rdev = status.st_rdev;
  output->nlink = status.st_nlink;
  output->uid = status.st_uid;
  output->gid = status.st_gid;
  return true;
}

bool ValidateDeviceWriteBoundary(int fd, uint64_t deadline_ns,
                                 const DeviceWriteBoundary& boundary) {
  uint64_t immediately_before_write = 0;
  KernelIdentity current;
  return ContinuousNs(&immediately_before_write) && immediately_before_write < deadline_ns &&
         getuid() == boundary.uid && geteuid() == boundary.uid &&
         getgid() == boundary.gid && getegid() == boundary.gid &&
         ReadKernelIdentity(fd, &current) && SameKernelIdentity(current, boundary.identity) &&
         S_ISCHR(current.mode) && current.nlink == 1 &&
         fcntl(fd, F_GETFL) == static_cast<int>(kExpectedDeviceStatusFlags) &&
         fcntl(fd, F_GETFD) == FD_CLOEXEC && isatty(fd);
}

bool NormalizeAndValidateControlSocket(int fd) {
  int status_flags = fcntl(fd, F_GETFL);
  int descriptor_flags = fcntl(fd, F_GETFD);
  if (descriptor_flags == FD_CLOEXEC && fcntl(fd, F_SETFD, 0) == 0) {
    descriptor_flags = fcntl(fd, F_GETFD);
  }
  struct stat status{};
  sockaddr_storage address{};
  socklen_t address_length = sizeof(address);
  int socket_type = 0;
  socklen_t type_length = sizeof(socket_type);
  return status_flags == O_RDWR && descriptor_flags == 0 &&
         fstat(fd, &status) == 0 && S_ISSOCK(status.st_mode) &&
         getsockname(fd, reinterpret_cast<sockaddr*>(&address), &address_length) == 0 &&
         address.ss_family == AF_UNIX &&
         getsockopt(fd, SOL_SOCKET, SO_TYPE, &socket_type, &type_length) == 0 &&
         socket_type == SOCK_STREAM;
}

void AppendTlv(std::vector<unsigned char>* output, uint16_t tag,
               const unsigned char* bytes, size_t length) {
  std::array<unsigned char, 6> framing{};
  WriteU16(framing.data(), tag);
  WriteU32(framing.data() + 2, static_cast<uint32_t>(length));
  output->insert(output->end(), framing.begin(), framing.end());
  output->insert(output->end(), bytes, bytes + length);
  SecureZero(framing.data(), framing.size());
}

void AppendU32Tlv(std::vector<unsigned char>* output, uint16_t tag, uint32_t value) {
  std::array<unsigned char, 4> bytes{};
  WriteU32(bytes.data(), value);
  AppendTlv(output, tag, bytes.data(), bytes.size());
  SecureZero(bytes.data(), bytes.size());
}

void AppendU64Tlv(std::vector<unsigned char>* output, uint16_t tag, uint64_t value) {
  std::array<unsigned char, 8> bytes{};
  WriteU64(bytes.data(), value);
  AppendTlv(output, tag, bytes.data(), bytes.size());
  SecureZero(bytes.data(), bytes.size());
}

void AppendI64Tlv(std::vector<unsigned char>* output, uint16_t tag, int64_t value) {
  std::array<unsigned char, 8> bytes{};
  WriteU64(bytes.data(), static_cast<uint64_t>(value));
  AppendTlv(output, tag, bytes.data(), bytes.size());
  SecureZero(bytes.data(), bytes.size());
}

bool DeriveDescriptorIdentity(int fd,
                              std::array<unsigned char, kDigestBytes>* digest,
                              ScopedFd* private_fd,
                              KernelIdentity* private_identity) {
  if (digest == nullptr || private_fd == nullptr || private_identity == nullptr) return false;
  struct stat status{};
  int status_flags = fcntl(fd, F_GETFL);
  int descriptor_flags = fcntl(fd, F_GETFD);
  if (status_flags == O_RDWR &&
      fcntl(fd, F_SETFL, kExpectedDeviceStatusFlags) == 0) {
    status_flags = fcntl(fd, F_GETFL);
  }
  if (descriptor_flags == FD_CLOEXEC && fcntl(fd, F_SETFD, 0) == 0) {
    descriptor_flags = fcntl(fd, F_GETFD);
  }
  if (fstat(fd, &status) != 0 || !S_ISCHR(status.st_mode) || status.st_nlink != 1 ||
      status_flags != static_cast<int>(kExpectedDeviceStatusFlags) ||
      descriptor_flags != 0 || !isatty(fd)) {
    return false;
  }
  const int duplicate = fcntl(fd, F_DUPFD_CLOEXEC, 64);
  if (duplicate < 0) return false;
  private_fd->Reset(duplicate);
  KernelIdentity source_identity{
      status.st_dev, status.st_ino, status.st_mode, status.st_rdev,
      status.st_nlink, status.st_uid, status.st_gid};
  KernelIdentity duplicate_identity;
  if (!ReadKernelIdentity(duplicate, &duplicate_identity) ||
      !SameKernelIdentity(source_identity, duplicate_identity) ||
      fcntl(duplicate, F_GETFL) != status_flags ||
      fcntl(duplicate, F_GETFD) != FD_CLOEXEC) return false;
  *private_identity = duplicate_identity;

  std::vector<unsigned char> encoded;
  encoded.insert(encoded.end(), kDescriptorIdentityMagic,
                 kDescriptorIdentityMagic + sizeof(kDescriptorIdentityMagic));
  std::array<unsigned char, 4> header{};
  WriteU16(header.data(), kVersion);
  WriteU16(header.data() + 2, 15);
  encoded.insert(encoded.end(), header.begin(), header.end());
  SecureZero(header.data(), header.size());
  AppendU32Tlv(&encoded, 1, 1);
  AppendTlv(&encoded, 2, reinterpret_cast<const unsigned char*>(kDescriptorRole),
            std::strlen(kDescriptorRole));
  AppendU32Tlv(&encoded, 3, kDelegatedDeviceFd);
  AppendTlv(&encoded, 4, reinterpret_cast<const unsigned char*>(kDescriptorPurpose),
            std::strlen(kDescriptorPurpose));
  AppendI64Tlv(&encoded, 5, static_cast<int64_t>(status.st_dev));
  AppendU64Tlv(&encoded, 6, static_cast<uint64_t>(status.st_ino));
  AppendI64Tlv(&encoded, 7, static_cast<int64_t>(status.st_rdev));
  AppendU32Tlv(&encoded, 8, static_cast<uint32_t>(status.st_mode));
  AppendU64Tlv(&encoded, 9, static_cast<uint64_t>(status.st_nlink));
  AppendU32Tlv(&encoded, 10, status.st_uid);
  AppendU32Tlv(&encoded, 11, status.st_gid);
  const unsigned char truth = 1;
  AppendTlv(&encoded, 12, &truth, 1);
  AppendU32Tlv(&encoded, 13, O_RDWR);
  AppendU32Tlv(&encoded, 14, static_cast<uint32_t>(status_flags));
  AppendU32Tlv(&encoded, 15, static_cast<uint32_t>(descriptor_flags));
  const bool succeeded = Sha256(encoded.data(), encoded.size(), digest);
  ZeroVector(&encoded);
  return succeeded;
}

bool DeriveResponseSinkIdentity(
    int fd,
    std::array<unsigned char, kDigestBytes>* digest,
    ScopedFd* private_fd,
    ResponseSinkBoundary* boundary) {
  if (digest == nullptr || private_fd == nullptr || boundary == nullptr) return false;
  struct stat status{};
  int status_flags = fcntl(fd, F_GETFL);
  int descriptor_flags = fcntl(fd, F_GETFD);
  if (descriptor_flags == FD_CLOEXEC && fcntl(fd, F_SETFD, 0) == 0) {
    descriptor_flags = fcntl(fd, F_GETFD);
  }
  const int expected_status_flags = O_WRONLY | O_APPEND;
  if (fstat(fd, &status) != 0 || !S_ISREG(status.st_mode) || status.st_nlink != 1 ||
      status.st_size != 0 || (status.st_mode & 077) != 0 ||
      (status.st_mode & S_IWUSR) == 0 || status_flags != expected_status_flags ||
      descriptor_flags != 0) return false;
  const int duplicate = fcntl(fd, F_DUPFD_CLOEXEC, 64);
  if (duplicate < 0) return false;
  private_fd->Reset(duplicate);
  KernelIdentity source_identity{
      status.st_dev, status.st_ino, status.st_mode, status.st_rdev,
      status.st_nlink, status.st_uid, status.st_gid};
  KernelIdentity duplicate_identity;
  struct stat duplicate_status{};
  if (!ReadKernelIdentity(duplicate, &duplicate_identity) ||
      !SameKernelIdentity(source_identity, duplicate_identity) ||
      fstat(duplicate, &duplicate_status) != 0 || duplicate_status.st_size != 0 ||
      fcntl(duplicate, F_GETFL) != expected_status_flags ||
      fcntl(duplicate, F_GETFD) != FD_CLOEXEC) return false;
  boundary->identity = duplicate_identity;
  boundary->initial_size = duplicate_status.st_size;

  std::vector<unsigned char> encoded;
  encoded.insert(encoded.end(), kResponseSinkIdentityMagic,
                 kResponseSinkIdentityMagic + sizeof(kResponseSinkIdentityMagic));
  std::array<unsigned char, 4> header{};
  WriteU16(header.data(), kVersion);
  WriteU16(header.data() + 2, 16);
  encoded.insert(encoded.end(), header.begin(), header.end());
  SecureZero(header.data(), header.size());
  AppendU32Tlv(&encoded, 1, 1);
  AppendTlv(&encoded, 2, reinterpret_cast<const unsigned char*>(kResponseSinkRole),
            std::strlen(kResponseSinkRole));
  AppendU32Tlv(&encoded, 3, kResponseVaultSinkFd);
  AppendTlv(&encoded, 4, reinterpret_cast<const unsigned char*>(kResponseSinkPurpose),
            std::strlen(kResponseSinkPurpose));
  AppendI64Tlv(&encoded, 5, static_cast<int64_t>(status.st_dev));
  AppendU64Tlv(&encoded, 6, static_cast<uint64_t>(status.st_ino));
  AppendI64Tlv(&encoded, 7, static_cast<int64_t>(status.st_rdev));
  AppendU32Tlv(&encoded, 8, static_cast<uint32_t>(status.st_mode));
  AppendU64Tlv(&encoded, 9, static_cast<uint64_t>(status.st_nlink));
  AppendU32Tlv(&encoded, 10, status.st_uid);
  AppendU32Tlv(&encoded, 11, status.st_gid);
  const unsigned char truth = 1;
  AppendTlv(&encoded, 12, &truth, 1);
  AppendU32Tlv(&encoded, 13, O_WRONLY);
  AppendU32Tlv(&encoded, 14, static_cast<uint32_t>(status_flags));
  AppendU32Tlv(&encoded, 15, static_cast<uint32_t>(descriptor_flags));
  AppendU64Tlv(&encoded, 16, static_cast<uint64_t>(status.st_size));
  const bool succeeded = Sha256(encoded.data(), encoded.size(), digest);
  ZeroVector(&encoded);
  return succeeded;
}

bool ValidChameleonFrame(const unsigned char* bytes, size_t length,
                         uint16_t expected_command, bool request) {
  if (bytes == nullptr || length < 10 || bytes[0] != 0x11 || bytes[1] != 0xef ||
      ReadU16(bytes + 2) != expected_command ||
      static_cast<size_t>(ReadU16(bytes + 6)) + 10U != length ||
      (request && ReadU16(bytes + 4) != 0)) return false;
  unsigned int header_sum = 0;
  for (size_t index = 2; index <= 8; ++index) header_sum += bytes[index];
  if ((header_sum & 0xffU) != 0) return false;
  unsigned int data_sum = 0;
  for (size_t index = 9; index < length; ++index) data_sum += bytes[index];
  return (data_sum & 0xffU) == 0;
}

bool FieldMatchesDigest(
    const FieldView& field,
    const std::array<unsigned char, kDigestBytes>& expected) {
  return field.length == expected.size() &&
         ConstantEqual(field.data, expected.data(), expected.size());
}

const hacker_bob_chameleon_bootstrap::OperationSemantic* FindBootstrapOperation(
    const FieldView& operation_id) {
  for (const auto& operation : hacker_bob_chameleon_bootstrap::kOperations) {
    if (operation_id.length == operation.operation_id_length &&
        ConstantEqual(operation_id.data,
                      reinterpret_cast<const unsigned char*>(operation.operation_id),
                      operation.operation_id_length)) {
      return &operation;
    }
  }
  return nullptr;
}

bool ValidFixtureOperationSemantics(const std::vector<FieldView>& context,
                                    const std::vector<FieldView>& dispatch,
                                    const std::vector<unsigned char>& command) {
  // Each fixture process still consumes exactly one command, but admission is
  // generated from the complete PH-P8 bootstrap registry. The signed launcher
  // context binds the exact manifest, registry, command set, and generated
  // table while the signed dispatch binds the normalized operation, its
  // digest, and the exact one-based position inside that command set.
  if (context.size() != 36 || dispatch.size() != 65 || command.size() != 10 ||
      !FieldEquals(dispatch[3], "bootstrap") ||
      !FieldEquals(dispatch[4], "observe") ||
      !FieldEquals(dispatch[5], "none") ||
      !FieldEquals(dispatch[6], "rf_off") ||
      !FieldEquals(dispatch[10], hacker_bob_chameleon_bootstrap::kProviderId) ||
      !FieldMatchesDigest(dispatch[13],
                          hacker_bob_chameleon_bootstrap::kSemanticManifestDigest) ||
      !FieldMatchesDigest(context[31],
                          hacker_bob_chameleon_bootstrap::kBootstrapManifestDigest) ||
      !FieldMatchesDigest(context[32],
                          hacker_bob_chameleon_bootstrap::kBootstrapOperationRegistryDigest) ||
      !FieldMatchesDigest(context[34],
                          hacker_bob_chameleon_bootstrap::kNativeSemanticTableDigest) ||
      !FieldMatchesDigest(context[35],
                          hacker_bob_chameleon_bootstrap::kBootstrapInvariantsDigest)) {
    return false;
  }
  const auto* operation = FindBootstrapOperation(dispatch[33]);
  if (operation == nullptr || !FieldMatchesDigest(dispatch[34], operation->operation_digest) ||
      !FieldMatchesDigest(context[33], operation->command_set_digest)) {
    return false;
  }
  const uint64_t sequence = ReadU64(dispatch[50].data);
  if (sequence == 0 || sequence > operation->command_count) return false;
  const size_t index = static_cast<size_t>(sequence - 1U);
  if (operation->command_sequences[index] != sequence) return false;
  return ValidChameleonFrame(command.data(), command.size(),
                             operation->command_ids[index], true);
}

bool ExecuteTransaction(int fd, const std::vector<unsigned char>& command,
                        uint32_t maximum_response, uint64_t deadline_ns,
                        const DeviceWriteBoundary& device_boundary,
                        std::vector<unsigned char>* response, bool* wrote_any) {
  if (response == nullptr || wrote_any == nullptr || command.size() < 10) return false;
  int pending = 0;
  if (ioctl(fd, FIONREAD, &pending) != 0 || pending != 0) return false;
  uint64_t immediately_before_write = 0;
  if (!ContinuousNs(&immediately_before_write) || immediately_before_write >= deadline_ns) {
    return false;
  }
  if (!WriteAll(fd, command.data(), command.size(), deadline_ns, wrote_any,
                &device_boundary)) return false;
  const uint16_t command_id = ReadU16(command.data() + 2);
  size_t expected_length = 0;
  while (true) {
    if (expected_length != 0 && response->size() == expected_length) break;
    if (!WaitFd(fd, POLLIN, deadline_ns)) return false;
    std::array<unsigned char, 4096> buffer{};
    const size_t remaining_limit = maximum_response > response->size()
        ? maximum_response - response->size() : 0;
    if (remaining_limit == 0) return false;
    const size_t wanted = std::min(buffer.size(), remaining_limit);
    const ssize_t count = read(fd, buffer.data(), wanted);
    if (count > 0) {
      response->insert(response->end(), buffer.data(),
                       buffer.data() + static_cast<size_t>(count));
      SecureZero(buffer.data(), static_cast<size_t>(count));
      if (expected_length == 0 && response->size() >= 8) {
        expected_length = static_cast<size_t>(ReadU16(response->data() + 6)) + 10U;
        if (expected_length < 10 || expected_length > maximum_response) return false;
      }
      if (expected_length != 0 && response->size() > expected_length) return false;
      continue;
    }
    SecureZero(buffer.data(), buffer.size());
    if (count == 0) return false;
    if (errno != EINTR && errno != EAGAIN && errno != EWOULDBLOCK) return false;
  }
  if (!ValidChameleonFrame(response->data(), response->size(), command_id, false)) {
    return false;
  }
  int trailing = 0;
  if (ioctl(fd, FIONREAD, &trailing) != 0 || trailing != 0) return false;
  uint64_t completed_ns = 0;
  return ContinuousNs(&completed_ns) && completed_ns < deadline_ns;
}

bool CrossBindContextAndDispatch(const std::vector<FieldView>& context,
                                 const std::vector<FieldView>& dispatch,
                                 const EnvelopeView& dispatch_envelope,
                                 const std::array<unsigned char, kDigestBytes>& context_digest,
                                 const std::array<unsigned char, kDigestBytes>& descriptor_digest,
                                 const std::array<unsigned char, kDigestBytes>& sink_descriptor_digest) {
  constexpr std::pair<uint16_t, uint16_t> pairs[] = {
      {5, 17}, {6, 18}, {7, 19}, {8, 20}, {9, 10}, {10, 11}, {11, 12},
      {12, 13}, {13, 14}, {14, 15}, {15, 16}, {16, 21}, {17, 23},
      {18, 58}, {19, 54}, {25, 59}, {26, 60}, {27, 61},
      {28, 62}, {29, 63}, {30, 64}};
  for (const auto& pair : pairs) {
    if (!SameField(context[pair.first], dispatch[pair.second])) return false;
  }
  if (context[20].length != dispatch_envelope.key_id.size() ||
      !ConstantEqual(context[20].data,
          reinterpret_cast<const unsigned char*>(dispatch_envelope.key_id.data()),
          context[20].length) ||
      !ConstantEqual(context[21].data, dispatch_envelope.public_key_digest.data(),
                     kDigestBytes) ||
      !ConstantEqual(dispatch[22].data, context_digest.data(), kDigestBytes) ||
      !ConstantEqual(dispatch[58].data, descriptor_digest.data(), kDigestBytes) ||
      !ConstantEqual(dispatch[62].data, sink_descriptor_digest.data(), kDigestBytes)) {
    return false;
  }
  return true;
}

bool ValidateRetainedTerminalResultSocket(int fd, const KernelIdentity& identity) {
  const int status_flags = fcntl(fd, F_GETFL);
  const int descriptor_flags = fcntl(fd, F_GETFD);
  KernelIdentity current;
  sockaddr_storage address{};
  socklen_t address_length = sizeof(address);
  int socket_type = 0;
  socklen_t type_length = sizeof(socket_type);
  return status_flags == O_RDWR && descriptor_flags == FD_CLOEXEC &&
         ReadKernelIdentity(fd, &current) && SameSocketKernelObject(current, identity) &&
         S_ISSOCK(current.mode) &&
         getsockname(fd, reinterpret_cast<sockaddr*>(&address), &address_length) == 0 &&
         address.ss_family == AF_UNIX &&
         getsockopt(fd, SOL_SOCKET, SO_TYPE, &socket_type, &type_length) == 0 &&
         socket_type == SOCK_STREAM;
}

bool ValidateFixedDescriptors(ScopedFd* private_terminal_result,
                              KernelIdentity* terminal_result_identity) {
  if (private_terminal_result == nullptr || terminal_result_identity == nullptr) return false;
  if (!NormalizeAndValidateControlSocket(kLauncherContextFd) ||
      !NormalizeAndValidateControlSocket(kDispatchInputFd) ||
      !NormalizeAndValidateControlSocket(kTerminalResultFd)) return false;
  KernelIdentity identities[5]{};
  const int fds[5] = {kLauncherContextFd, kDelegatedDeviceFd,
                      kDispatchInputFd, kTerminalResultFd, kResponseVaultSinkFd};
  for (size_t index = 0; index < 5; ++index) {
    if (!ReadKernelIdentity(fds[index], &identities[index])) return false;
  }
  for (size_t left = 0; left < 5; ++left) {
    for (size_t right = left + 1; right < 5; ++right) {
      if (SameKernelIdentity(identities[left], identities[right])) return false;
    }
  }
  if (shutdown(kLauncherContextFd, SHUT_WR) != 0 ||
      shutdown(kDispatchInputFd, SHUT_WR) != 0 ||
      shutdown(kTerminalResultFd, SHUT_RD) != 0) return false;
  // Darwin projects a shutdown direction into the socket inode mode.  Keep
  // the pre-shutdown identity above for topology/alias rejection, then pin
  // the retained result capability to its post-SHUT_RD kernel identity.
  KernelIdentity retained_identity;
  if (!ReadKernelIdentity(kTerminalResultFd, &retained_identity)) return false;
  const int duplicate = fcntl(kTerminalResultFd, F_DUPFD_CLOEXEC, 64);
  if (duplicate < 0) return false;
  private_terminal_result->Reset(duplicate);
  if (!ValidateRetainedTerminalResultSocket(duplicate, retained_identity)) return false;
  *terminal_result_identity = retained_identity;
  return true;
}

bool EmitTerminalResult(int terminal_result_fd,
                        const KernelIdentity& terminal_result_identity,
                        DispatchWork* work, uint64_t deadline_ns) {
  if (work == nullptr ||
      !ValidateRetainedTerminalResultSocket(terminal_result_fd,
                                            terminal_result_identity)) return false;
  std::array<unsigned char, kResultBytes> result{};
  std::copy(std::begin(kTerminalResultMagic), std::end(kTerminalResultMagic), result.begin());
  WriteU16(result.data() + 8, kVersion);
  WriteU16(result.data() + 10, static_cast<uint16_t>(work->status));
  WriteU32(result.data() + 12, work->flags);
  WriteU32(result.data() + 16, work->response_length);
  WriteU64(result.data() + 20, work->ticket_sequence);
  WriteU64(result.data() + 28, work->settled_ns);
  std::copy(work->envelope_digest.begin(), work->envelope_digest.end(), result.begin() + 36);
  std::copy(work->descriptor_digest.begin(), work->descriptor_digest.end(), result.begin() + 68);
  std::copy(work->response_digest.begin(), work->response_digest.end(), result.begin() + 100);
  std::copy(work->sink_descriptor_digest.begin(), work->sink_descriptor_digest.end(),
            result.begin() + 132);
  std::copy(work->sink_record_digest.begin(), work->sink_record_digest.end(),
            result.begin() + 164);
  bool wrote = false;
  const bool succeeded = SetNonblocking(terminal_result_fd) &&
      WriteAll(terminal_result_fd, result.data(), result.size(), deadline_ns, &wrote);
  SecureZero(result.data(), result.size());
  shutdown(terminal_result_fd, SHUT_WR);
  work->terminal_result_written = succeeded && wrote;
  return work->terminal_result_written;
}

bool RecordResponseObservation(DispatchWork* work) {
  if (work == nullptr) return false;
  if (work->response.empty()) {
    work->response_length = 0;
    work->response_digest.fill(0);
    return true;
  }
  if (work->response.size() > std::numeric_limits<uint32_t>::max()) return false;
  std::array<unsigned char, kDigestBytes> digest{};
  if (!Sha256(work->response.data(), work->response.size(), &digest)) {
    SecureZero(digest.data(), digest.size());
    return false;
  }
  work->response_length = static_cast<uint32_t>(work->response.size());
  std::copy(digest.begin(), digest.end(), work->response_digest.begin());
  SecureZero(digest.data(), digest.size());
  return true;
}

bool CommitResponseObservationToVaultSink(
    int fd,
    const ResponseSinkBoundary& boundary,
    const std::vector<FieldView>& dispatch,
    TerminalStatus status,
    uint64_t deadline_ns,
    const std::array<unsigned char, kDigestBytes>& sink_descriptor_digest,
    DispatchWork* work) {
  if (work == nullptr || dispatch.size() != 65 ||
      (status != TerminalStatus::kAmbiguousQuarantined &&
       status != TerminalStatus::kFixtureCompleteNonAuthorizing) ||
      work->response.size() != work->response_length ||
      work->response_length > ReadU32(dispatch[63].data)) return false;
  struct stat before{};
  KernelIdentity current;
  const int expected_flags = O_WRONLY | O_APPEND;
  if (fstat(fd, &before) != 0 || before.st_size != boundary.initial_size ||
      boundary.initial_size != 0 || !ReadKernelIdentity(fd, &current) ||
      !SameKernelIdentity(current, boundary.identity) || !S_ISREG(current.mode) ||
      current.nlink != 1 || (current.mode & 077) != 0 ||
      fcntl(fd, F_GETFL) != expected_flags || fcntl(fd, F_GETFD) != FD_CLOEXEC) {
    return false;
  }

  std::array<unsigned char, kResponseSinkHeaderBytes> header{};
  std::copy(std::begin(kResponseSinkRecordMagic), std::end(kResponseSinkRecordMagic),
            header.begin());
  WriteU16(header.data() + 8, kVersion);
  WriteU16(header.data() + 10, static_cast<uint16_t>(status));
  WriteU32(header.data() + 12, work->response_length);
  WriteU64(header.data() + 16, work->ticket_sequence);
  std::copy(dispatch[59].data, dispatch[59].data + kDigestBytes, header.begin() + 24);
  std::copy(work->envelope_digest.begin(), work->envelope_digest.end(), header.begin() + 56);
  std::copy(work->descriptor_digest.begin(), work->descriptor_digest.end(),
            header.begin() + 88);
  std::copy(sink_descriptor_digest.begin(), sink_descriptor_digest.end(),
            header.begin() + 120);
  std::copy(dispatch[60].data, dispatch[60].data + kDigestBytes, header.begin() + 152);
  std::copy(dispatch[61].data, dispatch[61].data + kDigestBytes, header.begin() + 184);
  std::copy(dispatch[64].data, dispatch[64].data + kDigestBytes, header.begin() + 216);
  std::copy(work->response_digest.begin(), work->response_digest.end(), header.begin() + 248);
  std::array<unsigned char, kDigestBytes> record_digest{};
  bool wrote = false;
  bool succeeded = Sha256(header.data(), header.size(), &record_digest) &&
      WriteAll(fd, header.data(), header.size(), deadline_ns, &wrote);
  const char* sink_fault = std::getenv(
      "BOB_CHAMELEON_DARWIN_NATIVE_DISPATCH_FIXTURE_SINK_FAULT");
  if (succeeded && sink_fault != nullptr && std::strcmp(sink_fault, "after_header") == 0) {
    succeeded = false;
  }
  if (succeeded && !work->response.empty()) {
    succeeded = WriteAll(fd, work->response.data(), work->response.size(), deadline_ns, &wrote);
  }
  if (succeeded) {
    uint64_t persisted_ns = 0;
    succeeded = fsync(fd) == 0 && ContinuousNs(&persisted_ns) && persisted_ns < deadline_ns;
  }
  struct stat after{};
  const uint64_t expected_size = static_cast<uint64_t>(header.size()) + work->response.size();
  if (succeeded) {
    succeeded = fstat(fd, &after) == 0 && after.st_size >= 0 &&
        static_cast<uint64_t>(after.st_size) == expected_size &&
        ReadKernelIdentity(fd, &current) && SameKernelIdentity(current, boundary.identity) &&
        (fcntl(fd, F_GETFL) & ~kDarwinKernelWasWrittenFlag) == expected_flags &&
        fcntl(fd, F_GETFD) == FD_CLOEXEC;
  }
  SecureZero(header.data(), header.size());
  if (!succeeded) {
    SecureZero(record_digest.data(), record_digest.size());
    return false;
  }
  std::copy(sink_descriptor_digest.begin(), sink_descriptor_digest.end(),
            work->sink_descriptor_digest.begin());
  std::copy(record_digest.begin(), record_digest.end(), work->sink_record_digest.begin());
  SecureZero(record_digest.data(), record_digest.size());
  return true;
}

void PerformDispatch(DispatchWork* work) {
  uint64_t start_ns = 0;
  if (work == nullptr || !ContinuousNs(&start_ns)) return;
  const uint64_t startup_deadline = start_ns > std::numeric_limits<uint64_t>::max() -
      kStartupWindowNs ? std::numeric_limits<uint64_t>::max() : start_ns + kStartupWindowNs;
  ScopedFd private_device;
  ScopedFd private_sink;
  ScopedFd private_terminal_result;
  DeviceWriteBoundary device_boundary;
  ResponseSinkBoundary sink_boundary;
  KernelIdentity terminal_result_identity;
  std::array<unsigned char, kDigestBytes> sink_descriptor_digest{};
  bool public_device_open = true;
  bool public_sink_open = true;
  bool wrote_any = false;
  bool descriptor_verified = false;
  bool signature_verified = false;
  bool deadline_rechecked = false;
  bool sink_committed = false;
  bool public_terminal_result_open = true;
  bool terminal_result_capability_validated = false;

  auto settle = [&]() {
    private_device.Reset();
    private_sink.Reset();
    if (public_device_open) {
      close(kDelegatedDeviceFd);
      public_device_open = false;
    }
    if (public_sink_open) {
      close(kResponseVaultSinkFd);
      public_sink_open = false;
    }
    if (public_terminal_result_open) {
      close(kTerminalResultFd);
      public_terminal_result_open = false;
    }
    if (wrote_any && work->status != TerminalStatus::kFixtureCompleteNonAuthorizing) {
      work->status = TerminalStatus::kAmbiguousQuarantined;
    }
    work->flags = (wrote_any ? 1U : 0U) | (signature_verified ? 2U : 0U) |
                  (descriptor_verified ? 4U : 0U) | (deadline_rechecked ? 8U : 0U) |
                  (sink_committed ? 16U : 0U);
    // A malformed or aliased descriptor topology has not established a safe
    // terminal channel.  Do not turn the purported result descriptor into an
    // effect surface; the trusted parent treats channel closure as no receipt.
    if (!terminal_result_capability_validated ||
        !ContinuousNs(&work->settled_ns)) return;
    const uint64_t result_deadline = work->settled_ns >
        std::numeric_limits<uint64_t>::max() - kResultWriteWindowNs
        ? std::numeric_limits<uint64_t>::max()
        : work->settled_ns + kResultWriteWindowNs;
    EmitTerminalResult(private_terminal_result.get(), terminal_result_identity,
                       work, result_deadline);
    private_terminal_result.Reset();
  };

  const char* fixture_gate = std::getenv("BOB_CHAMELEON_DARWIN_NATIVE_DISPATCH_FIXTURE");
  if (fixture_gate == nullptr || std::strcmp(fixture_gate, "1") != 0) {
    settle();
    return;
  }
  if (!ValidateFixedDescriptors(&private_terminal_result,
                                &terminal_result_identity)) {
    settle();
    return;
  }
  terminal_result_capability_validated = true;
  close(kTerminalResultFd);
  public_terminal_result_open = false;
  if (!DeriveDescriptorIdentity(kDelegatedDeviceFd, &work->descriptor_digest,
                                &private_device, &device_boundary.identity)) {
    settle();
    return;
  }
  descriptor_verified = true;
  if (close(kDelegatedDeviceFd) != 0) {
    settle();
    return;
  }
  public_device_open = false;
  if (!DeriveResponseSinkIdentity(kResponseVaultSinkFd, &sink_descriptor_digest,
                                  &private_sink, &sink_boundary)) {
    settle();
    return;
  }
  if (close(kResponseVaultSinkFd) != 0) {
    settle();
    return;
  }
  public_sink_open = false;
  if (!ReadToEof(kLauncherContextFd, kMaximumContextBytes, startup_deadline,
                 &work->context) ||
      !ReadToEof(kDispatchInputFd, kMaximumInputBytes, startup_deadline, &work->input)) {
    settle();
    return;
  }
  close(kLauncherContextFd);
  close(kDispatchInputFd);

  EnvelopeView context_envelope;
  std::vector<FieldView> context_fields;
  if (!ParseEnvelope(work->context.data(), work->context.size(), kContextEnvelopeMagic,
                     &context_envelope) ||
      !ParseTlv(context_envelope.payload, context_envelope.payload_length,
                kContextBodyMagic, 35, &context_fields) ||
      !ValidateContextFields(context_fields) ||
      !VerifyEd25519(context_envelope, context_fields[22], kContextSignatureDomain,
                     sizeof(kContextSignatureDomain) - 1U)) {
    settle();
    return;
  }
  const uid_t uid = getuid();
  const gid_t gid = getgid();
  if (uid != geteuid() || gid != getegid() || context_fields[3].length != 4 ||
      context_fields[4].length != 4 || ReadU32(context_fields[3].data) != uid ||
      ReadU32(context_fields[4].data) != gid) {
    settle();
    return;
  }
  device_boundary.uid = uid;
  device_boundary.gid = gid;
  std::array<unsigned char, kDigestBytes> context_digest{};
  if (!Sha256(work->context.data(), work->context.size(), &context_digest)) {
    settle();
    return;
  }

  if (work->input.size() < kInputHeaderBytes ||
      !ConstantEqual(work->input.data(), kDispatchInputMagic, 8) ||
      ReadU16(work->input.data() + 8) != kVersion) {
    SecureZero(context_digest.data(), context_digest.size());
    settle();
    return;
  }
  const uint32_t envelope_length = ReadU32(work->input.data() + 10);
  const uint32_t command_length = ReadU32(work->input.data() + 14);
  if (envelope_length < kEnvelopeHeaderBytes + 1 + 12 + kSignatureBytes ||
      envelope_length > kMaximumEnvelopeBytes || command_length == 0 ||
      command_length > kMaximumCommandBytes ||
      kInputHeaderBytes + static_cast<size_t>(envelope_length) +
          static_cast<size_t>(command_length) != work->input.size()) {
    SecureZero(context_digest.data(), context_digest.size());
    settle();
    return;
  }
  const unsigned char* dispatch_envelope_bytes = work->input.data() + kInputHeaderBytes;
  const unsigned char* command_bytes = dispatch_envelope_bytes + envelope_length;
  if (!Sha256(dispatch_envelope_bytes, envelope_length, &work->envelope_digest)) {
    SecureZero(context_digest.data(), context_digest.size());
    settle();
    return;
  }
  work->command.assign(command_bytes, command_bytes + command_length);

  EnvelopeView dispatch_envelope;
  std::vector<FieldView> dispatch_fields;
  if (!ParseEnvelope(dispatch_envelope_bytes, envelope_length, kDispatchEnvelopeMagic,
                     &dispatch_envelope) ||
      !ParseTlv(dispatch_envelope.payload, dispatch_envelope.payload_length,
                kDispatchPayloadMagic, 64, &dispatch_fields) ||
      !ValidateDispatchFields(dispatch_fields) ||
      !VerifyEd25519(dispatch_envelope, context_fields[23], kDispatchSignatureDomain,
                     sizeof(kDispatchSignatureDomain) - 1U) ||
      !CrossBindContextAndDispatch(context_fields, dispatch_fields, dispatch_envelope,
                                   context_digest, work->descriptor_digest,
                                   sink_descriptor_digest)) {
    SecureZero(context_digest.data(), context_digest.size());
    settle();
    return;
  }
  SecureZero(context_digest.data(), context_digest.size());
  signature_verified = true;

  std::array<unsigned char, kDigestBytes> command_digest{};
  if (!Sha256(work->command.data(), work->command.size(), &command_digest) ||
      work->command.size() != ReadU32(dispatch_fields[52].data) ||
      !ConstantEqual(command_digest.data(), dispatch_fields[51].data, kDigestBytes) ||
      !ValidFixtureOperationSemantics(context_fields, dispatch_fields, work->command)) {
    SecureZero(command_digest.data(), command_digest.size());
    settle();
    return;
  }
  SecureZero(command_digest.data(), command_digest.size());
  work->ticket_sequence = ReadU64(dispatch_fields[9].data);
  const uint64_t not_before = ReadU64(dispatch_fields[55].data);
  const uint64_t deadline = ReadU64(dispatch_fields[56].data);
  uint64_t current = 0;
  if (!ContinuousNs(&current) || current < not_before || current >= deadline) {
    settle();
    return;
  }
  deadline_rechecked = true;
  const uint32_t maximum_response = ReadU32(dispatch_fields[53].data);
  if (!ExecuteTransaction(private_device.get(), work->command, maximum_response,
                          deadline, device_boundary, &work->response, &wrote_any)) {
    // Once any request byte crossed the effect seam, retain a redacted digest
    // and length for whatever response prefix was actually read. A hashing
    // failure cannot produce a misleading terminal receipt.
    if (wrote_any) {
      work->status = TerminalStatus::kAmbiguousQuarantined;
      if (!RecordResponseObservation(work)) {
        settle();
        return;
      }
      sink_committed = CommitResponseObservationToVaultSink(
          private_sink.get(), sink_boundary, dispatch_fields, work->status, deadline,
          sink_descriptor_digest, work);
    }
    settle();
    return;
  }
  if (!RecordResponseObservation(work)) {
    settle();
    return;
  }
  work->status = TerminalStatus::kFixtureCompleteNonAuthorizing;
  sink_committed = CommitResponseObservationToVaultSink(
      private_sink.get(), sink_boundary, dispatch_fields, work->status, deadline,
      sink_descriptor_digest, work);
  if (!sink_committed) work->status = TerminalStatus::kAmbiguousQuarantined;
  settle();
}

void ExecuteDispatch(napi_env, void* data) {
  PerformDispatch(static_cast<DispatchWork*>(data));
}

void CompleteDispatch(napi_env env, napi_status status, void* data) {
  std::unique_ptr<DispatchWork> work(static_cast<DispatchWork*>(data));
  if (work == nullptr) return;
  if (work->work != nullptr) napi_delete_async_work(env, work->work);
  if (status == napi_ok && work->terminal_result_written) {
    napi_value undefined;
    if (napi_get_undefined(env, &undefined) == napi_ok) {
      napi_resolve_deferred(env, work->deferred, undefined);
      return;
    }
  }
  napi_value message;
  napi_value error;
  if (napi_create_string_utf8(env, "Darwin native dispatch custodian failed",
                              NAPI_AUTO_LENGTH, &message) == napi_ok &&
      napi_create_error(env, nullptr, message, &error) == napi_ok) {
    napi_reject_deferred(env, work->deferred, error);
  }
}

napi_value DispatchFixtureExact(napi_env env, napi_callback_info info) {
  size_t argc = 2;
  napi_value argv[2];
  if (napi_get_cb_info(env, info, &argc, argv, nullptr, nullptr) != napi_ok || argc != 0 ||
      g_started.exchange(true, std::memory_order_acq_rel)) {
    napi_throw_error(env, "darwin_native_dispatch_rejected",
                     "Darwin native dispatch custodian was rejected");
    return nullptr;
  }
  std::unique_ptr<DispatchWork> work(new (std::nothrow) DispatchWork());
  if (work == nullptr) {
    napi_throw_error(env, "darwin_native_dispatch_rejected",
                     "Darwin native dispatch custodian was rejected");
    return nullptr;
  }
  work->env = env;
  napi_value promise;
  napi_value resource_name;
  if (napi_create_promise(env, &work->deferred, &promise) != napi_ok ||
      napi_create_string_utf8(env, "bobDarwinNativeDispatchCustodian",
                              NAPI_AUTO_LENGTH, &resource_name) != napi_ok ||
      napi_create_async_work(env, nullptr, resource_name, ExecuteDispatch,
                             CompleteDispatch, work.get(), &work->work) != napi_ok ||
      napi_queue_async_work(env, work->work) != napi_ok) {
    if (work->work != nullptr) napi_delete_async_work(env, work->work);
    napi_throw_error(env, "darwin_native_dispatch_rejected",
                     "Darwin native dispatch custodian was rejected");
    return nullptr;
  }
  work.release();
  return promise;
}

napi_value Init(napi_env env, napi_value exports) {
  napi_property_descriptor property = {
      "dispatchFixtureExact", nullptr, DispatchFixtureExact, nullptr, nullptr,
      nullptr, napi_enumerable, nullptr};
  if (napi_define_properties(env, exports, 1, &property) != napi_ok) return nullptr;
  return exports;
}

}  // namespace

NAPI_MODULE(NODE_GYP_MODULE_NAME, Init)
