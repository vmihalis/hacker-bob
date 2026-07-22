#include "trusted_clock_protocol.h"

#include <CommonCrypto/CommonDigest.h>
#include <CoreFoundation/CoreFoundation.h>
#include <Security/Security.h>
#include <bsm/libbsm.h>
#include <errno.h>
#include <fcntl.h>
#include <launch.h>
#include <mach/mach_time.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/sysctl.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/un.h>
#include <unistd.h>

#include <array>
#include <initializer_list>
#include <utility>

namespace {

constexpr size_t kBootSessionMaximumBytes = 128;
constexpr size_t kReplayCapacity = 1024;

struct PeerIdentity {
  audit_token_t token;
  pid_t pid;
  uid_t uid;
  gid_t gid;
  int pid_version;
};

struct ReplayEntry {
  std::array<uint8_t, HB_CLOCK_DIGEST_BYTES> digest;
  bool occupied;
};

void SecureZero(void* bytes, size_t length) {
  volatile uint8_t* cursor = static_cast<volatile uint8_t*>(bytes);
  for (size_t index = 0; index < length; ++index) cursor[index] = 0;
}

class ScopedScrub {
 public:
  ScopedScrub(void* bytes, size_t length) : bytes_(bytes), length_(length) {}
  ~ScopedScrub() {
    if (bytes_ != nullptr && length_ != 0) SecureZero(bytes_, length_);
  }
  ScopedScrub(const ScopedScrub&) = delete;
  ScopedScrub& operator=(const ScopedScrub&) = delete;

 private:
  void* bytes_;
  size_t length_;
};

std::array<ReplayEntry, kReplayCapacity> g_replay{};
size_t g_replay_cursor = 0;

void StoreU16(uint8_t* output, uint16_t value) {
  output[0] = static_cast<uint8_t>((value >> 8U) & 0xffU);
  output[1] = static_cast<uint8_t>(value & 0xffU);
}

void StoreU32(uint8_t* output, uint32_t value) {
  output[0] = static_cast<uint8_t>((value >> 24U) & 0xffU);
  output[1] = static_cast<uint8_t>((value >> 16U) & 0xffU);
  output[2] = static_cast<uint8_t>((value >> 8U) & 0xffU);
  output[3] = static_cast<uint8_t>(value & 0xffU);
}

void StoreU64(uint8_t* output, uint64_t value) {
  for (size_t index = 0; index < sizeof(value); ++index) {
    const unsigned shift = static_cast<unsigned>((sizeof(value) - 1U - index) * 8U);
    output[index] = static_cast<uint8_t>((value >> shift) & 0xffU);
  }
}

uint16_t LoadU16(const uint8_t* input) {
  return static_cast<uint16_t>((static_cast<uint16_t>(input[0]) << 8U)
      | static_cast<uint16_t>(input[1]));
}

uint32_t LoadU32(const uint8_t* input) {
  return (static_cast<uint32_t>(input[0]) << 24U)
      | (static_cast<uint32_t>(input[1]) << 16U)
      | (static_cast<uint32_t>(input[2]) << 8U)
      | static_cast<uint32_t>(input[3]);
}

bool ReadExact(int descriptor, uint8_t* output, size_t length) {
  size_t offset = 0;
  while (offset < length) {
    const ssize_t count = read(descriptor, output + offset, length - offset);
    if (count == 0) return false;
    if (count < 0) {
      if (errno == EINTR) continue;
      return false;
    }
    offset += static_cast<size_t>(count);
  }
  return true;
}

bool ConfigureConnectedSocket(int descriptor) {
  timeval timeout{};
  timeout.tv_sec = HB_CLOCK_IO_TIMEOUT_SECONDS;
  const int no_sigpipe = 1;
  const int descriptor_flags = fcntl(descriptor, F_GETFD);
  return descriptor_flags >= 0
      && fcntl(descriptor, F_SETFD, descriptor_flags | FD_CLOEXEC) == 0
      && setsockopt(descriptor, SOL_SOCKET, SO_NOSIGPIPE,
                    &no_sigpipe, static_cast<socklen_t>(sizeof(no_sigpipe))) == 0
      && setsockopt(descriptor, SOL_SOCKET, SO_RCVTIMEO,
                    &timeout, static_cast<socklen_t>(sizeof(timeout))) == 0
      && setsockopt(descriptor, SOL_SOCKET, SO_SNDTIMEO,
                    &timeout, static_cast<socklen_t>(sizeof(timeout))) == 0;
}

bool ValidateLaunchdListener(int descriptor) {
  const int descriptor_flags = fcntl(descriptor, F_GETFD);
  if (descriptor_flags < 0
      || fcntl(descriptor, F_SETFD, descriptor_flags | FD_CLOEXEC) != 0) {
    return false;
  }
  int socket_type = 0;
  socklen_t socket_type_length = static_cast<socklen_t>(sizeof(socket_type));
  int accepting = 0;
  socklen_t accepting_length = static_cast<socklen_t>(sizeof(accepting));
  if (getsockopt(descriptor, SOL_SOCKET, SO_TYPE,
                 &socket_type, &socket_type_length) != 0
      || socket_type_length != static_cast<socklen_t>(sizeof(socket_type))
      || socket_type != SOCK_STREAM
      || getsockopt(descriptor, SOL_SOCKET, SO_ACCEPTCONN,
                    &accepting, &accepting_length) != 0
      || accepting_length != static_cast<socklen_t>(sizeof(accepting))
      || accepting != 1) {
    return false;
  }
  sockaddr_un address{};
  socklen_t address_length = static_cast<socklen_t>(sizeof(address));
  if (getsockname(descriptor, reinterpret_cast<sockaddr*>(&address),
                  &address_length) != 0
      || address.sun_family != AF_UNIX) {
    return false;
  }
  const size_t expected_length = sizeof(HB_CLOCK_SOCKET_PATH) - 1;
  const size_t minimum_length = offsetof(sockaddr_un, sun_path)
      + expected_length + 1;
  return static_cast<size_t>(address_length) >= minimum_length
      && strnlen(address.sun_path, sizeof(address.sun_path)) == expected_length
      && memcmp(address.sun_path, HB_CLOCK_SOCKET_PATH, expected_length + 1) == 0;
}

bool WriteExact(int descriptor, const uint8_t* input, size_t length) {
  size_t offset = 0;
  while (offset < length) {
    const ssize_t count = write(descriptor, input + offset, length - offset);
    if (count <= 0) {
      if (count < 0 && errno == EINTR) continue;
      return false;
    }
    offset += static_cast<size_t>(count);
  }
  return true;
}

bool ReadEndOfStream(int descriptor) {
  uint8_t extra = 0;
  for (;;) {
    const ssize_t count = read(descriptor, &extra, 1);
    if (count == 0) return true;
    if (count < 0 && errno == EINTR) continue;
    return false;
  }
}

bool AllZero(const uint8_t* input, size_t length) {
  uint8_t accumulator = 0;
  for (size_t index = 0; index < length; ++index) accumulator |= input[index];
  return accumulator == 0;
}

bool QualifiedEnrollmentPresent() {
  return HB_CLOCK_SOURCE_PROVISIONED == 1
      && HB_CLOCK_SERVICE_UID != UINT32_MAX
      && HB_CLOCK_SERVICE_GID != UINT32_MAX
      && HB_CLOCK_CLIENT_UID != UINT32_MAX
      && HB_CLOCK_CLIENT_GID != UINT32_MAX
      && HB_CLOCK_SERVICE_UID != HB_CLOCK_CLIENT_UID
      && HB_CLOCK_SERVICE_GID != HB_CLOCK_CLIENT_GID
      && static_cast<uint32_t>(geteuid()) == HB_CLOCK_SERVICE_UID
      && static_cast<uint32_t>(getegid()) == HB_CLOCK_SERVICE_GID
      && !AllZero(HB_CLOCK_SERVICE_IDENTITY_DIGEST, HB_CLOCK_DIGEST_BYTES)
      && !AllZero(HB_CLOCK_CLIENT_IDENTITY_DIGEST, HB_CLOCK_DIGEST_BYTES)
      && !AllZero(HB_CLOCK_ENROLLMENT_DIGEST, HB_CLOCK_DIGEST_BYTES)
      && memcmp(HB_CLOCK_SERVICE_IDENTITY_DIGEST,
                HB_CLOCK_CLIENT_IDENTITY_DIGEST,
                HB_CLOCK_DIGEST_BYTES) != 0;
}

bool CheckCodeRequirement(const audit_token_t& token, const char* requirement_text) {
  CFDataRef token_data = CFDataCreateWithBytesNoCopy(
      kCFAllocatorDefault,
      reinterpret_cast<const UInt8*>(&token),
      static_cast<CFIndex>(sizeof(token)),
      kCFAllocatorNull);
  if (token_data == nullptr) return false;
  const void* keys[] = {kSecGuestAttributeAudit};
  const void* values[] = {token_data};
  CFDictionaryRef attributes = CFDictionaryCreate(
      kCFAllocatorDefault,
      keys,
      values,
      1,
      &kCFTypeDictionaryKeyCallBacks,
      &kCFTypeDictionaryValueCallBacks);
  SecCodeRef code = nullptr;
  SecRequirementRef requirement = nullptr;
  bool valid = false;
  if (attributes != nullptr
      && SecCodeCopyGuestWithAttributes(
          nullptr, attributes, kSecCSDefaultFlags, &code) == errSecSuccess) {
    CFStringRef requirement_string = CFStringCreateWithCString(
        kCFAllocatorDefault, requirement_text, kCFStringEncodingUTF8);
    if (requirement_string != nullptr) {
      if (SecRequirementCreateWithString(
              requirement_string, kSecCSDefaultFlags, &requirement) == errSecSuccess
          && SecCodeCheckValidity(
              code, kSecCSStrictValidate, requirement) == errSecSuccess) {
        valid = true;
      }
      CFRelease(requirement_string);
    }
  }
  if (requirement != nullptr) CFRelease(requirement);
  if (code != nullptr) CFRelease(code);
  if (attributes != nullptr) CFRelease(attributes);
  CFRelease(token_data);
  return valid;
}

bool ReadPeerIdentity(int descriptor,
                      uid_t expected_uid,
                      gid_t expected_gid,
                      const char* requirement,
                      PeerIdentity* output) {
  if (output == nullptr) return false;
  socklen_t token_length = static_cast<socklen_t>(sizeof(output->token));
  socklen_t pid_length = static_cast<socklen_t>(sizeof(output->pid));
  if (getsockopt(descriptor, SOL_LOCAL, LOCAL_PEERTOKEN,
                 &output->token, &token_length) != 0
      || token_length != sizeof(output->token)
      || getsockopt(descriptor, SOL_LOCAL, LOCAL_PEERPID,
                    &output->pid, &pid_length) != 0
      || pid_length != sizeof(output->pid)
      || getpeereid(descriptor, &output->uid, &output->gid) != 0) {
    return false;
  }
  output->pid_version = audit_token_to_pidversion(output->token);
  return output->pid > 0 && output->pid_version > 0
      && output->uid == expected_uid && output->gid == expected_gid
      && audit_token_to_pid(output->token) == output->pid
      && audit_token_to_euid(output->token) == output->uid
      && audit_token_to_egid(output->token) == output->gid
      && CheckCodeRequirement(output->token, requirement);
}

bool HashParts(std::initializer_list<std::pair<const uint8_t*, size_t>> parts,
               uint8_t output[HB_CLOCK_DIGEST_BYTES]) {
  CC_SHA256_CTX context;
  ScopedScrub context_scrub(&context, sizeof(context));
  if (CC_SHA256_Init(&context) != 1) return false;
  for (const auto& part : parts) {
    if (part.second > static_cast<size_t>(UINT32_MAX)
        || CC_SHA256_Update(&context, part.first,
                           static_cast<CC_LONG>(part.second)) != 1) {
      return false;
    }
  }
  return CC_SHA256_Final(output, &context) == 1;
}

bool ReadBootSession(char output[kBootSessionMaximumBytes], size_t* output_length) {
  if (output == nullptr || output_length == nullptr) return false;
  size_t length = kBootSessionMaximumBytes;
  if (sysctlbyname(HB_CLOCK_BOOT_SESSION_SYSCTL, output, &length, nullptr, 0) != 0
      || length < 2 || length > kBootSessionMaximumBytes
      || output[length - 1] != '\0') {
    return false;
  }
  *output_length = length - 1;
  return true;
}

bool SampleContinuousClock(
    uint64_t* monotonic_ns,
    uint8_t boot_epoch_digest[HB_CLOCK_DIGEST_BYTES]) {
  char first[kBootSessionMaximumBytes] = {};
  char second[kBootSessionMaximumBytes] = {};
  ScopedScrub first_scrub(first, sizeof(first));
  ScopedScrub second_scrub(second, sizeof(second));
  size_t first_length = 0;
  size_t second_length = 0;
  if (!ReadBootSession(first, &first_length)) return false;
  mach_timebase_info_data_t timebase{};
  if (mach_timebase_info(&timebase) != KERN_SUCCESS || timebase.denom == 0) return false;
  const uint64_t ticks = mach_continuous_time();
  if (!ReadBootSession(second, &second_length)
      || first_length != second_length
      || memcmp(first, second, first_length) != 0) {
    return false;
  }
  const __uint128_t scaled = static_cast<__uint128_t>(ticks) * timebase.numer;
  const __uint128_t nanoseconds = scaled / timebase.denom;
  if (nanoseconds > UINT64_MAX) return false;
  *monotonic_ns = static_cast<uint64_t>(nanoseconds);
  const uint8_t separator = 0;
  uint8_t boot_length[2] = {
      static_cast<uint8_t>((first_length >> 8U) & 0xffU),
      static_cast<uint8_t>(first_length & 0xffU),
  };
  return HashParts({
      {reinterpret_cast<const uint8_t*>(HB_CLOCK_BOOT_EPOCH_DIGEST_DOMAIN),
       sizeof(HB_CLOCK_BOOT_EPOCH_DIGEST_DOMAIN) - 1},
      {&separator, 1},
      {boot_length, sizeof(boot_length)},
      {reinterpret_cast<const uint8_t*>(first), first_length},
      {HB_CLOCK_SERVICE_IDENTITY_DIGEST, HB_CLOCK_DIGEST_BYTES},
      {HB_CLOCK_ENROLLMENT_DIGEST, HB_CLOCK_DIGEST_BYTES},
  }, boot_epoch_digest);
}

bool ChallengeWasReplayed(const uint8_t digest[HB_CLOCK_DIGEST_BYTES]) {
  for (const auto& entry : g_replay) {
    if (entry.occupied
        && memcmp(entry.digest.data(), digest, HB_CLOCK_DIGEST_BYTES) == 0) {
      return true;
    }
  }
  memcpy(g_replay[g_replay_cursor].digest.data(), digest, HB_CLOCK_DIGEST_BYTES);
  g_replay[g_replay_cursor].occupied = true;
  g_replay_cursor = (g_replay_cursor + 1U) % kReplayCapacity;
  return false;
}

bool HandleOneConnection(int descriptor) {
  PeerIdentity peer{};
  ScopedScrub peer_scrub(&peer, sizeof(peer));
  if (!ReadPeerIdentity(descriptor,
                        static_cast<uid_t>(HB_CLOCK_CLIENT_UID),
                        static_cast<gid_t>(HB_CLOCK_CLIENT_GID),
                        HB_CLOCK_CLIENT_REQUIREMENT,
                        &peer)) {
    return false;
  }
  std::array<uint8_t, HB_CLOCK_REQUEST_BYTES> request{};
  ScopedScrub request_scrub(request.data(), request.size());
  if (!ReadExact(descriptor, request.data(), request.size())
      || memcmp(request.data(), HB_CLOCK_REQUEST_MAGIC,
                sizeof(HB_CLOCK_REQUEST_MAGIC)) != 0
      || LoadU16(request.data() + 8) != HB_CLOCK_SOURCE_VERSION
      || LoadU16(request.data() + 10) != HB_CLOCK_REQUEST_TYPE
      || LoadU32(request.data() + 12) != HB_CLOCK_REQUEST_BYTES
      || !ReadEndOfStream(descriptor)) {
    return false;
  }
  uint8_t challenge_digest[HB_CLOCK_DIGEST_BYTES] = {};
  ScopedScrub challenge_digest_scrub(challenge_digest, sizeof(challenge_digest));
  const uint8_t separator = 0;
  if (!HashParts({
      {reinterpret_cast<const uint8_t*>(HB_CLOCK_CHALLENGE_DIGEST_DOMAIN),
       sizeof(HB_CLOCK_CHALLENGE_DIGEST_DOMAIN) - 1},
      {&separator, 1},
      {request.data() + 16, HB_CLOCK_REQUEST_ID_BYTES},
      {request.data() + 32, HB_CLOCK_CHALLENGE_BYTES},
  }, challenge_digest) || ChallengeWasReplayed(challenge_digest)) {
    return false;
  }

  uint64_t monotonic_ns = 0;
  uint8_t boot_epoch_digest[HB_CLOCK_DIGEST_BYTES] = {};
  ScopedScrub boot_epoch_scrub(boot_epoch_digest, sizeof(boot_epoch_digest));
  if (!SampleContinuousClock(&monotonic_ns, boot_epoch_digest)) return false;

  std::array<uint8_t, HB_CLOCK_RESPONSE_BYTES> response{};
  ScopedScrub response_scrub(response.data(), response.size());
  memcpy(response.data(), HB_CLOCK_RESPONSE_MAGIC, sizeof(HB_CLOCK_RESPONSE_MAGIC));
  StoreU16(response.data() + 8, HB_CLOCK_SOURCE_VERSION);
  StoreU16(response.data() + 10, HB_CLOCK_RESPONSE_TYPE);
  StoreU32(response.data() + 12, HB_CLOCK_RESPONSE_BYTES);
  memcpy(response.data() + 16, request.data() + 16, HB_CLOCK_REQUEST_ID_BYTES);
  memcpy(response.data() + 32, challenge_digest, HB_CLOCK_DIGEST_BYTES);
  StoreU64(response.data() + 64, monotonic_ns);
  memcpy(response.data() + 72, boot_epoch_digest, HB_CLOCK_DIGEST_BYTES);
  memcpy(response.data() + 104, HB_CLOCK_SERVICE_IDENTITY_DIGEST, HB_CLOCK_DIGEST_BYTES);
  memcpy(response.data() + 136, HB_CLOCK_CLIENT_IDENTITY_DIGEST, HB_CLOCK_DIGEST_BYTES);
  memcpy(response.data() + 168, HB_CLOCK_ENROLLMENT_DIGEST, HB_CLOCK_DIGEST_BYTES);

  uint8_t monotonic_bytes[8] = {};
  ScopedScrub monotonic_scrub(monotonic_bytes, sizeof(monotonic_bytes));
  StoreU64(monotonic_bytes, monotonic_ns);
  if (!HashParts({
      {reinterpret_cast<const uint8_t*>(HB_CLOCK_SAMPLE_DIGEST_DOMAIN),
       sizeof(HB_CLOCK_SAMPLE_DIGEST_DOMAIN) - 1},
      {&separator, 1},
      {response.data() + 16, HB_CLOCK_REQUEST_ID_BYTES},
      {response.data() + 32, HB_CLOCK_DIGEST_BYTES},
      {monotonic_bytes, sizeof(monotonic_bytes)},
      {response.data() + 72, HB_CLOCK_DIGEST_BYTES},
      {response.data() + 104, HB_CLOCK_DIGEST_BYTES},
      {response.data() + 136, HB_CLOCK_DIGEST_BYTES},
      {response.data() + 168, HB_CLOCK_DIGEST_BYTES},
  }, response.data() + 200)) {
    return false;
  }
  return WriteExact(descriptor, response.data(), response.size());
}

}  // namespace

int main(int argc, char* argv[]) {
  (void)argv;
  if (argc != 1 || !QualifiedEnrollmentPresent()) return EXIT_FAILURE;
  int* descriptors = nullptr;
  size_t count = 0;
  if (launch_activate_socket(HB_CLOCK_LAUNCHD_SOCKET_NAME,
                             &descriptors, &count) != 0
      || descriptors == nullptr || count != 1) {
    free(descriptors);
    return EXIT_FAILURE;
  }
  const int listener = descriptors[0];
  free(descriptors);
  if (!ValidateLaunchdListener(listener)) {
    (void)close(listener);
    return EXIT_FAILURE;
  }
  for (;;) {
    const int connection = accept(listener, nullptr, nullptr);
    if (connection < 0) {
      if (errno == EINTR) continue;
      return EXIT_FAILURE;
    }
    const bool handled = ConfigureConnectedSocket(connection)
      && HandleOneConnection(connection);
    (void)shutdown(connection, SHUT_RDWR);
    (void)close(connection);
    if (!handled) continue;
  }
}
