#include "trusted_clock_protocol.h"

#include <CommonCrypto/CommonDigest.h>
#include <CoreFoundation/CoreFoundation.h>
#include <Security/Security.h>
#include <bsm/libbsm.h>
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/un.h>
#include <unistd.h>

#include <array>
#include <initializer_list>
#include <utility>

namespace {

struct PeerIdentity {
  audit_token_t token;
  pid_t pid;
  uid_t uid;
  gid_t gid;
  int pid_version;
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

uint64_t LoadU64(const uint8_t* input) {
  uint64_t output = 0;
  for (size_t index = 0; index < sizeof(output); ++index) {
    output = (output << 8U) | static_cast<uint64_t>(input[index]);
  }
  return output;
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

bool ReadEndOfStream(int descriptor) {
  uint8_t extra = 0;
  for (;;) {
    const ssize_t count = read(descriptor, &extra, 1);
    if (count == 0) return true;
    if (count < 0 && errno == EINTR) continue;
    return false;
  }
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
      && static_cast<uint32_t>(geteuid()) == HB_CLOCK_CLIENT_UID
      && static_cast<uint32_t>(getegid()) == HB_CLOCK_CLIENT_GID
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

bool ConnectFixedEndpoint(int* descriptor) {
  if (descriptor == nullptr) return false;
  const int connection = socket(AF_UNIX, SOCK_STREAM, 0);
  if (connection < 0) return false;
  if (!ConfigureConnectedSocket(connection)) {
    (void)close(connection);
    return false;
  }
  sockaddr_un address{};
  address.sun_family = AF_UNIX;
  const size_t path_length = sizeof(HB_CLOCK_SOCKET_PATH) - 1;
  if (path_length >= sizeof(address.sun_path)) {
    (void)close(connection);
    return false;
  }
  memcpy(address.sun_path, HB_CLOCK_SOCKET_PATH, path_length + 1);
  if (connect(connection, reinterpret_cast<const sockaddr*>(&address),
              static_cast<socklen_t>(sizeof(address))) != 0) {
    (void)close(connection);
    return false;
  }
  *descriptor = connection;
  return true;
}

bool VerifyResponse(
    const std::array<uint8_t, HB_CLOCK_REQUEST_BYTES>& request,
    const std::array<uint8_t, HB_CLOCK_RESPONSE_BYTES>& response,
    hb_clock_source_sample* output) {
  if (output == nullptr
      || memcmp(response.data(), HB_CLOCK_RESPONSE_MAGIC,
                sizeof(HB_CLOCK_RESPONSE_MAGIC)) != 0
      || LoadU16(response.data() + 8) != HB_CLOCK_SOURCE_VERSION
      || LoadU16(response.data() + 10) != HB_CLOCK_RESPONSE_TYPE
      || LoadU32(response.data() + 12) != HB_CLOCK_RESPONSE_BYTES
      || memcmp(response.data() + 16, request.data() + 16,
                HB_CLOCK_REQUEST_ID_BYTES) != 0
      || memcmp(response.data() + 104, HB_CLOCK_SERVICE_IDENTITY_DIGEST,
                HB_CLOCK_DIGEST_BYTES) != 0
      || memcmp(response.data() + 136, HB_CLOCK_CLIENT_IDENTITY_DIGEST,
                HB_CLOCK_DIGEST_BYTES) != 0
      || memcmp(response.data() + 168, HB_CLOCK_ENROLLMENT_DIGEST,
                HB_CLOCK_DIGEST_BYTES) != 0) {
    return false;
  }
  const uint8_t separator = 0;
  uint8_t expected_challenge_digest[HB_CLOCK_DIGEST_BYTES] = {};
  ScopedScrub challenge_scrub(
      expected_challenge_digest, sizeof(expected_challenge_digest));
  if (!HashParts({
      {reinterpret_cast<const uint8_t*>(HB_CLOCK_CHALLENGE_DIGEST_DOMAIN),
       sizeof(HB_CLOCK_CHALLENGE_DIGEST_DOMAIN) - 1},
      {&separator, 1},
      {request.data() + 16, HB_CLOCK_REQUEST_ID_BYTES},
      {request.data() + 32, HB_CLOCK_CHALLENGE_BYTES},
  }, expected_challenge_digest)
      || memcmp(response.data() + 32, expected_challenge_digest,
                HB_CLOCK_DIGEST_BYTES) != 0) {
    return false;
  }
  uint8_t expected_sample_digest[HB_CLOCK_DIGEST_BYTES] = {};
  ScopedScrub sample_scrub(expected_sample_digest, sizeof(expected_sample_digest));
  if (!HashParts({
      {reinterpret_cast<const uint8_t*>(HB_CLOCK_SAMPLE_DIGEST_DOMAIN),
       sizeof(HB_CLOCK_SAMPLE_DIGEST_DOMAIN) - 1},
      {&separator, 1},
      {response.data() + 16, HB_CLOCK_REQUEST_ID_BYTES},
      {response.data() + 32, HB_CLOCK_DIGEST_BYTES},
      {response.data() + 64, sizeof(uint64_t)},
      {response.data() + 72, HB_CLOCK_DIGEST_BYTES},
      {response.data() + 104, HB_CLOCK_DIGEST_BYTES},
      {response.data() + 136, HB_CLOCK_DIGEST_BYTES},
      {response.data() + 168, HB_CLOCK_DIGEST_BYTES},
  }, expected_sample_digest)
      || memcmp(response.data() + 200, expected_sample_digest,
                HB_CLOCK_DIGEST_BYTES) != 0) {
    return false;
  }
  output->monotonic_ns = LoadU64(response.data() + 64);
  memcpy(output->request_id, response.data() + 16, HB_CLOCK_REQUEST_ID_BYTES);
  memcpy(output->challenge_digest, response.data() + 32, HB_CLOCK_DIGEST_BYTES);
  memcpy(output->boot_epoch_digest, response.data() + 72, HB_CLOCK_DIGEST_BYTES);
  memcpy(output->service_identity_digest, response.data() + 104,
         HB_CLOCK_DIGEST_BYTES);
  memcpy(output->client_identity_digest, response.data() + 136,
         HB_CLOCK_DIGEST_BYTES);
  memcpy(output->enrollment_digest, response.data() + 168,
         HB_CLOCK_DIGEST_BYTES);
  memcpy(output->source_sample_digest, response.data() + 200,
         HB_CLOCK_DIGEST_BYTES);
  return true;
}

}  // namespace

// The production client surface is deliberately zero-argument apart from its
// fixed-size output buffer. It accepts no callback, path, readiness assertion,
// socket descriptor, requirement, enrollment, or clock selector.
extern "C" int hb_trusted_clock_sample(hb_clock_source_sample* output) {
  if (output == nullptr) return EINVAL;
  memset(output, 0, sizeof(*output));
  if (!QualifiedEnrollmentPresent()) return ENOTSUP;
  int connection = -1;
  if (!ConnectFixedEndpoint(&connection)) return ENOTCONN;

  PeerIdentity peer{};
  std::array<uint8_t, HB_CLOCK_REQUEST_BYTES> request{};
  std::array<uint8_t, HB_CLOCK_RESPONSE_BYTES> response{};
  ScopedScrub peer_scrub(&peer, sizeof(peer));
  ScopedScrub request_scrub(request.data(), request.size());
  ScopedScrub response_scrub(response.data(), response.size());
  int status = EPROTO;
  if (ReadPeerIdentity(connection,
                       static_cast<uid_t>(HB_CLOCK_SERVICE_UID),
                       static_cast<gid_t>(HB_CLOCK_SERVICE_GID),
                       HB_CLOCK_SERVICE_REQUIREMENT,
                       &peer)) {
    memcpy(request.data(), HB_CLOCK_REQUEST_MAGIC, sizeof(HB_CLOCK_REQUEST_MAGIC));
    StoreU16(request.data() + 8, HB_CLOCK_SOURCE_VERSION);
    StoreU16(request.data() + 10, HB_CLOCK_REQUEST_TYPE);
    StoreU32(request.data() + 12, HB_CLOCK_REQUEST_BYTES);
    if (SecRandomCopyBytes(kSecRandomDefault, HB_CLOCK_REQUEST_ID_BYTES,
                           request.data() + 16) == errSecSuccess
        && SecRandomCopyBytes(kSecRandomDefault, HB_CLOCK_CHALLENGE_BYTES,
                              request.data() + 32) == errSecSuccess
        && WriteExact(connection, request.data(), request.size())
        && shutdown(connection, SHUT_WR) == 0
        && ReadExact(connection, response.data(), response.size())
        && ReadEndOfStream(connection)
        && VerifyResponse(request, response, output)) {
      status = 0;
    }
  }
  (void)shutdown(connection, SHUT_RDWR);
  (void)close(connection);
  if (status != 0) memset(output, 0, sizeof(*output));
  return status;
}
