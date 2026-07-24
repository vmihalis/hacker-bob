#include <node_api.h>
#include <uv.h>

#include <CommonCrypto/CommonDigest.h>
#include <CoreFoundation/CoreFoundation.h>
#include <Security/Security.h>
#include <bsm/libbsm.h>
#include <dlfcn.h>
#include <fcntl.h>
#include <libproc.h>
#include <mach/mach.h>
#include <mach/mach_vm.h>
#include <mach/task_info.h>
#include <mach-o/dyld.h>
#include <mach-o/loader.h>
#include <poll.h>
#include <sys/proc_info.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <unistd.h>

#include <algorithm>
#include <atomic>
#include <cerrno>
#include <chrono>
#include <cmath>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <limits.h>
#include <limits>
#include <memory>
#include <mutex>
#include <new>
#include <string>
#include <utility>
#include <vector>

#include "tracked_accept_operation_fd.h"

namespace {

constexpr const char* kFailureCode = "darwin_native_peer_inspection_failed";
constexpr const char* kSelfFailureCode = "darwin_native_self_inspection_failed";
constexpr const char* kLoadedImageFailureCode =
    "darwin_native_loaded_image_inspection_failed";
constexpr const char* kAcceptorFailureCode = "darwin_native_acceptor_failed";
constexpr uint32_t kSnapshotVersion = 2;
constexpr const char* kSnapshotPrimitive =
    "darwin_local_peertoken_seccode_dynamic_identity_v2";
constexpr uint32_t kSelfSnapshotVersion = 1;
constexpr const char* kSelfSnapshotPrimitive =
    "darwin_task_audit_token_seccode_self_identity_v1";
constexpr napi_type_tag kRegisteredPeerDescriptorTypeTag = {
    0x7e5d349348ff7b03ULL,
    0xa63e18d1399c8a51ULL,
};
constexpr napi_type_tag kUnixAcceptorTypeTag = {
    0xb9abfb99179bb4e1ULL,
    0x8abff0dd09e175ccULL,
};
constexpr napi_type_tag kAcceptedUnixConnectionTypeTag = {
    0xe838f95365dd0b48ULL,
    0xbc2641e268332e22ULL,
};
constexpr uint32_t kLoadedImageSnapshotVersion = 1;
constexpr const char* kLoadedImageSnapshotPrimitive =
    "darwin_dladdr_dyld_macho_executable_segments_file_match_v1";
constexpr size_t kMaxLoadedImageBytes = 64 * 1024 * 1024;
constexpr uint32_t kMaxMachOLoadCommands = 4096;
constexpr uint32_t kMaxExecutableSegments = 32;
constexpr size_t kMaxMachOLoadCommandBytes = 4 * 1024 * 1024;
constexpr size_t kMaxIdentityStringBytes = 16 * 1024;
constexpr CFIndex kMaxCodeDirectoryHashes = 16;
constexpr CFIndex kMaxCertificates = 32;
constexpr CFIndex kMaxCertificateBytes = 1024 * 1024;
constexpr size_t kMaxCertificateChainBytes = 8 * 1024 * 1024;
constexpr CFIndex kMaxRequirementBytes = 1024 * 1024;
constexpr size_t kMaxNativeIpcFrameBytes = 64 * 1024;
constexpr int kMaxNativeIpcTimeoutMs = 10000;

struct CodeIdentityDomains {
  const char* certificate_chain;
  const char* code_directory_hashes;
  const char* signing_identifier;
  const char* team_identifier;
  const char* static_flags;
  const char* dynamic_status;
  const char* designated_requirement;
  const char* signing_identity;
  const char* mapped_code_identity;
};

constexpr CodeIdentityDomains kPeerCodeIdentityDomains = {
    "hacker-bob/darwin-peer-certificate-chain/v1",
    "hacker-bob/darwin-peer-code-directory-hashes/v1",
    "hacker-bob/darwin-peer-signing-identifier/v1",
    "hacker-bob/darwin-peer-team-identifier/v1",
    "hacker-bob/darwin-peer-static-code-flags/v1",
    "hacker-bob/darwin-peer-dynamic-code-status/v1",
    "hacker-bob/darwin-peer-designated-requirement/v1",
    "hacker-bob/darwin-peer-signing-identity/v1",
    "hacker-bob/darwin-peer-mapped-code-identity/v1",
};

constexpr CodeIdentityDomains kSelfCodeIdentityDomains = {
    "hacker-bob/darwin-self-certificate-chain/v1",
    "hacker-bob/darwin-self-code-directory-hashes/v1",
    "hacker-bob/darwin-self-signing-identifier/v1",
    "hacker-bob/darwin-self-team-identifier/v1",
    "hacker-bob/darwin-self-static-code-flags/v1",
    "hacker-bob/darwin-self-dynamic-code-status/v1",
    "hacker-bob/darwin-self-designated-requirement/v1",
    "hacker-bob/darwin-self-signing-identity/v1",
    "hacker-bob/darwin-self-mapped-code-identity/v1",
};

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
  }
}

class ScopedFd {
 public:
  explicit ScopedFd(int fd) : fd_(fd) {}
  ~ScopedFd() {
    if (fd_ >= 0) close(fd_);
  }
  int get() const { return fd_; }
  int Release() {
    const int fd = fd_;
    fd_ = -1;
    return fd;
  }

 private:
  int fd_;
};

class AcceptedConnectionState;

class RegisteredPeerDescriptor {
 public:
  RegisteredPeerDescriptor(
      int fd, std::string token_digest,
      std::shared_ptr<AcceptedConnectionState> accepted_connection = nullptr)
      : fd_(fd), token_digest_(std::move(token_digest)),
        accepted_connection_(std::move(accepted_connection)) {}
  RegisteredPeerDescriptor(const RegisteredPeerDescriptor&) = delete;
  RegisteredPeerDescriptor& operator=(const RegisteredPeerDescriptor&) = delete;
  ~RegisteredPeerDescriptor();
  int Release() {
    const int fd = fd_;
    fd_ = -1;
    return fd;
  }
  const std::string& token_digest() const { return token_digest_; }
  const std::shared_ptr<AcceptedConnectionState>& accepted_connection() const {
    return accepted_connection_;
  }

 private:
  int fd_;
  std::string token_digest_;
  std::shared_ptr<AcceptedConnectionState> accepted_connection_;
};

void FinalizeRegisteredPeerDescriptor(napi_env, void* data, void*) {
  delete static_cast<RegisteredPeerDescriptor*>(data);
}

class ScopedAuditTokenCopy {
 public:
  explicit ScopedAuditTokenCopy(const audit_token_t& token) : token_(token) {}
  ScopedAuditTokenCopy(const ScopedAuditTokenCopy&) = delete;
  ScopedAuditTokenCopy& operator=(const ScopedAuditTokenCopy&) = delete;
  ~ScopedAuditTokenCopy() { SecureZero(&token_, sizeof(token_)); }
  const UInt8* bytes() const {
    return reinterpret_cast<const UInt8*>(&token_);
  }
  CFIndex size() const { return static_cast<CFIndex>(sizeof(token_)); }

 private:
  audit_token_t token_{};
};

template <typename T>
class ScopedCF {
 public:
  ScopedCF() = default;
  explicit ScopedCF(T value) : value_(value) {}
  ScopedCF(const ScopedCF&) = delete;
  ScopedCF& operator=(const ScopedCF&) = delete;
  ~ScopedCF() {
    if (value_ != nullptr) CFRelease(value_);
  }
  T get() const { return value_; }
  T* out() {
    if (value_ != nullptr) {
      CFRelease(value_);
      value_ = nullptr;
    }
    return &value_;
  }

 private:
  T value_ = nullptr;
};

bool DefineDataProperty(napi_env env, napi_value object, const char* name,
                        napi_value value, napi_property_attributes attributes) {
  const napi_property_descriptor descriptor = {
      name, nullptr, nullptr, nullptr, nullptr, value, attributes, nullptr};
  return napi_define_properties(env, object, 1, &descriptor) == napi_ok;
}

bool CreateCodeError(napi_env env, const char* code, const char* message_text,
                     napi_value* error_output) {
  napi_value message;
  napi_value error;
  napi_value code_value;
  if (napi_create_string_utf8(env, message_text,
                              NAPI_AUTO_LENGTH, &message) != napi_ok ||
      napi_create_error(env, nullptr, message, &error) != napi_ok ||
      napi_create_string_utf8(env, code, NAPI_AUTO_LENGTH, &code_value) != napi_ok ||
      !DefineDataProperty(env, error, "code", code_value, napi_default)) {
    return false;
  }
  *error_output = error;
  return true;
}

void ThrowCode(napi_env env, const char* code, const char* message_text) {
  napi_value error;
  if (!CreateCodeError(env, code, message_text, &error)) {
    napi_throw_error(env, code, message_text);
    return;
  }
  napi_throw(env, error);
}

void ThrowPeerCode(napi_env env) {
  ThrowCode(env, kFailureCode, "Darwin native peer inspection failed");
}

void ThrowSelfCode(napi_env env) {
  ThrowCode(env, kSelfFailureCode, "Darwin native self inspection failed");
}

void ThrowLoadedImageCode(napi_env env) {
  ThrowCode(env, kLoadedImageFailureCode,
            "Darwin native loaded image inspection failed");
}

void ThrowAcceptorCode(napi_env env) {
  ThrowCode(env, kAcceptorFailureCode, "Darwin native acceptor operation failed");
}

bool SetString(napi_env env, napi_value object, const char* name,
               const std::string& value) {
  napi_value encoded;
  return napi_create_string_utf8(env, value.data(), value.size(), &encoded) == napi_ok &&
         DefineDataProperty(env, object, name, encoded, napi_enumerable);
}

bool SetCString(napi_env env, napi_value object, const char* name, const char* value) {
  napi_value encoded;
  return napi_create_string_utf8(env, value, NAPI_AUTO_LENGTH, &encoded) == napi_ok &&
         DefineDataProperty(env, object, name, encoded, napi_enumerable);
}

bool SetUint32(napi_env env, napi_value object, const char* name, uint32_t value) {
  napi_value encoded;
  return napi_create_uint32(env, value, &encoded) == napi_ok &&
         DefineDataProperty(env, object, name, encoded, napi_enumerable);
}

bool SetBool(napi_env env, napi_value object, const char* name, bool value) {
  napi_value encoded;
  return napi_get_boolean(env, value, &encoded) == napi_ok &&
         DefineDataProperty(env, object, name, encoded, napi_enumerable);
}

std::string Sha256Hex(const void* bytes, size_t length) {
  unsigned char digest[CC_SHA256_DIGEST_LENGTH];
  CC_SHA256(bytes, static_cast<CC_LONG>(length), digest);
  static constexpr char kHex[] = "0123456789abcdef";
  std::string result(CC_SHA256_DIGEST_LENGTH * 2, '0');
  for (size_t index = 0; index < CC_SHA256_DIGEST_LENGTH; ++index) {
    result[index * 2] = kHex[digest[index] >> 4];
    result[index * 2 + 1] = kHex[digest[index] & 0x0f];
  }
  SecureZero(digest, sizeof(digest));
  return result;
}

std::string HexBytes(const UInt8* bytes, size_t length) {
  static constexpr char kHex[] = "0123456789abcdef";
  std::string result(length * 2, '0');
  for (size_t index = 0; index < length; ++index) {
    result[index * 2] = kHex[bytes[index] >> 4];
    result[index * 2 + 1] = kHex[bytes[index] & 0x0f];
  }
  return result;
}

class FramedDigestBuilder {
 public:
  explicit FramedDigestBuilder(const char* domain) { Append(domain, std::strlen(domain)); }
  FramedDigestBuilder(const FramedDigestBuilder&) = delete;
  FramedDigestBuilder& operator=(const FramedDigestBuilder&) = delete;
  ~FramedDigestBuilder() { ZeroString(&basis_); }

  void Append(const void* bytes, size_t length) {
    unsigned char encoded_length[8];
    uint64_t remaining = static_cast<uint64_t>(length);
    for (int index = 7; index >= 0; --index) {
      encoded_length[index] = static_cast<unsigned char>(remaining & 0xff);
      remaining >>= 8;
    }
    basis_.append(reinterpret_cast<const char*>(encoded_length), sizeof(encoded_length));
    if (length > 0) basis_.append(static_cast<const char*>(bytes), length);
    SecureZero(encoded_length, sizeof(encoded_length));
  }

  void AppendString(const std::string& value) { Append(value.data(), value.size()); }

  void AppendCString(const char* value) { Append(value, std::strlen(value)); }

  void AppendUint32(uint32_t value) {
    unsigned char encoded[4] = {
        static_cast<unsigned char>((value >> 24) & 0xff),
        static_cast<unsigned char>((value >> 16) & 0xff),
        static_cast<unsigned char>((value >> 8) & 0xff),
        static_cast<unsigned char>(value & 0xff),
    };
    Append(encoded, sizeof(encoded));
    SecureZero(encoded, sizeof(encoded));
  }

  void AppendUint64(uint64_t value) {
    unsigned char encoded[8];
    for (int index = 7; index >= 0; --index) {
      encoded[index] = static_cast<unsigned char>(value & 0xff);
      value >>= 8;
    }
    Append(encoded, sizeof(encoded));
    SecureZero(encoded, sizeof(encoded));
  }

  std::string Finish() const { return Sha256Hex(basis_.data(), basis_.size()); }

 private:
  std::string basis_;
};

enum class AcceptedConnectionPhase {
  kAccepted,
  kPeerInspecting,
  kPeerInspected,
  kChallengeWriting,
  kChallengeSent,
  kRequestReading,
  kRequestReceived,
  kResponseWriting,
  kResponseSent,
  kClosed,
  kRejected,
};

class UnixAcceptorState {
 public:
  UnixAcceptorState(int fd, std::string path, const struct stat& root_stat,
                    const struct stat& socket_stat,
                    std::string root_identity_digest,
                    std::string socket_identity_digest,
                    std::string listener_identity_digest,
                    std::string acceptor_instance_digest)
      : fd_(fd), path_(std::move(path)), root_stat_(root_stat),
        socket_stat_(socket_stat),
        root_identity_digest_(std::move(root_identity_digest)),
        socket_identity_digest_(std::move(socket_identity_digest)),
        listener_identity_digest_(std::move(listener_identity_digest)),
        acceptor_instance_digest_(std::move(acceptor_instance_digest)) {}
  UnixAcceptorState(const UnixAcceptorState&) = delete;
  UnixAcceptorState& operator=(const UnixAcceptorState&) = delete;
  ~UnixAcceptorState() { CloseAndUnlink(); }

  bool BeginAccept(int* operation_fd, uint64_t* generation) {
    std::lock_guard<std::mutex> lock(mutex_);
    if (closed_ || accepting_ || fd_ < 0) return false;
    const int duplicate = fcntl(fd_, F_DUPFD_CLOEXEC, 0);
    if (duplicate < 0) return false;
    if (!accept_operation_fd_.Track(duplicate)) {
      close(duplicate);
      return false;
    }
    accepting_ = true;
    ++generation_;
    *operation_fd = duplicate;
    *generation = generation_;
    return true;
  }

  bool EndAccept(int operation_fd) {
    const int detached_operation_fd = accept_operation_fd_.Detach(operation_fd);
    if (detached_operation_fd < 0) return false;
    int detached_listener_fd = -1;
    bool accepted_before_close = false;
    {
      std::lock_guard<std::mutex> lock(mutex_);
      accepting_ = false;
      accepted_before_close = !closed_;
      if (closed_ && fd_ >= 0) {
        detached_listener_fd = fd_;
        fd_ = -1;
      }
    }
    if (detached_operation_fd >= 0) close(detached_operation_fd);
    if (detached_listener_fd >= 0) close(detached_listener_fd);
    return accepted_before_close;
  }

  bool RegisterAcceptWork(napi_env env, napi_async_work work) {
    std::lock_guard<std::mutex> lock(mutex_);
    if (closed_ || !accepting_ || active_accept_work_ != nullptr) return false;
    active_accept_env_ = env;
    active_accept_work_ = work;
    return true;
  }

  void UnregisterAcceptWork(napi_async_work work) {
    std::lock_guard<std::mutex> lock(mutex_);
    if (active_accept_work_ != work) return;
    active_accept_work_ = nullptr;
    active_accept_env_ = nullptr;
  }

  void Close() {
    napi_env accept_env = nullptr;
    napi_async_work accept_work = nullptr;
    int detached_listener_fd = -1;
    {
      std::lock_guard<std::mutex> lock(mutex_);
      if (!closed_) {
        closed_ = true;
        accept_operation_fd_.ShutdownTracked();
        if (!accepting_ && fd_ >= 0) {
          detached_listener_fd = fd_;
          fd_ = -1;
        }
      }
      accept_env = active_accept_env_;
      accept_work = active_accept_work_;
      UnlinkIfOwned();
    }
    if (detached_listener_fd >= 0) close(detached_listener_fd);
    if (accept_env != nullptr && accept_work != nullptr) {
      napi_cancel_async_work(accept_env, accept_work);
    }
  }

  bool closed() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return closed_;
  }

  const std::string& root_identity_digest() const {
    return root_identity_digest_;
  }
  const std::string& socket_identity_digest() const {
    return socket_identity_digest_;
  }
  const std::string& listener_identity_digest() const {
    return listener_identity_digest_;
  }
  const std::string& acceptor_instance_digest() const {
    return acceptor_instance_digest_;
  }

 private:
  void CloseAndUnlink() {
    Close();
    ZeroString(&path_);
    ZeroString(&root_identity_digest_);
    ZeroString(&socket_identity_digest_);
    ZeroString(&listener_identity_digest_);
    ZeroString(&acceptor_instance_digest_);
    SecureZero(&root_stat_, sizeof(root_stat_));
    SecureZero(&socket_stat_, sizeof(socket_stat_));
  }

  void UnlinkIfOwned() {
    if (unlinked_) return;
    struct stat current{};
    if (!path_.empty() && lstat(path_.c_str(), &current) == 0 &&
        S_ISSOCK(current.st_mode) && current.st_dev == socket_stat_.st_dev &&
        current.st_ino == socket_stat_.st_ino) {
      unlink(path_.c_str());
    }
    unlinked_ = true;
  }

  mutable std::mutex mutex_;
  int fd_ = -1;
  hacker_bob_native_darwin::TrackedAcceptOperationFd accept_operation_fd_;
  bool closed_ = false;
  bool accepting_ = false;
  bool unlinked_ = false;
  napi_env active_accept_env_ = nullptr;
  napi_async_work active_accept_work_ = nullptr;
  uint64_t generation_ = 0;
  std::string path_;
  struct stat root_stat_{};
  struct stat socket_stat_{};
  std::string root_identity_digest_;
  std::string socket_identity_digest_;
  std::string listener_identity_digest_;
  std::string acceptor_instance_digest_;
};

class AcceptedConnectionState {
 public:
  AcceptedConnectionState(
      int fd, uint64_t generation, std::string registration_token_digest,
      std::string connection_identity_digest,
      std::string root_identity_digest, std::string socket_identity_digest,
      std::string listener_identity_digest,
      std::string acceptor_instance_digest)
      : fd_(fd), generation_(generation),
        registration_token_digest_(std::move(registration_token_digest)),
        connection_identity_digest_(std::move(connection_identity_digest)),
        root_identity_digest_(std::move(root_identity_digest)),
        socket_identity_digest_(std::move(socket_identity_digest)),
        listener_identity_digest_(std::move(listener_identity_digest)),
        acceptor_instance_digest_(std::move(acceptor_instance_digest)) {}
  AcceptedConnectionState(const AcceptedConnectionState&) = delete;
  AcceptedConnectionState& operator=(const AcceptedConnectionState&) = delete;
  ~AcceptedConnectionState() {
    Close();
    ZeroString(&registration_token_digest_);
    ZeroString(&connection_identity_digest_);
    ZeroString(&root_identity_digest_);
    ZeroString(&socket_identity_digest_);
    ZeroString(&listener_identity_digest_);
    ZeroString(&acceptor_instance_digest_);
  }

  bool BeginPeerInspection(const std::string& token_digest) {
    std::lock_guard<std::mutex> lock(mutex_);
    if (phase_ != AcceptedConnectionPhase::kAccepted || fd_ < 0 ||
        token_digest != registration_token_digest_) {
      RejectLocked();
      return false;
    }
    phase_ = AcceptedConnectionPhase::kPeerInspecting;
    return true;
  }

  void FinishPeerInspection(bool success) {
    std::lock_guard<std::mutex> lock(mutex_);
    if (phase_ != AcceptedConnectionPhase::kPeerInspecting || !success) {
      RejectLocked();
      return;
    }
    phase_ = AcceptedConnectionPhase::kPeerInspected;
  }

  void RegistrationAbandoned() {
    std::lock_guard<std::mutex> lock(mutex_);
    if (phase_ == AcceptedConnectionPhase::kAccepted) RejectLocked();
  }

  bool BeginWrite(int* operation_fd, bool* challenge) {
    std::lock_guard<std::mutex> lock(mutex_);
    if (fd_ < 0) return false;
    AcceptedConnectionPhase next;
    if (phase_ == AcceptedConnectionPhase::kPeerInspected) {
      next = AcceptedConnectionPhase::kChallengeWriting;
      *challenge = true;
    } else if (phase_ == AcceptedConnectionPhase::kRequestReceived) {
      next = AcceptedConnectionPhase::kResponseWriting;
      *challenge = false;
    } else {
      return false;
    }
    const int duplicate = fcntl(fd_, F_DUPFD_CLOEXEC, 0);
    if (duplicate < 0) return false;
    phase_ = next;
    *operation_fd = duplicate;
    return true;
  }

  void FinishWrite(bool challenge, bool success) {
    std::lock_guard<std::mutex> lock(mutex_);
    const AcceptedConnectionPhase expected = challenge
        ? AcceptedConnectionPhase::kChallengeWriting
        : AcceptedConnectionPhase::kResponseWriting;
    if (!success || phase_ != expected) {
      RejectLocked();
      return;
    }
    phase_ = challenge ? AcceptedConnectionPhase::kChallengeSent
                       : AcceptedConnectionPhase::kResponseSent;
  }

  bool BeginRead(int* operation_fd) {
    std::lock_guard<std::mutex> lock(mutex_);
    if (phase_ != AcceptedConnectionPhase::kChallengeSent || fd_ < 0) {
      return false;
    }
    const int duplicate = fcntl(fd_, F_DUPFD_CLOEXEC, 0);
    if (duplicate < 0) return false;
    phase_ = AcceptedConnectionPhase::kRequestReading;
    *operation_fd = duplicate;
    return true;
  }

  void FinishRead(bool success) {
    std::lock_guard<std::mutex> lock(mutex_);
    if (!success || phase_ != AcceptedConnectionPhase::kRequestReading) {
      RejectLocked();
      return;
    }
    phase_ = AcceptedConnectionPhase::kRequestReceived;
  }

  bool DuplicateForReadback(int* duplicate) const {
    std::lock_guard<std::mutex> lock(mutex_);
    if (fd_ < 0 || phase_ == AcceptedConnectionPhase::kAccepted ||
        phase_ == AcceptedConnectionPhase::kPeerInspecting ||
        phase_ == AcceptedConnectionPhase::kClosed ||
        phase_ == AcceptedConnectionPhase::kRejected) {
      return false;
    }
    *duplicate = fcntl(fd_, F_DUPFD_CLOEXEC, 0);
    return *duplicate >= 0;
  }

  void Reject() {
    std::lock_guard<std::mutex> lock(mutex_);
    RejectLocked();
  }

  void Close() {
    std::lock_guard<std::mutex> lock(mutex_);
    if (phase_ == AcceptedConnectionPhase::kClosed) return;
    if (fd_ >= 0) {
      shutdown(fd_, SHUT_RDWR);
      close(fd_);
      fd_ = -1;
    }
    phase_ = AcceptedConnectionPhase::kClosed;
  }

  uint64_t generation() const { return generation_; }
  const std::string& registration_token_digest() const {
    return registration_token_digest_;
  }
  const std::string& connection_identity_digest() const {
    return connection_identity_digest_;
  }
  const std::string& root_identity_digest() const {
    return root_identity_digest_;
  }
  const std::string& socket_identity_digest() const {
    return socket_identity_digest_;
  }
  const std::string& listener_identity_digest() const {
    return listener_identity_digest_;
  }
  const std::string& acceptor_instance_digest() const {
    return acceptor_instance_digest_;
  }

 private:
  void RejectLocked() {
    if (fd_ >= 0) {
      shutdown(fd_, SHUT_RDWR);
      close(fd_);
      fd_ = -1;
    }
    phase_ = AcceptedConnectionPhase::kRejected;
  }

  mutable std::mutex mutex_;
  int fd_ = -1;
  AcceptedConnectionPhase phase_ = AcceptedConnectionPhase::kAccepted;
  uint64_t generation_ = 0;
  std::string registration_token_digest_;
  std::string connection_identity_digest_;
  std::string root_identity_digest_;
  std::string socket_identity_digest_;
  std::string listener_identity_digest_;
  std::string acceptor_instance_digest_;
};

RegisteredPeerDescriptor::~RegisteredPeerDescriptor() {
  if (fd_ >= 0) close(fd_);
  if (accepted_connection_ != nullptr) {
    accepted_connection_->RegistrationAbandoned();
  }
  ZeroString(&token_digest_);
}

std::string DigestBytes(const char* domain, const void* bytes, size_t length) {
  FramedDigestBuilder builder(domain);
  builder.Append(bytes, length);
  return builder.Finish();
}

std::string DigestUint32(const char* domain, uint32_t value) {
  FramedDigestBuilder builder(domain);
  builder.AppendUint32(value);
  return builder.Finish();
}

bool ReadBoundedNapiString(napi_env env, napi_value value, size_t maximum,
                           std::string* output) {
  napi_valuetype type = napi_undefined;
  size_t length = 0;
  if (napi_typeof(env, value, &type) != napi_ok || type != napi_string ||
      napi_get_value_string_utf8(env, value, nullptr, 0, &length) != napi_ok ||
      length == 0 || length > maximum) {
    return false;
  }
  std::vector<char> bytes(length + 1, 0);
  size_t copied = 0;
  if (napi_get_value_string_utf8(env, value, bytes.data(), bytes.size(),
                                 &copied) != napi_ok ||
      copied != length || std::memchr(bytes.data(), '\0', length) != nullptr) {
    SecureZero(bytes.data(), bytes.size());
    return false;
  }
  output->assign(bytes.data(), length);
  SecureZero(bytes.data(), bytes.size());
  return true;
}

std::string DigestSocketFileIdentity(const char* domain,
                                     const std::string& canonical_path,
                                     const struct stat& value) {
  FramedDigestBuilder builder(domain);
  builder.AppendString(canonical_path);
  builder.AppendUint64(static_cast<uint64_t>(value.st_dev));
  builder.AppendUint64(static_cast<uint64_t>(value.st_ino));
  builder.AppendUint32(static_cast<uint32_t>(value.st_mode));
  builder.AppendUint32(static_cast<uint32_t>(value.st_uid));
  builder.AppendUint32(static_cast<uint32_t>(value.st_gid));
  builder.AppendUint64(static_cast<uint64_t>(value.st_nlink));
  return builder.Finish();
}

bool MintRegistrationTokenDigest(int fd, std::string* token_digest,
                                 audit_token_t* peer_token_output = nullptr) {
  unsigned char registration_secret[32]{};
  audit_token_t registration_peer_token{};
  socklen_t registration_peer_token_length = sizeof(registration_peer_token);
  const bool success =
      SecRandomCopyBytes(kSecRandomDefault, sizeof(registration_secret),
                         registration_secret) == errSecSuccess &&
      getsockopt(fd, SOL_LOCAL, LOCAL_PEERTOKEN, &registration_peer_token,
                 &registration_peer_token_length) == 0 &&
      registration_peer_token_length == sizeof(registration_peer_token);
  if (!success) {
    SecureZero(registration_secret, sizeof(registration_secret));
    SecureZero(&registration_peer_token, sizeof(registration_peer_token));
    return false;
  }
  FramedDigestBuilder builder(
      "hacker-bob/darwin-native-registered-descriptor-token/v1");
  builder.Append(registration_secret, sizeof(registration_secret));
  builder.Append(&registration_peer_token, sizeof(registration_peer_token));
  *token_digest = builder.Finish();
  if (peer_token_output != nullptr) {
    *peer_token_output = registration_peer_token;
  }
  SecureZero(registration_secret, sizeof(registration_secret));
  SecureZero(&registration_peer_token, sizeof(registration_peer_token));
  return true;
}

bool CreateRegistrationTokenObject(
    napi_env env, int fd, const std::string& token_digest,
    std::shared_ptr<AcceptedConnectionState> accepted_connection,
    napi_value* token_output) {
  RegisteredPeerDescriptor* registration = new (std::nothrow)
      RegisteredPeerDescriptor(fd, token_digest, std::move(accepted_connection));
  if (registration == nullptr) {
    if (fd >= 0) close(fd);
    return false;
  }
  napi_value token;
  napi_value token_digest_value;
  if (napi_create_object(env, &token) != napi_ok ||
      napi_type_tag_object(env, token, &kRegisteredPeerDescriptorTypeTag) != napi_ok ||
      napi_create_string_utf8(env, registration->token_digest().data(),
                              registration->token_digest().size(),
                              &token_digest_value) != napi_ok ||
      !DefineDataProperty(env, token, "registration_token_digest",
                          token_digest_value, napi_default)) {
    delete registration;
    return false;
  }
  if (napi_wrap(env, token, registration, FinalizeRegisteredPeerDescriptor,
                nullptr, nullptr) != napi_ok) {
    delete registration;
    return false;
  }
  if (napi_object_freeze(env, token) != napi_ok) {
    const int owned_fd = registration->Release();
    if (owned_fd >= 0) close(owned_fd);
    return false;
  }
  *token_output = token;
  return true;
}

template <typename T>
void FinalizeSharedState(napi_env, void* data, void*) {
  delete static_cast<std::shared_ptr<T>*>(data);
}

template <typename T>
bool WrapSharedState(napi_env env, napi_value token,
                     const napi_type_tag* type_tag,
                     const std::shared_ptr<T>& state) {
  std::shared_ptr<T>* holder =
      new (std::nothrow) std::shared_ptr<T>(state);
  if (holder == nullptr) return false;
  if (napi_type_tag_object(env, token, type_tag) != napi_ok ||
      napi_wrap(env, token, holder, FinalizeSharedState<T>, nullptr,
                nullptr) != napi_ok) {
    delete holder;
    return false;
  }
  return true;
}

template <typename T>
bool UnwrapSharedState(napi_env env, napi_value token,
                       const napi_type_tag* type_tag,
                       std::shared_ptr<T>* state) {
  napi_valuetype type = napi_undefined;
  napi_value null_value;
  bool is_null = false;
  bool tagged = false;
  void* raw = nullptr;
  if (napi_typeof(env, token, &type) != napi_ok || type != napi_object ||
      napi_get_null(env, &null_value) != napi_ok ||
      napi_strict_equals(env, token, null_value, &is_null) != napi_ok || is_null ||
      napi_check_object_type_tag(env, token, type_tag, &tagged) != napi_ok ||
      !tagged || napi_unwrap(env, token, &raw) != napi_ok || raw == nullptr) {
    return false;
  }
  *state = *static_cast<std::shared_ptr<T>*>(raw);
  return *state != nullptr;
}

struct ScopedCanonicalPath {
  char value[PATH_MAX]{};
  ~ScopedCanonicalPath() { SecureZero(value, sizeof(value)); }
};

bool SameFileStat(const struct stat& left, const struct stat& right) {
  return left.st_dev == right.st_dev &&
         left.st_ino == right.st_ino &&
         left.st_mode == right.st_mode &&
         left.st_uid == right.st_uid &&
         left.st_gid == right.st_gid &&
         left.st_nlink == right.st_nlink &&
         left.st_size == right.st_size &&
         left.st_mtimespec.tv_sec == right.st_mtimespec.tv_sec &&
         left.st_mtimespec.tv_nsec == right.st_mtimespec.tv_nsec &&
         left.st_ctimespec.tv_sec == right.st_ctimespec.tv_sec &&
         left.st_ctimespec.tv_nsec == right.st_ctimespec.tv_nsec;
}

bool SameStableDirectoryIdentity(const struct stat& left,
                                 const struct stat& right) {
  const bool link_count_expected =
      right.st_nlink == left.st_nlink ||
      (left.st_nlink < std::numeric_limits<nlink_t>::max() &&
       right.st_nlink == left.st_nlink + 1);
  return S_ISDIR(left.st_mode) && S_ISDIR(right.st_mode) &&
         left.st_dev == right.st_dev &&
         left.st_ino == right.st_ino &&
         left.st_mode == right.st_mode &&
         left.st_uid == right.st_uid &&
         left.st_gid == right.st_gid && link_count_expected;
}

bool ReadExactAt(int fd, void* output, size_t length, off_t offset) {
  unsigned char* cursor = static_cast<unsigned char*>(output);
  size_t remaining = length;
  while (remaining > 0) {
    const ssize_t read_count = pread(fd, cursor, remaining, offset);
    if (read_count < 0 && errno == EINTR) continue;
    if (read_count <= 0) return false;
    cursor += static_cast<size_t>(read_count);
    remaining -= static_cast<size_t>(read_count);
    offset += static_cast<off_t>(read_count);
  }
  return true;
}

bool AddSlideAddress(uint64_t vm_address, intptr_t slide,
                     uintptr_t* runtime_address) {
  if (vm_address > std::numeric_limits<uintptr_t>::max()) return false;
  uintptr_t value = static_cast<uintptr_t>(vm_address);
  if (slide >= 0) {
    const uintptr_t positive_slide = static_cast<uintptr_t>(slide);
    if (value > std::numeric_limits<uintptr_t>::max() - positive_slide) {
      return false;
    }
    value += positive_slide;
  } else {
    const uintptr_t negative_slide =
        static_cast<uintptr_t>(-(slide + 1)) + 1;
    if (value < negative_slide) return false;
    value -= negative_slide;
  }
  *runtime_address = value;
  return true;
}

bool RangeHasReadExecuteOnlyProtection(uintptr_t address, size_t length) {
  if (length == 0 || address > std::numeric_limits<uintptr_t>::max() - length) {
    return false;
  }
  const mach_vm_address_t end =
      static_cast<mach_vm_address_t>(address + length);
  mach_vm_address_t cursor = static_cast<mach_vm_address_t>(address);
  while (cursor < end) {
    mach_vm_address_t region_address = cursor;
    mach_vm_size_t region_size = 0;
    vm_region_basic_info_data_64_t region_info{};
    mach_msg_type_number_t info_count = VM_REGION_BASIC_INFO_COUNT_64;
    mach_port_t object_name = MACH_PORT_NULL;
    const kern_return_t result = mach_vm_region(
        mach_task_self(), &region_address, &region_size,
        VM_REGION_BASIC_INFO_64,
        reinterpret_cast<vm_region_info_t>(&region_info),
        &info_count, &object_name);
    if (object_name != MACH_PORT_NULL) {
      mach_port_deallocate(mach_task_self(), object_name);
    }
    if (result != KERN_SUCCESS || info_count != VM_REGION_BASIC_INFO_COUNT_64 ||
        region_size == 0 || region_address > cursor ||
        region_address > std::numeric_limits<mach_vm_address_t>::max() -
                             region_size ||
        (region_info.protection & (VM_PROT_READ | VM_PROT_EXECUTE)) !=
            (VM_PROT_READ | VM_PROT_EXECUTE) ||
        (region_info.protection & VM_PROT_WRITE) != 0) {
      return false;
    }
    const mach_vm_address_t region_end = region_address + region_size;
    if (region_end <= cursor) return false;
    cursor = std::min(region_end, end);
  }
  return true;
}

struct ExecutableSegmentMeasurement {
  char name[16]{};
  uint64_t vm_address = 0;
  uint64_t vm_size = 0;
  uint64_t file_offset = 0;
  uint64_t file_size = 0;
  uintptr_t runtime_address = 0;
};

struct LoadedImageMeasurement {
  std::string file_sha256;
  std::string identity_digest;
  std::string path_digest;
  std::string file_identity_digest;
  std::string uuid_digest;
  std::string header_and_load_commands_digest;
  std::string executable_segments_digest;
  uint32_t executable_segment_count = 0;
  uint64_t executable_file_bytes = 0;
  bool callback_in_executable_segment = false;

  ~LoadedImageMeasurement() {
    ZeroString(&file_sha256);
    ZeroString(&identity_digest);
    ZeroString(&path_digest);
    ZeroString(&file_identity_digest);
    ZeroString(&uuid_digest);
    ZeroString(&header_and_load_commands_digest);
    ZeroString(&executable_segments_digest);
  }
};

bool MeasureLoadedImage(const void* callback_address,
                        LoadedImageMeasurement* measurement) {
  if (callback_address == nullptr || measurement == nullptr) return false;
  Dl_info dynamic_info{};
  if (dladdr(callback_address, &dynamic_info) == 0 ||
      dynamic_info.dli_fbase == nullptr || dynamic_info.dli_fname == nullptr ||
      dynamic_info.dli_fname[0] == '\0') {
    return false;
  }
  const mach_header_64* mapped_header =
      static_cast<const mach_header_64*>(dynamic_info.dli_fbase);
  if (mapped_header->magic != MH_MAGIC_64 ||
      mapped_header->cputype != CPU_TYPE_ARM64 ||
      mapped_header->filetype != MH_BUNDLE ||
      mapped_header->ncmds == 0 ||
      mapped_header->ncmds > kMaxMachOLoadCommands ||
      mapped_header->sizeofcmds == 0 ||
      mapped_header->sizeofcmds > kMaxMachOLoadCommandBytes) {
    return false;
  }
  const size_t header_bytes =
      sizeof(mach_header_64) + static_cast<size_t>(mapped_header->sizeofcmds);

  uint32_t matching_dyld_headers = 0;
  uint32_t matching_dyld_index = 0;
  const uint32_t image_count = _dyld_image_count();
  for (uint32_t index = 0; index < image_count; ++index) {
    if (_dyld_get_image_header(index) ==
        reinterpret_cast<const mach_header*>(mapped_header)) {
      matching_dyld_headers += 1;
      matching_dyld_index = index;
    }
  }
  if (matching_dyld_headers != 1) return false;
  const intptr_t image_slide =
      _dyld_get_image_vmaddr_slide(matching_dyld_index);
  const char* dyld_image_name = _dyld_get_image_name(matching_dyld_index);
  if (dyld_image_name == nullptr || dyld_image_name[0] == '\0') return false;

  ScopedCanonicalPath canonical_path;
  ScopedCanonicalPath dyld_canonical_path;
  if (realpath(dynamic_info.dli_fname, canonical_path.value) == nullptr ||
      realpath(dyld_image_name, dyld_canonical_path.value) == nullptr ||
      std::strcmp(canonical_path.value, dyld_canonical_path.value) != 0) {
    return false;
  }
  const int opened = open(canonical_path.value,
                          O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
  if (opened < 0) return false;
  ScopedFd file(opened);
  struct stat descriptor_before{};
  struct stat path_before{};
  if (fstat(file.get(), &descriptor_before) != 0 ||
      lstat(canonical_path.value, &path_before) != 0 ||
      !SameFileStat(descriptor_before, path_before) ||
      !S_ISREG(descriptor_before.st_mode) || descriptor_before.st_nlink != 1 ||
      (descriptor_before.st_mode & 0022) != 0 ||
      descriptor_before.st_size <= 0 ||
      static_cast<uint64_t>(descriptor_before.st_size) > kMaxLoadedImageBytes ||
      static_cast<uint64_t>(descriptor_before.st_size) < header_bytes) {
    return false;
  }
  std::vector<unsigned char> file_bytes(
      static_cast<size_t>(descriptor_before.st_size));
  if (!ReadExactAt(file.get(), file_bytes.data(), file_bytes.size(), 0)) {
    return false;
  }
  struct stat descriptor_after{};
  struct stat path_after{};
  if (fstat(file.get(), &descriptor_after) != 0 ||
      lstat(canonical_path.value, &path_after) != 0 ||
      !SameFileStat(descriptor_before, descriptor_after) ||
      !SameFileStat(descriptor_before, path_after)) {
    return false;
  }

  mach_header_64 file_header{};
  std::memcpy(&file_header, file_bytes.data(), sizeof(file_header));
  if (file_header.magic != MH_MAGIC_64 ||
      file_header.cputype != CPU_TYPE_ARM64 ||
      file_header.filetype != MH_BUNDLE ||
      file_header.ncmds != mapped_header->ncmds ||
      file_header.sizeofcmds != mapped_header->sizeofcmds ||
      std::memcmp(mapped_header, file_bytes.data(), header_bytes) != 0) {
    return false;
  }

  std::vector<ExecutableSegmentMeasurement> executable_segments;
  executable_segments.reserve(4);
  size_t command_offset = sizeof(mach_header_64);
  uint32_t uuid_count = 0;
  unsigned char uuid_bytes[16]{};
  for (uint32_t index = 0; index < file_header.ncmds; ++index) {
    if (command_offset > header_bytes - sizeof(load_command)) return false;
    load_command command{};
    std::memcpy(&command, file_bytes.data() + command_offset, sizeof(command));
    if (command.cmdsize < sizeof(load_command) || (command.cmdsize % 8) != 0 ||
        command.cmdsize > header_bytes - command_offset) {
      return false;
    }
    if (command.cmd == LC_UUID) {
      if (command.cmdsize != sizeof(uuid_command) || uuid_count != 0) {
        return false;
      }
      uuid_command uuid{};
      std::memcpy(&uuid, file_bytes.data() + command_offset, sizeof(uuid));
      std::memcpy(uuid_bytes, uuid.uuid, sizeof(uuid_bytes));
      uuid_count += 1;
    } else if (command.cmd == LC_SEGMENT_64) {
      if (command.cmdsize < sizeof(segment_command_64)) return false;
      segment_command_64 segment{};
      std::memcpy(&segment, file_bytes.data() + command_offset,
                  sizeof(segment));
      const uint64_t section_bytes =
          static_cast<uint64_t>(segment.nsects) * sizeof(section_64);
      if (section_bytes != command.cmdsize - sizeof(segment_command_64) ||
          segment.filesize > segment.vmsize ||
          segment.fileoff > file_bytes.size() ||
          segment.filesize > file_bytes.size() - segment.fileoff) {
        return false;
      }
      if ((segment.initprot & VM_PROT_EXECUTE) != 0) {
        if (segment.filesize == 0 || segment.vmsize == 0 ||
            (segment.initprot & VM_PROT_READ) == 0 ||
            (segment.initprot & VM_PROT_WRITE) != 0 ||
            segment.vmsize != segment.filesize ||
            executable_segments.size() >= kMaxExecutableSegments ||
            segment.filesize > std::numeric_limits<size_t>::max()) {
          return false;
        }
        ExecutableSegmentMeasurement executable;
        std::memcpy(executable.name, segment.segname, sizeof(executable.name));
        executable.vm_address = segment.vmaddr;
        executable.vm_size = segment.vmsize;
        executable.file_offset = segment.fileoff;
        executable.file_size = segment.filesize;
        if (!AddSlideAddress(segment.vmaddr, image_slide,
                             &executable.runtime_address) ||
            executable.runtime_address >
                std::numeric_limits<uintptr_t>::max() - segment.filesize) {
          return false;
        }
        executable_segments.push_back(executable);
      }
    }
    command_offset += command.cmdsize;
  }
  if (command_offset != header_bytes || uuid_count != 1 ||
      executable_segments.empty()) {
    SecureZero(uuid_bytes, sizeof(uuid_bytes));
    return false;
  }

  std::sort(executable_segments.begin(), executable_segments.end(),
            [](const ExecutableSegmentMeasurement& left,
               const ExecutableSegmentMeasurement& right) {
              return left.runtime_address < right.runtime_address;
            });
  FramedDigestBuilder executable_builder(
      "hacker-bob/darwin-native-loaded-image-executable-segments/v1");
  const uintptr_t callback = reinterpret_cast<uintptr_t>(callback_address);
  bool header_in_executable_segment = false;
  for (size_t index = 0; index < executable_segments.size(); ++index) {
    const ExecutableSegmentMeasurement& segment = executable_segments[index];
    for (size_t previous_index = 0; previous_index < index; ++previous_index) {
      const ExecutableSegmentMeasurement& previous =
          executable_segments[previous_index];
      const bool file_ranges_overlap =
          previous.file_offset < segment.file_offset + segment.file_size &&
          segment.file_offset < previous.file_offset + previous.file_size;
      if (file_ranges_overlap) {
        SecureZero(uuid_bytes, sizeof(uuid_bytes));
        return false;
      }
    }
    if (index > 0) {
      const ExecutableSegmentMeasurement& previous =
          executable_segments[index - 1];
      if (previous.runtime_address >
              std::numeric_limits<uintptr_t>::max() - previous.file_size ||
          previous.runtime_address + previous.file_size >
              segment.runtime_address) {
        SecureZero(uuid_bytes, sizeof(uuid_bytes));
        return false;
      }
    }
    const size_t segment_size = static_cast<size_t>(segment.file_size);
    if (!RangeHasReadExecuteOnlyProtection(segment.runtime_address,
                                           segment_size)) {
      SecureZero(uuid_bytes, sizeof(uuid_bytes));
      return false;
    }
    const unsigned char* mapped_bytes =
        reinterpret_cast<const unsigned char*>(segment.runtime_address);
    const unsigned char* corresponding_file_bytes =
        file_bytes.data() + static_cast<size_t>(segment.file_offset);
    if (std::memcmp(mapped_bytes, corresponding_file_bytes, segment_size) != 0) {
      SecureZero(uuid_bytes, sizeof(uuid_bytes));
      return false;
    }
    const uintptr_t segment_end = segment.runtime_address + segment_size;
    if (reinterpret_cast<uintptr_t>(mapped_header) >= segment.runtime_address &&
        reinterpret_cast<uintptr_t>(mapped_header) <= segment_end &&
        header_bytes <= segment_end - reinterpret_cast<uintptr_t>(mapped_header)) {
      header_in_executable_segment = true;
    }
    if (callback >= segment.runtime_address && callback < segment_end) {
      measurement->callback_in_executable_segment = true;
    }
    executable_builder.Append(segment.name, sizeof(segment.name));
    executable_builder.AppendUint64(segment.vm_address);
    executable_builder.AppendUint64(segment.vm_size);
    executable_builder.AppendUint64(segment.file_offset);
    executable_builder.AppendUint64(segment.file_size);
    const std::string segment_digest = Sha256Hex(mapped_bytes, segment_size);
    executable_builder.AppendString(segment_digest);
    if (measurement->executable_file_bytes >
        std::numeric_limits<uint64_t>::max() - segment.file_size) {
      SecureZero(uuid_bytes, sizeof(uuid_bytes));
      return false;
    }
    measurement->executable_file_bytes += segment.file_size;
  }
  if (!header_in_executable_segment ||
      !measurement->callback_in_executable_segment) {
    SecureZero(uuid_bytes, sizeof(uuid_bytes));
    return false;
  }

  measurement->file_sha256 = Sha256Hex(file_bytes.data(), file_bytes.size());
  measurement->path_digest = DigestBytes(
      "hacker-bob/darwin-native-loaded-image-canonical-path/v1",
      canonical_path.value, std::strlen(canonical_path.value));
  FramedDigestBuilder identity_builder(
      "hacker-bob/darwin-native-loaded-image-file-identity/v1");
  identity_builder.AppendUint64(static_cast<uint64_t>(descriptor_before.st_dev));
  identity_builder.AppendUint64(static_cast<uint64_t>(descriptor_before.st_ino));
  identity_builder.AppendUint64(static_cast<uint64_t>(descriptor_before.st_mode));
  identity_builder.AppendUint64(static_cast<uint64_t>(descriptor_before.st_uid));
  identity_builder.AppendUint64(static_cast<uint64_t>(descriptor_before.st_gid));
  identity_builder.AppendUint64(static_cast<uint64_t>(descriptor_before.st_nlink));
  identity_builder.AppendUint64(static_cast<uint64_t>(descriptor_before.st_size));
  identity_builder.AppendUint64(
      static_cast<uint64_t>(descriptor_before.st_mtimespec.tv_sec));
  identity_builder.AppendUint64(
      static_cast<uint64_t>(descriptor_before.st_mtimespec.tv_nsec));
  identity_builder.AppendUint64(
      static_cast<uint64_t>(descriptor_before.st_ctimespec.tv_sec));
  identity_builder.AppendUint64(
      static_cast<uint64_t>(descriptor_before.st_ctimespec.tv_nsec));
  measurement->file_identity_digest = identity_builder.Finish();
  measurement->uuid_digest = DigestBytes(
      "hacker-bob/darwin-native-loaded-image-lc-uuid/v1",
      uuid_bytes, sizeof(uuid_bytes));
  measurement->header_and_load_commands_digest = DigestBytes(
      "hacker-bob/darwin-native-loaded-image-header-load-commands/v1",
      mapped_header, header_bytes);
  measurement->executable_segments_digest = executable_builder.Finish();
  measurement->executable_segment_count =
      static_cast<uint32_t>(executable_segments.size());
  FramedDigestBuilder loaded_identity_builder(
      "hacker-bob/darwin-native-loaded-image-identity/v1");
  loaded_identity_builder.AppendString(measurement->file_sha256);
  loaded_identity_builder.AppendString(measurement->path_digest);
  loaded_identity_builder.AppendString(measurement->file_identity_digest);
  loaded_identity_builder.AppendString(measurement->uuid_digest);
  loaded_identity_builder.AppendString(
      measurement->header_and_load_commands_digest);
  loaded_identity_builder.AppendString(
      measurement->executable_segments_digest);
  loaded_identity_builder.AppendUint32(measurement->executable_segment_count);
  loaded_identity_builder.AppendUint64(measurement->executable_file_bytes);
  loaded_identity_builder.AppendUint32(1);
  loaded_identity_builder.AppendUint32(0);
  measurement->identity_digest = loaded_identity_builder.Finish();
  if (_dyld_image_count() != image_count ||
      _dyld_get_image_header(matching_dyld_index) !=
          reinterpret_cast<const mach_header*>(mapped_header) ||
      _dyld_get_image_vmaddr_slide(matching_dyld_index) != image_slide) {
    SecureZero(uuid_bytes, sizeof(uuid_bytes));
    return false;
  }
  const char* final_dyld_image_name =
      _dyld_get_image_name(matching_dyld_index);
  ScopedCanonicalPath final_dyld_canonical_path;
  if (final_dyld_image_name == nullptr ||
      realpath(final_dyld_image_name,
               final_dyld_canonical_path.value) == nullptr ||
      std::strcmp(canonical_path.value,
                  final_dyld_canonical_path.value) != 0) {
    SecureZero(uuid_bytes, sizeof(uuid_bytes));
    return false;
  }
  SecureZero(uuid_bytes, sizeof(uuid_bytes));
  return true;
}

bool ReadUint32(CFTypeRef value, uint32_t* output) {
  if (value == nullptr || CFGetTypeID(value) != CFNumberGetTypeID()) return false;
  int64_t number = -1;
  if (!CFNumberGetValue(static_cast<CFNumberRef>(value), kCFNumberSInt64Type, &number) ||
      number < 0 || number > std::numeric_limits<uint32_t>::max()) {
    return false;
  }
  *output = static_cast<uint32_t>(number);
  return true;
}

bool ReadUtf8String(CFTypeRef value, std::string* output) {
  if (value == nullptr || CFGetTypeID(value) != CFStringGetTypeID()) return false;
  const CFStringRef string = static_cast<CFStringRef>(value);
  const CFIndex characters = CFStringGetLength(string);
  if (characters <= 0) return false;
  const CFIndex maximum =
      CFStringGetMaximumSizeForEncoding(characters, kCFStringEncodingUTF8);
  if (maximum <= 0 || maximum > static_cast<CFIndex>(kMaxIdentityStringBytes)) return false;
  std::string bytes(static_cast<size_t>(maximum), '\0');
  CFIndex used = 0;
  const CFIndex converted = CFStringGetBytes(
      string, CFRangeMake(0, characters), kCFStringEncodingUTF8, 0, false,
      reinterpret_cast<UInt8*>(bytes.data()), maximum, &used);
  if (converted != characters || used <= 0 || used > maximum ||
      std::find(bytes.begin(), bytes.begin() + used, '\0') != bytes.begin() + used) {
    ZeroString(&bytes);
    return false;
  }
  bytes.resize(static_cast<size_t>(used));
  *output = std::move(bytes);
  return true;
}

bool ReadBoundedData(CFTypeRef value, CFIndex minimum, CFIndex maximum,
                     CFDataRef* output) {
  if (value == nullptr || CFGetTypeID(value) != CFDataGetTypeID()) return false;
  const CFDataRef data = static_cast<CFDataRef>(value);
  const CFIndex length = CFDataGetLength(data);
  if (length < minimum || length > maximum || CFDataGetBytePtr(data) == nullptr) return false;
  *output = data;
  return true;
}

struct KernelSnapshot {
  audit_token_t token{};
  uid_t euid = 0;
  gid_t egid = 0;
  uid_t ruid = 0;
  gid_t rgid = 0;
  pid_t pid = 0;
  int pidversion = 0;
  proc_bsdinfo process{};
  std::string executable_path;

  KernelSnapshot() = default;
  KernelSnapshot(const KernelSnapshot&) = delete;
  KernelSnapshot& operator=(const KernelSnapshot&) = delete;
  ~KernelSnapshot() {
    ZeroString(&executable_path);
    SecureZero(&token, sizeof(token));
    SecureZero(&process, sizeof(process));
  }
};

struct CodeIdentity {
  uint32_t cdhash_algorithm = 0;
  uint32_t certificate_count = 0;
  bool team_identifier_present = false;
  bool signer_identity_complete = false;
  std::string signature_class;
  std::string code_directory_hash;
  std::string code_directory_hashes_digest;
  std::string signing_identifier_digest;
  std::string team_identifier_digest;
  std::string certificate_chain_digest;
  std::string designated_requirement_digest;
  std::string static_flags_digest;
  std::string dynamic_status_digest;
  std::string signing_identity_digest;
  std::string mapped_code_identity_digest;

  CodeIdentity() = default;
  CodeIdentity(const CodeIdentity&) = delete;
  CodeIdentity& operator=(const CodeIdentity&) = delete;
  ~CodeIdentity() {
    ZeroString(&signature_class);
    ZeroString(&code_directory_hash);
    ZeroString(&code_directory_hashes_digest);
    ZeroString(&signing_identifier_digest);
    ZeroString(&team_identifier_digest);
    ZeroString(&certificate_chain_digest);
    ZeroString(&designated_requirement_digest);
    ZeroString(&static_flags_digest);
    ZeroString(&dynamic_status_digest);
    ZeroString(&signing_identity_digest);
    ZeroString(&mapped_code_identity_digest);
  }
};

struct ScopedPathBuffer {
  char value[PROC_PIDPATHINFO_MAXSIZE]{};
  ~ScopedPathBuffer() { SecureZero(value, sizeof(value)); }
};

bool IsUnixStreamSocket(int fd) {
  int type = 0;
  socklen_t type_length = sizeof(type);
  if (getsockopt(fd, SOL_SOCKET, SO_TYPE, &type, &type_length) != 0 ||
      type_length != sizeof(type) || type != SOCK_STREAM) {
    return false;
  }
  sockaddr_storage local{};
  sockaddr_storage peer{};
  socklen_t local_length = sizeof(local);
  socklen_t peer_length = sizeof(peer);
  if (getsockname(fd, reinterpret_cast<sockaddr*>(&local), &local_length) != 0 ||
      getpeername(fd, reinterpret_cast<sockaddr*>(&peer), &peer_length) != 0) {
    return false;
  }
  return local.ss_family == AF_UNIX && peer.ss_family == AF_UNIX;
}

bool ReadKernelSnapshot(int fd, KernelSnapshot* snapshot) {
  socklen_t token_length = sizeof(snapshot->token);
  if (getsockopt(fd, SOL_LOCAL, LOCAL_PEERTOKEN, &snapshot->token, &token_length) != 0 ||
      token_length != sizeof(snapshot->token)) {
    return false;
  }

  uid_t socket_euid = 0;
  gid_t socket_egid = 0;
  if (getpeereid(fd, &socket_euid, &socket_egid) != 0) return false;

  pid_t socket_pid = 0;
  socklen_t pid_length = sizeof(socket_pid);
  if (getsockopt(fd, SOL_LOCAL, LOCAL_PEERPID, &socket_pid, &pid_length) != 0 ||
      pid_length != sizeof(socket_pid)) {
    return false;
  }

  snapshot->euid = audit_token_to_euid(snapshot->token);
  snapshot->egid = audit_token_to_egid(snapshot->token);
  snapshot->ruid = audit_token_to_ruid(snapshot->token);
  snapshot->rgid = audit_token_to_rgid(snapshot->token);
  snapshot->pid = audit_token_to_pid(snapshot->token);
  snapshot->pidversion = audit_token_to_pidversion(snapshot->token);
  if (snapshot->pid <= 0 || snapshot->pidversion < 0 ||
      snapshot->pid != socket_pid || snapshot->euid != socket_euid ||
      snapshot->egid != socket_egid) {
    return false;
  }

  const int process_bytes = proc_pidinfo(snapshot->pid, PROC_PIDTBSDINFO, 0,
                                        &snapshot->process, sizeof(snapshot->process));
  if (process_bytes != static_cast<int>(sizeof(snapshot->process)) ||
      snapshot->process.pbi_pid != static_cast<uint32_t>(snapshot->pid) ||
      snapshot->process.pbi_uid != snapshot->euid ||
      snapshot->process.pbi_gid != snapshot->egid ||
      snapshot->process.pbi_ruid != snapshot->ruid ||
      snapshot->process.pbi_rgid != snapshot->rgid ||
      snapshot->process.pbi_start_tvsec == 0 ||
      snapshot->process.pbi_start_tvusec >= 1000000) {
    return false;
  }

  ScopedPathBuffer path;
  audit_token_t token_copy = snapshot->token;
  const int path_bytes = proc_pidpath_audittoken(
      &token_copy, path.value, static_cast<uint32_t>(sizeof(path.value)));
  SecureZero(&token_copy, sizeof(token_copy));
  if (path_bytes <= 0 || path_bytes >= static_cast<int>(sizeof(path.value))) return false;
  const size_t path_length = strnlen(path.value, sizeof(path.value));
  if (path_length == 0 || path_length >= sizeof(path.value) || path.value[0] != '/') {
    return false;
  }
  snapshot->executable_path.assign(path.value, path_length);
  return true;
}

bool ReadSelfKernelSnapshot(KernelSnapshot* snapshot) {
  mach_msg_type_number_t token_count = TASK_AUDIT_TOKEN_COUNT;
  if (task_info(mach_task_self(), TASK_AUDIT_TOKEN,
                reinterpret_cast<task_info_t>(&snapshot->token),
                &token_count) != KERN_SUCCESS ||
      token_count != TASK_AUDIT_TOKEN_COUNT) {
    return false;
  }

  snapshot->euid = audit_token_to_euid(snapshot->token);
  snapshot->egid = audit_token_to_egid(snapshot->token);
  snapshot->ruid = audit_token_to_ruid(snapshot->token);
  snapshot->rgid = audit_token_to_rgid(snapshot->token);
  snapshot->pid = audit_token_to_pid(snapshot->token);
  snapshot->pidversion = audit_token_to_pidversion(snapshot->token);
  if (snapshot->pid <= 0 || snapshot->pidversion < 0 ||
      snapshot->pid != getpid() || snapshot->euid != geteuid() ||
      snapshot->egid != getegid() || snapshot->ruid != getuid() ||
      snapshot->rgid != getgid()) {
    return false;
  }

  const int process_bytes = proc_pidinfo(snapshot->pid, PROC_PIDTBSDINFO, 0,
                                        &snapshot->process, sizeof(snapshot->process));
  if (process_bytes != static_cast<int>(sizeof(snapshot->process)) ||
      snapshot->process.pbi_pid != static_cast<uint32_t>(snapshot->pid) ||
      snapshot->process.pbi_uid != snapshot->euid ||
      snapshot->process.pbi_gid != snapshot->egid ||
      snapshot->process.pbi_ruid != snapshot->ruid ||
      snapshot->process.pbi_rgid != snapshot->rgid ||
      snapshot->process.pbi_start_tvsec == 0 ||
      snapshot->process.pbi_start_tvusec >= 1000000) {
    return false;
  }

  ScopedPathBuffer path;
  audit_token_t token_copy = snapshot->token;
  const int path_bytes = proc_pidpath_audittoken(
      &token_copy, path.value, static_cast<uint32_t>(sizeof(path.value)));
  SecureZero(&token_copy, sizeof(token_copy));
  if (path_bytes <= 0 || path_bytes >= static_cast<int>(sizeof(path.value))) return false;
  const size_t path_length = strnlen(path.value, sizeof(path.value));
  if (path_length == 0 || path_length >= sizeof(path.value) || path.value[0] != '/') {
    return false;
  }
  snapshot->executable_path.assign(path.value, path_length);
  return true;
}

bool SameKernelSnapshot(const KernelSnapshot& left, const KernelSnapshot& right) {
  return std::memcmp(&left.token, &right.token, sizeof(left.token)) == 0 &&
         left.euid == right.euid && left.egid == right.egid &&
         left.ruid == right.ruid && left.rgid == right.rgid &&
         left.pid == right.pid && left.pidversion == right.pidversion &&
         left.process.pbi_start_tvsec == right.process.pbi_start_tvsec &&
         left.process.pbi_start_tvusec == right.process.pbi_start_tvusec &&
         left.executable_path == right.executable_path;
}

bool ReadCertificateChainDigest(CFDictionaryRef information, uint32_t* count,
                                const CodeIdentityDomains& domains,
                                std::string* digest) {
  const CFTypeRef value = CFDictionaryGetValue(information, kSecCodeInfoCertificates);
  FramedDigestBuilder builder(domains.certificate_chain);
  if (value == nullptr) {
    builder.AppendUint32(0);
    *count = 0;
    *digest = builder.Finish();
    return true;
  }
  if (CFGetTypeID(value) != CFArrayGetTypeID()) return false;
  const CFArrayRef certificates = static_cast<CFArrayRef>(value);
  const CFIndex length = CFArrayGetCount(certificates);
  if (length < 0 || length > kMaxCertificates) return false;
  builder.AppendUint32(static_cast<uint32_t>(length));
  size_t total_bytes = 0;
  for (CFIndex index = 0; index < length; ++index) {
    const CFTypeRef certificate = CFArrayGetValueAtIndex(certificates, index);
    if (certificate == nullptr || CFGetTypeID(certificate) != SecCertificateGetTypeID()) {
      return false;
    }
    const SecCertificateRef certificate_ref = static_cast<SecCertificateRef>(
        const_cast<void*>(certificate));
    ScopedCF<CFDataRef> data(
        SecCertificateCopyData(certificate_ref));
    CFDataRef checked = nullptr;
    if (!ReadBoundedData(data.get(), 1, kMaxCertificateBytes, &checked)) return false;
    const size_t certificate_bytes = static_cast<size_t>(CFDataGetLength(checked));
    if (certificate_bytes > kMaxCertificateChainBytes - total_bytes) return false;
    total_bytes += certificate_bytes;
    builder.Append(CFDataGetBytePtr(checked), certificate_bytes);
  }
  *count = static_cast<uint32_t>(length);
  *digest = builder.Finish();
  return true;
}

bool ReadCodeDirectoryHashes(CFDictionaryRef information, uint32_t selected_algorithm,
                             CFDataRef selected_hash,
                             const CodeIdentityDomains& domains,
                             std::string* all_hashes_digest) {
  const CFTypeRef hash_value =
      CFDictionaryGetValue(information, kSecCodeInfoCdHashes);
  const CFTypeRef algorithm_value =
      CFDictionaryGetValue(information, kSecCodeInfoDigestAlgorithms);
  if (hash_value == nullptr || algorithm_value == nullptr ||
      CFGetTypeID(hash_value) != CFArrayGetTypeID() ||
      CFGetTypeID(algorithm_value) != CFArrayGetTypeID()) {
    return false;
  }
  const CFArrayRef hashes = static_cast<CFArrayRef>(hash_value);
  const CFArrayRef algorithms = static_cast<CFArrayRef>(algorithm_value);
  const CFIndex count = CFArrayGetCount(hashes);
  if (count <= 0 || count > kMaxCodeDirectoryHashes ||
      CFArrayGetCount(algorithms) != count) {
    return false;
  }
  FramedDigestBuilder builder(domains.code_directory_hashes);
  builder.AppendUint32(static_cast<uint32_t>(count));
  size_t selected_matches = 0;
  for (CFIndex index = 0; index < count; ++index) {
    uint32_t algorithm = 0;
    CFDataRef hash = nullptr;
    if (!ReadUint32(CFArrayGetValueAtIndex(algorithms, index), &algorithm) ||
        !ReadBoundedData(CFArrayGetValueAtIndex(hashes, index), 16, 64, &hash)) {
      return false;
    }
    builder.AppendUint32(algorithm);
    builder.Append(CFDataGetBytePtr(hash), static_cast<size_t>(CFDataGetLength(hash)));
    if (algorithm == selected_algorithm &&
        CFDataGetLength(hash) == CFDataGetLength(selected_hash) &&
        std::memcmp(CFDataGetBytePtr(hash), CFDataGetBytePtr(selected_hash),
                    static_cast<size_t>(CFDataGetLength(hash))) == 0) {
      ++selected_matches;
    }
  }
  if (selected_matches != 1) return false;
  *all_hashes_digest = builder.Finish();
  return true;
}

bool ReadCodeIdentityInformation(CFDictionaryRef information,
                                 const audit_token_t& token,
                                 const CodeIdentityDomains& domains,
                                 CodeIdentity* identity) {
  if (information == nullptr || CFGetTypeID(information) != CFDictionaryGetTypeID()) {
    return false;
  }

  CFDataRef selected_hash = nullptr;
  if (!ReadBoundedData(CFDictionaryGetValue(information, kSecCodeInfoUnique),
                       16, 64, &selected_hash) ||
      !ReadUint32(CFDictionaryGetValue(information, kSecCodeInfoDigestAlgorithm),
                  &identity->cdhash_algorithm)) {
    return false;
  }
  identity->code_directory_hash =
      HexBytes(CFDataGetBytePtr(selected_hash),
               static_cast<size_t>(CFDataGetLength(selected_hash)));
  if (!ReadCodeDirectoryHashes(information, identity->cdhash_algorithm,
                               selected_hash, domains,
                               &identity->code_directory_hashes_digest)) {
    return false;
  }

  std::string signing_identifier;
  if (!ReadUtf8String(CFDictionaryGetValue(information, kSecCodeInfoIdentifier),
                      &signing_identifier)) {
    return false;
  }
  identity->signing_identifier_digest = DigestBytes(
      domains.signing_identifier,
      signing_identifier.data(), signing_identifier.size());

  std::string team_identifier;
  const CFTypeRef team_value =
      CFDictionaryGetValue(information, kSecCodeInfoTeamIdentifier);
  if (team_value != nullptr) {
    if (!ReadUtf8String(team_value, &team_identifier)) {
      ZeroString(&signing_identifier);
      return false;
    }
    identity->team_identifier_present = true;
  }
  FramedDigestBuilder team_builder(domains.team_identifier);
  team_builder.AppendCString(identity->team_identifier_present ? "present" : "absent");
  if (identity->team_identifier_present) team_builder.AppendString(team_identifier);
  identity->team_identifier_digest = team_builder.Finish();

  uint32_t static_flags = 0;
  uint32_t dynamic_status = 0;
  if (!ReadUint32(CFDictionaryGetValue(information, kSecCodeInfoFlags),
                  &static_flags) ||
      !ReadUint32(CFDictionaryGetValue(information, kSecCodeInfoStatus),
                  &dynamic_status) ||
      (dynamic_status & kSecCodeStatusValid) == 0) {
    ZeroString(&signing_identifier);
    ZeroString(&team_identifier);
    return false;
  }
  identity->static_flags_digest = DigestUint32(
      domains.static_flags, static_flags);
  identity->dynamic_status_digest = DigestUint32(
      domains.dynamic_status, dynamic_status);

  if (!ReadCertificateChainDigest(information, &identity->certificate_count,
                                  domains,
                                  &identity->certificate_chain_digest)) {
    ZeroString(&signing_identifier);
    ZeroString(&team_identifier);
    return false;
  }

  const CFTypeRef requirement_value =
      CFDictionaryGetValue(information, kSecCodeInfoDesignatedRequirement);
  if (requirement_value == nullptr ||
      CFGetTypeID(requirement_value) != SecRequirementGetTypeID()) {
    ZeroString(&signing_identifier);
    ZeroString(&team_identifier);
    return false;
  }
  ScopedCF<CFDataRef> requirement_data;
  const SecRequirementRef requirement_ref = static_cast<SecRequirementRef>(
      const_cast<void*>(requirement_value));
  if (SecRequirementCopyData(requirement_ref,
                             kSecCSDefaultFlags,
                             requirement_data.out()) != errSecSuccess) {
    ZeroString(&signing_identifier);
    ZeroString(&team_identifier);
    return false;
  }
  CFDataRef checked_requirement = nullptr;
  if (!ReadBoundedData(requirement_data.get(), 1, kMaxRequirementBytes,
                       &checked_requirement)) {
    ZeroString(&signing_identifier);
    ZeroString(&team_identifier);
    return false;
  }
  identity->designated_requirement_digest = DigestBytes(
      domains.designated_requirement,
      CFDataGetBytePtr(checked_requirement),
      static_cast<size_t>(CFDataGetLength(checked_requirement)));

  const bool ad_hoc = (static_flags & kSecCodeSignatureAdhoc) != 0;
  if (ad_hoc && (identity->team_identifier_present || identity->certificate_count != 0)) {
    ZeroString(&signing_identifier);
    ZeroString(&team_identifier);
    return false;
  }
  if (ad_hoc) {
    identity->signature_class = "adhoc";
  } else if (identity->certificate_count > 0) {
    identity->signature_class = "certificate_signed";
  } else {
    identity->signature_class = "non_adhoc_certificate_absent";
  }
  identity->signer_identity_complete =
      identity->signature_class == "certificate_signed" &&
      identity->team_identifier_present;

  FramedDigestBuilder signing_builder(domains.signing_identity);
  signing_builder.AppendString(identity->signature_class);
  signing_builder.AppendString(identity->code_directory_hash);
  signing_builder.AppendUint32(identity->cdhash_algorithm);
  signing_builder.AppendString(identity->code_directory_hashes_digest);
  signing_builder.AppendString(identity->signing_identifier_digest);
  signing_builder.AppendString(identity->team_identifier_digest);
  signing_builder.AppendString(identity->certificate_chain_digest);
  signing_builder.AppendString(identity->designated_requirement_digest);
  signing_builder.AppendString(identity->static_flags_digest);
  identity->signing_identity_digest = signing_builder.Finish();

  FramedDigestBuilder mapped_builder(domains.mapped_code_identity);
  mapped_builder.Append(&token, sizeof(token));
  mapped_builder.AppendString(identity->signing_identity_digest);
  mapped_builder.AppendString(identity->dynamic_status_digest);
  identity->mapped_code_identity_digest = mapped_builder.Finish();

  ZeroString(&signing_identifier);
  ZeroString(&team_identifier);
  return true;
}

bool SameCodeIdentity(const CodeIdentity& left, const CodeIdentity& right) {
  return left.cdhash_algorithm == right.cdhash_algorithm &&
         left.certificate_count == right.certificate_count &&
         left.team_identifier_present == right.team_identifier_present &&
         left.signer_identity_complete == right.signer_identity_complete &&
         left.signature_class == right.signature_class &&
         left.code_directory_hash == right.code_directory_hash &&
         left.code_directory_hashes_digest == right.code_directory_hashes_digest &&
         left.signing_identifier_digest == right.signing_identifier_digest &&
         left.team_identifier_digest == right.team_identifier_digest &&
         left.certificate_chain_digest == right.certificate_chain_digest &&
         left.designated_requirement_digest == right.designated_requirement_digest &&
         left.static_flags_digest == right.static_flags_digest &&
         left.dynamic_status_digest == right.dynamic_status_digest &&
         left.signing_identity_digest == right.signing_identity_digest &&
         left.mapped_code_identity_digest == right.mapped_code_identity_digest;
}

bool ReadStableCodeIdentity(SecCodeRef code, const audit_token_t& token,
                            const CodeIdentityDomains& domains,
                            CodeIdentity* identity) {
  if (code == nullptr ||
      SecCodeCheckValidity(code, kSecCSDefaultFlags, nullptr) != errSecSuccess) {
    return false;
  }

  constexpr SecCSFlags kInformationFlags =
      kSecCSDynamicInformation | kSecCSSigningInformation |
      kSecCSRequirementInformation;
  ScopedCF<CFDictionaryRef> first_information;
  if (SecCodeCopySigningInformation(code, kInformationFlags,
                                    first_information.out()) != errSecSuccess ||
      !ReadCodeIdentityInformation(first_information.get(), token, domains, identity) ||
      SecCodeCheckValidity(code, kSecCSDefaultFlags, nullptr) != errSecSuccess) {
    return false;
  }

  CodeIdentity second;
  ScopedCF<CFDictionaryRef> second_information;
  if (SecCodeCopySigningInformation(code, kInformationFlags,
                                    second_information.out()) != errSecSuccess ||
      !ReadCodeIdentityInformation(second_information.get(), token, domains, &second) ||
      SecCodeCheckValidity(code, kSecCSDefaultFlags, nullptr) != errSecSuccess ||
      !SameCodeIdentity(*identity, second)) {
    return false;
  }
  return true;
}

bool ReadStableAuditTokenGuestIdentity(const audit_token_t& token,
                                       const CodeIdentityDomains& domains,
                                       CodeIdentity* identity) {
  ScopedAuditTokenCopy token_copy(token);
  ScopedCF<CFDataRef> token_data(CFDataCreateWithBytesNoCopy(
      kCFAllocatorDefault, token_copy.bytes(), token_copy.size(), kCFAllocatorNull));
  if (token_data.get() == nullptr) return false;

  const void* keys[] = {kSecGuestAttributeAudit};
  const void* values[] = {token_data.get()};
  ScopedCF<CFDictionaryRef> attributes(CFDictionaryCreate(
      kCFAllocatorDefault, keys, values, 1, &kCFTypeDictionaryKeyCallBacks,
      &kCFTypeDictionaryValueCallBacks));
  if (attributes.get() == nullptr) return false;

  ScopedCF<SecCodeRef> code;
  return SecCodeCopyGuestWithAttributes(nullptr, attributes.get(),
                                        kSecCSDefaultFlags,
                                        code.out()) == errSecSuccess &&
         code.get() != nullptr &&
         ReadStableCodeIdentity(code.get(), token, domains, identity);
}

bool ReadStableMappedCodeIdentity(const audit_token_t& token,
                                  CodeIdentity* identity) {
  return ReadStableAuditTokenGuestIdentity(
      token, kPeerCodeIdentityDomains, identity);
}

bool ReadStableSelfCodeIdentity(const audit_token_t& token,
                                CodeIdentity* identity) {
  ScopedCF<SecCodeRef> copied_self;
  if (!ReadStableAuditTokenGuestIdentity(token, kSelfCodeIdentityDomains,
                                         identity) ||
      SecCodeCopySelf(kSecCSDefaultFlags, copied_self.out()) != errSecSuccess ||
      copied_self.get() == nullptr) {
    return false;
  }
  CodeIdentity self_identity;
  return ReadStableCodeIdentity(copied_self.get(), token,
                                kSelfCodeIdentityDomains, &self_identity) &&
         SameCodeIdentity(*identity, self_identity);
}

napi_value InspectLoadedImage(napi_env env, napi_callback_info info) {
  size_t argc = 1;
  napi_value argv[1];
  if (napi_get_cb_info(env, info, &argc, argv, nullptr, nullptr) != napi_ok ||
      argc != 0) {
    ThrowLoadedImageCode(env);
    return nullptr;
  }
  const void* callback_address = reinterpret_cast<const void*>(
      reinterpret_cast<uintptr_t>(&InspectLoadedImage));
  LoadedImageMeasurement measurement;
  if (!MeasureLoadedImage(callback_address, &measurement)) {
    ThrowLoadedImageCode(env);
    return nullptr;
  }
  const std::string executable_file_bytes =
      std::to_string(measurement.executable_file_bytes);
  napi_value result;
  if (napi_create_object(env, &result) != napi_ok ||
      !SetUint32(env, result, "version", kLoadedImageSnapshotVersion) ||
      !SetCString(env, result, "primitive", kLoadedImageSnapshotPrimitive) ||
      !SetString(env, result, "image_file_sha256", measurement.file_sha256) ||
      !SetString(env, result, "image_identity_digest",
                 measurement.identity_digest) ||
      !SetString(env, result, "image_canonical_path_digest",
                 measurement.path_digest) ||
      !SetString(env, result, "image_file_identity_digest",
                 measurement.file_identity_digest) ||
      !SetString(env, result, "image_lc_uuid_digest",
                 measurement.uuid_digest) ||
      !SetString(env, result, "image_header_and_load_commands_digest",
                 measurement.header_and_load_commands_digest) ||
      !SetString(env, result, "image_executable_segments_digest",
                 measurement.executable_segments_digest) ||
      !SetUint32(env, result, "image_executable_segment_count",
                 measurement.executable_segment_count) ||
      !SetString(env, result, "image_executable_file_bytes",
                 executable_file_bytes) ||
      !SetBool(env, result, "dyld_header_unique", true) ||
      !SetBool(env, result, "dladdr_base_matches_dyld", true) ||
      !SetBool(env, result, "dyld_snapshot_stable", true) ||
      !SetBool(env, result, "dyld_canonical_path_matches_dladdr", true) ||
      !SetBool(env, result, "callback_in_executable_segment",
               measurement.callback_in_executable_segment) ||
      !SetBool(env, result, "header_and_load_commands_match_file", true) ||
      !SetBool(env, result, "executable_segments_match_file", true) ||
      !SetBool(env, result, "executable_pages_read_execute_only", true) ||
      !SetBool(env, result, "executable_segment_file_size_equals_vm_size",
               true) ||
      !SetBool(env, result, "non_executable_runtime_state_measured", false) ||
      !SetBool(env, result, "executable_image_identity_complete", true) ||
      !SetBool(env, result, "full_runtime_state_identity_complete", false)) {
    ThrowLoadedImageCode(env);
    return nullptr;
  }
  return result;
}

bool SetUint64Decimal(napi_env env, napi_value object, const char* name,
                      uint64_t value) {
  return SetString(env, object, name, std::to_string(value));
}

bool CreateAcceptorSnapshot(napi_env env,
                            const std::shared_ptr<UnixAcceptorState>& state,
                            napi_value* output) {
  napi_value snapshot;
  if (napi_create_object(env, &snapshot) != napi_ok ||
      !SetUint32(env, snapshot, "version", 1) ||
      !SetCString(env, snapshot, "primitive",
                  "darwin_native_unix_acceptor_opaque_channel_v1") ||
      !SetString(env, snapshot, "socket_root_identity_digest",
                 state->root_identity_digest()) ||
      !SetString(env, snapshot, "socket_identity_digest",
                 state->socket_identity_digest()) ||
      !SetString(env, snapshot, "listener_identity_digest",
                 state->listener_identity_digest()) ||
      !SetString(env, snapshot, "acceptor_instance_digest",
                 state->acceptor_instance_digest()) ||
      !SetBool(env, snapshot, "native_listener_created", true) ||
      !SetBool(env, snapshot, "javascript_descriptor_handoff_used", false) ||
      napi_object_freeze(env, snapshot) != napi_ok) {
    return false;
  }
  *output = snapshot;
  return true;
}

napi_value CreateUnixAcceptor(napi_env env, napi_callback_info info) {
  size_t argc = 2;
  napi_value argv[2];
  if (napi_get_cb_info(env, info, &argc, argv, nullptr, nullptr) != napi_ok ||
      argc != 1) {
    ThrowAcceptorCode(env);
    return nullptr;
  }
  std::string socket_path;
  if (!ReadBoundedNapiString(
          env, argv[0],
          sizeof(sockaddr_un) - offsetof(sockaddr_un, sun_path) - 1,
                             &socket_path) || socket_path[0] != '/') {
    ThrowAcceptorCode(env);
    return nullptr;
  }
  const size_t separator = socket_path.find_last_of('/');
  if (separator == std::string::npos || separator == 0 ||
      separator + 1 >= socket_path.size()) {
    ZeroString(&socket_path);
    ThrowAcceptorCode(env);
    return nullptr;
  }
  const std::string root_path = socket_path.substr(0, separator);
  const std::string socket_name = socket_path.substr(separator + 1);
  if (socket_name == "." || socket_name == ".." ||
      socket_name.find('/') != std::string::npos) {
    ZeroString(&socket_path);
    ThrowAcceptorCode(env);
    return nullptr;
  }
  ScopedCanonicalPath canonical_root;
  struct stat root_stat{};
  struct stat root_descriptor_stat{};
  struct stat existing{};
  if (realpath(root_path.c_str(), canonical_root.value) == nullptr ||
      root_path != canonical_root.value ||
      lstat(canonical_root.value, &root_stat) != 0 ||
      !S_ISDIR(root_stat.st_mode) || S_ISLNK(root_stat.st_mode) ||
      root_stat.st_uid != geteuid() || root_stat.st_nlink == 0 ||
      (root_stat.st_mode & (S_IWGRP | S_IWOTH)) != 0 ||
      (lstat(socket_path.c_str(), &existing) == 0 || errno != ENOENT)) {
    ZeroString(&socket_path);
    ThrowAcceptorCode(env);
    return nullptr;
  }
  const int root_fd = open(canonical_root.value,
                           O_RDONLY | O_DIRECTORY | O_NOFOLLOW);
  if (root_fd < 0 || fcntl(root_fd, F_SETFD, FD_CLOEXEC) != 0 ||
      fstat(root_fd, &root_descriptor_stat) != 0 ||
      !SameFileStat(root_stat, root_descriptor_stat)) {
    if (root_fd >= 0) close(root_fd);
    ZeroString(&socket_path);
    ThrowAcceptorCode(env);
    return nullptr;
  }
  ScopedFd root_descriptor(root_fd);

  const int listener_fd = socket(AF_UNIX, SOCK_STREAM, 0);
  if (listener_fd < 0 ||
      fcntl(listener_fd, F_SETFD, FD_CLOEXEC) != 0) {
    if (listener_fd >= 0) close(listener_fd);
    ZeroString(&socket_path);
    ThrowAcceptorCode(env);
    return nullptr;
  }
  ScopedFd listener(listener_fd);
  sockaddr_un address{};
  address.sun_family = AF_UNIX;
  std::memcpy(address.sun_path, socket_path.data(), socket_path.size());
  address.sun_path[socket_path.size()] = '\0';
  const socklen_t address_length = static_cast<socklen_t>(
      offsetof(sockaddr_un, sun_path) + socket_path.size() + 1);
  bool bound = false;
  struct stat socket_stat{};
  struct stat socket_path_stat{};
  struct stat root_after{};
  if (bind(listener.get(), reinterpret_cast<sockaddr*>(&address),
           address_length) != 0) {
    ZeroString(&socket_path);
    ThrowAcceptorCode(env);
    return nullptr;
  }
  bound = true;
  if (chmod(socket_path.c_str(), 0600) != 0 ||
      listen(listener.get(), 32) != 0 ||
      fstat(root_descriptor.get(), &root_after) != 0 ||
      !SameStableDirectoryIdentity(root_stat, root_after) ||
      fstatat(root_descriptor.get(), socket_name.c_str(), &socket_stat,
              AT_SYMLINK_NOFOLLOW) != 0 ||
      lstat(socket_path.c_str(), &socket_path_stat) != 0 ||
      !SameFileStat(socket_stat, socket_path_stat) ||
      !S_ISSOCK(socket_stat.st_mode) || socket_stat.st_uid != geteuid() ||
      (socket_stat.st_mode & 0777) != 0600) {
    if (bound) unlink(socket_path.c_str());
    ZeroString(&socket_path);
    ThrowAcceptorCode(env);
    return nullptr;
  }

  const std::string root_digest = DigestSocketFileIdentity(
      "hacker-bob/darwin-native-socket-root/v1", root_path, root_stat);
  const std::string socket_digest = DigestSocketFileIdentity(
      "hacker-bob/darwin-native-listener-socket/v1", socket_path,
      socket_stat);
  FramedDigestBuilder listener_builder(
      "hacker-bob/darwin-native-unix-listener/v1");
  listener_builder.AppendString(root_digest);
  listener_builder.AppendString(socket_digest);
  listener_builder.Append(&address, address_length);
  const std::string listener_digest = listener_builder.Finish();
  unsigned char instance_secret[32]{};
  if (SecRandomCopyBytes(kSecRandomDefault, sizeof(instance_secret),
                         instance_secret) != errSecSuccess) {
    unlink(socket_path.c_str());
    ZeroString(&socket_path);
    ThrowAcceptorCode(env);
    return nullptr;
  }
  FramedDigestBuilder instance_builder(
      "hacker-bob/darwin-native-unix-acceptor-instance/v1");
  instance_builder.Append(instance_secret, sizeof(instance_secret));
  instance_builder.AppendString(listener_digest);
  const std::string instance_digest = instance_builder.Finish();
  SecureZero(instance_secret, sizeof(instance_secret));

  std::shared_ptr<UnixAcceptorState> state;
  try {
    state = std::make_shared<UnixAcceptorState>(
        listener.get(), socket_path, root_stat, socket_stat, root_digest,
        socket_digest, listener_digest, instance_digest);
  } catch (...) {
    unlink(socket_path.c_str());
    ZeroString(&socket_path);
    ThrowAcceptorCode(env);
    return nullptr;
  }
  listener.Release();
  ZeroString(&socket_path);

  napi_value token;
  napi_value snapshot;
  napi_value result;
  if (napi_create_object(env, &token) != napi_ok ||
      !WrapSharedState(env, token, &kUnixAcceptorTypeTag, state) ||
      napi_object_freeze(env, token) != napi_ok ||
      !CreateAcceptorSnapshot(env, state, &snapshot) ||
      napi_create_object(env, &result) != napi_ok ||
      !DefineDataProperty(env, result, "acceptor_token", token,
                          napi_enumerable) ||
      !DefineDataProperty(env, result, "snapshot", snapshot,
                          napi_enumerable) ||
      napi_object_freeze(env, result) != napi_ok) {
    state->Close();
    ThrowAcceptorCode(env);
    return nullptr;
  }
  return result;
}

struct AcceptWork {
  napi_env env = nullptr;
  napi_deferred deferred = nullptr;
  napi_async_work work = nullptr;
  napi_ref token_reference = nullptr;
  std::shared_ptr<UnixAcceptorState> acceptor;
  int listener_fd = -1;
  uint64_t generation = 0;
  int registration_fd = -1;
  std::shared_ptr<AcceptedConnectionState> connection;
  bool success = false;
};

void ExecuteAccept(napi_env, void* data) {
  AcceptWork* work = static_cast<AcceptWork*>(data);
  int accepted = -1;
  while (!work->acceptor->closed()) {
    pollfd descriptor{work->listener_fd, POLLIN, 0};
    const int ready = poll(&descriptor, 1, 50);
    if (ready < 0 && errno == EINTR) continue;
    if (ready < 0) break;
    if (ready == 0) continue;
    if ((descriptor.revents & (POLLERR | POLLHUP | POLLNVAL)) != 0) break;
    if ((descriptor.revents & POLLIN) == 0) continue;
    if (work->acceptor->closed()) break;
    do {
      accepted = accept(work->listener_fd, nullptr, nullptr);
    } while (accepted < 0 && errno == EINTR);
    break;
  }
  const bool accepted_before_close =
      work->acceptor->EndAccept(work->listener_fd);
  work->listener_fd = -1;
  if (accepted < 0) return;
  ScopedFd channel(accepted);
  if (!accepted_before_close) return;
  if (fcntl(channel.get(), F_SETFD, FD_CLOEXEC) != 0 ||
      !IsUnixStreamSocket(channel.get())) {
    return;
  }
  int no_sigpipe = 1;
  if (setsockopt(channel.get(), SOL_SOCKET, SO_NOSIGPIPE, &no_sigpipe,
                 sizeof(no_sigpipe)) != 0) {
    return;
  }
  const int registration_fd = fcntl(channel.get(), F_DUPFD_CLOEXEC, 0);
  if (registration_fd < 0) return;
  ScopedFd registration(registration_fd);
  std::string registration_digest;
  audit_token_t peer_token{};
  if (!MintRegistrationTokenDigest(registration.get(), &registration_digest,
                                   &peer_token)) {
    return;
  }
  FramedDigestBuilder connection_builder(
      "hacker-bob/darwin-native-accepted-connection/v1");
  connection_builder.AppendString(work->acceptor->acceptor_instance_digest());
  connection_builder.AppendString(work->acceptor->listener_identity_digest());
  connection_builder.AppendUint64(work->generation);
  connection_builder.AppendString(registration_digest);
  connection_builder.Append(&peer_token, sizeof(peer_token));
  const std::string connection_digest = connection_builder.Finish();
  SecureZero(&peer_token, sizeof(peer_token));
  try {
    work->connection = std::make_shared<AcceptedConnectionState>(
        channel.get(), work->generation, registration_digest,
        connection_digest, work->acceptor->root_identity_digest(),
        work->acceptor->socket_identity_digest(),
        work->acceptor->listener_identity_digest(),
        work->acceptor->acceptor_instance_digest());
  } catch (...) {
    return;
  }
  channel.Release();
  work->registration_fd = registration.Release();
  work->success = true;
}

void RejectAcceptorDeferred(napi_env env, napi_deferred deferred) {
  napi_value error;
  if (!CreateCodeError(env, kAcceptorFailureCode,
                       "Darwin native acceptor operation failed", &error)) {
    napi_get_undefined(env, &error);
  }
  napi_reject_deferred(env, deferred, error);
}

void CleanupAcceptWork(AcceptWork* work) {
  if (work->listener_fd >= 0) {
    work->acceptor->EndAccept(work->listener_fd);
    work->listener_fd = -1;
  }
  if (work->registration_fd >= 0) close(work->registration_fd);
  if (work->token_reference != nullptr) {
    napi_delete_reference(work->env, work->token_reference);
  }
  if (work->work != nullptr) {
    work->acceptor->UnregisterAcceptWork(work->work);
    napi_delete_async_work(work->env, work->work);
  }
  delete work;
}

void CompleteAccept(napi_env env, napi_status status, void* data) {
  AcceptWork* work = static_cast<AcceptWork*>(data);
  if (status != napi_ok || !work->success || work->connection == nullptr ||
      work->registration_fd < 0) {
    if (work->connection != nullptr) work->connection->Reject();
    RejectAcceptorDeferred(env, work->deferred);
    CleanupAcceptWork(work);
    return;
  }
  napi_value registration_token;
  napi_value connection_token;
  napi_value snapshot;
  napi_value result;
  const std::string generation = std::to_string(work->connection->generation());
  if (!CreateRegistrationTokenObject(
          env, work->registration_fd,
          work->connection->registration_token_digest(), work->connection,
          &registration_token)) {
    work->registration_fd = -1;
    work->connection->Reject();
    RejectAcceptorDeferred(env, work->deferred);
    CleanupAcceptWork(work);
    return;
  }
  work->registration_fd = -1;
  if (napi_create_object(env, &connection_token) != napi_ok ||
      !WrapSharedState(env, connection_token, &kAcceptedUnixConnectionTypeTag,
                       work->connection) ||
      napi_object_freeze(env, connection_token) != napi_ok ||
      napi_create_object(env, &snapshot) != napi_ok ||
      !SetUint32(env, snapshot, "version", 1) ||
      !SetCString(env, snapshot, "primitive",
                  "darwin_native_accepted_unix_connection_v1") ||
      !SetString(env, snapshot, "connection_identity_digest",
                 work->connection->connection_identity_digest()) ||
      !SetString(env, snapshot, "descriptor_registration_token_digest",
                 work->connection->registration_token_digest()) ||
      !SetString(env, snapshot, "socket_root_identity_digest",
                 work->connection->root_identity_digest()) ||
      !SetString(env, snapshot, "socket_identity_digest",
                 work->connection->socket_identity_digest()) ||
      !SetString(env, snapshot, "listener_identity_digest",
                 work->connection->listener_identity_digest()) ||
      !SetString(env, snapshot, "acceptor_instance_digest",
                 work->connection->acceptor_instance_digest()) ||
      !SetString(env, snapshot, "connection_generation", generation) ||
      !SetBool(env, snapshot, "accepted_and_registered_before_javascript",
               true) ||
      !SetBool(env, snapshot, "javascript_descriptor_handoff_used", false) ||
      napi_object_freeze(env, snapshot) != napi_ok ||
      napi_create_object(env, &result) != napi_ok ||
      !DefineDataProperty(env, result, "connection_token", connection_token,
                          napi_enumerable) ||
      !DefineDataProperty(env, result, "registration_token",
                          registration_token, napi_enumerable) ||
      !DefineDataProperty(env, result, "snapshot", snapshot,
                          napi_enumerable) ||
      napi_object_freeze(env, result) != napi_ok) {
    work->connection->Reject();
    RejectAcceptorDeferred(env, work->deferred);
    CleanupAcceptWork(work);
    return;
  }
  napi_resolve_deferred(env, work->deferred, result);
  CleanupAcceptWork(work);
}

napi_value AcceptUnixConnection(napi_env env, napi_callback_info info) {
  size_t argc = 2;
  napi_value argv[2];
  if (napi_get_cb_info(env, info, &argc, argv, nullptr, nullptr) != napi_ok ||
      argc != 1) {
    ThrowAcceptorCode(env);
    return nullptr;
  }
  std::shared_ptr<UnixAcceptorState> acceptor;
  if (!UnwrapSharedState(env, argv[0], &kUnixAcceptorTypeTag, &acceptor)) {
    ThrowAcceptorCode(env);
    return nullptr;
  }
  AcceptWork* work = new (std::nothrow) AcceptWork();
  if (work == nullptr) {
    ThrowAcceptorCode(env);
    return nullptr;
  }
  work->env = env;
  work->acceptor = acceptor;
  if (!acceptor->BeginAccept(&work->listener_fd, &work->generation)) {
    delete work;
    ThrowAcceptorCode(env);
    return nullptr;
  }
  napi_value promise;
  napi_value resource_name;
  if (napi_create_promise(env, &work->deferred, &promise) != napi_ok ||
      napi_create_reference(env, argv[0], 1, &work->token_reference) != napi_ok ||
      napi_create_string_utf8(env, "darwinNativeAccept", NAPI_AUTO_LENGTH,
                              &resource_name) != napi_ok ||
      napi_create_async_work(env, nullptr, resource_name, ExecuteAccept,
                             CompleteAccept, work, &work->work) != napi_ok ||
      !acceptor->RegisterAcceptWork(env, work->work) ||
      napi_queue_async_work(env, work->work) != napi_ok) {
    acceptor->Close();
    CleanupAcceptWork(work);
    ThrowAcceptorCode(env);
    return nullptr;
  }
  return promise;
}

using SteadyDeadline = std::chrono::steady_clock::time_point;

bool WaitForDescriptor(int fd, short events, const SteadyDeadline& deadline) {
  while (true) {
    const auto now = std::chrono::steady_clock::now();
    if (now >= deadline) return false;
    const auto remaining = std::chrono::duration_cast<std::chrono::milliseconds>(
        deadline - now);
    int timeout = static_cast<int>(remaining.count());
    if (timeout < 1) timeout = 1;
    pollfd descriptor{fd, events, 0};
    const int result = poll(&descriptor, 1, timeout);
    if (result < 0 && errno == EINTR) continue;
    if (result <= 0 || (descriptor.revents & (POLLERR | POLLNVAL)) != 0) {
      return false;
    }
    if ((descriptor.revents & events) != 0) return true;
    if ((descriptor.revents & POLLHUP) != 0) return false;
  }
}

bool ReadExactWithDeadline(int fd, unsigned char* output, size_t length,
                           const SteadyDeadline& deadline) {
  size_t offset = 0;
  while (offset < length) {
    if (!WaitForDescriptor(fd, POLLIN, deadline)) return false;
    const ssize_t count = read(fd, output + offset, length - offset);
    if (count < 0 && errno == EINTR) continue;
    if (count <= 0) return false;
    offset += static_cast<size_t>(count);
  }
  return true;
}

bool WriteExactWithDeadline(int fd, const unsigned char* input, size_t length,
                            const SteadyDeadline& deadline) {
  size_t offset = 0;
  while (offset < length) {
    if (!WaitForDescriptor(fd, POLLOUT, deadline)) return false;
    const ssize_t count = write(fd, input + offset, length - offset);
    if (count < 0 && errno == EINTR) continue;
    if (count <= 0) return false;
    offset += static_cast<size_t>(count);
  }
  return true;
}

bool DescriptorHasInputOrHalfClose(int fd) {
  pollfd descriptor{fd, static_cast<short>(POLLIN | POLLHUP), 0};
  const int result = poll(&descriptor, 1, 0);
  if (result < 0) return true;
  if (result == 0) return false;
  if ((descriptor.revents & (POLLERR | POLLNVAL | POLLHUP | POLLIN)) != 0) {
    return true;
  }
  return false;
}

enum class IoOperation { kReadRequest, kWriteChallenge, kWriteResponse };

struct IoWork {
  napi_env env = nullptr;
  napi_deferred deferred = nullptr;
  napi_async_work work = nullptr;
  napi_ref token_reference = nullptr;
  std::shared_ptr<AcceptedConnectionState> connection;
  IoOperation operation = IoOperation::kReadRequest;
  int operation_fd = -1;
  SteadyDeadline deadline{};
  uv_timer_t* deadline_timer = nullptr;
  std::atomic<bool> timed_out{false};
  std::vector<unsigned char> bytes;
  std::string frame_digest;
  bool success = false;
};

void ExecuteIo(napi_env, void* data) {
  IoWork* work = static_cast<IoWork*>(data);
  if (work->timed_out.load(std::memory_order_acquire) ||
      std::chrono::steady_clock::now() >= work->deadline) {
    return;
  }
  if (work->operation == IoOperation::kReadRequest) {
    unsigned char header[4]{};
    if (!ReadExactWithDeadline(work->operation_fd, header, sizeof(header),
                               work->deadline)) {
      return;
    }
    const uint32_t body_length =
        (static_cast<uint32_t>(header[0]) << 24) |
        (static_cast<uint32_t>(header[1]) << 16) |
        (static_cast<uint32_t>(header[2]) << 8) |
        static_cast<uint32_t>(header[3]);
    if (body_length == 0 || body_length > kMaxNativeIpcFrameBytes) return;
    try {
      work->bytes.resize(body_length);
    } catch (...) {
      return;
    }
    if (!ReadExactWithDeadline(work->operation_fd, work->bytes.data(),
                               work->bytes.size(), work->deadline) ||
        DescriptorHasInputOrHalfClose(work->operation_fd)) {
      return;
    }
    work->frame_digest = Sha256Hex(work->bytes.data(), work->bytes.size());
    work->success = true;
    return;
  }
  if (work->operation == IoOperation::kWriteChallenge &&
      DescriptorHasInputOrHalfClose(work->operation_fd)) {
    return;
  }
  if (work->operation == IoOperation::kWriteResponse &&
      DescriptorHasInputOrHalfClose(work->operation_fd)) {
    return;
  }
  work->success = WriteExactWithDeadline(
      work->operation_fd, work->bytes.data(), work->bytes.size(),
      work->deadline);
}

void CloseIoDeadlineTimer(IoWork* work) {
  uv_timer_t* timer = work->deadline_timer;
  if (timer == nullptr) return;
  work->deadline_timer = nullptr;
  timer->data = nullptr;
  uv_timer_stop(timer);
  if (!uv_is_closing(reinterpret_cast<uv_handle_t*>(timer))) {
    uv_close(reinterpret_cast<uv_handle_t*>(timer), [](uv_handle_t* handle) {
      delete reinterpret_cast<uv_timer_t*>(handle);
    });
  }
}

void OnIoDeadline(uv_timer_t* timer) {
  IoWork* work = static_cast<IoWork*>(timer->data);
  if (work == nullptr ||
      work->timed_out.exchange(true, std::memory_order_acq_rel)) {
    return;
  }
  if (work->operation_fd >= 0) {
    shutdown(work->operation_fd, SHUT_RDWR);
  }
  if (work->work != nullptr) {
    napi_cancel_async_work(work->env, work->work);
  }
}

bool StartIoDeadlineTimer(IoWork* work) {
  uv_loop_t* loop = nullptr;
  if (napi_get_uv_event_loop(work->env, &loop) != napi_ok || loop == nullptr) {
    return false;
  }
  uv_timer_t* timer = new (std::nothrow) uv_timer_t();
  if (timer == nullptr) return false;
  if (uv_timer_init(loop, timer) != 0) {
    delete timer;
    return false;
  }
  timer->data = work;
  work->deadline_timer = timer;
  const auto now = std::chrono::steady_clock::now();
  uint64_t delay_ms = 0;
  if (now < work->deadline) {
    const auto remaining = std::chrono::duration_cast<std::chrono::milliseconds>(
        work->deadline - now);
    delay_ms = static_cast<uint64_t>(remaining.count());
    if (delay_ms == 0) delay_ms = 1;
  }
  if (uv_timer_start(timer, OnIoDeadline, delay_ms, 0) != 0) {
    CloseIoDeadlineTimer(work);
    return false;
  }
  return true;
}

void CleanupIoWork(IoWork* work) {
  CloseIoDeadlineTimer(work);
  if (!work->bytes.empty()) SecureZero(work->bytes.data(), work->bytes.size());
  ZeroString(&work->frame_digest);
  if (work->operation_fd >= 0) close(work->operation_fd);
  if (work->token_reference != nullptr) {
    napi_delete_reference(work->env, work->token_reference);
  }
  if (work->work != nullptr) napi_delete_async_work(work->env, work->work);
  delete work;
}

void CompleteIo(napi_env env, napi_status status, void* data) {
  IoWork* work = static_cast<IoWork*>(data);
  const bool success = status == napi_ok && work->success &&
      !work->timed_out.load(std::memory_order_acquire) &&
      std::chrono::steady_clock::now() < work->deadline;
  if (work->operation == IoOperation::kReadRequest) {
    work->connection->FinishRead(success);
  } else {
    work->connection->FinishWrite(
        work->operation == IoOperation::kWriteChallenge, success);
  }
  if (!success) {
    RejectAcceptorDeferred(env, work->deferred);
    CleanupIoWork(work);
    return;
  }
  if (work->operation == IoOperation::kReadRequest) {
    napi_value body;
    if (napi_create_buffer_copy(env, work->bytes.size(), work->bytes.data(),
                                nullptr, &body) != napi_ok) {
      work->connection->Reject();
      RejectAcceptorDeferred(env, work->deferred);
      CleanupIoWork(work);
      return;
    }
    napi_resolve_deferred(env, work->deferred, body);
    CleanupIoWork(work);
    return;
  }
  napi_value result;
  if (napi_create_object(env, &result) != napi_ok ||
      !SetUint32(env, result, "version", 1) ||
      !SetCString(env, result, "operation",
                  work->operation == IoOperation::kWriteChallenge
                      ? "challenge_written"
                      : "response_written") ||
      !SetString(env, result, "frame_sha256", work->frame_digest) ||
      !SetUint64Decimal(env, result, "frame_bytes", work->bytes.size()) ||
      napi_object_freeze(env, result) != napi_ok) {
    work->connection->Reject();
    RejectAcceptorDeferred(env, work->deferred);
    CleanupIoWork(work);
    return;
  }
  napi_resolve_deferred(env, work->deferred, result);
  CleanupIoWork(work);
}

bool ReadTimeoutArgument(napi_env env, napi_value value, int* timeout) {
  napi_valuetype type = napi_undefined;
  double raw = 0;
  if (napi_typeof(env, value, &type) != napi_ok || type != napi_number ||
      napi_get_value_double(env, value, &raw) != napi_ok ||
      !std::isfinite(raw) || std::trunc(raw) != raw || raw < 1 ||
      raw > kMaxNativeIpcTimeoutMs) {
    return false;
  }
  *timeout = static_cast<int>(raw);
  return true;
}

napi_value QueueIoWork(napi_env env, napi_value token,
                       const std::shared_ptr<AcceptedConnectionState>& connection,
                       IoOperation operation, int operation_fd, int timeout_ms,
                       std::vector<unsigned char> bytes) {
  IoWork* work = new (std::nothrow) IoWork();
  if (work == nullptr) {
    close(operation_fd);
    connection->Reject();
    ThrowAcceptorCode(env);
    return nullptr;
  }
  work->env = env;
  work->connection = connection;
  work->operation = operation;
  work->operation_fd = operation_fd;
  work->deadline = std::chrono::steady_clock::now() +
      std::chrono::milliseconds(timeout_ms);
  work->bytes = std::move(bytes);
  if (operation != IoOperation::kReadRequest) {
    work->frame_digest = Sha256Hex(work->bytes.data(), work->bytes.size());
  }
  napi_value promise;
  napi_value resource_name;
  if (napi_create_promise(env, &work->deferred, &promise) != napi_ok ||
      napi_create_reference(env, token, 1, &work->token_reference) != napi_ok ||
      napi_create_string_utf8(env, "darwinNativeIpcIo", NAPI_AUTO_LENGTH,
                              &resource_name) != napi_ok ||
      napi_create_async_work(env, nullptr, resource_name, ExecuteIo, CompleteIo,
                             work, &work->work) != napi_ok ||
      !StartIoDeadlineTimer(work) ||
      napi_queue_async_work(env, work->work) != napi_ok) {
    connection->Reject();
    CleanupIoWork(work);
    ThrowAcceptorCode(env);
    return nullptr;
  }
  return promise;
}

napi_value WriteAcceptedConnectionFrame(napi_env env,
                                        napi_callback_info info) {
  size_t argc = 4;
  napi_value argv[4];
  if (napi_get_cb_info(env, info, &argc, argv, nullptr, nullptr) != napi_ok ||
      argc != 3) {
    ThrowAcceptorCode(env);
    return nullptr;
  }
  std::shared_ptr<AcceptedConnectionState> connection;
  int timeout_ms = 0;
  bool is_buffer = false;
  void* raw_bytes = nullptr;
  size_t length = 0;
  if (!UnwrapSharedState(env, argv[0], &kAcceptedUnixConnectionTypeTag,
                         &connection) ||
      napi_is_buffer(env, argv[1], &is_buffer) != napi_ok || !is_buffer ||
      napi_get_buffer_info(env, argv[1], &raw_bytes, &length) != napi_ok ||
      raw_bytes == nullptr || length < 5 ||
      length > kMaxNativeIpcFrameBytes + 4 ||
      !ReadTimeoutArgument(env, argv[2], &timeout_ms)) {
    ThrowAcceptorCode(env);
    return nullptr;
  }
  const unsigned char* bytes = static_cast<const unsigned char*>(raw_bytes);
  const uint32_t body_length =
      (static_cast<uint32_t>(bytes[0]) << 24) |
      (static_cast<uint32_t>(bytes[1]) << 16) |
      (static_cast<uint32_t>(bytes[2]) << 8) |
      static_cast<uint32_t>(bytes[3]);
  if (body_length == 0 || static_cast<size_t>(body_length) + 4 != length) {
    connection->Reject();
    ThrowAcceptorCode(env);
    return nullptr;
  }
  std::vector<unsigned char> copy;
  try {
    copy.assign(bytes, bytes + length);
  } catch (...) {
    connection->Reject();
    ThrowAcceptorCode(env);
    return nullptr;
  }
  int operation_fd = -1;
  bool challenge = false;
  if (!connection->BeginWrite(&operation_fd, &challenge)) {
    SecureZero(copy.data(), copy.size());
    connection->Reject();
    ThrowAcceptorCode(env);
    return nullptr;
  }
  return QueueIoWork(env, argv[0], connection,
                     challenge ? IoOperation::kWriteChallenge
                               : IoOperation::kWriteResponse,
                     operation_fd, timeout_ms, std::move(copy));
}

napi_value ReadAcceptedConnectionFrame(napi_env env,
                                       napi_callback_info info) {
  size_t argc = 3;
  napi_value argv[3];
  if (napi_get_cb_info(env, info, &argc, argv, nullptr, nullptr) != napi_ok ||
      argc != 2) {
    ThrowAcceptorCode(env);
    return nullptr;
  }
  std::shared_ptr<AcceptedConnectionState> connection;
  int timeout_ms = 0;
  int operation_fd = -1;
  if (!UnwrapSharedState(env, argv[0], &kAcceptedUnixConnectionTypeTag,
                         &connection) ||
      !ReadTimeoutArgument(env, argv[1], &timeout_ms) ||
      !connection->BeginRead(&operation_fd)) {
    if (connection != nullptr) connection->Reject();
    ThrowAcceptorCode(env);
    return nullptr;
  }
  return QueueIoWork(env, argv[0], connection, IoOperation::kReadRequest,
                     operation_fd, timeout_ms, {});
}

napi_value ReadAcceptedConnectionIdentity(napi_env env,
                                          napi_callback_info info) {
  size_t argc = 2;
  napi_value argv[2];
  if (napi_get_cb_info(env, info, &argc, argv, nullptr, nullptr) != napi_ok ||
      argc != 1) {
    ThrowAcceptorCode(env);
    return nullptr;
  }
  std::shared_ptr<AcceptedConnectionState> connection;
  int duplicate = -1;
  if (!UnwrapSharedState(env, argv[0], &kAcceptedUnixConnectionTypeTag,
                         &connection) ||
      !connection->DuplicateForReadback(&duplicate)) {
    ThrowAcceptorCode(env);
    return nullptr;
  }
  ScopedFd fd(duplicate);
  KernelSnapshot before;
  KernelSnapshot after;
  CodeIdentity code_identity;
  if (!IsUnixStreamSocket(fd.get()) ||
      !ReadKernelSnapshot(fd.get(), &before) ||
      !ReadStableMappedCodeIdentity(before.token, &code_identity) ||
      !ReadKernelSnapshot(fd.get(), &after) ||
      !SameKernelSnapshot(before, after)) {
    connection->Reject();
    ThrowAcceptorCode(env);
    return nullptr;
  }
  FramedDigestBuilder audit_builder("hacker-bob/darwin-peer-audit-token/v2");
  audit_builder.Append(&before.token, sizeof(before.token));
  const std::string audit_digest = audit_builder.Finish();
  FramedDigestBuilder start_builder("hacker-bob/darwin-peer-process-start/v2");
  start_builder.AppendString(audit_digest);
  start_builder.AppendUint32(static_cast<uint32_t>(before.pid));
  start_builder.AppendUint32(static_cast<uint32_t>(before.pidversion));
  start_builder.AppendString(std::to_string(before.process.pbi_start_tvsec));
  start_builder.AppendString(std::to_string(before.process.pbi_start_tvusec));
  const std::string start_digest = start_builder.Finish();
  FramedDigestBuilder readback_builder(
      "hacker-bob/darwin-native-accepted-connection-readback/v1");
  readback_builder.AppendString(connection->connection_identity_digest());
  readback_builder.AppendString(connection->registration_token_digest());
  readback_builder.AppendString(audit_digest);
  readback_builder.AppendString(start_digest);
  readback_builder.AppendString(code_identity.mapped_code_identity_digest);
  readback_builder.AppendUint64(connection->generation());
  const std::string readback_digest = readback_builder.Finish();
  napi_value result;
  if (napi_create_object(env, &result) != napi_ok ||
      !SetUint32(env, result, "version", 1) ||
      !SetCString(env, result, "primitive",
                  "darwin_native_accepted_connection_readback_v1") ||
      !SetString(env, result, "connection_identity_digest",
                 connection->connection_identity_digest()) ||
      !SetString(env, result, "descriptor_registration_token_digest",
                 connection->registration_token_digest()) ||
      !SetString(env, result, "socket_root_identity_digest",
                 connection->root_identity_digest()) ||
      !SetString(env, result, "socket_identity_digest",
                 connection->socket_identity_digest()) ||
      !SetString(env, result, "listener_identity_digest",
                 connection->listener_identity_digest()) ||
      !SetString(env, result, "acceptor_instance_digest",
                 connection->acceptor_instance_digest()) ||
      !SetUint64Decimal(env, result, "connection_generation",
                        connection->generation()) ||
      !SetString(env, result, "peer_audit_token_digest", audit_digest) ||
      !SetString(env, result, "peer_process_start_token_digest",
                 start_digest) ||
      !SetString(env, result, "peer_mapped_code_identity_digest",
                 code_identity.mapped_code_identity_digest) ||
      !SetString(env, result, "descriptor_readback_digest",
                 readback_digest) ||
      !SetBool(env, result, "kernel_snapshot_stable", true) ||
      napi_object_freeze(env, result) != napi_ok) {
    connection->Reject();
    ThrowAcceptorCode(env);
    return nullptr;
  }
  return result;
}

napi_value CloseUnixAcceptor(napi_env env, napi_callback_info info) {
  size_t argc = 2;
  napi_value argv[2];
  std::shared_ptr<UnixAcceptorState> acceptor;
  if (napi_get_cb_info(env, info, &argc, argv, nullptr, nullptr) != napi_ok ||
      argc != 1 ||
      !UnwrapSharedState(env, argv[0], &kUnixAcceptorTypeTag, &acceptor)) {
    ThrowAcceptorCode(env);
    return nullptr;
  }
  acceptor->Close();
  napi_value undefined;
  napi_get_undefined(env, &undefined);
  return undefined;
}

napi_value CloseAcceptedConnection(napi_env env, napi_callback_info info) {
  size_t argc = 2;
  napi_value argv[2];
  std::shared_ptr<AcceptedConnectionState> connection;
  if (napi_get_cb_info(env, info, &argc, argv, nullptr, nullptr) != napi_ok ||
      argc != 1 ||
      !UnwrapSharedState(env, argv[0], &kAcceptedUnixConnectionTypeTag,
                         &connection)) {
    ThrowAcceptorCode(env);
    return nullptr;
  }
  connection->Close();
  napi_value undefined;
  napi_get_undefined(env, &undefined);
  return undefined;
}

napi_value RegisterUnixPeerDescriptor(napi_env env, napi_callback_info info) {
  size_t argc = 2;
  napi_value argv[2];
  if (napi_get_cb_info(env, info, &argc, argv, nullptr, nullptr) != napi_ok || argc != 1) {
    ThrowPeerCode(env);
    return nullptr;
  }
  napi_valuetype type = napi_undefined;
  double raw_fd = -1;
  if (napi_typeof(env, argv[0], &type) != napi_ok || type != napi_number ||
      napi_get_value_double(env, argv[0], &raw_fd) != napi_ok ||
      !std::isfinite(raw_fd) || std::trunc(raw_fd) != raw_fd || raw_fd < 0 ||
      raw_fd > static_cast<double>(INT32_MAX)) {
    ThrowPeerCode(env);
    return nullptr;
  }

  const int duplicate = fcntl(static_cast<int>(raw_fd), F_DUPFD_CLOEXEC, 0);
  if (duplicate < 0) {
    ThrowPeerCode(env);
    return nullptr;
  }
  ScopedFd fd(duplicate);
  if (!IsUnixStreamSocket(fd.get())) {
    ThrowPeerCode(env);
    return nullptr;
  }

  std::string registration_token_digest;
  if (!MintRegistrationTokenDigest(fd.get(), &registration_token_digest)) {
    ThrowPeerCode(env);
    return nullptr;
  }
  napi_value token;
  const int owned_fd = fd.Release();
  if (!CreateRegistrationTokenObject(env, owned_fd,
                                     registration_token_digest, nullptr,
                                     &token)) {
    ThrowPeerCode(env);
    return nullptr;
  }
  return token;
}

napi_value InspectRegisteredUnixPeer(napi_env env, napi_callback_info info) {
  size_t argc = 2;
  napi_value argv[2];
  if (napi_get_cb_info(env, info, &argc, argv, nullptr, nullptr) != napi_ok || argc != 1) {
    ThrowPeerCode(env);
    return nullptr;
  }
  napi_valuetype type = napi_undefined;
  napi_value null_value;
  bool is_null = false;
  if (napi_typeof(env, argv[0], &type) != napi_ok || type != napi_object ||
      napi_get_null(env, &null_value) != napi_ok ||
      napi_strict_equals(env, argv[0], null_value, &is_null) != napi_ok ||
      is_null) {
    ThrowPeerCode(env);
    return nullptr;
  }
  bool tagged = false;
  if (napi_check_object_type_tag(env, argv[0],
                                 &kRegisteredPeerDescriptorTypeTag,
                                 &tagged) != napi_ok ||
      !tagged) {
    ThrowPeerCode(env);
    return nullptr;
  }
  void* raw_registration = nullptr;
  if (napi_remove_wrap(env, argv[0], &raw_registration) != napi_ok ||
      raw_registration == nullptr) {
    ThrowPeerCode(env);
    return nullptr;
  }
  RegisteredPeerDescriptor* registration =
      static_cast<RegisteredPeerDescriptor*>(raw_registration);
  const std::string registration_token_digest =
      registration->token_digest();
  const std::shared_ptr<AcceptedConnectionState> accepted_connection =
      registration->accepted_connection();
  if (accepted_connection != nullptr &&
      !accepted_connection->BeginPeerInspection(registration_token_digest)) {
    ScopedFd rejected_fd(registration->Release());
    delete registration;
    ThrowPeerCode(env);
    return nullptr;
  }
  ScopedFd fd(registration->Release());
  delete registration;
  if (fd.get() < 0 || !IsUnixStreamSocket(fd.get())) {
    if (accepted_connection != nullptr) {
      accepted_connection->FinishPeerInspection(false);
    }
    ThrowPeerCode(env);
    return nullptr;
  }

  KernelSnapshot before;
  KernelSnapshot after;
  CodeIdentity code_identity;
  if (!ReadKernelSnapshot(fd.get(), &before) ||
      !ReadStableMappedCodeIdentity(before.token, &code_identity) ||
      !ReadKernelSnapshot(fd.get(), &after) ||
      !SameKernelSnapshot(before, after)) {
    if (accepted_connection != nullptr) {
      accepted_connection->FinishPeerInspection(false);
    }
    ThrowPeerCode(env);
    return nullptr;
  }

  FramedDigestBuilder audit_builder(
      "hacker-bob/darwin-peer-audit-token/v2");
  audit_builder.Append(&before.token, sizeof(before.token));
  const std::string audit_digest = audit_builder.Finish();

  FramedDigestBuilder start_builder(
      "hacker-bob/darwin-peer-process-start/v2");
  start_builder.AppendString(audit_digest);
  start_builder.AppendUint32(static_cast<uint32_t>(before.pid));
  start_builder.AppendUint32(static_cast<uint32_t>(before.pidversion));
  const std::string start_seconds =
      std::to_string(before.process.pbi_start_tvsec);
  const std::string start_microseconds =
      std::to_string(before.process.pbi_start_tvusec);
  start_builder.AppendString(start_seconds);
  start_builder.AppendString(start_microseconds);
  const std::string start_digest = start_builder.Finish();

  FramedDigestBuilder path_builder(
      "hacker-bob/darwin-peer-executable-path/v2");
  path_builder.AppendString(before.executable_path);
  const std::string path_digest = path_builder.Finish();

  napi_value result;
  if (napi_create_object(env, &result) != napi_ok ||
      !SetUint32(env, result, "version", kSnapshotVersion) ||
      !SetCString(env, result, "primitive", kSnapshotPrimitive) ||
      !SetString(env, result, "descriptor_registration_token_digest",
                 registration_token_digest) ||
      !SetUint32(env, result, "peer_euid", static_cast<uint32_t>(before.euid)) ||
      !SetUint32(env, result, "peer_egid", static_cast<uint32_t>(before.egid)) ||
      !SetUint32(env, result, "peer_ruid", static_cast<uint32_t>(before.ruid)) ||
      !SetUint32(env, result, "peer_rgid", static_cast<uint32_t>(before.rgid)) ||
      !SetUint32(env, result, "peer_pid", static_cast<uint32_t>(before.pid)) ||
      !SetUint32(env, result, "peer_pidversion", static_cast<uint32_t>(before.pidversion)) ||
      !SetString(env, result, "peer_process_start_tvsec", start_seconds) ||
      !SetString(env, result, "peer_process_start_tvusec", start_microseconds) ||
      !SetString(env, result, "peer_audit_token_digest", audit_digest) ||
      !SetString(env, result, "peer_process_start_token_digest", start_digest) ||
      !SetString(env, result, "peer_executable_path_digest", path_digest) ||
      !SetCString(env, result, "peer_code_identity_scheme",
                  "darwin_seccode_guest_audit_token_dynamic_cdhash_v1") ||
      !SetCString(env, result, "peer_code_identity_completeness",
                  "dynamic_seccode_identity_complete") ||
      !SetBool(env, result, "peer_code_identity_audit_token_bound", true) ||
      !SetBool(env, result, "peer_code_identity_stable", true) ||
      !SetCString(env, result, "peer_code_dynamic_validity_scheme",
                  "darwin_seccode_check_validity_dynamic_default_v1") ||
      !SetCString(env, result, "peer_code_dynamic_validity", "valid") ||
      !SetString(env, result, "peer_code_directory_hash",
                 code_identity.code_directory_hash) ||
      !SetUint32(env, result, "peer_code_directory_hash_algorithm",
                 code_identity.cdhash_algorithm) ||
      !SetString(env, result, "peer_code_directory_hashes_digest",
                 code_identity.code_directory_hashes_digest) ||
      !SetString(env, result, "peer_code_signing_identifier_digest",
                 code_identity.signing_identifier_digest) ||
      !SetCString(env, result, "peer_code_team_identifier_state",
                  code_identity.team_identifier_present ? "present" : "absent") ||
      !SetString(env, result, "peer_code_team_identifier_digest",
                 code_identity.team_identifier_digest) ||
      !SetCString(env, result, "peer_code_certificate_chain_state",
                  code_identity.certificate_count > 0 ? "present" : "absent") ||
      !SetUint32(env, result, "peer_code_certificate_count",
                 code_identity.certificate_count) ||
      !SetString(env, result, "peer_code_certificate_chain_digest",
                 code_identity.certificate_chain_digest) ||
      !SetString(env, result, "peer_code_designated_requirement_digest",
                 code_identity.designated_requirement_digest) ||
      !SetString(env, result, "peer_code_static_flags_digest",
                 code_identity.static_flags_digest) ||
      !SetString(env, result, "peer_code_dynamic_status_digest",
                 code_identity.dynamic_status_digest) ||
      !SetString(env, result, "peer_code_signature_class",
                 code_identity.signature_class) ||
      !SetBool(env, result, "peer_code_signer_identity_complete",
               code_identity.signer_identity_complete) ||
      !SetString(env, result, "peer_code_signing_identity_digest",
                 code_identity.signing_identity_digest) ||
      !SetString(env, result, "peer_mapped_code_identity_digest",
                 code_identity.mapped_code_identity_digest) ||
      !SetBool(env, result, "kernel_snapshot_stable", true)) {
    if (accepted_connection != nullptr) {
      accepted_connection->FinishPeerInspection(false);
    }
    ThrowPeerCode(env);
    return nullptr;
  }
  if (accepted_connection != nullptr) {
    accepted_connection->FinishPeerInspection(true);
  }
  return result;
}

napi_value InspectCurrentSelf(napi_env env, napi_callback_info info) {
  size_t argc = 1;
  napi_value argv[1];
  if (napi_get_cb_info(env, info, &argc, argv, nullptr, nullptr) != napi_ok || argc != 0) {
    ThrowSelfCode(env);
    return nullptr;
  }

  KernelSnapshot before;
  KernelSnapshot after;
  CodeIdentity code_identity;
  if (!ReadSelfKernelSnapshot(&before) ||
      !ReadStableSelfCodeIdentity(before.token, &code_identity) ||
      !ReadSelfKernelSnapshot(&after) ||
      !SameKernelSnapshot(before, after)) {
    ThrowSelfCode(env);
    return nullptr;
  }

  FramedDigestBuilder audit_builder(
      "hacker-bob/darwin-self-audit-token/v1");
  audit_builder.Append(&before.token, sizeof(before.token));
  const std::string audit_digest = audit_builder.Finish();

  FramedDigestBuilder start_builder(
      "hacker-bob/darwin-self-process-start/v1");
  start_builder.AppendString(audit_digest);
  start_builder.AppendUint32(static_cast<uint32_t>(before.pid));
  start_builder.AppendUint32(static_cast<uint32_t>(before.pidversion));
  const std::string start_seconds =
      std::to_string(before.process.pbi_start_tvsec);
  const std::string start_microseconds =
      std::to_string(before.process.pbi_start_tvusec);
  start_builder.AppendString(start_seconds);
  start_builder.AppendString(start_microseconds);
  const std::string start_digest = start_builder.Finish();

  FramedDigestBuilder path_builder(
      "hacker-bob/darwin-self-executable-path/v1");
  path_builder.AppendString(before.executable_path);
  const std::string path_digest = path_builder.Finish();

  napi_value result;
  if (napi_create_object(env, &result) != napi_ok ||
      !SetUint32(env, result, "version", kSelfSnapshotVersion) ||
      !SetCString(env, result, "primitive", kSelfSnapshotPrimitive) ||
      !SetUint32(env, result, "self_euid", static_cast<uint32_t>(before.euid)) ||
      !SetUint32(env, result, "self_egid", static_cast<uint32_t>(before.egid)) ||
      !SetUint32(env, result, "self_ruid", static_cast<uint32_t>(before.ruid)) ||
      !SetUint32(env, result, "self_rgid", static_cast<uint32_t>(before.rgid)) ||
      !SetUint32(env, result, "self_pid", static_cast<uint32_t>(before.pid)) ||
      !SetUint32(env, result, "self_pidversion",
                 static_cast<uint32_t>(before.pidversion)) ||
      !SetString(env, result, "self_process_start_tvsec", start_seconds) ||
      !SetString(env, result, "self_process_start_tvusec", start_microseconds) ||
      !SetString(env, result, "self_audit_token_digest", audit_digest) ||
      !SetString(env, result, "self_process_start_token_digest", start_digest) ||
      !SetString(env, result, "self_executable_path_digest", path_digest) ||
      !SetCString(env, result, "self_code_identity_scheme",
                  "darwin_task_audit_token_guest_and_seccode_self_cdhash_v1") ||
      !SetCString(env, result, "self_code_identity_completeness",
                  "dynamic_seccode_identity_complete") ||
      !SetBool(env, result, "self_code_identity_audit_token_bound", true) ||
      !SetBool(env, result, "self_code_identity_seccode_self_cross_checked", true) ||
      !SetBool(env, result, "self_code_identity_stable", true) ||
      !SetCString(env, result, "self_code_dynamic_validity_scheme",
                  "darwin_seccode_check_validity_dynamic_default_v1") ||
      !SetCString(env, result, "self_code_dynamic_validity", "valid") ||
      !SetString(env, result, "self_code_directory_hash",
                 code_identity.code_directory_hash) ||
      !SetUint32(env, result, "self_code_directory_hash_algorithm",
                 code_identity.cdhash_algorithm) ||
      !SetString(env, result, "self_code_directory_hashes_digest",
                 code_identity.code_directory_hashes_digest) ||
      !SetString(env, result, "self_code_signing_identifier_digest",
                 code_identity.signing_identifier_digest) ||
      !SetCString(env, result, "self_code_team_identifier_state",
                  code_identity.team_identifier_present ? "present" : "absent") ||
      !SetString(env, result, "self_code_team_identifier_digest",
                 code_identity.team_identifier_digest) ||
      !SetCString(env, result, "self_code_certificate_chain_state",
                  code_identity.certificate_count > 0 ? "present" : "absent") ||
      !SetUint32(env, result, "self_code_certificate_count",
                 code_identity.certificate_count) ||
      !SetString(env, result, "self_code_certificate_chain_digest",
                 code_identity.certificate_chain_digest) ||
      !SetString(env, result, "self_code_designated_requirement_digest",
                 code_identity.designated_requirement_digest) ||
      !SetString(env, result, "self_code_static_flags_digest",
                 code_identity.static_flags_digest) ||
      !SetString(env, result, "self_code_dynamic_status_digest",
                 code_identity.dynamic_status_digest) ||
      !SetString(env, result, "self_code_signature_class",
                 code_identity.signature_class) ||
      !SetBool(env, result, "self_code_signer_identity_complete",
               code_identity.signer_identity_complete) ||
      !SetString(env, result, "self_code_signing_identity_digest",
                 code_identity.signing_identity_digest) ||
      !SetString(env, result, "self_mapped_code_identity_digest",
                 code_identity.mapped_code_identity_digest) ||
      !SetBool(env, result, "self_kernel_snapshot_stable", true)) {
    ThrowSelfCode(env);
    return nullptr;
  }
  return result;
}

napi_value Initialize(napi_env env, napi_value exports) {
  napi_value register_peer_function;
  napi_value inspect_peer_function;
  napi_value inspect_loaded_image_function;
  napi_value self_function;
  napi_value create_acceptor_function;
  napi_value accept_connection_function;
  napi_value read_connection_identity_function;
  napi_value write_connection_frame_function;
  napi_value read_connection_frame_function;
  napi_value close_acceptor_function;
  napi_value close_connection_function;
  if (napi_create_function(env, "registerUnixPeerDescriptor", NAPI_AUTO_LENGTH,
                           RegisterUnixPeerDescriptor, nullptr,
                           &register_peer_function) != napi_ok ||
      napi_create_function(env, "inspectRegisteredUnixPeer", NAPI_AUTO_LENGTH,
                           InspectRegisteredUnixPeer, nullptr,
                           &inspect_peer_function) != napi_ok ||
      napi_create_function(env, "inspectLoadedImage", NAPI_AUTO_LENGTH,
                           InspectLoadedImage, nullptr,
                           &inspect_loaded_image_function) != napi_ok ||
      napi_create_function(env, "inspectCurrentSelf", NAPI_AUTO_LENGTH,
                           InspectCurrentSelf, nullptr, &self_function) != napi_ok ||
      napi_create_function(env, "createUnixAcceptor", NAPI_AUTO_LENGTH,
                           CreateUnixAcceptor, nullptr,
                           &create_acceptor_function) != napi_ok ||
      napi_create_function(env, "acceptUnixConnection", NAPI_AUTO_LENGTH,
                           AcceptUnixConnection, nullptr,
                           &accept_connection_function) != napi_ok ||
      napi_create_function(env, "readAcceptedConnectionIdentity",
                           NAPI_AUTO_LENGTH, ReadAcceptedConnectionIdentity,
                           nullptr, &read_connection_identity_function) != napi_ok ||
      napi_create_function(env, "writeAcceptedConnectionFrame",
                           NAPI_AUTO_LENGTH, WriteAcceptedConnectionFrame,
                           nullptr, &write_connection_frame_function) != napi_ok ||
      napi_create_function(env, "readAcceptedConnectionFrame",
                           NAPI_AUTO_LENGTH, ReadAcceptedConnectionFrame,
                           nullptr, &read_connection_frame_function) != napi_ok ||
      napi_create_function(env, "closeUnixAcceptor", NAPI_AUTO_LENGTH,
                           CloseUnixAcceptor, nullptr,
                           &close_acceptor_function) != napi_ok ||
      napi_create_function(env, "closeAcceptedConnection", NAPI_AUTO_LENGTH,
                           CloseAcceptedConnection, nullptr,
                           &close_connection_function) != napi_ok ||
      !DefineDataProperty(env, exports, "registerUnixPeerDescriptor",
                          register_peer_function, napi_enumerable) ||
      !DefineDataProperty(env, exports, "inspectRegisteredUnixPeer",
                          inspect_peer_function,
                          napi_enumerable) ||
      !DefineDataProperty(env, exports, "inspectLoadedImage",
                          inspect_loaded_image_function, napi_enumerable) ||
      !DefineDataProperty(env, exports, "inspectCurrentSelf", self_function,
                          napi_enumerable) ||
      !DefineDataProperty(env, exports, "createUnixAcceptor",
                          create_acceptor_function, napi_enumerable) ||
      !DefineDataProperty(env, exports, "acceptUnixConnection",
                          accept_connection_function, napi_enumerable) ||
      !DefineDataProperty(env, exports, "readAcceptedConnectionIdentity",
                          read_connection_identity_function, napi_enumerable) ||
      !DefineDataProperty(env, exports, "writeAcceptedConnectionFrame",
                          write_connection_frame_function, napi_enumerable) ||
      !DefineDataProperty(env, exports, "readAcceptedConnectionFrame",
                          read_connection_frame_function, napi_enumerable) ||
      !DefineDataProperty(env, exports, "closeUnixAcceptor",
                          close_acceptor_function, napi_enumerable) ||
      !DefineDataProperty(env, exports, "closeAcceptedConnection",
                          close_connection_function, napi_enumerable)) {
    ThrowPeerCode(env);
    return nullptr;
  }
  return exports;
}

}  // namespace

NAPI_MODULE(NODE_GYP_MODULE_NAME, Initialize)
