#ifndef HACKER_BOB_TRACKED_ACCEPT_OPERATION_FD_H_
#define HACKER_BOB_TRACKED_ACCEPT_OPERATION_FD_H_

#include <sys/socket.h>

#include <mutex>

namespace hacker_bob_native_darwin {

// The tracked numeric descriptor is never closed while it remains published
// here. Detach transfers the sole close right to the accept completion path;
// shutdown therefore cannot target a descriptor that was closed and reused.
class TrackedAcceptOperationFd {
 public:
  bool Track(int fd) {
    std::lock_guard<std::mutex> lock(mutex_);
    if (fd < 0 || fd_ >= 0) return false;
    fd_ = fd;
    return true;
  }

  int Detach(int expected_fd) {
    std::lock_guard<std::mutex> lock(mutex_);
    if (fd_ < 0 || fd_ != expected_fd) return -1;
    const int detached = fd_;
    fd_ = -1;
    return detached;
  }

  void ShutdownTracked() {
    std::lock_guard<std::mutex> lock(mutex_);
    if (fd_ >= 0) shutdown(fd_, SHUT_RDWR);
  }

 private:
  std::mutex mutex_;
  int fd_ = -1;
};

}  // namespace hacker_bob_native_darwin

#endif  // HACKER_BOB_TRACKED_ACCEPT_OPERATION_FD_H_
