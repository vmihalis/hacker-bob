#include <sys/socket.h>
#include <unistd.h>

#include "tracked_accept_operation_fd.h"

int main() {
  int tracked_pair[2]{-1, -1};
  int unrelated_pair[2]{-1, -1};
  if (socketpair(AF_UNIX, SOCK_STREAM, 0, tracked_pair) != 0 ||
      socketpair(AF_UNIX, SOCK_STREAM, 0, unrelated_pair) != 0) {
    return 1;
  }

  hacker_bob_native_darwin::TrackedAcceptOperationFd slot;
  const int reused_number = tracked_pair[0];
  if (!slot.Track(reused_number)) return 2;
  const int detached = slot.Detach(reused_number);
  if (detached != reused_number) return 3;
  close(detached);
  tracked_pair[0] = -1;

  // Force an unrelated live socket onto the exact numeric descriptor that the
  // accept operation used. A stale tracked integer would shut this socket down.
  if (dup2(unrelated_pair[0], reused_number) != reused_number) return 4;
  slot.ShutdownTracked();

  const unsigned char sent = 0x5a;
  unsigned char received = 0;
  if (write(unrelated_pair[1], &sent, 1) != 1 ||
      read(reused_number, &received, 1) != 1 || received != sent) {
    return 5;
  }

  close(reused_number);
  close(tracked_pair[1]);
  close(unrelated_pair[0]);
  close(unrelated_pair[1]);
  return 0;
}
