#define _DARWIN_C_SOURCE 1

/*
 * Source-only Darwin post-exec capability-release fixture.
 *
 * The production gate is deliberately terminal: Security.framework live-guest
 * validation, retained-FD-to-live-MH_EXECUTE measurement, durable one-use
 * state, and authenticated outbox persistence are explicit fail-closed stubs.
 * The test gate exercises only the powerless pathname-exec, fresh AF_UNIX peer
 * binding, SCM_RIGHTS descriptor hygiene, READY_NO_EFFECT, and COMMIT_GO
 * ordering mechanics with temporary files and a socketpair effect surrogate.
 * It never opens or enumerates hardware and is not linked into the shipped
 * diagnostic launcher fixture.
 */
#if defined(HB_POST_EXEC_RELEASE_SOURCE_ONLY) == defined(HB_POST_EXEC_RELEASE_TEST_ONLY)
#error "define exactly one post-exec capability-release build gate"
#endif

#include <CommonCrypto/CommonDigest.h>
#include <bsm/libbsm.h>
#include <libproc.h>
#include <mach/mach.h>
#include <mach/task_info.h>
#include <mach-o/dyld.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/un.h>
#include <sys/wait.h>

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <poll.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define HB_PROTOCOL_VERSION 1U
#define HB_PROTOCOL_MAGIC 0x48425058U
#define HB_NONCE_BYTES 32U
#define HB_CAPABILITY_COUNT 4
#define HB_MAX_RECEIVED_FDS 8
#define HB_CONNECTION_FD 3
#define HB_FIRST_CAPABILITY_FD 4
#define HB_LAST_CAPABILITY_FD 7
#define HB_RETAINED_FD_BASE 64
#define HB_IO_TIMEOUT_MS 1500
#define HB_CHILD_GATE "--test-only-post-exec-child-v1"
#define HB_SELFTEST_GATE "--test-only-post-exec-selftest-v1"
#define HB_READY_NO_EFFECT 0x52454144U
#define HB_COMMIT_GO 0x434f4d4dU
#define HB_RESULT_EFFECT_ONCE 0x52455331U
#define HB_TERMINAL_IDENTITY_ACCEPTED 0x5445524dU
#define HB_STATUS_POLICY_MASK \
  (O_ACCMODE | O_NONBLOCK | O_APPEND | O_ASYNC | O_EVTONLY)

enum hb_message_kind {
  HB_MESSAGE_HELLO = 1,
  HB_MESSAGE_GRANT = 2,
  HB_MESSAGE_READY = 3,
  HB_MESSAGE_GO = 4,
  HB_MESSAGE_RESULT = 5,
  HB_MESSAGE_TERMINAL_ACK = 6
};

enum hb_test_case {
  HB_CASE_SUCCESS = 1,
  HB_CASE_INHERITED_CONNECTED_SOCKET = 2,
  HB_CASE_WRONG_PEER = 3,
  HB_CASE_WRONG_NONCE = 4,
  HB_CASE_WRONG_GENERATION = 5,
  HB_CASE_EXTRA_DESCRIPTORS = 6,
  HB_CASE_ANCILLARY_TRUNCATION = 7,
  HB_CASE_DESCRIPTOR_ALIAS = 8,
  HB_CASE_DESCRIPTOR_ORDER = 9,
  HB_CASE_MISSING_CLOEXEC = 10,
  HB_CASE_UNEXPECTED_DESCRIPTOR = 11,
  HB_CASE_REPLAYED_GRANT = 12,
  HB_CASE_REPLAYED_GO = 13,
  HB_CASE_PRE_GO_EFFECT = 14,
  HB_CASE_CRASH_AFTER_HELLO = 15,
  HB_CASE_CRASH_AFTER_GRANT = 16,
  HB_CASE_CRASH_AFTER_READY = 17,
  HB_CASE_CRASH_AFTER_GO = 18,
  HB_CASE_CRASH_AFTER_EFFECT = 19,
  HB_CASE_SPLIT_ANCILLARY_RECORDS = 20,
  HB_CASE_MALFORMED_ANCILLARY_BOUNDS = 21,
  HB_CASE_CRASH_AFTER_RESULT = 22,
  HB_CASE_PRODUCTION_GATES_CLOSED = 23
};

enum hb_fixture_outcome {
  HB_FIXTURE_SUCCESS = 1,
  HB_FIXTURE_REJECTED_NO_EFFECT = 2,
  HB_FIXTURE_HOSTILE_REJECTED = 3,
  HB_FIXTURE_AMBIGUOUS_QUARANTINED = 4
};

struct hb_wire_frame {
  uint32_t magic;
  uint32_t version;
  uint32_t kind;
  uint32_t state;
  uint64_t listener_generation;
  uint64_t sequence;
  unsigned char nonce[HB_NONCE_BYTES];
  uint64_t process_start_seconds;
  uint64_t process_start_microseconds;
  int32_t pid;
  int32_t pidversion;
  int32_t parent_pid;
  uint32_t uid;
  uint32_t gid;
  uint32_t inventory_before_count;
  uint32_t inventory_after_count;
  uint32_t effect_count;
  uint32_t capability_count;
  uint32_t descriptor_flags_mask;
  uint32_t descriptor_flags_value;
  uint32_t reserved;
  unsigned char capability_digest[CC_SHA256_DIGEST_LENGTH];
  unsigned char capability_abi_digest[CC_SHA256_DIGEST_LENGTH];
};

struct hb_kernel_identity {
  audit_token_t token;
  pid_t pid;
  pid_t parent_pid;
  int pidversion;
  uid_t euid;
  gid_t egid;
  uid_t ruid;
  gid_t rgid;
  uint64_t start_seconds;
  uint64_t start_microseconds;
  char executable_path[PROC_PIDPATHINFO_MAXSIZE];
};

struct hb_capability_identity {
  uint64_t dev;
  uint64_t ino;
  uint64_t rdev;
  uint64_t mode;
  uint64_t nlink;
  uint64_t uid;
  uint64_t gid;
  int access_mode;
  int status_flags;
  int socket_type;
};

struct hb_production_release_plan {
  int accepted_connection_fd;
  int retained_executable_fd;
  audit_token_t peer_audit_token;
  unsigned char serialized_requirement_digest[CC_SHA256_DIGEST_LENGTH];
  unsigned char mapped_image_policy_digest[CC_SHA256_DIGEST_LENGTH];
  unsigned char durable_state_policy_digest[CC_SHA256_DIGEST_LENGTH];
};

/*
 * Required production implementation: create a live SecCodeRef using
 * SecCodeCopyGuestWithAttributes(..., kSecGuestAttributeAudit, ...), load the
 * exact signed SecRequirement bytes, and call SecCodeCheckValidity.  Merely
 * observing a PID, nonce, path, or audit token is not an attestation.
 */
__attribute__((unused))
static int hb_security_framework_live_guest_attestation_fail_closed(
  const struct hb_production_release_plan *plan
) {
  (void)plan;
  errno = ENOTSUP;
  return -1;
}

/*
 * Required production implementation: compare the retained executable FD and
 * every executable Mach-O segment to the live MH_EXECUTE mappings.  A pathname
 * reopen or matching pathname digest is not accepted.
 */
__attribute__((unused))
static int hb_retained_fd_live_mh_execute_measurement_fail_closed(
  const struct hb_production_release_plan *plan
) {
  (void)plan;
  errno = ENOTSUP;
  return -1;
}

/*
 * Required production implementation: authenticate and durably reserve the
 * one-use grant and GO sequences and reconcile a child outbox after restart.
 * Caller-owned files and unkeyed checksums are not authority.
 */
__attribute__((unused))
static int hb_authenticated_durable_grant_go_outbox_fail_closed(
  const struct hb_production_release_plan *plan
) {
  (void)plan;
  errno = ENOTSUP;
  return -1;
}

__attribute__((unused))
static int hb_post_exec_capability_release_production_unavailable(
  const struct hb_production_release_plan *plan
) {
  if (plan == NULL
      || hb_security_framework_live_guest_attestation_fail_closed(plan) != 0
      || hb_retained_fd_live_mh_execute_measurement_fail_closed(plan) != 0
      || hb_authenticated_durable_grant_go_outbox_fail_closed(plan) != 0) {
    return -1;
  }
  return -1;
}

#ifdef HB_POST_EXEC_RELEASE_TEST_ONLY

struct hb_test_fixture {
  char directory[PATH_MAX];
  char listener_path[sizeof(((struct sockaddr_un *)0)->sun_path)];
  char executable_path[PATH_MAX];
  int listener_fd;
  int accepted_fd;
  int capability_fds[HB_CAPABILITY_COUNT];
  int effect_peer_fd;
  int inherited_peer_fd;
  int inherited_child_fd;
  pid_t direct_child;
  pid_t attacker_child;
  uint64_t generation;
  uint64_t grant_sequence;
  uint64_t go_sequence;
  unsigned char nonce[HB_NONCE_BYTES];
  unsigned char capability_digest[CC_SHA256_DIGEST_LENGTH];
  unsigned char capability_abi_digest[CC_SHA256_DIGEST_LENGTH];
};

static int hb_set_cloexec(int fd) {
  int flags = fcntl(fd, F_GETFD);
  return flags < 0 ? -1 : fcntl(fd, F_SETFD, flags | FD_CLOEXEC);
}

static int hb_set_no_sigpipe(int fd) {
  int enabled = 1;
  return setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &enabled, sizeof(enabled));
}

static int hb_poll_fd(int fd, short events, int timeout_ms) {
  struct pollfd descriptor;
  int result;
  descriptor.fd = fd;
  descriptor.events = events;
  descriptor.revents = 0;
  do {
    result = poll(&descriptor, 1, timeout_ms);
  } while (result < 0 && errno == EINTR);
  if (result != 1 || (descriptor.revents & events) == 0) return -1;
  if ((descriptor.revents & (POLLERR | POLLNVAL)) != 0) return -1;
  return 0;
}

static int hb_write_all(int fd, const void *bytes, size_t length) {
  const unsigned char *cursor = (const unsigned char *)bytes;
  size_t remaining = length;
  while (remaining > 0) {
    ssize_t written;
    if (hb_poll_fd(fd, POLLOUT, HB_IO_TIMEOUT_MS) != 0) return -1;
    do {
      written = write(fd, cursor, remaining);
    } while (written < 0 && errno == EINTR);
    if (written <= 0) return -1;
    cursor += (size_t)written;
    remaining -= (size_t)written;
  }
  return 0;
}

static int hb_read_all(int fd, void *bytes, size_t length) {
  unsigned char *cursor = (unsigned char *)bytes;
  size_t remaining = length;
  while (remaining > 0) {
    ssize_t received;
    if (hb_poll_fd(fd, POLLIN, HB_IO_TIMEOUT_MS) != 0) return -1;
    do {
      received = read(fd, cursor, remaining);
    } while (received < 0 && errno == EINTR);
    if (received <= 0) return -1;
    cursor += (size_t)received;
    remaining -= (size_t)received;
  }
  return 0;
}

static int hb_frame_base_valid(
  const struct hb_wire_frame *frame,
  enum hb_message_kind kind,
  uint64_t generation,
  const unsigned char nonce[HB_NONCE_BYTES]
) {
  return frame != NULL
    && frame->magic == HB_PROTOCOL_MAGIC
    && frame->version == HB_PROTOCOL_VERSION
    && frame->kind == (uint32_t)kind
    && frame->listener_generation == generation
    && memcmp(frame->nonce, nonce, HB_NONCE_BYTES) == 0
    && frame->reserved == 0;
}

static void hb_init_frame(
  struct hb_wire_frame *frame,
  enum hb_message_kind kind,
  uint64_t generation,
  const unsigned char nonce[HB_NONCE_BYTES]
) {
  memset(frame, 0, sizeof(*frame));
  frame->magic = HB_PROTOCOL_MAGIC;
  frame->version = HB_PROTOCOL_VERSION;
  frame->kind = (uint32_t)kind;
  frame->listener_generation = generation;
  memcpy(frame->nonce, nonce, HB_NONCE_BYTES);
}

static int hb_collect_fd_inventory(int fds[], int maximum, int *count_output) {
  struct proc_fdinfo raw[128];
  int received = proc_pidinfo(
    getpid(),
    PROC_PIDLISTFDS,
    0,
    raw,
    (int)sizeof(raw)
  );
  int count;
  int index;
  if (received <= 0 || received % (int)sizeof(raw[0]) != 0) return -1;
  count = received / (int)sizeof(raw[0]);
  if (count <= 0 || count > maximum) return -1;
  for (index = 0; index < count; index += 1) fds[index] = raw[index].proc_fd;
  for (index = 0; index < count; index += 1) {
    int right;
    for (right = index + 1; right < count; right += 1) {
      if (fds[right] < fds[index]) {
        int temporary = fds[index];
        fds[index] = fds[right];
        fds[right] = temporary;
      }
    }
  }
  *count_output = count;
  return 0;
}

static int hb_fd_inventory_exact(int last_fd) {
  int fds[128];
  int count;
  int index;
  if (last_fd < 0 || hb_collect_fd_inventory(fds, 128, &count) != 0
      || count != last_fd + 1) return 0;
  for (index = 0; index <= last_fd; index += 1) {
    if (fds[index] != index) return 0;
  }
  return 1;
}

static void hb_close_all_except(int retained_fd) {
  int limit = getdtablesize();
  int fd;
  if (limit < 0 || limit > 65536) limit = 65536;
  for (fd = 3; fd < limit; fd += 1) {
    if (fd == retained_fd) continue;
    while (close(fd) != 0 && errno == EINTR) {}
  }
}

static int hb_capture_self_identity(struct hb_kernel_identity *identity) {
  struct proc_bsdinfo information;
  mach_msg_type_number_t token_count = TASK_AUDIT_TOKEN_COUNT;
  audit_token_t token_copy;
  int received;
  int path_length;
  if (identity == NULL) return -1;
  memset(identity, 0, sizeof(*identity));
  if (task_info(
      mach_task_self(),
      TASK_AUDIT_TOKEN,
      (task_info_t)&identity->token,
      &token_count
    ) != KERN_SUCCESS || token_count != TASK_AUDIT_TOKEN_COUNT) return -1;
  identity->pid = audit_token_to_pid(identity->token);
  identity->pidversion = audit_token_to_pidversion(identity->token);
  identity->euid = audit_token_to_euid(identity->token);
  identity->egid = audit_token_to_egid(identity->token);
  identity->ruid = audit_token_to_ruid(identity->token);
  identity->rgid = audit_token_to_rgid(identity->token);
  received = proc_pidinfo(
    identity->pid,
    PROC_PIDTBSDINFO,
    0,
    &information,
    (int)sizeof(information)
  );
  if (received != (int)sizeof(information)
      || identity->pid != getpid()
      || identity->pidversion < 0
      || information.pbi_pid != (uint32_t)identity->pid
      || information.pbi_ppid == 0
      || information.pbi_uid != identity->euid
      || information.pbi_gid != identity->egid
      || information.pbi_ruid != identity->ruid
      || information.pbi_rgid != identity->rgid
      || information.pbi_start_tvsec == 0
      || information.pbi_start_tvusec >= 1000000) return -1;
  identity->parent_pid = (pid_t)information.pbi_ppid;
  identity->start_seconds = information.pbi_start_tvsec;
  identity->start_microseconds = information.pbi_start_tvusec;
  token_copy = identity->token;
  path_length = proc_pidpath_audittoken(
    &token_copy,
    identity->executable_path,
    (uint32_t)sizeof(identity->executable_path)
  );
  memset(&token_copy, 0, sizeof(token_copy));
  if (path_length <= 0 || path_length >= (int)sizeof(identity->executable_path)
      || identity->executable_path[0] != '/') return -1;
  return 0;
}

static int hb_capture_peer_identity(int fd, struct hb_kernel_identity *identity) {
  struct proc_bsdinfo information;
  uid_t socket_euid;
  gid_t socket_egid;
  pid_t socket_pid;
  socklen_t token_length;
  socklen_t pid_length;
  audit_token_t token_copy;
  int received;
  int path_length;
  if (identity == NULL) return -1;
  memset(identity, 0, sizeof(*identity));
  token_length = (socklen_t)sizeof(identity->token);
  if (getsockopt(fd, SOL_LOCAL, LOCAL_PEERTOKEN, &identity->token, &token_length) != 0
      || token_length != sizeof(identity->token)
      || getpeereid(fd, &socket_euid, &socket_egid) != 0) return -1;
  pid_length = (socklen_t)sizeof(socket_pid);
  if (getsockopt(fd, SOL_LOCAL, LOCAL_PEERPID, &socket_pid, &pid_length) != 0
      || pid_length != sizeof(socket_pid)) return -1;
  identity->pid = audit_token_to_pid(identity->token);
  identity->pidversion = audit_token_to_pidversion(identity->token);
  identity->euid = audit_token_to_euid(identity->token);
  identity->egid = audit_token_to_egid(identity->token);
  identity->ruid = audit_token_to_ruid(identity->token);
  identity->rgid = audit_token_to_rgid(identity->token);
  if (identity->pid <= 0 || identity->pidversion < 0
      || identity->pid != socket_pid
      || identity->euid != socket_euid
      || identity->egid != socket_egid) return -1;
  received = proc_pidinfo(
    identity->pid,
    PROC_PIDTBSDINFO,
    0,
    &information,
    (int)sizeof(information)
  );
  if (received != (int)sizeof(information)
      || information.pbi_pid != (uint32_t)identity->pid
      || information.pbi_ppid == 0
      || information.pbi_uid != identity->euid
      || information.pbi_gid != identity->egid
      || information.pbi_ruid != identity->ruid
      || information.pbi_rgid != identity->rgid
      || information.pbi_start_tvsec == 0
      || information.pbi_start_tvusec >= 1000000) return -1;
  identity->parent_pid = (pid_t)information.pbi_ppid;
  identity->start_seconds = information.pbi_start_tvsec;
  identity->start_microseconds = information.pbi_start_tvusec;
  token_copy = identity->token;
  path_length = proc_pidpath_audittoken(
    &token_copy,
    identity->executable_path,
    (uint32_t)sizeof(identity->executable_path)
  );
  memset(&token_copy, 0, sizeof(token_copy));
  if (path_length <= 0 || path_length >= (int)sizeof(identity->executable_path)
      || identity->executable_path[0] != '/') return -1;
  return 0;
}

static int hb_kernel_identity_equal(
  const struct hb_kernel_identity *left,
  const struct hb_kernel_identity *right
) {
  return memcmp(&left->token, &right->token, sizeof(left->token)) == 0
    && left->pid == right->pid
    && left->parent_pid == right->parent_pid
    && left->pidversion == right->pidversion
    && left->euid == right->euid
    && left->egid == right->egid
    && left->ruid == right->ruid
    && left->rgid == right->rgid
    && left->start_seconds == right->start_seconds
    && left->start_microseconds == right->start_microseconds
    && strcmp(left->executable_path, right->executable_path) == 0;
}

static int hb_capture_capability_identity(
  int fd,
  struct hb_capability_identity *identity
) {
  struct stat status;
  int flags;
  int socket_type = 0;
  socklen_t socket_length = (socklen_t)sizeof(socket_type);
  if (identity == NULL) return -1;
  memset(identity, 0, sizeof(*identity));
  if (fstat(fd, &status) != 0
      || (flags = fcntl(fd, F_GETFL)) < 0) return -1;
  if (S_ISSOCK(status.st_mode)
      && (getsockopt(fd, SOL_SOCKET, SO_TYPE, &socket_type, &socket_length) != 0
        || socket_length != sizeof(socket_type))) return -1;
  identity->dev = (uint64_t)status.st_dev;
  identity->ino = (uint64_t)status.st_ino;
  identity->rdev = (uint64_t)status.st_rdev;
  identity->mode = (uint64_t)status.st_mode;
  identity->nlink = (uint64_t)status.st_nlink;
  identity->uid = (uint64_t)status.st_uid;
  identity->gid = (uint64_t)status.st_gid;
  identity->access_mode = flags & O_ACCMODE;
  /* Darwin may expose kernel-private bits through F_GETFL; bind the complete
   * public, caller-controllable status mask and bind FD_CLOEXEC separately. */
  identity->status_flags = flags & HB_STATUS_POLICY_MASK;
  identity->socket_type = socket_type;
  return 0;
}

static int hb_capability_role_valid(
  int role,
  const struct hb_capability_identity *identity
) {
  switch (role) {
    case 0:
    case 1:
      return S_ISREG((mode_t)identity->mode)
        && identity->access_mode == O_RDONLY
        && identity->status_flags == O_RDONLY
        && identity->socket_type == 0;
    case 2:
      return S_ISSOCK((mode_t)identity->mode)
        && identity->access_mode == O_RDWR
        && identity->status_flags == O_RDWR
        && identity->socket_type == SOCK_STREAM;
    case 3:
      return S_ISREG((mode_t)identity->mode)
        && identity->access_mode == O_WRONLY
        && identity->status_flags == (O_WRONLY | O_APPEND)
        && identity->socket_type == 0;
    default:
      return 0;
  }
}

static int hb_capability_abi_digest(
  unsigned char output[CC_SHA256_DIGEST_LENGTH]
) {
  static const char domain[] =
    "hacker-bob/darwin-post-exec-capability-abi/v1\n";
  static const uint32_t role_table[HB_CAPABILITY_COUNT][8] = {
    {0U, 4U, S_IFREG, O_RDONLY, HB_STATUS_POLICY_MASK, O_RDONLY,
      FD_CLOEXEC, FD_CLOEXEC},
    {1U, 5U, S_IFREG, O_RDONLY, HB_STATUS_POLICY_MASK, O_RDONLY,
      FD_CLOEXEC, FD_CLOEXEC},
    {2U, 6U, S_IFSOCK, O_RDWR, HB_STATUS_POLICY_MASK, O_RDWR,
      FD_CLOEXEC, FD_CLOEXEC},
    {3U, 7U, S_IFREG, O_WRONLY, HB_STATUS_POLICY_MASK, O_WRONLY | O_APPEND,
      FD_CLOEXEC, FD_CLOEXEC},
  };
  CC_SHA256_CTX digest;
  uint32_t count = HB_CAPABILITY_COUNT;
  if (CC_SHA256_Init(&digest) != 1
      || CC_SHA256_Update(&digest, domain, (CC_LONG)(sizeof(domain) - 1U)) != 1
      || CC_SHA256_Update(&digest, &count, (CC_LONG)sizeof(count)) != 1
      || CC_SHA256_Update(
        &digest,
        role_table,
        (CC_LONG)sizeof(role_table)
      ) != 1) return -1;
  return CC_SHA256_Final(output, &digest) == 1 ? 0 : -1;
}

static int hb_capability_alias(
  const struct hb_capability_identity *left,
  const struct hb_capability_identity *right
) {
  return left->dev == right->dev
    && left->ino == right->ino
    && left->rdev == right->rdev
    && (left->mode & S_IFMT) == (right->mode & S_IFMT);
}

static int hb_capability_digest(
  const int fds[HB_CAPABILITY_COUNT],
  unsigned char output[CC_SHA256_DIGEST_LENGTH]
) {
  static const char domain[] =
    "hacker-bob/darwin-post-exec-capability-set/v1\n";
  struct hb_capability_identity identities[HB_CAPABILITY_COUNT];
  CC_SHA256_CTX digest;
  int index;
  if (CC_SHA256_Init(&digest) != 1
      || CC_SHA256_Update(&digest, domain, (CC_LONG)(sizeof(domain) - 1U)) != 1) return -1;
  for (index = 0; index < HB_CAPABILITY_COUNT; index += 1) {
    int prior;
    uint32_t role = (uint32_t)index;
    int descriptor_flags = fcntl(fds[index], F_GETFD);
    if (hb_capture_capability_identity(fds[index], &identities[index]) != 0
        || descriptor_flags != FD_CLOEXEC
        || !hb_capability_role_valid(index, &identities[index])) return -1;
    for (prior = 0; prior < index; prior += 1) {
      if (hb_capability_alias(&identities[index], &identities[prior])) return -1;
    }
    if (CC_SHA256_Update(&digest, &role, (CC_LONG)sizeof(role)) != 1
        || CC_SHA256_Update(
          &digest,
          &identities[index],
          (CC_LONG)sizeof(identities[index])
        ) != 1) return -1;
  }
  return CC_SHA256_Final(output, &digest) == 1 ? 0 : -1;
}

static int hb_send_capability_grant(
  int connection_fd,
  const struct hb_wire_frame *grant,
  const int descriptors[],
  int descriptor_count
) {
  unsigned char control[CMSG_SPACE(sizeof(int) * HB_MAX_RECEIVED_FDS)];
  struct msghdr message;
  struct iovec vector;
  struct cmsghdr *header;
  ssize_t sent;
  if (descriptor_count <= 0 || descriptor_count > HB_MAX_RECEIVED_FDS) return -1;
  memset(control, 0, sizeof(control));
  memset(&message, 0, sizeof(message));
  vector.iov_base = (void *)grant;
  vector.iov_len = sizeof(*grant);
  message.msg_iov = &vector;
  message.msg_iovlen = 1;
  message.msg_control = control;
  message.msg_controllen = (socklen_t)CMSG_SPACE(
    sizeof(int) * (size_t)descriptor_count
  );
  header = CMSG_FIRSTHDR(&message);
  if (header == NULL) return -1;
  header->cmsg_level = SOL_SOCKET;
  header->cmsg_type = SCM_RIGHTS;
  header->cmsg_len = (socklen_t)CMSG_LEN(
    sizeof(int) * (size_t)descriptor_count
  );
  memcpy(CMSG_DATA(header), descriptors, sizeof(int) * (size_t)descriptor_count);
  if (hb_poll_fd(connection_fd, POLLOUT, HB_IO_TIMEOUT_MS) != 0) return -1;
  do {
    sent = sendmsg(connection_fd, &message, 0);
  } while (sent < 0 && errno == EINTR);
  return sent == (ssize_t)sizeof(*grant) ? 0 : -1;
}

static int hb_send_split_capability_grant(
  int connection_fd,
  const struct hb_wire_frame *grant,
  const int descriptors[HB_CAPABILITY_COUNT]
) {
  unsigned char control[
    CMSG_SPACE(sizeof(int) * 2U) + CMSG_SPACE(sizeof(int) * 2U)
  ];
  struct msghdr message;
  struct iovec vector;
  struct cmsghdr *first;
  struct cmsghdr *second;
  ssize_t sent;
  memset(control, 0, sizeof(control));
  memset(&message, 0, sizeof(message));
  vector.iov_base = (void *)grant;
  vector.iov_len = sizeof(*grant);
  message.msg_iov = &vector;
  message.msg_iovlen = 1;
  message.msg_control = control;
  message.msg_controllen = (socklen_t)sizeof(control);
  first = CMSG_FIRSTHDR(&message);
  if (first == NULL) return -1;
  first->cmsg_level = SOL_SOCKET;
  first->cmsg_type = SCM_RIGHTS;
  first->cmsg_len = (socklen_t)CMSG_LEN(sizeof(int) * 2U);
  memcpy(CMSG_DATA(first), descriptors, sizeof(int) * 2U);
  second = CMSG_NXTHDR(&message, first);
  if (second == NULL) return -1;
  second->cmsg_level = SOL_SOCKET;
  second->cmsg_type = SCM_RIGHTS;
  second->cmsg_len = (socklen_t)CMSG_LEN(sizeof(int) * 2U);
  memcpy(CMSG_DATA(second), &descriptors[2], sizeof(int) * 2U);
  if (CMSG_NXTHDR(&message, second) != NULL
      || hb_poll_fd(connection_fd, POLLOUT, HB_IO_TIMEOUT_MS) != 0) return -1;
  do {
    sent = sendmsg(connection_fd, &message, 0);
  } while (sent < 0 && errno == EINTR);
  return sent == (ssize_t)sizeof(*grant) ? 0 : -1;
}

static void hb_close_fd_array(int fds[], int count);

static int hb_extract_exact_capability_rights(
  struct msghdr *message,
  int received_fds[HB_MAX_RECEIVED_FDS],
  int *received_count
) {
  uintptr_t control_start;
  uintptr_t control_end;
  struct cmsghdr *header;
  int count = 0;
  int control_record_count = 0;
  int valid = 1;
  if (received_count == NULL) return -1;
  *received_count = 0;
  if (received_fds == NULL || message == NULL || message->msg_control == NULL
      || message->msg_controllen < sizeof(struct cmsghdr)) return -1;
  control_start = (uintptr_t)message->msg_control;
  if ((size_t)message->msg_controllen > UINTPTR_MAX - control_start) return -1;
  control_end = control_start + (uintptr_t)message->msg_controllen;
  for (header = CMSG_FIRSTHDR(message); header != NULL;
       header = CMSG_NXTHDR(message, header)) {
    uintptr_t header_start = (uintptr_t)(void *)header;
    size_t available;
    size_t payload_bytes;
    int descriptor_count;
    control_record_count += 1;
    if (header_start < control_start || header_start > control_end
        || control_end - header_start < sizeof(*header)) {
      valid = 0;
      break;
    }
    available = (size_t)(control_end - header_start);
    if (header->cmsg_level != SOL_SOCKET || header->cmsg_type != SCM_RIGHTS
        || header->cmsg_len < CMSG_LEN(0)
        || (size_t)header->cmsg_len > available) {
      valid = 0;
      break;
    }
    payload_bytes = header->cmsg_len - CMSG_LEN(0);
    if (payload_bytes == 0 || payload_bytes % sizeof(int) != 0) {
      valid = 0;
      break;
    }
    descriptor_count = (int)(payload_bytes / sizeof(int));
    if (descriptor_count <= 0 || count > HB_MAX_RECEIVED_FDS - descriptor_count) {
      valid = 0;
      break;
    }
    memcpy(
      &received_fds[count],
      CMSG_DATA(header),
      sizeof(int) * (size_t)descriptor_count
    );
    count += descriptor_count;
  }
  if (control_record_count != 1
      || count != HB_CAPABILITY_COUNT
      || (control_record_count == 1
        && CMSG_FIRSTHDR(message)->cmsg_len
          != CMSG_LEN(sizeof(int) * HB_CAPABILITY_COUNT))) valid = 0;
  if (!valid) {
    hb_close_fd_array(received_fds, count);
    return -1;
  }
  *received_count = count;
  return 0;
}

static int hb_receive_capability_grant(
  int connection_fd,
  struct hb_wire_frame *grant,
  int received_fds[HB_MAX_RECEIVED_FDS],
  int *received_count,
  int force_truncation
) {
  unsigned char control[CMSG_SPACE(sizeof(int) * HB_MAX_RECEIVED_FDS)];
  struct msghdr message;
  struct iovec vector;
  ssize_t received;
  memset(control, 0, sizeof(control));
  memset(&message, 0, sizeof(message));
  memset(grant, 0, sizeof(*grant));
  vector.iov_base = grant;
  vector.iov_len = sizeof(*grant);
  message.msg_iov = &vector;
  message.msg_iovlen = 1;
  message.msg_control = control;
  message.msg_controllen = force_truncation
    ? CMSG_SPACE(sizeof(int) * 2U)
    : sizeof(control);
  if (hb_poll_fd(connection_fd, POLLIN, HB_IO_TIMEOUT_MS) != 0) return -1;
  do {
    received = recvmsg(connection_fd, &message, MSG_WAITALL);
  } while (received < 0 && errno == EINTR);
  if (hb_extract_exact_capability_rights(
      &message,
      received_fds,
      received_count
    ) != 0) return -1;
  if (received != (ssize_t)sizeof(*grant)
      || (message.msg_flags & (MSG_CTRUNC | MSG_TRUNC)) != 0) {
    hb_close_fd_array(received_fds, *received_count);
    *received_count = 0;
    return -1;
  }
  return 0;
}

static void hb_close_fd_array(int fds[], int count) {
  int index;
  for (index = 0; index < count; index += 1) {
    if (fds[index] >= 0) {
      (void)close(fds[index]);
      fds[index] = -1;
    }
  }
}

static int hb_test_split_control_records_rejected(
  const int descriptors[HB_CAPABILITY_COUNT]
) {
  unsigned char control[
    CMSG_SPACE(sizeof(int) * 2U) + CMSG_SPACE(sizeof(int) * 2U)
  ];
  struct msghdr message;
  struct cmsghdr *first;
  struct cmsghdr *second;
  int duplicated[HB_CAPABILITY_COUNT] = {-1, -1, -1, -1};
  int received_fds[HB_MAX_RECEIVED_FDS];
  int received_count = 0;
  int index;
  int result = -1;
  memset(control, 0, sizeof(control));
  memset(&message, 0, sizeof(message));
  memset(received_fds, -1, sizeof(received_fds));
  for (index = 0; index < HB_CAPABILITY_COUNT; index += 1) {
    duplicated[index] = fcntl(descriptors[index], F_DUPFD_CLOEXEC, 128);
    if (duplicated[index] < 0) goto cleanup;
  }
  message.msg_control = control;
  message.msg_controllen = (socklen_t)sizeof(control);
  first = CMSG_FIRSTHDR(&message);
  if (first == NULL) goto cleanup;
  first->cmsg_level = SOL_SOCKET;
  first->cmsg_type = SCM_RIGHTS;
  first->cmsg_len = (socklen_t)CMSG_LEN(sizeof(int) * 2U);
  memcpy(CMSG_DATA(first), duplicated, sizeof(int) * 2U);
  second = CMSG_NXTHDR(&message, first);
  if (second == NULL) goto cleanup;
  second->cmsg_level = SOL_SOCKET;
  second->cmsg_type = SCM_RIGHTS;
  second->cmsg_len = (socklen_t)CMSG_LEN(sizeof(int) * 2U);
  memcpy(CMSG_DATA(second), &duplicated[2], sizeof(int) * 2U);
  if (CMSG_NXTHDR(&message, second) != NULL
      || hb_extract_exact_capability_rights(
        &message,
        received_fds,
        &received_count
      ) == 0
      || received_count != 0) goto cleanup;
  for (index = 0; index < HB_CAPABILITY_COUNT; index += 1) {
    if (fcntl(duplicated[index], F_GETFD) >= 0 || errno != EBADF) goto cleanup;
    duplicated[index] = -1;
  }
  result = 0;

cleanup:
  hb_close_fd_array(received_fds, received_count);
  hb_close_fd_array(duplicated, HB_CAPABILITY_COUNT);
  return result;
}

static int hb_test_oversized_control_record_rejected(
  const int descriptors[HB_CAPABILITY_COUNT]
) {
  unsigned char control[CMSG_SPACE(sizeof(int) * HB_CAPABILITY_COUNT)];
  struct msghdr message;
  struct cmsghdr *header;
  int duplicated[HB_CAPABILITY_COUNT] = {-1, -1, -1, -1};
  int received_fds[HB_MAX_RECEIVED_FDS];
  int received_count = 7;
  int index;
  int result = -1;
  memset(control, 0, sizeof(control));
  memset(&message, 0, sizeof(message));
  memset(received_fds, -1, sizeof(received_fds));
  for (index = 0; index < HB_CAPABILITY_COUNT; index += 1) {
    duplicated[index] = fcntl(descriptors[index], F_DUPFD_CLOEXEC, 128);
    if (duplicated[index] < 0) goto cleanup;
  }
  message.msg_control = control;
  message.msg_controllen = (socklen_t)sizeof(control);
  header = CMSG_FIRSTHDR(&message);
  if (header == NULL) goto cleanup;
  header->cmsg_level = SOL_SOCKET;
  header->cmsg_type = SCM_RIGHTS;
  header->cmsg_len = (socklen_t)(sizeof(control) + 1U);
  memcpy(CMSG_DATA(header), duplicated, sizeof(duplicated));
  if (hb_extract_exact_capability_rights(
      &message,
      received_fds,
      &received_count
    ) == 0 || received_count != 0) goto cleanup;
  for (index = 0; index < HB_CAPABILITY_COUNT; index += 1) {
    if (fcntl(duplicated[index], F_GETFD) != FD_CLOEXEC) goto cleanup;
  }
  result = 0;

cleanup:
  hb_close_fd_array(received_fds, received_count);
  hb_close_fd_array(duplicated, HB_CAPABILITY_COUNT);
  return result;
}

static int hb_install_received_capabilities(
  int received_fds[HB_MAX_RECEIVED_FDS],
  int received_count,
  enum hb_test_case test_case,
  const unsigned char expected_digest[CC_SHA256_DIGEST_LENGTH]
) {
  int retained[HB_CAPABILITY_COUNT] = {-1, -1, -1, -1};
  int installed[HB_CAPABILITY_COUNT] = {
    HB_FIRST_CAPABILITY_FD,
    HB_FIRST_CAPABILITY_FD + 1,
    HB_FIRST_CAPABILITY_FD + 2,
    HB_FIRST_CAPABILITY_FD + 3,
  };
  unsigned char digest[CC_SHA256_DIGEST_LENGTH];
  int index;
  int result = -1;
  if (received_count != HB_CAPABILITY_COUNT) goto cleanup;
  for (index = 0; index < received_count; index += 1) {
    if (fcntl(received_fds[index], F_GETFD) != 0
        || hb_set_cloexec(received_fds[index]) != 0) goto cleanup;
    retained[index] = fcntl(received_fds[index], F_DUPFD_CLOEXEC, HB_RETAINED_FD_BASE);
    if (retained[index] < 0) goto cleanup;
  }
  hb_close_fd_array(received_fds, received_count);
  for (index = HB_FIRST_CAPABILITY_FD; index <= HB_LAST_CAPABILITY_FD; index += 1) {
    (void)close(index);
  }
  for (index = 0; index < HB_CAPABILITY_COUNT; index += 1) {
    if (dup2(retained[index], installed[index]) != installed[index]) goto cleanup;
    if (test_case != HB_CASE_MISSING_CLOEXEC || index != 2) {
      if (hb_set_cloexec(installed[index]) != 0) goto cleanup;
    }
  }
  for (index = 0; index < HB_CAPABILITY_COUNT; index += 1) {
    (void)close(retained[index]);
    retained[index] = -1;
  }
  if (test_case == HB_CASE_UNEXPECTED_DESCRIPTOR) {
    int unexpected = open("/dev/null", O_RDONLY | O_CLOEXEC);
    if (unexpected < 0) goto cleanup;
  }
  if (!hb_fd_inventory_exact(HB_LAST_CAPABILITY_FD)) goto cleanup;
  for (index = 0; index < HB_CAPABILITY_COUNT; index += 1) {
    int flags = fcntl(installed[index], F_GETFD);
    if (flags < 0 || (flags & FD_CLOEXEC) == 0) goto cleanup;
  }
  if (hb_capability_digest(installed, digest) != 0
      || memcmp(digest, expected_digest, sizeof(digest)) != 0) goto cleanup;
  result = 0;

cleanup:
  hb_close_fd_array(received_fds, received_count);
  for (index = 0; index < HB_CAPABILITY_COUNT; index += 1) {
    if (retained[index] >= 0) (void)close(retained[index]);
  }
  if (result != 0) {
    for (index = HB_FIRST_CAPABILITY_FD; index <= HB_LAST_CAPABILITY_FD; index += 1) {
      (void)close(index);
    }
  }
  return result;
}

static int hb_parse_hex_nonce(
  const char *hex,
  unsigned char nonce[HB_NONCE_BYTES]
) {
  size_t index;
  if (hex == NULL || strlen(hex) != HB_NONCE_BYTES * 2U) return -1;
  for (index = 0; index < HB_NONCE_BYTES; index += 1) {
    unsigned int value;
    if (sscanf(&hex[index * 2U], "%2x", &value) != 1 || value > 255U) return -1;
    nonce[index] = (unsigned char)value;
  }
  return 0;
}

static int hb_parse_u64(const char *text, uint64_t *value) {
  char *end = NULL;
  unsigned long long parsed;
  if (text == NULL || text[0] == '\0' || text[0] == '-') return -1;
  errno = 0;
  parsed = strtoull(text, &end, 10);
  if (errno != 0 || end == text || *end != '\0') return -1;
  *value = (uint64_t)parsed;
  return 0;
}

static int hb_parse_int(const char *text, int *value) {
  char *end = NULL;
  long parsed;
  if (text == NULL || text[0] == '\0') return -1;
  errno = 0;
  parsed = strtol(text, &end, 10);
  if (errno != 0 || end == text || *end != '\0' || parsed < 0 || parsed > INT_MAX) return -1;
  *value = (int)parsed;
  return 0;
}

static int hb_connect_fresh(const char *listener_path) {
  struct sockaddr_un address;
  int fd;
  if (listener_path == NULL || listener_path[0] != '/'
      || strlen(listener_path) >= sizeof(address.sun_path)) return -1;
  fd = socket(AF_UNIX, SOCK_STREAM, 0);
  if (fd < 0 || fd != HB_CONNECTION_FD || hb_set_cloexec(fd) != 0
      || hb_set_no_sigpipe(fd) != 0) {
    if (fd >= 0) (void)close(fd);
    return -1;
  }
  memset(&address, 0, sizeof(address));
  address.sun_family = AF_UNIX;
  (void)strlcpy(address.sun_path, listener_path, sizeof(address.sun_path));
  if (connect(fd, (struct sockaddr *)&address, sizeof(address)) != 0) {
    (void)close(fd);
    return -1;
  }
  return fd;
}

static int hb_child_post_exec(
  const char *listener_path,
  const char *nonce_hex,
  const char *generation_text,
  const char *test_case_text,
  const char *inherited_fd_text
) {
  struct hb_kernel_identity identity;
  struct hb_wire_frame hello;
  struct hb_wire_frame grant;
  struct hb_wire_frame ready;
  struct hb_wire_frame go;
  struct hb_wire_frame result;
  struct hb_wire_frame terminal_ack;
  unsigned char nonce[HB_NONCE_BYTES];
  unsigned char capability_abi_digest[CC_SHA256_DIGEST_LENGTH];
  int decoys[HB_CAPABILITY_COUNT] = {-1, -1, -1, -1};
  int received_fds[HB_MAX_RECEIVED_FDS];
  int received_count = 0;
  int connection_fd;
  int inventory_fds[128];
  int inventory_before_count;
  int inventory_after_count;
  int inherited_fd;
  int test_case_number;
  uint64_t generation;
  int index;
  int go_consumed = 0;
  int replayed_go_rejected = 0;
  enum hb_test_case test_case;
  memset(received_fds, -1, sizeof(received_fds));
  if (hb_parse_hex_nonce(nonce_hex, nonce) != 0
      || hb_parse_u64(generation_text, &generation) != 0
      || hb_parse_int(test_case_text, &test_case_number) != 0
      || hb_parse_int(inherited_fd_text, &inherited_fd) != 0
      || generation == 0
      || test_case_number < HB_CASE_SUCCESS
      || test_case_number > HB_CASE_PRODUCTION_GATES_CLOSED
      || hb_capability_abi_digest(capability_abi_digest) != 0) return 64;
  test_case = (enum hb_test_case)test_case_number;
  if (hb_collect_fd_inventory(inventory_fds, 128, &inventory_before_count) != 0) return 65;
  if (test_case == HB_CASE_INHERITED_CONNECTED_SOCKET) {
    connection_fd = inherited_fd;
    if (connection_fd < 3 || hb_set_cloexec(connection_fd) != 0) return 66;
  } else {
    if (inventory_before_count != 3 || !hb_fd_inventory_exact(2)) return 67;
    connection_fd = hb_connect_fresh(listener_path);
    if (connection_fd != HB_CONNECTION_FD) return 68;
  }
  if (hb_collect_fd_inventory(inventory_fds, 128, &inventory_after_count) != 0
      || hb_capture_self_identity(&identity) != 0) return 69;
  hb_init_frame(&hello, HB_MESSAGE_HELLO, generation, nonce);
  hello.pid = (int32_t)identity.pid;
  hello.pidversion = identity.pidversion;
  hello.parent_pid = (int32_t)identity.parent_pid;
  hello.uid = identity.euid;
  hello.gid = identity.egid;
  hello.process_start_seconds = identity.start_seconds;
  hello.process_start_microseconds = identity.start_microseconds;
  hello.inventory_before_count = (uint32_t)inventory_before_count;
  hello.inventory_after_count = (uint32_t)inventory_after_count;
  if (test_case == HB_CASE_WRONG_NONCE) hello.nonce[0] ^= 0xffU;
  if (test_case == HB_CASE_WRONG_GENERATION) hello.listener_generation += 1U;
  if (hb_write_all(connection_fd, &hello, sizeof(hello)) != 0) return 70;
  if (test_case == HB_CASE_CRASH_AFTER_HELLO) _exit(71);
  for (index = 0; index < HB_CAPABILITY_COUNT; index += 1) {
    decoys[index] = open("/dev/null", O_RDONLY | O_CLOEXEC);
    if (decoys[index] != HB_FIRST_CAPABILITY_FD + index) return 72;
  }
  if (hb_receive_capability_grant(
      connection_fd,
      &grant,
      received_fds,
      &received_count,
      test_case == HB_CASE_ANCILLARY_TRUNCATION
    ) != 0) return 73;
  if (!hb_frame_base_valid(&grant, HB_MESSAGE_GRANT, generation, nonce)
      || grant.sequence == 0
      || grant.state != 0
      || grant.effect_count != 0
      || grant.capability_count != HB_CAPABILITY_COUNT
      || grant.descriptor_flags_mask != FD_CLOEXEC
      || grant.descriptor_flags_value != FD_CLOEXEC
      || memcmp(
        grant.capability_abi_digest,
        capability_abi_digest,
        sizeof(capability_abi_digest)
      ) != 0
      || hb_install_received_capabilities(
        received_fds,
        received_count,
        test_case,
        grant.capability_digest
      ) != 0) return 74;
  if (test_case == HB_CASE_REPLAYED_GRANT) {
    struct hb_wire_frame replay;
    int replay_fds[HB_MAX_RECEIVED_FDS];
    int replay_count = 0;
    memset(replay_fds, -1, sizeof(replay_fds));
    if (hb_receive_capability_grant(
        connection_fd,
        &replay,
        replay_fds,
        &replay_count,
        0
      ) == 0) hb_close_fd_array(replay_fds, replay_count);
    return 75;
  }
  if (test_case == HB_CASE_CRASH_AFTER_GRANT) _exit(76);
  if (test_case == HB_CASE_PRE_GO_EFFECT) {
    static const unsigned char effect = 0xa5U;
    if (hb_write_all(HB_FIRST_CAPABILITY_FD + 2, &effect, sizeof(effect)) != 0) return 77;
  }
  hb_init_frame(&ready, HB_MESSAGE_READY, generation, nonce);
  ready.state = HB_READY_NO_EFFECT;
  ready.sequence = grant.sequence;
  ready.inventory_before_count = 3;
  ready.inventory_after_count = HB_LAST_CAPABILITY_FD + 1U;
  ready.capability_count = HB_CAPABILITY_COUNT;
  ready.descriptor_flags_mask = FD_CLOEXEC;
  ready.descriptor_flags_value = FD_CLOEXEC;
  memcpy(ready.capability_digest, grant.capability_digest, sizeof(ready.capability_digest));
  memcpy(ready.capability_abi_digest, capability_abi_digest,
    sizeof(ready.capability_abi_digest));
  if (hb_write_all(connection_fd, &ready, sizeof(ready)) != 0) return 78;
  if (test_case == HB_CASE_CRASH_AFTER_READY) _exit(79);
  if (hb_read_all(connection_fd, &go, sizeof(go)) != 0
      || !hb_frame_base_valid(&go, HB_MESSAGE_GO, generation, nonce)
      || go.state != HB_COMMIT_GO
      || go.sequence <= grant.sequence
      || go.effect_count != 0
      || go.capability_count != HB_CAPABILITY_COUNT
      || go.descriptor_flags_mask != FD_CLOEXEC
      || go.descriptor_flags_value != FD_CLOEXEC
      || memcmp(go.capability_digest, grant.capability_digest,
        sizeof(go.capability_digest)) != 0
      || memcmp(go.capability_abi_digest, capability_abi_digest,
        sizeof(go.capability_abi_digest)) != 0
      || go_consumed != 0) return 80;
  go_consumed = 1;
  if (test_case == HB_CASE_CRASH_AFTER_GO) _exit(81);
  {
    static const unsigned char effect = 0x5aU;
    if (hb_write_all(HB_FIRST_CAPABILITY_FD + 2, &effect, sizeof(effect)) != 0) return 82;
  }
  if (test_case == HB_CASE_CRASH_AFTER_EFFECT) _exit(83);
  hb_init_frame(&result, HB_MESSAGE_RESULT, generation, nonce);
  result.state = HB_RESULT_EFFECT_ONCE;
  result.sequence = go.sequence;
  result.effect_count = 1;
  result.capability_count = HB_CAPABILITY_COUNT;
  result.descriptor_flags_mask = FD_CLOEXEC;
  result.descriptor_flags_value = FD_CLOEXEC;
  memcpy(result.capability_digest, grant.capability_digest,
    sizeof(result.capability_digest));
  memcpy(result.capability_abi_digest, capability_abi_digest,
    sizeof(result.capability_abi_digest));
  if (hb_write_all(connection_fd, &result, sizeof(result)) != 0) return 84;
  if (test_case == HB_CASE_CRASH_AFTER_RESULT) _exit(87);
  if (test_case == HB_CASE_REPLAYED_GO) {
    struct hb_wire_frame replay;
    if (hb_read_all(connection_fd, &replay, sizeof(replay)) != 0
        || !hb_frame_base_valid(&replay, HB_MESSAGE_GO, generation, nonce)
        || replay.sequence != go.sequence
        || go_consumed != 1) return 85;
    replayed_go_rejected = 1;
  }
  if (hb_read_all(connection_fd, &terminal_ack, sizeof(terminal_ack)) != 0
      || !hb_frame_base_valid(
        &terminal_ack, HB_MESSAGE_TERMINAL_ACK, generation, nonce
      )
      || terminal_ack.state != HB_TERMINAL_IDENTITY_ACCEPTED
      || terminal_ack.sequence != go.sequence
      || terminal_ack.effect_count != 1
      || terminal_ack.capability_count != HB_CAPABILITY_COUNT
      || terminal_ack.descriptor_flags_mask != FD_CLOEXEC
      || terminal_ack.descriptor_flags_value != FD_CLOEXEC
      || memcmp(terminal_ack.capability_digest, grant.capability_digest,
        sizeof(terminal_ack.capability_digest)) != 0
      || memcmp(terminal_ack.capability_abi_digest, capability_abi_digest,
        sizeof(terminal_ack.capability_abi_digest)) != 0) return 88;
  return replayed_go_rejected ? 86 : 0;
}

static int hb_make_regular_file(
  const char *directory,
  const char *name,
  int open_flags,
  int *fd_output
) {
  char path[PATH_MAX];
  int create_fd;
  int fd;
  if (snprintf(path, sizeof(path), "%s/%s", directory, name) <= 0) return -1;
  create_fd = open(path, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
  if (create_fd < 0 || write(create_fd, name, strlen(name)) != (ssize_t)strlen(name)
      || fsync(create_fd) != 0 || close(create_fd) != 0) return -1;
  fd = open(path, open_flags | O_CLOEXEC);
  if (fd < 0) return -1;
  *fd_output = fd;
  return 0;
}

static int hb_setup_fixture(struct hb_test_fixture *fixture) {
  struct sockaddr_un address;
  struct stat directory_status;
  int effect_pair[2] = {-1, -1};
  char directory_template[] = "/tmp/hb-post-exec-release.XXXXXX";
  char *directory;
  uint64_t random_values[2];
  int index;
  memset(fixture, 0, sizeof(*fixture));
  fixture->listener_fd = -1;
  fixture->accepted_fd = -1;
  fixture->effect_peer_fd = -1;
  fixture->inherited_peer_fd = -1;
  fixture->inherited_child_fd = -1;
  fixture->direct_child = -1;
  fixture->attacker_child = -1;
  for (index = 0; index < HB_CAPABILITY_COUNT; index += 1) {
    fixture->capability_fds[index] = -1;
  }
  directory = mkdtemp(directory_template);
  if (directory == NULL || chmod(directory, 0700) != 0
      || lstat(directory, &directory_status) != 0
      || !S_ISDIR(directory_status.st_mode)
      || S_ISLNK(directory_status.st_mode)
      || directory_status.st_uid != getuid()
      || (directory_status.st_mode & 0777U) != 0700U
      || strlcpy(fixture->directory, directory, sizeof(fixture->directory))
        >= sizeof(fixture->directory)
      || snprintf(
        fixture->listener_path,
        sizeof(fixture->listener_path),
        "%s/listener",
        directory
      ) <= 0) return -1;
  {
    uint32_t path_size = (uint32_t)sizeof(fixture->executable_path);
    char unresolved[PATH_MAX];
    if (_NSGetExecutablePath(unresolved, &path_size) != 0
        || realpath(unresolved, fixture->executable_path) == NULL) return -1;
  }
  fixture->listener_fd = socket(AF_UNIX, SOCK_STREAM, 0);
  if (fixture->listener_fd < 0 || hb_set_cloexec(fixture->listener_fd) != 0
      || hb_set_no_sigpipe(fixture->listener_fd) != 0) return -1;
  memset(&address, 0, sizeof(address));
  address.sun_family = AF_UNIX;
  (void)strlcpy(address.sun_path, fixture->listener_path, sizeof(address.sun_path));
  if (bind(fixture->listener_fd, (struct sockaddr *)&address, sizeof(address)) != 0
      || listen(fixture->listener_fd, 2) != 0) return -1;
  if (hb_make_regular_file(
      fixture->directory, "artifact", O_RDONLY, &fixture->capability_fds[0]
    ) != 0
      || hb_make_regular_file(
        fixture->directory, "context", O_RDONLY, &fixture->capability_fds[1]
      ) != 0
      || socketpair(AF_UNIX, SOCK_STREAM, 0, effect_pair) != 0
      || hb_set_cloexec(effect_pair[0]) != 0
      || hb_set_cloexec(effect_pair[1]) != 0
      || hb_set_no_sigpipe(effect_pair[0]) != 0
      || hb_set_no_sigpipe(effect_pair[1]) != 0
      || hb_make_regular_file(
        fixture->directory,
        "result",
        O_WRONLY | O_APPEND,
        &fixture->capability_fds[3]
      ) != 0) return -1;
  fixture->capability_fds[2] = effect_pair[0];
  fixture->effect_peer_fd = effect_pair[1];
  arc4random_buf(fixture->nonce, sizeof(fixture->nonce));
  arc4random_buf(random_values, sizeof(random_values));
  fixture->generation = random_values[0] == 0 ? 1 : random_values[0];
  fixture->grant_sequence = random_values[1] == 0 || random_values[1] == UINT64_MAX
    ? 1 : random_values[1];
  fixture->go_sequence = fixture->grant_sequence + 1U;
  if (hb_capability_digest(fixture->capability_fds, fixture->capability_digest) != 0
      || hb_capability_abi_digest(fixture->capability_abi_digest) != 0) return -1;
  return 0;
}

static void hb_reap_or_kill(pid_t child) {
  int status;
  pid_t waited;
  int attempts;
  if (child <= 0) return;
  for (attempts = 0; attempts < 20; attempts += 1) {
    waited = waitpid(child, &status, WNOHANG);
    if (waited == child || (waited < 0 && errno == ECHILD)) return;
    (void)usleep(10000U);
  }
  (void)kill(child, SIGKILL);
  do {
    waited = waitpid(child, &status, 0);
  } while (waited < 0 && errno == EINTR);
}

static void hb_cleanup_fixture(struct hb_test_fixture *fixture) {
  int index;
  for (index = 0; index < HB_CAPABILITY_COUNT; index += 1) {
    if (fixture->capability_fds[index] >= 0) (void)close(fixture->capability_fds[index]);
  }
  if (fixture->accepted_fd >= 0) (void)close(fixture->accepted_fd);
  if (fixture->listener_fd >= 0) (void)close(fixture->listener_fd);
  if (fixture->effect_peer_fd >= 0) (void)close(fixture->effect_peer_fd);
  if (fixture->inherited_peer_fd >= 0) (void)close(fixture->inherited_peer_fd);
  if (fixture->inherited_child_fd >= 0) (void)close(fixture->inherited_child_fd);
  hb_reap_or_kill(fixture->attacker_child);
  hb_reap_or_kill(fixture->direct_child);
  if (fixture->listener_path[0] != '\0') (void)unlink(fixture->listener_path);
  if (fixture->directory[0] != '\0') {
    char path[PATH_MAX];
    static const char *const names[] = {"artifact", "context", "result"};
    for (index = 0; index < 3; index += 1) {
      if (snprintf(path, sizeof(path), "%s/%s", fixture->directory, names[index]) > 0) {
        (void)unlink(path);
      }
    }
    (void)rmdir(fixture->directory);
  }
}

static void hb_nonce_hex(
  const unsigned char nonce[HB_NONCE_BYTES],
  char output[HB_NONCE_BYTES * 2U + 1U]
) {
  static const char digits[] = "0123456789abcdef";
  size_t index;
  for (index = 0; index < HB_NONCE_BYTES; index += 1) {
    output[index * 2U] = digits[nonce[index] >> 4U];
    output[index * 2U + 1U] = digits[nonce[index] & 0x0fU];
  }
  output[HB_NONCE_BYTES * 2U] = '\0';
}

static int hb_spawn_direct_child(
  struct hb_test_fixture *fixture,
  enum hb_test_case test_case
) {
  char nonce_hex[HB_NONCE_BYTES * 2U + 1U];
  char generation_text[32];
  char test_case_text[16];
  char inherited_fd_text[16];
  int inherited_pair[2] = {-1, -1};
  pid_t child;
  if (test_case == HB_CASE_INHERITED_CONNECTED_SOCKET) {
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, inherited_pair) != 0
        || fcntl(inherited_pair[1], F_SETFD, 0) != 0
        || hb_set_no_sigpipe(inherited_pair[1]) != 0) return -1;
    fixture->inherited_peer_fd = inherited_pair[0];
    fixture->inherited_child_fd = inherited_pair[1];
  }
  hb_nonce_hex(fixture->nonce, nonce_hex);
  if (snprintf(generation_text, sizeof(generation_text), "%llu",
      (unsigned long long)fixture->generation) <= 0
      || snprintf(test_case_text, sizeof(test_case_text), "%d", (int)test_case) <= 0
      || snprintf(
        inherited_fd_text,
        sizeof(inherited_fd_text),
        "%d",
        test_case == HB_CASE_INHERITED_CONNECTED_SOCKET
          ? fixture->inherited_child_fd : 0
      ) <= 0) return -1;
  child = fork();
  if (child < 0) return -1;
  if (child == 0) {
    char *const child_argv[] = {
      fixture->executable_path,
      (char *)HB_CHILD_GATE,
      fixture->listener_path,
      nonce_hex,
      generation_text,
      test_case_text,
      inherited_fd_text,
      NULL,
    };
    char *const empty_environment[] = {NULL};
    int retained = test_case == HB_CASE_INHERITED_CONNECTED_SOCKET
      ? fixture->inherited_child_fd : -1;
    hb_close_all_except(retained);
    if (chdir("/var/empty") != 0) _exit(120);
    execve(fixture->executable_path, child_argv, empty_environment);
    _exit(121);
  }
  fixture->direct_child = child;
  if (fixture->inherited_child_fd >= 0) {
    (void)close(fixture->inherited_child_fd);
    fixture->inherited_child_fd = -1;
  }
  return 0;
}

static int hb_spawn_wrong_peer(struct hb_test_fixture *fixture) {
  pid_t attacker = fork();
  if (attacker < 0) return -1;
  if (attacker == 0) {
    struct hb_wire_frame hello;
    struct hb_kernel_identity identity;
    int fd;
    hb_close_all_except(-1);
    fd = hb_connect_fresh(fixture->listener_path);
    if (fd != HB_CONNECTION_FD || hb_capture_self_identity(&identity) != 0) _exit(122);
    hb_init_frame(&hello, HB_MESSAGE_HELLO, fixture->generation, fixture->nonce);
    hello.pid = (int32_t)identity.pid;
    hello.pidversion = identity.pidversion;
    hello.parent_pid = (int32_t)identity.parent_pid;
    hello.uid = identity.euid;
    hello.gid = identity.egid;
    hello.process_start_seconds = identity.start_seconds;
    hello.process_start_microseconds = identity.start_microseconds;
    hello.inventory_before_count = 3;
    hello.inventory_after_count = 4;
    if (hb_write_all(fd, &hello, sizeof(hello)) != 0) _exit(123);
    {
      unsigned char terminal;
      ssize_t received;
      do {
        received = read(fd, &terminal, sizeof(terminal));
      } while (received < 0 && errno == EINTR);
    }
    _exit(0);
  }
  fixture->attacker_child = attacker;
  return 0;
}

static int hb_accept_peer(struct hb_test_fixture *fixture) {
  if (hb_poll_fd(fixture->listener_fd, POLLIN, HB_IO_TIMEOUT_MS) != 0) return -1;
  do {
    fixture->accepted_fd = accept(fixture->listener_fd, NULL, NULL);
  } while (fixture->accepted_fd < 0 && errno == EINTR);
  if (fixture->accepted_fd < 0 || hb_set_cloexec(fixture->accepted_fd) != 0
      || hb_set_no_sigpipe(fixture->accepted_fd) != 0) return -1;
  return 0;
}

static int hb_peer_and_hello_valid_for_pid(
  struct hb_test_fixture *fixture,
  const struct hb_wire_frame *hello,
  pid_t expected_pid,
  struct hb_kernel_identity *identity
) {
  struct hb_kernel_identity repeated;
  if (expected_pid <= 0
      || hb_capture_peer_identity(fixture->accepted_fd, identity) != 0
      || identity->pid != expected_pid
      || identity->parent_pid != getpid()
      || identity->euid != geteuid()
      || identity->egid != getegid()
      || identity->ruid != getuid()
      || identity->rgid != getgid()
      || strcmp(identity->executable_path, fixture->executable_path) != 0
      || !hb_frame_base_valid(
        hello, HB_MESSAGE_HELLO, fixture->generation, fixture->nonce
      )
      || hello->state != 0
      || hello->sequence != 0
      || hello->pid != (int32_t)identity->pid
      || hello->pidversion != identity->pidversion
      || hello->parent_pid != (int32_t)identity->parent_pid
      || hello->uid != identity->euid
      || hello->gid != identity->egid
      || hello->process_start_seconds != identity->start_seconds
      || hello->process_start_microseconds != identity->start_microseconds
      || hello->inventory_before_count != 3
      || hello->inventory_after_count != 4
      || hello->effect_count != 0
      || hello->capability_count != 0
      || hello->descriptor_flags_mask != 0
      || hello->descriptor_flags_value != 0
      || hb_capture_peer_identity(fixture->accepted_fd, &repeated) != 0
      || !hb_kernel_identity_equal(identity, &repeated)) return 0;
  return 1;
}

static int hb_direct_peer_and_hello_valid(
  struct hb_test_fixture *fixture,
  const struct hb_wire_frame *hello,
  struct hb_kernel_identity *identity
) {
  return hb_peer_and_hello_valid_for_pid(
    fixture,
    hello,
    fixture->direct_child,
    identity
  );
}

static int hb_wrong_peer_rejection_exact(
  struct hb_test_fixture *fixture,
  const struct hb_wire_frame *hello
) {
  struct hb_kernel_identity identity;
  return fixture->attacker_child > 0
    && fixture->direct_child > 0
    && fixture->attacker_child != fixture->direct_child
    && hb_peer_and_hello_valid_for_pid(
      fixture,
      hello,
      fixture->attacker_child,
      &identity
    )
    && identity.pid == fixture->attacker_child
    && identity.pid != fixture->direct_child;
}

static int hb_effect_count(struct hb_test_fixture *fixture) {
  unsigned char bytes[8];
  ssize_t received;
  if (hb_poll_fd(fixture->effect_peer_fd, POLLIN, 100) != 0) return 0;
  do {
    received = read(fixture->effect_peer_fd, bytes, sizeof(bytes));
  } while (received < 0 && errno == EINTR);
  return received < 0 ? -1 : (int)received;
}

static int hb_child_exit_status(pid_t child, int *exit_status) {
  int status;
  pid_t waited;
  do {
    waited = waitpid(child, &status, 0);
  } while (waited < 0 && errno == EINTR);
  if (waited != child || !WIFEXITED(status)) return -1;
  *exit_status = WEXITSTATUS(status);
  return 0;
}

static enum hb_fixture_outcome hb_supervise_test_launch(
  struct hb_test_fixture *fixture,
  enum hb_test_case test_case
) {
  struct hb_wire_frame hello;
  struct hb_wire_frame grant;
  struct hb_wire_frame ready;
  struct hb_wire_frame go;
  struct hb_wire_frame result;
  struct hb_wire_frame terminal_ack;
  struct hb_kernel_identity identity_before;
  struct hb_kernel_identity identity_after;
  struct hb_kernel_identity identity_terminal;
  int sent_fds[HB_MAX_RECEIVED_FDS];
  int sent_count = HB_CAPABILITY_COUNT;
  int effect_count;
  int child_status = -1;
  int index;
  for (index = 0; index < HB_CAPABILITY_COUNT; index += 1) {
    sent_fds[index] = fixture->capability_fds[index];
  }
  if (test_case == HB_CASE_INHERITED_CONNECTED_SOCKET) {
    if (hb_poll_fd(fixture->listener_fd, POLLIN, 250) == 0) {
      (void)hb_accept_peer(fixture);
    }
    return HB_FIXTURE_HOSTILE_REJECTED;
  }
  if ((fixture->accepted_fd < 0 && hb_accept_peer(fixture) != 0)
      || hb_read_all(fixture->accepted_fd, &hello, sizeof(hello)) != 0) {
    return HB_FIXTURE_REJECTED_NO_EFFECT;
  }
  if (test_case == HB_CASE_WRONG_PEER) {
    if (!hb_wrong_peer_rejection_exact(fixture, &hello)) {
      return HB_FIXTURE_REJECTED_NO_EFFECT;
    }
    return hb_effect_count(fixture) == 0
      ? HB_FIXTURE_HOSTILE_REJECTED : HB_FIXTURE_AMBIGUOUS_QUARANTINED;
  }
  if (!hb_direct_peer_and_hello_valid(fixture, &hello, &identity_before)) {
    return test_case == HB_CASE_CRASH_AFTER_HELLO
      ? HB_FIXTURE_REJECTED_NO_EFFECT : HB_FIXTURE_HOSTILE_REJECTED;
  }
  if (test_case == HB_CASE_CRASH_AFTER_HELLO) {
    if (hb_child_exit_status(fixture->direct_child, &child_status) == 0) {
      fixture->direct_child = -1;
    }
    return hb_effect_count(fixture) == 0
      ? HB_FIXTURE_REJECTED_NO_EFFECT
      : HB_FIXTURE_AMBIGUOUS_QUARANTINED;
  }
  if (fixture->grant_sequence == 0
      || fixture->go_sequence <= fixture->grant_sequence) {
    return HB_FIXTURE_REJECTED_NO_EFFECT;
  }
  hb_init_frame(&grant, HB_MESSAGE_GRANT, fixture->generation, fixture->nonce);
  grant.sequence = fixture->grant_sequence;
  grant.capability_count = HB_CAPABILITY_COUNT;
  grant.descriptor_flags_mask = FD_CLOEXEC;
  grant.descriptor_flags_value = FD_CLOEXEC;
  memcpy(grant.capability_digest, fixture->capability_digest,
    sizeof(grant.capability_digest));
  memcpy(grant.capability_abi_digest, fixture->capability_abi_digest,
    sizeof(grant.capability_abi_digest));
  if (test_case == HB_CASE_MALFORMED_ANCILLARY_BOUNDS) {
    if (hb_test_oversized_control_record_rejected(sent_fds) != 0) {
      return HB_FIXTURE_REJECTED_NO_EFFECT;
    }
    return hb_effect_count(fixture) == 0
      ? HB_FIXTURE_HOSTILE_REJECTED : HB_FIXTURE_AMBIGUOUS_QUARANTINED;
  }
  if (test_case == HB_CASE_EXTRA_DESCRIPTORS) {
    sent_fds[4] = fixture->effect_peer_fd;
    sent_count = 5;
  } else if (test_case == HB_CASE_ANCILLARY_TRUNCATION) {
    sent_fds[4] = fixture->effect_peer_fd;
    sent_fds[5] = fixture->listener_fd;
    sent_count = 6;
  } else if (test_case == HB_CASE_DESCRIPTOR_ALIAS) {
    sent_fds[1] = sent_fds[0];
  } else if (test_case == HB_CASE_DESCRIPTOR_ORDER) {
    int temporary = sent_fds[0];
    sent_fds[0] = sent_fds[1];
    sent_fds[1] = temporary;
  }
  if (test_case == HB_CASE_SPLIT_ANCILLARY_RECORDS) {
    if (hb_test_split_control_records_rejected(sent_fds) != 0) {
      return HB_FIXTURE_REJECTED_NO_EFFECT;
    }
    /* Darwin may reject or canonicalize duplicate SCM_RIGHTS records before
     * delivery. Attempt the real hostile send as well as exercising the exact
     * receiver parser above; neither path is allowed to reach GO. */
    (void)hb_send_split_capability_grant(
      fixture->accepted_fd,
      &grant,
      sent_fds
    );
    return hb_effect_count(fixture) == 0
      ? HB_FIXTURE_HOSTILE_REJECTED : HB_FIXTURE_AMBIGUOUS_QUARANTINED;
  }
  if (hb_send_capability_grant(
      fixture->accepted_fd, &grant, sent_fds, sent_count
    ) != 0) return HB_FIXTURE_REJECTED_NO_EFFECT;
  if (test_case == HB_CASE_REPLAYED_GRANT) {
    (void)hb_send_capability_grant(
      fixture->accepted_fd, &grant, sent_fds, sent_count
    );
  }
  if (test_case == HB_CASE_EXTRA_DESCRIPTORS
      || test_case == HB_CASE_ANCILLARY_TRUNCATION
      || test_case == HB_CASE_DESCRIPTOR_ALIAS
      || test_case == HB_CASE_DESCRIPTOR_ORDER
      || test_case == HB_CASE_MISSING_CLOEXEC
      || test_case == HB_CASE_UNEXPECTED_DESCRIPTOR
      || test_case == HB_CASE_REPLAYED_GRANT
      || test_case == HB_CASE_CRASH_AFTER_GRANT) {
    (void)hb_child_exit_status(fixture->direct_child, &child_status);
    fixture->direct_child = -1;
    return hb_effect_count(fixture) == 0
      ? (test_case == HB_CASE_CRASH_AFTER_GRANT
        ? HB_FIXTURE_REJECTED_NO_EFFECT
        : HB_FIXTURE_HOSTILE_REJECTED)
      : HB_FIXTURE_AMBIGUOUS_QUARANTINED;
  }
  {
    int ready_read = hb_read_all(fixture->accepted_fd, &ready, sizeof(ready));
    int capability_stable = ready_read == 0
      ? hb_capability_digest(fixture->capability_fds, fixture->capability_digest) : -1;
    int peer_stable = ready_read == 0
      ? hb_capture_peer_identity(fixture->accepted_fd, &identity_after) : -1;
    if (ready_read != 0
        || !hb_frame_base_valid(
          &ready, HB_MESSAGE_READY, fixture->generation, fixture->nonce
        )
        || ready.state != HB_READY_NO_EFFECT
        || ready.sequence != fixture->grant_sequence
        || ready.inventory_before_count != 3
        || ready.inventory_after_count != 8
        || ready.effect_count != 0
        || ready.capability_count != HB_CAPABILITY_COUNT
        || ready.descriptor_flags_mask != FD_CLOEXEC
        || ready.descriptor_flags_value != FD_CLOEXEC
        || memcmp(ready.capability_digest, fixture->capability_digest,
          sizeof(ready.capability_digest)) != 0
        || memcmp(ready.capability_abi_digest, fixture->capability_abi_digest,
          sizeof(ready.capability_abi_digest)) != 0
        || capability_stable != 0
        || peer_stable != 0
        || !hb_kernel_identity_equal(&identity_before, &identity_after)) {
      return HB_FIXTURE_REJECTED_NO_EFFECT;
    }
  }
  effect_count = hb_effect_count(fixture);
  if (test_case == HB_CASE_PRE_GO_EFFECT) {
    return effect_count == 1
      ? HB_FIXTURE_AMBIGUOUS_QUARANTINED
      : HB_FIXTURE_REJECTED_NO_EFFECT;
  }
  if (effect_count != 0) return HB_FIXTURE_AMBIGUOUS_QUARANTINED;
  if (test_case == HB_CASE_CRASH_AFTER_READY) {
    (void)hb_child_exit_status(fixture->direct_child, &child_status);
    fixture->direct_child = -1;
    return hb_effect_count(fixture) == 0
      ? HB_FIXTURE_REJECTED_NO_EFFECT
      : HB_FIXTURE_AMBIGUOUS_QUARANTINED;
  }
  hb_init_frame(&go, HB_MESSAGE_GO, fixture->generation, fixture->nonce);
  go.state = HB_COMMIT_GO;
  go.sequence = fixture->go_sequence;
  go.capability_count = HB_CAPABILITY_COUNT;
  go.descriptor_flags_mask = FD_CLOEXEC;
  go.descriptor_flags_value = FD_CLOEXEC;
  memcpy(go.capability_digest, fixture->capability_digest,
    sizeof(go.capability_digest));
  memcpy(go.capability_abi_digest, fixture->capability_abi_digest,
    sizeof(go.capability_abi_digest));
  if (hb_write_all(fixture->accepted_fd, &go, sizeof(go)) != 0) {
    return HB_FIXTURE_AMBIGUOUS_QUARANTINED;
  }
  if (test_case == HB_CASE_REPLAYED_GO) {
    (void)hb_write_all(fixture->accepted_fd, &go, sizeof(go));
  }
  if (test_case == HB_CASE_CRASH_AFTER_GO) {
    (void)hb_child_exit_status(fixture->direct_child, &child_status);
    fixture->direct_child = -1;
    return HB_FIXTURE_AMBIGUOUS_QUARANTINED;
  }
  if (test_case == HB_CASE_CRASH_AFTER_EFFECT) {
    (void)hb_child_exit_status(fixture->direct_child, &child_status);
    fixture->direct_child = -1;
    return hb_effect_count(fixture) == 1
      ? HB_FIXTURE_AMBIGUOUS_QUARANTINED
      : HB_FIXTURE_REJECTED_NO_EFFECT;
  }
  if (hb_read_all(fixture->accepted_fd, &result, sizeof(result)) != 0
      || !hb_frame_base_valid(
        &result, HB_MESSAGE_RESULT, fixture->generation, fixture->nonce
      )
      || result.state != HB_RESULT_EFFECT_ONCE
      || result.sequence != fixture->go_sequence
      || result.effect_count != 1
      || result.capability_count != HB_CAPABILITY_COUNT
      || result.descriptor_flags_mask != FD_CLOEXEC
      || result.descriptor_flags_value != FD_CLOEXEC
      || memcmp(result.capability_digest, fixture->capability_digest,
        sizeof(result.capability_digest)) != 0
      || memcmp(result.capability_abi_digest, fixture->capability_abi_digest,
        sizeof(result.capability_abi_digest)) != 0
      || hb_effect_count(fixture) != 1) return HB_FIXTURE_AMBIGUOUS_QUARANTINED;
  if (test_case == HB_CASE_CRASH_AFTER_RESULT) (void)usleep(100000U);
  if (hb_capture_peer_identity(fixture->accepted_fd, &identity_terminal) != 0
      || !hb_kernel_identity_equal(&identity_before, &identity_terminal)) {
    return HB_FIXTURE_AMBIGUOUS_QUARANTINED;
  }
  hb_init_frame(
    &terminal_ack,
    HB_MESSAGE_TERMINAL_ACK,
    fixture->generation,
    fixture->nonce
  );
  terminal_ack.state = HB_TERMINAL_IDENTITY_ACCEPTED;
  terminal_ack.sequence = fixture->go_sequence;
  terminal_ack.effect_count = 1;
  terminal_ack.capability_count = HB_CAPABILITY_COUNT;
  terminal_ack.descriptor_flags_mask = FD_CLOEXEC;
  terminal_ack.descriptor_flags_value = FD_CLOEXEC;
  memcpy(terminal_ack.capability_digest, fixture->capability_digest,
    sizeof(terminal_ack.capability_digest));
  memcpy(terminal_ack.capability_abi_digest, fixture->capability_abi_digest,
    sizeof(terminal_ack.capability_abi_digest));
  if (hb_write_all(
      fixture->accepted_fd,
      &terminal_ack,
      sizeof(terminal_ack)
    ) != 0) return HB_FIXTURE_AMBIGUOUS_QUARANTINED;
  if (hb_child_exit_status(fixture->direct_child, &child_status) != 0) {
    return HB_FIXTURE_AMBIGUOUS_QUARANTINED;
  }
  fixture->direct_child = -1;
  if (test_case == HB_CASE_REPLAYED_GO) {
    return child_status == 86 ? HB_FIXTURE_HOSTILE_REJECTED
      : HB_FIXTURE_AMBIGUOUS_QUARANTINED;
  }
  return child_status == 0 ? HB_FIXTURE_SUCCESS : HB_FIXTURE_AMBIGUOUS_QUARANTINED;
}

static enum hb_fixture_outcome hb_expected_outcome(enum hb_test_case test_case) {
  switch (test_case) {
    case HB_CASE_SUCCESS:
      return HB_FIXTURE_SUCCESS;
    case HB_CASE_CRASH_AFTER_HELLO:
    case HB_CASE_CRASH_AFTER_GRANT:
    case HB_CASE_CRASH_AFTER_READY:
      return HB_FIXTURE_REJECTED_NO_EFFECT;
    case HB_CASE_CRASH_AFTER_GO:
    case HB_CASE_CRASH_AFTER_EFFECT:
    case HB_CASE_CRASH_AFTER_RESULT:
    case HB_CASE_PRE_GO_EFFECT:
      return HB_FIXTURE_AMBIGUOUS_QUARANTINED;
    default:
      return HB_FIXTURE_HOSTILE_REJECTED;
  }
}

static int hb_run_test_case(enum hb_test_case test_case) {
  struct hb_test_fixture fixture;
  struct hb_production_release_plan production_plan;
  enum hb_fixture_outcome outcome;
  int result;
  if (test_case == HB_CASE_PRODUCTION_GATES_CLOSED) {
    memset(&production_plan, 0, sizeof(production_plan));
    return hb_post_exec_capability_release_production_unavailable(&production_plan) == -1
      && hb_security_framework_live_guest_attestation_fail_closed(&production_plan) == -1
      && hb_retained_fd_live_mh_execute_measurement_fail_closed(&production_plan) == -1
      && hb_authenticated_durable_grant_go_outbox_fail_closed(&production_plan) == -1
      ? 0 : 1;
  }
  if (hb_setup_fixture(&fixture) != 0) {
    hb_cleanup_fixture(&fixture);
    return 2;
  }
  if (test_case == HB_CASE_WRONG_PEER
      && (hb_spawn_wrong_peer(&fixture) != 0
        || hb_accept_peer(&fixture) != 0)) {
    hb_cleanup_fixture(&fixture);
    return 3;
  }
  if (hb_spawn_direct_child(&fixture, test_case) != 0) {
    hb_cleanup_fixture(&fixture);
    return 3;
  }
  outcome = hb_supervise_test_launch(&fixture, test_case);
  result = outcome == hb_expected_outcome(test_case) ? 0 : 4 + (int)outcome;
  hb_cleanup_fixture(&fixture);
  return result;
}

static int hb_run_selftests(void) {
  int test_case;
  for (test_case = HB_CASE_SUCCESS;
       test_case <= HB_CASE_PRODUCTION_GATES_CLOSED;
       test_case += 1) {
    int result = hb_run_test_case((enum hb_test_case)test_case);
    if (result != 0) {
      (void)fprintf(stderr, "post-exec release selftest failed: %d (%d)\n", test_case, result);
      return 65;
    }
  }
  (void)printf(
    "{\"version\":1,\"kind\":\"darwin_post_exec_capability_release_selftest\","
    "\"tests\":23,\"path_exec_powerless\":true,\"fresh_unix_peer_bound\":true,"
    "\"wrong_peer_preaccepted_before_direct_child\":true,"
    "\"scm_rights_closed_set_once\":true,\"ready_no_effect_then_commit_go\":true,"
    "\"terminal_peer_identity_refreshed\":true,"
    "\"security_framework_attested\":false,\"mapped_image_bound\":false,"
    "\"durable_state_authenticated\":false,\"production_attested\":false,"
    "\"production_ready\":false,\"hardware_access_authorized\":false}\n"
  );
  return 0;
}

int main(int argc, char **argv) {
  if (argc == 2 && strcmp(argv[1], HB_SELFTEST_GATE) == 0) {
    return hb_run_selftests();
  }
  if (argc == 7 && strcmp(argv[1], HB_CHILD_GATE) == 0) {
    return hb_child_post_exec(argv[2], argv[3], argv[4], argv[5], argv[6]);
  }
  return 64;
}
#endif
