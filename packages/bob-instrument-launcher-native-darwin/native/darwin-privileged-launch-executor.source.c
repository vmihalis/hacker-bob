#define _DARWIN_C_SOURCE 1

/*
 * Source-only Darwin privileged launch executor.
 *
 * This translation unit is intentionally not linked into the installed
 * diagnostic launcher fixture.  A release build may compile it only after an
 * independently authenticated wire parser has produced hb_launch_context and
 * after the resulting executable has passed signed-prebuild, immutable-install,
 * and HIL qualification.  The test build replaces only credential and exec
 * syscalls; descriptor projection and inventory use real local PTY/socket
 * fixtures.
 */
#if defined(HB_PRIVILEGED_LAUNCH_SOURCE_ONLY) == defined(HB_PRIVILEGED_LAUNCH_TEST_ONLY)
#error "define exactly one privileged-launch executor build gate"
#endif

#include <CommonCrypto/CommonDigest.h>
#include <libproc.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>

#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#ifdef HB_PRIVILEGED_LAUNCH_TEST_ONLY
#include <util.h>
#endif

#define HB_CONTEXT_SOURCE_FD 7
#define HB_DEVICE_SOURCE_FD 8
#define HB_DISPATCH_SOURCE_FD 9
#define HB_RESULT_SOURCE_FD 10
#define HB_VAULT_SINK_SOURCE_FD 11
#define HB_CONTEXT_CHILD_FD 3
#define HB_DEVICE_CHILD_FD 4
#define HB_DISPATCH_CHILD_FD 5
#define HB_RESULT_CHILD_FD 6
#define HB_VAULT_SINK_CHILD_FD 7
#define HB_DESCRIPTOR_COUNT 5
#define HB_CHILD_DESCRIPTOR_COUNT 8
#define HB_FIRST_RETAINED_FD 64
#define HB_MAX_INVENTORY_FDS 1024
#define HB_MAX_SUPPLEMENTARY_GROUPS 16
#define HB_RESULT_RECORD_BYTES 196
#define HB_CONTEXT_VERSION 1U
#define HB_CHILD_IMAGE_KIND_STANDALONE 1U
#define HB_CHILD_GATE "--fixture-native-dispatch-custodian-v1"
#define HB_CHILD_IMAGE "/Library/HackerBob/OptionalProviders/chameleon_ultra/current/bin/bob-chameleon-native-dispatch-custodian"
#define HB_CHILD_WORKING_DIRECTORY "/var/empty"

enum hb_launch_status {
  HB_LAUNCH_EXEC_REACHED = 1,
  HB_LAUNCH_REJECTED = -1,
  HB_LAUNCH_DESCRIPTOR_REJECTED = -2,
  HB_LAUNCH_INVENTORY_REJECTED = -3,
  HB_LAUNCH_CREDENTIAL_REJECTED = -4,
  HB_LAUNCH_EXEC_REJECTED = -5
};

enum hb_descriptor_role {
  HB_DESCRIPTOR_CONTEXT = 1,
  HB_DESCRIPTOR_DEVICE = 2,
  HB_DESCRIPTOR_DISPATCH = 3,
  HB_DESCRIPTOR_RESULT = 4,
  HB_DESCRIPTOR_VAULT_SINK = 5
};

struct hb_descriptor_identity {
  uint64_t dev;
  uint64_t ino;
  uint64_t rdev;
  uint64_t mode;
  uint64_t nlink;
  uint64_t uid;
  uint64_t gid;
  uint64_t size;
  int access_mode;
  int status_flags;
  int descriptor_flags;
  int socket_type;
};

struct hb_descriptor_binding {
  int source_fd;
  int target_fd;
  enum hb_descriptor_role role;
  struct hb_descriptor_identity expected;
};

struct hb_credential_plan {
  uid_t target_uid;
  gid_t target_gid;
  int supplementary_group_count;
  gid_t supplementary_groups[HB_MAX_SUPPLEMENTARY_GROUPS];
};

struct hb_launch_context {
  uint32_t version;
  uint32_t child_image_kind;
  int wire_authority_verified;
  int production_attested;
  int production_ready;
  int hardware_authorized;
  unsigned char authority_envelope_digest[CC_SHA256_DIGEST_LENGTH];
  unsigned char credential_plan_digest[CC_SHA256_DIGEST_LENGTH];
  unsigned char executable_identity_digest[CC_SHA256_DIGEST_LENGTH];
  struct hb_credential_plan credentials;
  struct hb_descriptor_identity expected_descriptors[HB_DESCRIPTOR_COUNT];
};

struct hb_process_provenance {
  pid_t pid;
  pid_t parent_pid;
  uint64_t process_start_seconds;
  uint64_t process_start_microseconds;
  unsigned char launcher_path_digest[CC_SHA256_DIGEST_LENGTH];
  unsigned char descriptor_inventory_before_digest[CC_SHA256_DIGEST_LENGTH];
  unsigned char descriptor_inventory_after_digest[CC_SHA256_DIGEST_LENGTH];
  int descriptor_inventory_before_count;
  int descriptor_inventory_after_count;
  int descriptor_projection_complete;
  int credential_drop_complete;
  int child_exec_contract_complete;
  int production_attested;
  int production_ready;
  int hardware_authorized;
  int mapped_process_image_identity_bound;
  int provenance_persisted_by_parent;
};

struct hb_inventory {
  int count;
  int fds[HB_MAX_INVENTORY_FDS];
  unsigned char digest[CC_SHA256_DIGEST_LENGTH];
};

#ifdef HB_PRIVILEGED_LAUNCH_TEST_ONLY
enum hb_test_injection {
  HB_TEST_NONE = 0,
  HB_TEST_DUPLICATE_TARGET = 1,
  HB_TEST_DUPLICATE_SOURCE = 2,
  HB_TEST_CLOSE_FAILURE = 3,
  HB_TEST_SOURCE_SUBSTITUTION = 4,
  HB_TEST_CREDENTIAL_DRIFT = 5,
  HB_TEST_EXTRA_FD_AFTER_CLOSE = 6,
  HB_TEST_EXEC_FAILURE = 7
};

static enum hb_test_injection hb_test_injection = HB_TEST_NONE;
static int hb_test_close_failure_consumed = 0;
static int hb_test_substitute_fd = -1;
static int hb_test_credential_order = 0;
static uid_t hb_test_uid = 0;
static gid_t hb_test_gid = 0;
static gid_t hb_test_groups[HB_MAX_SUPPLEMENTARY_GROUPS];
static int hb_test_group_count = 0;
static int hb_test_projection_phase = 0;
static int hb_test_identity_difference = 0;
static int hb_test_child_verify_phase = 0;
#endif

static int hb_bytes_nonzero(const unsigned char *bytes, size_t length) {
  unsigned char aggregate = 0;
  size_t index;
  for (index = 0; index < length; index += 1) aggregate |= bytes[index];
  return aggregate != 0;
}

static int hb_int_compare(const void *left, const void *right) {
  int left_value = *(const int *)left;
  int right_value = *(const int *)right;
  return (left_value > right_value) - (left_value < right_value);
}

static int hb_gid_compare(const void *left, const void *right) {
  gid_t left_value = *(const gid_t *)left;
  gid_t right_value = *(const gid_t *)right;
  return (left_value > right_value) - (left_value < right_value);
}

static int hb_close(int fd) {
#ifdef HB_PRIVILEGED_LAUNCH_TEST_ONLY
  if (hb_test_injection == HB_TEST_CLOSE_FAILURE && fd == HB_DEVICE_SOURCE_FD
      && !hb_test_close_failure_consumed) {
    hb_test_close_failure_consumed = 1;
    errno = EIO;
    return -1;
  }
#endif
  return close(fd);
}

static int hb_capture_descriptor_identity(
  int fd,
  struct hb_descriptor_identity *identity
) {
  struct stat status;
  int socket_type = 0;
  socklen_t socket_type_length = (socklen_t)sizeof(socket_type);
  int status_flags;
  int descriptor_flags;
  if (identity == NULL || fstat(fd, &status) != 0
      || (status_flags = fcntl(fd, F_GETFL)) < 0
      || (descriptor_flags = fcntl(fd, F_GETFD)) < 0) return -1;
  if (S_ISSOCK(status.st_mode)) {
    if (getsockopt(fd, SOL_SOCKET, SO_TYPE, &socket_type, &socket_type_length) != 0
        || socket_type_length != sizeof(socket_type)) return -1;
  }
  identity->dev = (uint64_t)status.st_dev;
  identity->ino = (uint64_t)status.st_ino;
  identity->rdev = (uint64_t)status.st_rdev;
  identity->mode = (uint64_t)status.st_mode;
  identity->nlink = (uint64_t)status.st_nlink;
  identity->uid = (uint64_t)status.st_uid;
  identity->gid = (uint64_t)status.st_gid;
  identity->size = (uint64_t)status.st_size;
  identity->access_mode = status_flags & O_ACCMODE;
  identity->status_flags = status_flags;
  identity->descriptor_flags = descriptor_flags;
  identity->socket_type = socket_type;
  return 0;
}

static int hb_identity_equal(
  const struct hb_descriptor_identity *left,
  const struct hb_descriptor_identity *right,
  int compare_descriptor_flags
) {
  return left->dev == right->dev
    && left->ino == right->ino
    && left->rdev == right->rdev
    && left->mode == right->mode
    && left->nlink == right->nlink
    && left->uid == right->uid
    && left->gid == right->gid
    && left->size == right->size
    && left->access_mode == right->access_mode
    && left->status_flags == right->status_flags
    && (!compare_descriptor_flags || left->descriptor_flags == right->descriptor_flags)
    && left->socket_type == right->socket_type;
}

static int hb_identity_alias(
  const struct hb_descriptor_identity *left,
  const struct hb_descriptor_identity *right
) {
  return left->dev == right->dev
    && left->ino == right->ino
    && left->rdev == right->rdev
    && (left->mode & S_IFMT) == (right->mode & S_IFMT);
}

static int hb_descriptor_policy_valid(
  enum hb_descriptor_role role,
  const struct hb_descriptor_identity *identity
) {
  if (role == HB_DESCRIPTOR_DEVICE) {
    return S_ISCHR((mode_t)identity->mode)
      && identity->access_mode == O_RDWR
      && identity->status_flags == (O_RDWR | O_NONBLOCK)
      && identity->socket_type == 0;
  }
  if (role == HB_DESCRIPTOR_VAULT_SINK) {
    return S_ISREG((mode_t)identity->mode)
      && identity->nlink == 1
      && identity->size == 0
      && (identity->mode & 077U) == 0
      && (identity->mode & S_IWUSR) != 0
      && identity->access_mode == O_WRONLY
      && identity->status_flags == (O_WRONLY | O_APPEND)
      && identity->socket_type == 0;
  }
  return S_ISSOCK((mode_t)identity->mode)
    && identity->access_mode == O_RDWR
    && identity->status_flags == O_RDWR
    && identity->socket_type == SOCK_STREAM;
}

static int hb_binding_shape_valid(
  const struct hb_descriptor_binding bindings[HB_DESCRIPTOR_COUNT]
) {
  static const int sources[HB_DESCRIPTOR_COUNT] = {
    HB_CONTEXT_SOURCE_FD,
    HB_DEVICE_SOURCE_FD,
    HB_DISPATCH_SOURCE_FD,
    HB_RESULT_SOURCE_FD,
    HB_VAULT_SINK_SOURCE_FD,
  };
  static const int targets[HB_DESCRIPTOR_COUNT] = {
    HB_CONTEXT_CHILD_FD,
    HB_DEVICE_CHILD_FD,
    HB_DISPATCH_CHILD_FD,
    HB_RESULT_CHILD_FD,
    HB_VAULT_SINK_CHILD_FD,
  };
  int left;
  int right;
  for (left = 0; left < HB_DESCRIPTOR_COUNT; left += 1) {
    if (bindings[left].source_fd != sources[left]
        || bindings[left].target_fd != targets[left]
        || bindings[left].role != (enum hb_descriptor_role)(left + 1)
        || bindings[left].source_fd == bindings[left].target_fd) return 0;
    for (right = left + 1; right < HB_DESCRIPTOR_COUNT; right += 1) {
      if (bindings[left].source_fd == bindings[right].source_fd
          || bindings[left].target_fd == bindings[right].target_fd) return 0;
      if ((bindings[left].source_fd == bindings[right].target_fd
          || bindings[left].target_fd == bindings[right].source_fd)
          && !(left == 0 && right == 4
            && bindings[left].source_fd == bindings[right].target_fd)) return 0;
    }
  }
  return 1;
}

static int hb_context_valid(const struct hb_launch_context *context) {
  int index;
  if (context == NULL || context->version != HB_CONTEXT_VERSION
      || context->child_image_kind != HB_CHILD_IMAGE_KIND_STANDALONE
      || context->wire_authority_verified != 1
      || context->production_attested != 0
      || context->production_ready != 0
      || context->hardware_authorized != 0
      || !hb_bytes_nonzero(context->authority_envelope_digest, CC_SHA256_DIGEST_LENGTH)
      || !hb_bytes_nonzero(context->credential_plan_digest, CC_SHA256_DIGEST_LENGTH)
      || !hb_bytes_nonzero(context->executable_identity_digest, CC_SHA256_DIGEST_LENGTH)
      || context->credentials.target_uid == 0 || context->credentials.target_gid == 0
      || context->credentials.supplementary_group_count < 0
      || context->credentials.supplementary_group_count > HB_MAX_SUPPLEMENTARY_GROUPS
      || context->expected_descriptors[4].uid
        == (uint64_t)context->credentials.target_uid) return 0;
  for (index = 0; index < context->credentials.supplementary_group_count; index += 1) {
    if (context->credentials.supplementary_groups[index] == 0
        || (index > 0 && context->credentials.supplementary_groups[index - 1]
          >= context->credentials.supplementary_groups[index])) return 0;
  }
  for (; index < HB_MAX_SUPPLEMENTARY_GROUPS; index += 1) {
    if (context->credentials.supplementary_groups[index] != 0) return 0;
  }
  return 1;
}

static int hb_credential_plan_equal(
  const struct hb_credential_plan *left,
  const struct hb_credential_plan *right
) {
  int index;
  if (left->target_uid != right->target_uid || left->target_gid != right->target_gid
      || left->supplementary_group_count != right->supplementary_group_count) return 0;
  for (index = 0; index < HB_MAX_SUPPLEMENTARY_GROUPS; index += 1) {
    if (left->supplementary_groups[index] != right->supplementary_groups[index]) return 0;
  }
  return 1;
}

static int hb_inventory_digest(struct hb_inventory *inventory) {
  CC_SHA256_CTX digest_context;
  char line[256];
  int index;
  if (CC_SHA256_Init(&digest_context) != 1
      || CC_SHA256_Update(
        &digest_context,
        "hacker-bob/darwin-privileged-launch-descriptor-inventory/v1\n",
        (CC_LONG)strlen("hacker-bob/darwin-privileged-launch-descriptor-inventory/v1\n")
      ) != 1) return -1;
  for (index = 0; index < inventory->count; index += 1) {
    struct hb_descriptor_identity identity;
    int length;
    if (hb_capture_descriptor_identity(inventory->fds[index], &identity) != 0) return -1;
    length = snprintf(
      line,
      sizeof(line),
      "%d|%llu|%llu|%llu|%llo|%llu|%llu|%llu|%llu|%d|%d|%d|%d\n",
      inventory->fds[index],
      (unsigned long long)identity.dev,
      (unsigned long long)identity.ino,
      (unsigned long long)identity.rdev,
      (unsigned long long)identity.mode,
      (unsigned long long)identity.nlink,
      (unsigned long long)identity.uid,
      (unsigned long long)identity.gid,
      (unsigned long long)identity.size,
      identity.access_mode,
      identity.status_flags,
      identity.descriptor_flags,
      identity.socket_type
    );
    if (length <= 0 || (size_t)length >= sizeof(line)
        || CC_SHA256_Update(&digest_context, line, (CC_LONG)length) != 1) return -1;
  }
  return CC_SHA256_Final(inventory->digest, &digest_context) == 1 ? 0 : -1;
}

static int hb_collect_inventory(struct hb_inventory *inventory) {
  struct proc_fdinfo raw[HB_MAX_INVENTORY_FDS + 1];
  int received;
  int count;
  int index;
  if (inventory == NULL) return -1;
  received = proc_pidinfo(
    getpid(),
    PROC_PIDLISTFDS,
    0,
    raw,
    (int)sizeof(raw)
  );
  if (received <= 0 || received % (int)sizeof(raw[0]) != 0) return -1;
  count = received / (int)sizeof(raw[0]);
  if (count <= 0 || count > HB_MAX_INVENTORY_FDS) return -1;
  inventory->count = count;
  for (index = 0; index < count; index += 1) inventory->fds[index] = raw[index].proc_fd;
  qsort(inventory->fds, (size_t)count, sizeof(inventory->fds[0]), hb_int_compare);
  for (index = 1; index < count; index += 1) {
    if (inventory->fds[index - 1] == inventory->fds[index]) return -1;
  }
  return hb_inventory_digest(inventory);
}

static int hb_child_inventory_exact(const struct hb_inventory *inventory) {
  int index;
  if (inventory->count != HB_CHILD_DESCRIPTOR_COUNT) return 0;
  for (index = 0; index < HB_CHILD_DESCRIPTOR_COUNT; index += 1) {
    if (inventory->fds[index] != index) return 0;
  }
  return 1;
}

static void hb_fail_closed_cleanup(void) {
  int limit = getdtablesize();
  int fd;
  if (limit < 0 || limit > 65536) limit = 65536;
  for (fd = 3; fd < limit; fd += 1) {
    while (hb_close(fd) != 0 && errno == EINTR) {}
  }
}

static int hb_reopen_standard_descriptors(void) {
  int null_fd;
  int target;
  do {
    null_fd = open("/dev/null", O_RDWR | O_CLOEXEC);
  } while (null_fd < 0 && errno == EINTR);
  if (null_fd < 0) return -1;
  for (target = 0; target <= 2; target += 1) {
    if (dup2(null_fd, target) != target || fcntl(target, F_SETFD, 0) != 0) {
      if (null_fd > 2) (void)hb_close(null_fd);
      return -1;
    }
  }
  if (null_fd > 2 && hb_close(null_fd) != 0) return -1;
  return 0;
}

static int hb_collect_process_provenance(struct hb_process_provenance *evidence) {
  struct proc_bsdinfo information;
  char path[PROC_PIDPATHINFO_MAXSIZE];
  int received;
  int path_length;
  if (evidence == NULL) return -1;
  memset(evidence, 0, sizeof(*evidence));
  received = proc_pidinfo(
    getpid(),
    PROC_PIDTBSDINFO,
    0,
    &information,
    (int)sizeof(information)
  );
  if (received != (int)sizeof(information)) return -1;
  path_length = proc_pidpath(getpid(), path, (uint32_t)sizeof(path));
  if (path_length <= 0 || path_length >= (int)sizeof(path)) return -1;
  if (information.pbi_ppid > (uint32_t)INT_MAX) return -1;
  evidence->pid = getpid();
  evidence->parent_pid = (pid_t)information.pbi_ppid;
  evidence->process_start_seconds = information.pbi_start_tvsec;
  evidence->process_start_microseconds = information.pbi_start_tvusec;
  if (evidence->pid <= 1 || evidence->parent_pid <= 0
      || evidence->process_start_seconds == 0
      || CC_SHA256(path, (CC_LONG)path_length, evidence->launcher_path_digest) == NULL) return -1;
  evidence->production_attested = 0;
  evidence->production_ready = 0;
  evidence->hardware_authorized = 0;
  evidence->mapped_process_image_identity_bound = 0;
  evidence->provenance_persisted_by_parent = 0;
  return 0;
}

static int hb_prepare_bindings(
  const struct hb_launch_context *context,
  struct hb_descriptor_binding bindings[HB_DESCRIPTOR_COUNT]
) {
  static const int sources[HB_DESCRIPTOR_COUNT] = {
    HB_CONTEXT_SOURCE_FD,
    HB_DEVICE_SOURCE_FD,
    HB_DISPATCH_SOURCE_FD,
    HB_RESULT_SOURCE_FD,
    HB_VAULT_SINK_SOURCE_FD,
  };
  static const int targets[HB_DESCRIPTOR_COUNT] = {
    HB_CONTEXT_CHILD_FD,
    HB_DEVICE_CHILD_FD,
    HB_DISPATCH_CHILD_FD,
    HB_RESULT_CHILD_FD,
    HB_VAULT_SINK_CHILD_FD,
  };
  int index;
  for (index = 0; index < HB_DESCRIPTOR_COUNT; index += 1) {
    bindings[index].source_fd = sources[index];
    bindings[index].target_fd = targets[index];
    bindings[index].role = (enum hb_descriptor_role)(index + 1);
    bindings[index].expected = context->expected_descriptors[index];
  }
#ifdef HB_PRIVILEGED_LAUNCH_TEST_ONLY
  if (hb_test_injection == HB_TEST_DUPLICATE_TARGET) {
    bindings[3].target_fd = bindings[2].target_fd;
  } else if (hb_test_injection == HB_TEST_DUPLICATE_SOURCE) {
    bindings[2].source_fd = bindings[0].source_fd;
  }
#endif
  return hb_binding_shape_valid(bindings) ? 0 : -1;
}

static struct hb_descriptor_identity hb_directional_identity(
  const struct hb_descriptor_binding *binding
) {
  struct hb_descriptor_identity expected = binding->expected;
  if (binding->role == HB_DESCRIPTOR_CONTEXT
      || binding->role == HB_DESCRIPTOR_DISPATCH) {
    expected.mode &= ~(uint64_t)0222U;
  } else if (binding->role == HB_DESCRIPTOR_RESULT) {
    expected.mode &= ~(uint64_t)0444U;
  }
  return expected;
}

static int hb_verify_sources(
  const struct hb_descriptor_binding bindings[HB_DESCRIPTOR_COUNT],
  int directions_applied
) {
  struct hb_descriptor_identity current[HB_DESCRIPTOR_COUNT];
  int left;
  int right;
  for (left = 0; left < HB_DESCRIPTOR_COUNT; left += 1) {
    struct hb_descriptor_identity expected = directions_applied
      ? hb_directional_identity(&bindings[left])
      : bindings[left].expected;
    if (hb_capture_descriptor_identity(bindings[left].source_fd, &current[left]) != 0) return -1;
#ifdef HB_PRIVILEGED_LAUNCH_TEST_ONLY
    if (!hb_identity_equal(&current[left], &expected, 1)) {
      if (current[left].dev != expected.dev) hb_test_identity_difference = 1;
      else if (current[left].ino != expected.ino) hb_test_identity_difference = 2;
      else if (current[left].rdev != expected.rdev) hb_test_identity_difference = 3;
      else if (current[left].mode != expected.mode) hb_test_identity_difference = 4;
      else if (current[left].nlink != expected.nlink) hb_test_identity_difference = 5;
      else if (current[left].uid != expected.uid) hb_test_identity_difference = 6;
      else if (current[left].gid != expected.gid) hb_test_identity_difference = 7;
      else if (current[left].size != expected.size) hb_test_identity_difference = 8;
      else if (current[left].access_mode != expected.access_mode) hb_test_identity_difference = 9;
      else if (current[left].status_flags != expected.status_flags) hb_test_identity_difference = 10;
      else if (current[left].descriptor_flags != expected.descriptor_flags) hb_test_identity_difference = 11;
      else if (current[left].socket_type != expected.socket_type) hb_test_identity_difference = 12;
      return -1;
    }
#else
    if (!hb_identity_equal(&current[left], &expected, 1)) return -1;
#endif
    if (!hb_descriptor_policy_valid(bindings[left].role, &current[left])
        || current[left].descriptor_flags != FD_CLOEXEC
        || (!directions_applied && bindings[left].role != HB_DESCRIPTOR_DEVICE
          && bindings[left].role != HB_DESCRIPTOR_VAULT_SINK
          && (current[left].mode & 0666U) != 0666U)) return -1;
    for (right = 0; right < left; right += 1) {
      if (hb_identity_alias(&current[left], &current[right])) return -1;
    }
  }
  return 0;
}

static int hb_shutdown_socket_directions(
  const struct hb_descriptor_binding bindings[HB_DESCRIPTOR_COUNT]
) {
  if (shutdown(bindings[0].source_fd, SHUT_WR) != 0
      || shutdown(bindings[2].source_fd, SHUT_WR) != 0
      || shutdown(bindings[3].source_fd, SHUT_RD) != 0) return -1;
  return 0;
}

static int hb_verify_child_descriptors(
  const struct hb_descriptor_binding bindings[HB_DESCRIPTOR_COUNT]
) {
  struct hb_descriptor_identity child[HB_DESCRIPTOR_COUNT];
  struct hb_descriptor_identity standard[3];
  int left;
  int right;
  for (left = 0; left < HB_DESCRIPTOR_COUNT; left += 1) {
    struct hb_descriptor_identity expected = hb_directional_identity(&bindings[left]);
    if (hb_capture_descriptor_identity(bindings[left].target_fd, &child[left]) != 0) {
#ifdef HB_PRIVILEGED_LAUNCH_TEST_ONLY
      hb_test_child_verify_phase = 10 + left;
#endif
      return -1;
    }
    if (!hb_identity_equal(&child[left], &expected, 0)) {
#ifdef HB_PRIVILEGED_LAUNCH_TEST_ONLY
      hb_test_child_verify_phase = 20 + left;
#endif
      return -1;
    }
    if (child[left].descriptor_flags != 0) {
#ifdef HB_PRIVILEGED_LAUNCH_TEST_ONLY
      hb_test_child_verify_phase = 30 + left;
#endif
      return -1;
    }
    if (!hb_descriptor_policy_valid(bindings[left].role, &child[left])) {
#ifdef HB_PRIVILEGED_LAUNCH_TEST_ONLY
      hb_test_child_verify_phase = 40 + left;
#endif
      return -1;
    }
    for (right = 0; right < left; right += 1) {
      if (hb_identity_alias(&child[left], &child[right])) {
#ifdef HB_PRIVILEGED_LAUNCH_TEST_ONLY
        hb_test_child_verify_phase = 50 + left;
#endif
        return -1;
      }
    }
  }
  for (left = 0; left < 3; left += 1) {
    if (hb_capture_descriptor_identity(left, &standard[left]) != 0
        || !S_ISCHR((mode_t)standard[left].mode)
        || standard[left].access_mode != O_RDWR
        || standard[left].status_flags != O_RDWR
        || standard[left].descriptor_flags != 0
        || standard[left].socket_type != 0
        || hb_identity_alias(&standard[left], &child[1])) {
#ifdef HB_PRIVILEGED_LAUNCH_TEST_ONLY
      hb_test_child_verify_phase = 60 + left;
#endif
      return -1;
    }
  }
  return 0;
}

static int hb_install_descriptor_projection(
  const struct hb_descriptor_binding bindings[HB_DESCRIPTOR_COUNT],
  struct hb_process_provenance *evidence
) {
  int retained[HB_DESCRIPTOR_COUNT] = {-1, -1, -1, -1, -1};
  int index;
  int result = -1;
  struct hb_inventory before;
  struct hb_inventory after;
#ifdef HB_PRIVILEGED_LAUNCH_TEST_ONLY
  hb_test_projection_phase = 11;
#endif
  if (hb_collect_inventory(&before) != 0) return -1;
#ifdef HB_PRIVILEGED_LAUNCH_TEST_ONLY
  hb_test_projection_phase = 12;
#endif
  if (hb_verify_sources(bindings, 0) != 0) return -1;
#ifdef HB_PRIVILEGED_LAUNCH_TEST_ONLY
  hb_test_projection_phase = 13;
#endif
  if (hb_shutdown_socket_directions(bindings) != 0) return -1;
#ifdef HB_PRIVILEGED_LAUNCH_TEST_ONLY
  hb_test_projection_phase = 14;
#endif
  if (hb_verify_sources(bindings, 1) != 0) return -1;
  for (index = 0; index < HB_DESCRIPTOR_COUNT; index += 1) {
    struct hb_descriptor_identity retained_identity;
    struct hb_descriptor_identity directional_expected =
      hb_directional_identity(&bindings[index]);
    do {
      retained[index] = fcntl(
        bindings[index].source_fd,
        F_DUPFD_CLOEXEC,
        HB_FIRST_RETAINED_FD
      );
    } while (retained[index] < 0 && errno == EINTR);
    if (retained[index] < 0
        || hb_capture_descriptor_identity(retained[index], &retained_identity) != 0
        || !hb_identity_equal(&retained_identity, &directional_expected, 0)
        || retained_identity.descriptor_flags != FD_CLOEXEC) goto cleanup;
  }
#ifdef HB_PRIVILEGED_LAUNCH_TEST_ONLY
  hb_test_projection_phase = 2;
#endif
#ifdef HB_PRIVILEGED_LAUNCH_TEST_ONLY
  if (hb_test_injection == HB_TEST_SOURCE_SUBSTITUTION) {
    if (hb_test_substitute_fd < 0
        || dup2(hb_test_substitute_fd, HB_DISPATCH_SOURCE_FD) != HB_DISPATCH_SOURCE_FD
        || fcntl(HB_DISPATCH_SOURCE_FD, F_SETFD, FD_CLOEXEC) != 0) goto cleanup;
  }
#endif
  if (hb_verify_sources(bindings, 1) != 0) goto cleanup;
#ifdef HB_PRIVILEGED_LAUNCH_TEST_ONLY
  hb_test_projection_phase = 3;
#endif
  for (index = 0; index < HB_DESCRIPTOR_COUNT; index += 1) {
    struct hb_descriptor_identity target_identity;
    struct hb_descriptor_identity directional_expected =
      hb_directional_identity(&bindings[index]);
    if (dup2(retained[index], bindings[index].target_fd) != bindings[index].target_fd
        || fcntl(bindings[index].target_fd, F_SETFD, 0) != 0
        || hb_capture_descriptor_identity(bindings[index].target_fd, &target_identity) != 0
        || !hb_identity_equal(&target_identity, &directional_expected, 0)
        || target_identity.descriptor_flags != 0
        || !hb_descriptor_policy_valid(bindings[index].role, &target_identity)) goto cleanup;
  }
#ifdef HB_PRIVILEGED_LAUNCH_TEST_ONLY
  hb_test_projection_phase = 4;
#endif
  for (index = 0; index < HB_DESCRIPTOR_COUNT; index += 1) {
    if (hb_close(retained[index]) != 0) goto cleanup;
    retained[index] = -1;
  }
#ifdef HB_PRIVILEGED_LAUNCH_TEST_ONLY
  hb_test_projection_phase = 5;
#endif
  {
    int close_failed = 0;
    for (index = 0; index < before.count; index += 1) {
      int fd = before.fds[index];
      if (fd > HB_VAULT_SINK_CHILD_FD && hb_close(fd) != 0) close_failed = 1;
    }
#ifdef HB_PRIVILEGED_LAUNCH_TEST_ONLY
    if (hb_test_injection == HB_TEST_EXTRA_FD_AFTER_CLOSE) {
      int injected = open("/dev/null", O_RDONLY | O_CLOEXEC);
      if (injected < 0) close_failed = 1;
    }
#endif
    if (close_failed || hb_collect_inventory(&after) != 0
        || !hb_child_inventory_exact(&after)) goto cleanup;
  }
#ifdef HB_PRIVILEGED_LAUNCH_TEST_ONLY
  hb_test_projection_phase = 6;
#endif
  memcpy(
    evidence->descriptor_inventory_before_digest,
    before.digest,
    CC_SHA256_DIGEST_LENGTH
  );
  memcpy(
    evidence->descriptor_inventory_after_digest,
    after.digest,
    CC_SHA256_DIGEST_LENGTH
  );
  evidence->descriptor_inventory_before_count = before.count;
  evidence->descriptor_inventory_after_count = after.count;
  evidence->descriptor_projection_complete = 1;
  result = 0;

cleanup:
  for (index = 0; index < HB_DESCRIPTOR_COUNT; index += 1) {
    if (retained[index] >= 0) (void)hb_close(retained[index]);
  }
  return result;
}

static int hb_setgroups_exact(int count, const gid_t *groups) {
#ifdef HB_PRIVILEGED_LAUNCH_TEST_ONLY
  int index;
  if (hb_test_credential_order != 0) return -1;
  hb_test_credential_order = 1;
  hb_test_group_count = count;
  for (index = 0; index < count; index += 1) hb_test_groups[index] = groups[index];
  return 0;
#else
  return setgroups(count, groups);
#endif
}

static int hb_setgid_exact(gid_t gid) {
#ifdef HB_PRIVILEGED_LAUNCH_TEST_ONLY
  if (hb_test_credential_order != 1) return -1;
  hb_test_credential_order = 2;
  hb_test_gid = gid;
  return 0;
#else
  return setgid(gid);
#endif
}

static int hb_setuid_exact(uid_t uid) {
#ifdef HB_PRIVILEGED_LAUNCH_TEST_ONLY
  if (hb_test_credential_order != 2) return -1;
  hb_test_credential_order = 3;
  hb_test_uid = uid;
  return 0;
#else
  return setuid(uid);
#endif
}

static int hb_readback_credentials(const struct hb_credential_plan *plan) {
  gid_t observed_groups[HB_MAX_SUPPLEMENTARY_GROUPS];
  int observed_count;
  int index;
#ifdef HB_PRIVILEGED_LAUNCH_TEST_ONLY
  if (hb_test_credential_order != 3 || hb_test_uid != plan->target_uid
      || hb_test_gid != plan->target_gid) return -1;
  observed_count = hb_test_group_count;
  for (index = 0; index < observed_count; index += 1) {
    observed_groups[index] = hb_test_groups[index];
  }
#else
  struct proc_bsdinfo information;
  int received = proc_pidinfo(
    getpid(),
    PROC_PIDTBSDINFO,
    0,
    &information,
    (int)sizeof(information)
  );
  if (received != (int)sizeof(information)
      || information.pbi_ruid != plan->target_uid
      || information.pbi_uid != plan->target_uid
      || information.pbi_svuid != plan->target_uid
      || information.pbi_rgid != plan->target_gid
      || information.pbi_gid != plan->target_gid
      || information.pbi_svgid != plan->target_gid) return -1;
  observed_count = getgroups(HB_MAX_SUPPLEMENTARY_GROUPS, observed_groups);
#endif
  if (observed_count != plan->supplementary_group_count) return -1;
  qsort(observed_groups, (size_t)observed_count, sizeof(observed_groups[0]), hb_gid_compare);
  for (index = 0; index < observed_count; index += 1) {
    if (observed_groups[index] != plan->supplementary_groups[index]) return -1;
  }
  return 0;
}

static int hb_validate_exec_contract(
  const char *path,
  char *const argv[],
  char *const environment[]
) {
  return path != NULL && strcmp(path, HB_CHILD_IMAGE) == 0
    && argv != NULL && argv[0] != NULL && argv[1] != NULL && argv[2] == NULL
    && strcmp(argv[0], HB_CHILD_IMAGE) == 0
    && strcmp(argv[1], HB_CHILD_GATE) == 0
    && environment != NULL && environment[0] == NULL;
}

static int hb_exec_child(
  const char *path,
  char *const argv[],
  char *const environment[]
) {
#ifdef HB_PRIVILEGED_LAUNCH_TEST_ONLY
  if (!hb_validate_exec_contract(path, argv, environment)
      || hb_test_injection == HB_TEST_EXEC_FAILURE) {
    errno = ENOEXEC;
    return -1;
  }
  return HB_LAUNCH_EXEC_REACHED;
#else
  execve(path, argv, environment);
  return -1;
#endif
}

__attribute__((unused))
static int hb_privileged_launch_execute(
  struct hb_launch_context *context,
  struct hb_process_provenance *evidence
) {
  struct hb_credential_plan credential_snapshot;
  struct hb_descriptor_binding bindings[HB_DESCRIPTOR_COUNT];
  struct hb_inventory terminal_inventory;
  char *const empty_environment[] = {NULL};
  char *const child_argv[] = {(char *)HB_CHILD_IMAGE, (char *)HB_CHILD_GATE, NULL};
  int status = HB_LAUNCH_REJECTED;
  if (!hb_context_valid(context) || evidence == NULL
      || hb_collect_process_provenance(evidence) != 0
      || hb_reopen_standard_descriptors() != 0
      || hb_prepare_bindings(context, bindings) != 0) goto rejected;
  credential_snapshot = context->credentials;
  if (hb_install_descriptor_projection(bindings, evidence) != 0) {
    status = HB_LAUNCH_DESCRIPTOR_REJECTED;
    goto rejected;
  }
#ifdef HB_PRIVILEGED_LAUNCH_TEST_ONLY
  if (hb_test_injection == HB_TEST_CREDENTIAL_DRIFT) context->credentials.target_uid += 1;
#endif
  if (!hb_credential_plan_equal(&credential_snapshot, &context->credentials)) {
    status = HB_LAUNCH_CREDENTIAL_REJECTED;
    goto rejected;
  }
  if (chdir(HB_CHILD_WORKING_DIRECTORY) != 0) {
    status = HB_LAUNCH_EXEC_REJECTED;
    goto rejected;
  }
  if (hb_setgroups_exact(
      credential_snapshot.supplementary_group_count,
      credential_snapshot.supplementary_groups
    ) != 0
      || hb_setgid_exact(credential_snapshot.target_gid) != 0
      || hb_setuid_exact(credential_snapshot.target_uid) != 0
      || hb_readback_credentials(&credential_snapshot) != 0) {
    status = HB_LAUNCH_CREDENTIAL_REJECTED;
    goto rejected;
  }
  evidence->credential_drop_complete = 1;
  if (hb_collect_inventory(&terminal_inventory) != 0
      || !hb_child_inventory_exact(&terminal_inventory)
      || hb_verify_child_descriptors(bindings) != 0
      || !hb_validate_exec_contract(HB_CHILD_IMAGE, child_argv, empty_environment)) {
    status = HB_LAUNCH_INVENTORY_REJECTED;
    goto rejected;
  }
  evidence->child_exec_contract_complete = 1;
  status = hb_exec_child(HB_CHILD_IMAGE, child_argv, empty_environment);
#ifdef HB_PRIVILEGED_LAUNCH_TEST_ONLY
  if (status == HB_LAUNCH_EXEC_REACHED) return status;
#endif
  status = HB_LAUNCH_EXEC_REJECTED;

rejected:
  hb_fail_closed_cleanup();
#ifdef HB_PRIVILEGED_LAUNCH_SOURCE_ONLY
  _exit(status == HB_LAUNCH_EXEC_REJECTED ? 126 : 125);
#else
  return status;
#endif
}

#ifdef HB_PRIVILEGED_LAUNCH_TEST_ONLY
struct hb_test_fixture {
  struct hb_launch_context context;
  int peer_fds[HB_DESCRIPTOR_COUNT];
  char vault_path[PATH_MAX];
};

static int hb_set_cloexec(int fd) {
  int flags = fcntl(fd, F_GETFD);
  return flags < 0 ? -1 : fcntl(fd, F_SETFD, flags | FD_CLOEXEC);
}

static int hb_move_to_source(int retained, int source_fd) {
  if (retained < 0 || dup2(retained, source_fd) != source_fd
      || hb_set_cloexec(source_fd) != 0) {
    return -1;
  }
  return 0;
}

static int hb_test_setup_fixture(struct hb_test_fixture *fixture) {
  int context_pair[2];
  int dispatch_pair[2];
  int result_pair[2];
  int pty_master;
  int pty_slave;
  int vault_seed;
  int vault_writer;
  int vault_reader;
  int device_flags;
  int index;
  int path_length;
  int child_ends[HB_DESCRIPTOR_COUNT];
  int counterpart_ends[HB_DESCRIPTOR_COUNT];
  int retained_child[HB_DESCRIPTOR_COUNT] = {-1, -1, -1, -1, -1};
  char vault_template[] = "/tmp/hacker-bob-launch-vault.XXXXXX";
  memset(fixture, 0, sizeof(*fixture));
  for (index = 0; index < HB_DESCRIPTOR_COUNT; index += 1) fixture->peer_fds[index] = -1;
  if (socketpair(AF_UNIX, SOCK_STREAM, 0, context_pair) != 0
      || socketpair(AF_UNIX, SOCK_STREAM, 0, dispatch_pair) != 0
      || socketpair(AF_UNIX, SOCK_STREAM, 0, result_pair) != 0
      || openpty(&pty_master, &pty_slave, NULL, NULL, NULL) != 0) return -1;
  vault_seed = mkstemp(vault_template);
  path_length = snprintf(fixture->vault_path, sizeof(fixture->vault_path), "%s", vault_template);
  if (vault_seed < 0 || path_length <= 0 || (size_t)path_length >= sizeof(fixture->vault_path)
      || fchmod(vault_seed, S_IRUSR | S_IWUSR) != 0
      || close(vault_seed) != 0) return -1;
  vault_writer = open(fixture->vault_path, O_WRONLY | O_APPEND | O_CLOEXEC);
  vault_reader = open(fixture->vault_path, O_RDONLY | O_CLOEXEC);
  if (vault_writer < 0 || vault_reader < 0) return -1;
  child_ends[0] = context_pair[0];
  child_ends[1] = pty_slave;
  child_ends[2] = dispatch_pair[0];
  child_ends[3] = result_pair[0];
  child_ends[4] = vault_writer;
  counterpart_ends[0] = context_pair[1];
  counterpart_ends[1] = pty_master;
  counterpart_ends[2] = dispatch_pair[1];
  counterpart_ends[3] = result_pair[1];
  counterpart_ends[4] = vault_reader;
  device_flags = fcntl(pty_slave, F_GETFL);
  if (device_flags < 0 || fcntl(pty_slave, F_SETFL, device_flags | O_NONBLOCK) != 0) return -1;
  for (index = 0; index < HB_DESCRIPTOR_COUNT; index += 1) {
    retained_child[index] = fcntl(child_ends[index], F_DUPFD_CLOEXEC, 32);
    fixture->peer_fds[index] = fcntl(counterpart_ends[index], F_DUPFD_CLOEXEC, 40);
    if (retained_child[index] < 0 || fixture->peer_fds[index] < 0) return -1;
  }
  for (index = 0; index < HB_DESCRIPTOR_COUNT; index += 1) {
    (void)close(child_ends[index]);
    (void)close(counterpart_ends[index]);
  }
  for (index = 0; index < HB_DESCRIPTOR_COUNT; index += 1) {
    if (hb_move_to_source(retained_child[index], HB_CONTEXT_SOURCE_FD + index) != 0) return -1;
    (void)close(retained_child[index]);
  }
  fixture->context.version = HB_CONTEXT_VERSION;
  fixture->context.child_image_kind = HB_CHILD_IMAGE_KIND_STANDALONE;
  fixture->context.wire_authority_verified = 1;
  memset(fixture->context.authority_envelope_digest, 0x11, CC_SHA256_DIGEST_LENGTH);
  memset(fixture->context.credential_plan_digest, 0x22, CC_SHA256_DIGEST_LENGTH);
  memset(fixture->context.executable_identity_digest, 0x33, CC_SHA256_DIGEST_LENGTH);
  fixture->context.credentials.target_uid = 502;
  fixture->context.credentials.target_gid = 602;
  fixture->context.credentials.supplementary_group_count = 2;
  fixture->context.credentials.supplementary_groups[0] = 701;
  fixture->context.credentials.supplementary_groups[1] = 702;
  for (index = 0; index < HB_DESCRIPTOR_COUNT; index += 1) {
    if (hb_capture_descriptor_identity(
      HB_CONTEXT_SOURCE_FD + index,
      &fixture->context.expected_descriptors[index]
    ) != 0) return -1;
  }
  return 0;
}

static int hb_test_all_child_fds_closed(void) {
  int fd;
  for (fd = 3; fd <= HB_VAULT_SINK_SOURCE_FD; fd += 1) {
    if (fcntl(fd, F_GETFD) >= 0 || errno != EBADF) return 0;
  }
  return 1;
}

static int hb_test_exec_contract_rejections(void) {
  char *const correct_argv[] = {(char *)HB_CHILD_IMAGE, (char *)HB_CHILD_GATE, NULL};
  char *const injected_argv[] = {
    (char *)HB_CHILD_IMAGE,
    (char *)HB_CHILD_GATE,
    (char *)"--injected",
    NULL,
  };
  char *const empty_environment[] = {NULL};
  char *const injected_environment[] = {(char *)"PATH=/tmp", NULL};
  return hb_validate_exec_contract(HB_CHILD_IMAGE, correct_argv, empty_environment)
    && !hb_validate_exec_contract("/tmp/attacker", correct_argv, empty_environment)
    && !hb_validate_exec_contract(HB_CHILD_IMAGE, injected_argv, empty_environment)
    && !hb_validate_exec_contract(HB_CHILD_IMAGE, correct_argv, injected_environment);
}

static int hb_test_run_child(int test_case, struct hb_test_fixture *fixture) {
  struct hb_process_provenance evidence;
  int status;
  int flags;
  int substitute[2] = {-1, -1};
  hb_test_injection = HB_TEST_NONE;
  hb_test_close_failure_consumed = 0;
  hb_test_substitute_fd = -1;
  hb_test_credential_order = 0;
  hb_test_uid = 0;
  hb_test_gid = 0;
  hb_test_group_count = 0;
  hb_test_projection_phase = 0;
  hb_test_identity_difference = 0;
  hb_test_child_verify_phase = 0;
  if (test_case == 9) return hb_test_exec_contract_rejections() ? 0 : 1;
  if (fixture == NULL) return 1;
  switch (test_case) {
    case 1:
      break;
    case 2:
      if (dup2(HB_CONTEXT_SOURCE_FD, HB_DISPATCH_SOURCE_FD) != HB_DISPATCH_SOURCE_FD
          || hb_set_cloexec(HB_DISPATCH_SOURCE_FD) != 0
          || hb_capture_descriptor_identity(
            HB_DISPATCH_SOURCE_FD,
            &fixture->context.expected_descriptors[2]
          ) != 0) return 1;
      break;
    case 3:
      hb_test_injection = HB_TEST_DUPLICATE_TARGET;
      break;
    case 4:
      hb_test_injection = HB_TEST_DUPLICATE_SOURCE;
      break;
    case 5:
      flags = fcntl(HB_DEVICE_SOURCE_FD, F_GETFL);
      if (flags < 0 || fcntl(HB_DEVICE_SOURCE_FD, F_SETFL, flags & ~O_NONBLOCK) != 0) return 1;
      break;
    case 6:
      hb_test_injection = HB_TEST_CLOSE_FAILURE;
      break;
    case 7:
      if (socketpair(AF_UNIX, SOCK_STREAM, 0, substitute) != 0) return 1;
      hb_test_substitute_fd = substitute[0];
      hb_test_injection = HB_TEST_SOURCE_SUBSTITUTION;
      break;
    case 8:
      hb_test_injection = HB_TEST_CREDENTIAL_DRIFT;
      break;
    case 10:
      hb_test_injection = HB_TEST_EXTRA_FD_AFTER_CLOSE;
      break;
    case 11:
      hb_test_injection = HB_TEST_EXEC_FAILURE;
      break;
    case 12:
      if (dup2(fixture->peer_fds[0], HB_DEVICE_SOURCE_FD) != HB_DEVICE_SOURCE_FD
          || hb_set_cloexec(HB_DEVICE_SOURCE_FD) != 0
          || hb_capture_descriptor_identity(
            HB_DEVICE_SOURCE_FD,
            &fixture->context.expected_descriptors[1]
          ) != 0) return 1;
      break;
    case 13: {
      char device_path[PATH_MAX];
      int read_only_device;
      if (ttyname_r(HB_DEVICE_SOURCE_FD, device_path, sizeof(device_path)) != 0) return 1;
      read_only_device = open(device_path, O_RDONLY | O_NONBLOCK | O_CLOEXEC | O_NOCTTY);
      if (read_only_device < 0
          || dup2(read_only_device, HB_DEVICE_SOURCE_FD) != HB_DEVICE_SOURCE_FD
          || hb_set_cloexec(HB_DEVICE_SOURCE_FD) != 0
          || hb_capture_descriptor_identity(
            HB_DEVICE_SOURCE_FD,
            &fixture->context.expected_descriptors[1]
          ) != 0) {
        if (read_only_device >= 0) (void)close(read_only_device);
        return 1;
      }
      (void)close(read_only_device);
      break;
    }
    case 14:
      if (shutdown(HB_CONTEXT_SOURCE_FD, SHUT_RD) != 0
          || hb_capture_descriptor_identity(
            HB_CONTEXT_SOURCE_FD,
            &fixture->context.expected_descriptors[0]
          ) != 0) return 1;
      break;
    case 15:
      flags = fcntl(HB_VAULT_SINK_SOURCE_FD, F_GETFL);
      if (flags < 0
          || fcntl(HB_VAULT_SINK_SOURCE_FD, F_SETFL, flags & ~O_APPEND) != 0
          || hb_capture_descriptor_identity(
            HB_VAULT_SINK_SOURCE_FD,
            &fixture->context.expected_descriptors[4]
          ) != 0) return 1;
      break;
    case 16:
      if (fchmod(HB_VAULT_SINK_SOURCE_FD, S_IRUSR | S_IWUSR | S_IRGRP) != 0
          || hb_capture_descriptor_identity(
            HB_VAULT_SINK_SOURCE_FD,
            &fixture->context.expected_descriptors[4]
          ) != 0) return 1;
      break;
    case 17: {
      static const unsigned char occupied = 0x41;
      if (write(HB_VAULT_SINK_SOURCE_FD, &occupied, sizeof(occupied))
            != (ssize_t)sizeof(occupied)
          || hb_capture_descriptor_identity(
            HB_VAULT_SINK_SOURCE_FD,
            &fixture->context.expected_descriptors[4]
          ) != 0) return 1;
      break;
    }
    case 18:
      if (dup2(HB_RESULT_SOURCE_FD, HB_VAULT_SINK_SOURCE_FD) != HB_VAULT_SINK_SOURCE_FD
          || hb_set_cloexec(HB_VAULT_SINK_SOURCE_FD) != 0
          || hb_capture_descriptor_identity(
            HB_VAULT_SINK_SOURCE_FD,
            &fixture->context.expected_descriptors[4]
          ) != 0) return 1;
      break;
    case 19:
      fixture->context.credentials.target_uid =
        (uid_t)fixture->context.expected_descriptors[4].uid;
      break;
    default:
      return 1;
  }
  status = hb_privileged_launch_execute(&fixture->context, &evidence);
  if (substitute[0] >= 0) {
    (void)close(substitute[0]);
    (void)close(substitute[1]);
  }
  if (test_case == 1) {
    struct hb_descriptor_identity context_target;
    struct hb_descriptor_identity device_target;
    struct hb_descriptor_identity dispatch_target;
    struct hb_descriptor_identity result_target;
    struct hb_descriptor_identity vault_sink_target;
    if (status != HB_LAUNCH_EXEC_REACHED) {
      if (status == HB_LAUNCH_INVENTORY_REJECTED
          && hb_test_child_verify_phase != 0) return 150 + hb_test_child_verify_phase;
      return status == HB_LAUNCH_DESCRIPTOR_REJECTED
        ? (hb_test_identity_difference != 0
          ? 100 + hb_test_identity_difference
          : 50 + hb_test_projection_phase)
        : 20 - status;
    }
    if (evidence.pid != getpid()) return 31;
    if (evidence.parent_pid <= 0) return 32;
    if (evidence.descriptor_inventory_before_count <= HB_CHILD_DESCRIPTOR_COUNT) return 33;
    if (evidence.descriptor_inventory_after_count != HB_CHILD_DESCRIPTOR_COUNT) return 34;
    if (evidence.descriptor_projection_complete != 1) return 35;
    if (evidence.credential_drop_complete != 1) return 36;
    if (evidence.child_exec_contract_complete != 1) return 37;
    if (evidence.production_attested != 0 || evidence.production_ready != 0
        || evidence.hardware_authorized != 0) return 38;
    if (evidence.mapped_process_image_identity_bound != 0
        || evidence.provenance_persisted_by_parent != 0) return 39;
    if (!hb_bytes_nonzero(
      evidence.descriptor_inventory_before_digest,
      CC_SHA256_DIGEST_LENGTH
    )) return 40;
    if (!hb_bytes_nonzero(
      evidence.descriptor_inventory_after_digest,
      CC_SHA256_DIGEST_LENGTH
    )) return 41;
    if (hb_capture_descriptor_identity(HB_CONTEXT_CHILD_FD, &context_target) != 0
        || hb_capture_descriptor_identity(HB_DEVICE_CHILD_FD, &device_target) != 0
        || hb_capture_descriptor_identity(HB_DISPATCH_CHILD_FD, &dispatch_target) != 0
        || hb_capture_descriptor_identity(HB_RESULT_CHILD_FD, &result_target) != 0
        || hb_capture_descriptor_identity(
          HB_VAULT_SINK_CHILD_FD,
          &vault_sink_target
        ) != 0) return 42;
    if ((context_target.mode & 0222U) != 0 || (dispatch_target.mode & 0222U) != 0
        || (result_target.mode & 0444U) != 0) return 43;
    if (context_target.status_flags != O_RDWR || dispatch_target.status_flags != O_RDWR
        || result_target.status_flags != O_RDWR
        || device_target.status_flags != (O_RDWR | O_NONBLOCK)
        || vault_sink_target.status_flags != (O_WRONLY | O_APPEND)) return 44;
    if (context_target.descriptor_flags != 0 || device_target.descriptor_flags != 0
        || dispatch_target.descriptor_flags != 0
        || result_target.descriptor_flags != 0
        || vault_sink_target.descriptor_flags != 0) return 45;
    if (!S_ISREG((mode_t)vault_sink_target.mode) || vault_sink_target.nlink != 1
        || vault_sink_target.size != 0 || (vault_sink_target.mode & 077U) != 0
        || (vault_sink_target.mode & S_IWUSR) == 0
        || vault_sink_target.access_mode != O_WRONLY) return 46;
    return 0;
  }
  return status < 0 && hb_test_all_child_fds_closed() ? 0 : 1;
}

static void hb_test_cleanup_fixture(struct hb_test_fixture *fixture) {
  int index;
  for (index = HB_CONTEXT_SOURCE_FD; index <= HB_VAULT_SINK_SOURCE_FD; index += 1) {
    (void)close(index);
  }
  for (index = 0; index < HB_DESCRIPTOR_COUNT; index += 1) {
    if (fixture->peer_fds[index] >= 0) {
      (void)close(fixture->peer_fds[index]);
      fixture->peer_fds[index] = -1;
    }
  }
  if (fixture->vault_path[0] != '\0') {
    (void)unlink(fixture->vault_path);
    fixture->vault_path[0] = '\0';
  }
}

static int hb_test_run_isolated(int test_case) {
  struct hb_test_fixture fixture;
  struct hb_test_fixture *fixture_pointer = NULL;
  pid_t child;
  pid_t waited;
  int status;
  if (test_case != 9) {
    if (hb_test_setup_fixture(&fixture) != 0) return 1;
    fixture_pointer = &fixture;
  }
  child = fork();
  if (child < 0) {
    if (fixture_pointer != NULL) hb_test_cleanup_fixture(&fixture);
    return 1;
  }
  if (child == 0) _exit(hb_test_run_child(test_case, fixture_pointer));
  do {
    waited = waitpid(child, &status, 0);
  } while (waited < 0 && errno == EINTR);
  if (fixture_pointer != NULL) hb_test_cleanup_fixture(&fixture);
  if (waited != child) return 1;
  if (!WIFEXITED(status)) return 255;
  return WEXITSTATUS(status);
}

int main(int argc, char **argv) {
  static const int test_cases[] = {
    1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19,
  };
  size_t index;
  if (argc != 2 || strcmp(argv[1], "--test-only-selftest-v1") != 0) return 64;
  for (index = 0; index < sizeof(test_cases) / sizeof(test_cases[0]); index += 1) {
    int result = hb_test_run_isolated(test_cases[index]);
    if (result != 0) {
      (void)fprintf(
        stderr,
        "privileged launch selftest failed: %d (%d)\n",
        test_cases[index],
        result
      );
      return 65;
    }
  }
  (void)printf(
    "{\"version\":1,\"kind\":\"darwin_privileged_launch_executor_selftest\","
    "\"tests\":19,\"result_record_bytes\":%d,\"production_ready\":false}\n",
    HB_RESULT_RECORD_BYTES
  );
  return 0;
}
#endif
