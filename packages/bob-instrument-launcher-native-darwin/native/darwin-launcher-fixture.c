#define _DARWIN_C_SOURCE 1

#include <CommonCrypto/CommonDigest.h>
#include <libproc.h>
#include <sys/param.h>
#include <sys/stat.h>
#include <sys/types.h>

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define HB_RECORD_DOMAIN "hacker-bob/instrument-darwin-native-launcher-fixture-contract-record/v2"
#define HB_ROOT_DOMAIN "hacker-bob/instrument-darwin-native-fixture-root-identity/v1"
#define HB_WALK_DOMAIN "hacker-bob/instrument-darwin-native-fixture-openat-walk/v1"
#define HB_FD_DOMAIN "hacker-bob/instrument-darwin-native-fixture-fd-enumeration/v1"
#define HB_CREDENTIAL_DOMAIN "hacker-bob/instrument-darwin-native-fixture-credential-observation/v1"
#define HB_IMPLEMENTATION_DOMAIN "hacker-bob/instrument-darwin-native-launcher-fixture-implementation/v1"
#define HB_MANIFEST_RELATIVE "config/native-launch-fixture.manifest"
#define HB_REPORT_FD 3
#define HB_ENTRY_COUNT 8
#define HB_DIGEST_HEX_LENGTH 64
#define HB_MAX_MANIFEST_BYTES (64U * 1024U)
#define HB_MAX_ENTRY_BYTES (128ULL * 1024ULL * 1024ULL)
#define HB_MAX_TOTAL_ENTRY_BYTES (256ULL * 1024ULL * 1024ULL)
#define HB_MAX_RECORD_BYTES (16U * 1024U)
#define HB_MAX_GROUPS 256
#define HB_MAX_ANCESTRY_COMPONENTS 32

extern char **environ;

static const char *const HB_ENTRY_PATHS[HB_ENTRY_COUNT] = {
  "bin",
  "bin/node",
  "config",
  "config/worker.json",
  "lib",
  "lib/worker.js",
  "native",
  "native/driver.node",
};

static const char *const HB_PRODUCTION_BLOCKERS =
  "adhoc_native_signature_not_production_qualified,"
  "root_owned_immutable_install_not_qualified,"
  "real_credential_drop_readback_hil_missing,"
  "negative_principal_matrix_hil_missing,"
  "capability_fd_projection_not_linked_into_fixture,"
  "privileged_launch_wire_authority_verifier_not_integrated,"
  "privileged_launch_provenance_persistence_not_integrated,"
  "standalone_native_dispatch_custodian_prebuild_missing,"
  "node_fixture_adapter_argv_not_executor_contract,"
  "production_executor_not_linked,"
  "fixture_mode_execve_disabled,"
  "root_owned_immutable_ancestry_hil_missing,"
  "darwin_fd_bound_exec_unavailable,"
  "native_launcher_mapped_process_image_identity_unbound,"
  "native_fixture_record_provenance_unattested,"
  "writable_fixture_bracketing_not_production_immutability";

struct hb_identity {
  uint64_t dev;
  uint64_t ino;
  uint64_t uid;
  uint64_t gid;
  uint64_t mode;
  uint64_t nlink;
  uint64_t size;
  uint64_t gen;
  int64_t mtime_sec;
  int64_t mtime_nsec;
  int64_t ctime_sec;
  int64_t ctime_nsec;
};

struct hb_entry {
  char path[PATH_MAX];
  char type;
  struct hb_identity identity;
  char content_digest[HB_DIGEST_HEX_LENGTH + 1];
  char canonical_line[2048];
};

struct hb_manifest {
  char role[64];
  char root_path[PATH_MAX];
  char executable_path[PATH_MAX];
  char entrypoint_path[PATH_MAX];
  char config_manifest_path[PATH_MAX];
  char launch_plan_digest[65];
  char worker_bundle_projection_digest[65];
  char native_evidence_digest[65];
  char path_plan_digest[65];
  char argv_digest[65];
  char environment_digest[65];
  char fd_set_digest[65];
  char credential_plan_digest[65];
  struct hb_identity root_identity;
  struct hb_entry entries[HB_ENTRY_COUNT];
};

struct hb_retained_bundle {
  int fds[HB_ENTRY_COUNT];
  struct hb_identity opened_identities[HB_ENTRY_COUNT];
  char first_pass_content_digests[HB_ENTRY_COUNT][HB_DIGEST_HEX_LENGTH + 1];
};

struct hb_absolute_chain {
  char absolute_path[PATH_MAX];
  char components[HB_MAX_ANCESTRY_COMPONENTS][NAME_MAX + 1];
  int fds[HB_MAX_ANCESTRY_COMPONENTS];
  struct hb_identity identities[HB_MAX_ANCESTRY_COMPONENTS];
  size_t count;
  int final_directory;
};

static void hb_hex(const unsigned char *bytes, size_t length, char output[65]) {
  static const char alphabet[] = "0123456789abcdef";
  size_t index;
  for (index = 0; index < length; index += 1) {
    output[index * 2] = alphabet[(bytes[index] >> 4) & 0x0fU];
    output[index * 2 + 1] = alphabet[bytes[index] & 0x0fU];
  }
  output[length * 2] = '\0';
}

static int hb_sha256_bytes(const void *bytes, size_t length, char output[65]) {
  unsigned char digest[CC_SHA256_DIGEST_LENGTH];
  if (length > UINT32_MAX || CC_SHA256(bytes, (CC_LONG)length, digest) == NULL) return -1;
  hb_hex(digest, sizeof(digest), output);
  return 0;
}

static int hb_sha256_fd(int fd, char output[65]) {
  CC_SHA256_CTX context;
  unsigned char digest[CC_SHA256_DIGEST_LENGTH];
  unsigned char buffer[16384];
  ssize_t count;
  if (lseek(fd, 0, SEEK_SET) < 0 || CC_SHA256_Init(&context) != 1) return -1;
  for (;;) {
    count = read(fd, buffer, sizeof(buffer));
    if (count == 0) break;
    if (count < 0) {
      if (errno == EINTR) continue;
      return -1;
    }
    if (CC_SHA256_Update(&context, buffer, (CC_LONG)count) != 1) return -1;
  }
  if (CC_SHA256_Final(digest, &context) != 1 || lseek(fd, 0, SEEK_SET) < 0) return -1;
  hb_hex(digest, sizeof(digest), output);
  return 0;
}

static int hb_is_hex_digest(const char *value) {
  size_t index;
  if (value == NULL || strlen(value) != HB_DIGEST_HEX_LENGTH) return 0;
  for (index = 0; index < HB_DIGEST_HEX_LENGTH; index += 1) {
    if (!((value[index] >= '0' && value[index] <= '9')
          || (value[index] >= 'a' && value[index] <= 'f'))) return 0;
  }
  return 1;
}

static int hb_is_role(const char *value) {
  return strcmp(value, "issuer_peer") == 0
    || strcmp(value, "active_device_worker") == 0
    || strcmp(value, "cleanup_only_worker") == 0
    || strcmp(value, "safety_supervisor") == 0;
}

static int hb_is_canonical_absolute_path(const char *value) {
  size_t length;
  size_t index;
  if (value == NULL || value[0] != '/') return 0;
  length = strlen(value);
  if (length < 2 || length >= PATH_MAX || value[length - 1] == '/') return 0;
  for (index = 0; index < length; index += 1) {
    unsigned char character = (unsigned char)value[index];
    if (character == '\\' || character < 0x20U || character > 0x7eU) return 0;
    if (index > 0 && value[index] == '/' && value[index - 1] == '/') return 0;
  }
  if (strstr(value, "/../") != NULL || strstr(value, "/./") != NULL
      || (length >= 3 && strcmp(value + length - 3, "/..") == 0)
      || (length >= 2 && strcmp(value + length - 2, "/.") == 0)) return 0;
  return 1;
}

static int hb_copy_string(char *destination, size_t capacity, const char *source) {
  size_t length = strlen(source);
  if (length + 1 > capacity) return -1;
  memcpy(destination, source, length + 1);
  return 0;
}

static int hb_parse_uint64(const char *value, unsigned int base, uint64_t *output) {
  uint64_t result = 0;
  size_t index;
  if (value == NULL || value[0] == '\0' || (base != 8U && base != 10U)) return -1;
  for (index = 0; value[index] != '\0'; index += 1) {
    unsigned int digit;
    if (value[index] < '0' || value[index] > '9') return -1;
    digit = (unsigned int)(value[index] - '0');
    if (digit >= base || result > (UINT64_MAX - digit) / base) return -1;
    result = result * base + digit;
  }
  *output = result;
  return 0;
}

static int hb_parse_int64(const char *value, int64_t *output) {
  uint64_t magnitude;
  int negative = 0;
  if (value == NULL || value[0] == '\0') return -1;
  if (value[0] == '-') {
    negative = 1;
    value += 1;
  }
  if (hb_parse_uint64(value, 10U, &magnitude) != 0
      || magnitude > (negative ? ((uint64_t)INT64_MAX + 1U) : (uint64_t)INT64_MAX)) return -1;
  if (negative && magnitude == (uint64_t)INT64_MAX + 1U) {
    *output = INT64_MIN;
  } else {
    *output = negative ? -(int64_t)magnitude : (int64_t)magnitude;
  }
  return 0;
}

static struct hb_identity hb_identity_from_stat(const struct stat *status) {
  struct hb_identity identity;
  identity.dev = (uint64_t)status->st_dev;
  identity.ino = (uint64_t)status->st_ino;
  identity.uid = (uint64_t)status->st_uid;
  identity.gid = (uint64_t)status->st_gid;
  identity.mode = (uint64_t)(status->st_mode & 07777U);
  identity.nlink = (uint64_t)status->st_nlink;
  identity.size = (uint64_t)status->st_size;
  identity.gen = (uint64_t)status->st_gen;
  identity.mtime_sec = (int64_t)status->st_mtimespec.tv_sec;
  identity.mtime_nsec = (int64_t)status->st_mtimespec.tv_nsec;
  identity.ctime_sec = (int64_t)status->st_ctimespec.tv_sec;
  identity.ctime_nsec = (int64_t)status->st_ctimespec.tv_nsec;
  return identity;
}

static int hb_identity_equal(const struct hb_identity *left, const struct hb_identity *right) {
  return left->dev == right->dev
    && left->ino == right->ino
    && left->uid == right->uid
    && left->gid == right->gid
    && left->mode == right->mode
    && left->nlink == right->nlink
    && left->size == right->size
    && left->gen == right->gen
    && left->mtime_sec == right->mtime_sec
    && left->mtime_nsec == right->mtime_nsec
    && left->ctime_sec == right->ctime_sec
    && left->ctime_nsec == right->ctime_nsec;
}

static int hb_parse_identity_fields(char **fields, struct hb_identity *identity) {
  if (hb_parse_uint64(fields[0], 10U, &identity->dev) != 0
      || hb_parse_uint64(fields[1], 10U, &identity->ino) != 0
      || hb_parse_uint64(fields[2], 10U, &identity->uid) != 0
      || hb_parse_uint64(fields[3], 10U, &identity->gid) != 0
      || hb_parse_uint64(fields[4], 8U, &identity->mode) != 0
      || hb_parse_uint64(fields[5], 10U, &identity->nlink) != 0
      || hb_parse_uint64(fields[6], 10U, &identity->size) != 0
      || hb_parse_uint64(fields[7], 10U, &identity->gen) != 0
      || hb_parse_int64(fields[8], &identity->mtime_sec) != 0
      || hb_parse_int64(fields[9], &identity->mtime_nsec) != 0
      || hb_parse_int64(fields[10], &identity->ctime_sec) != 0
      || hb_parse_int64(fields[11], &identity->ctime_nsec) != 0
      || identity->mode > 07777U || identity->mtime_nsec < 0
      || identity->mtime_nsec >= 1000000000LL || identity->ctime_nsec < 0
      || identity->ctime_nsec >= 1000000000LL) return -1;
  return 0;
}

static int hb_split_exact(char *value, char delimiter, char **fields, size_t count) {
  size_t index = 0;
  char *cursor = value;
  fields[index++] = cursor;
  while (*cursor != '\0') {
    if (*cursor == delimiter) {
      if (index >= count) return -1;
      *cursor = '\0';
      fields[index++] = cursor + 1;
    }
    cursor += 1;
  }
  return index == count ? 0 : -1;
}

static int hb_expect_line(char *line, const char *key, char *destination, size_t capacity) {
  size_t key_length = strlen(key);
  if (strncmp(line, key, key_length) != 0 || line[key_length] != '=') return -1;
  return hb_copy_string(destination, capacity, line + key_length + 1);
}

static int hb_expect_digest_line(char *line, const char *key, char destination[65]) {
  if (hb_expect_line(line, key, destination, 65) != 0 || !hb_is_hex_digest(destination)) return -1;
  return 0;
}

static int hb_parse_manifest(char *bytes, size_t length, struct hb_manifest *manifest) {
  char *lines[24];
  size_t line_count = 0;
  size_t index;
  char *cursor = bytes;
  char expected_path[PATH_MAX];
  uint64_t entry_count;
  uint64_t total_file_bytes = 0;
  if (length == 0 || bytes[length - 1] != '\n' || memchr(bytes, '\0', length) != NULL) return -1;
  bytes[length - 1] = '\0';
  lines[line_count++] = cursor;
  while (*cursor != '\0') {
    if (*cursor == '\n') {
      if (line_count >= sizeof(lines) / sizeof(lines[0])) return -1;
      *cursor = '\0';
      lines[line_count++] = cursor + 1;
    }
    cursor += 1;
  }
  if (line_count != 24 || strcmp(lines[0], "version=1") != 0
      || hb_expect_line(lines[1], "role", manifest->role, sizeof(manifest->role)) != 0
      || !hb_is_role(manifest->role)
      || hb_expect_line(lines[2], "root_path", manifest->root_path, sizeof(manifest->root_path)) != 0
      || !hb_is_canonical_absolute_path(manifest->root_path)
      || hb_expect_line(lines[3], "executable_path", manifest->executable_path,
                        sizeof(manifest->executable_path)) != 0
      || hb_expect_line(lines[4], "entrypoint_path", manifest->entrypoint_path,
                        sizeof(manifest->entrypoint_path)) != 0
      || hb_expect_line(lines[5], "config_manifest_path", manifest->config_manifest_path,
                        sizeof(manifest->config_manifest_path)) != 0
      || hb_expect_digest_line(lines[6], "launch_plan_digest", manifest->launch_plan_digest) != 0
      || hb_expect_digest_line(lines[7], "worker_bundle_projection_digest",
                               manifest->worker_bundle_projection_digest) != 0
      || hb_expect_digest_line(lines[8], "native_evidence_digest", manifest->native_evidence_digest) != 0
      || hb_expect_digest_line(lines[9], "path_plan_digest", manifest->path_plan_digest) != 0
      || hb_expect_digest_line(lines[10], "argv_digest", manifest->argv_digest) != 0
      || hb_expect_digest_line(lines[11], "environment_digest", manifest->environment_digest) != 0
      || hb_expect_digest_line(lines[12], "fd_set_digest", manifest->fd_set_digest) != 0
      || hb_expect_digest_line(lines[13], "credential_plan_digest", manifest->credential_plan_digest) != 0) {
    return -1;
  }
  {
    int path_length = snprintf(expected_path, sizeof(expected_path), "%s/bin/node",
                               manifest->root_path);
    if (path_length < 0 || (size_t)path_length >= sizeof(expected_path)
        || strcmp(expected_path, manifest->executable_path) != 0) return -1;
    path_length = snprintf(expected_path, sizeof(expected_path), "%s/lib/worker.js",
                           manifest->root_path);
    if (path_length < 0 || (size_t)path_length >= sizeof(expected_path)
        || strcmp(expected_path, manifest->entrypoint_path) != 0) return -1;
    path_length = snprintf(expected_path, sizeof(expected_path), "%s/config/worker.json",
                           manifest->root_path);
    if (path_length < 0 || (size_t)path_length >= sizeof(expected_path)
        || strcmp(expected_path, manifest->config_manifest_path) != 0) return -1;
  }
  {
    char *root_fields[12];
    if (strncmp(lines[14], "root=", 5) != 0
        || hb_split_exact(lines[14] + 5, '|', root_fields, 12) != 0
        || hb_parse_identity_fields(root_fields, &manifest->root_identity) != 0
        || manifest->root_identity.mode != 0500U
        || strncmp(lines[15], "entry_count=", 12) != 0
        || hb_parse_uint64(lines[15] + 12, 10U, &entry_count) != 0
        || entry_count != HB_ENTRY_COUNT) return -1;
  }
  for (index = 0; index < HB_ENTRY_COUNT; index += 1) {
    char *entry_fields[15];
    struct hb_entry *entry = &manifest->entries[index];
    if (strncmp(lines[16 + index], "entry=", 6) != 0
        || hb_copy_string(entry->canonical_line, sizeof(entry->canonical_line), lines[16 + index] + 6) != 0
        || hb_split_exact(lines[16 + index] + 6, '|', entry_fields, 15) != 0
        || strcmp(entry_fields[0], HB_ENTRY_PATHS[index]) != 0
        || hb_copy_string(entry->path, sizeof(entry->path), entry_fields[0]) != 0
        || strlen(entry_fields[1]) != 1
        || (entry_fields[1][0] != 'd' && entry_fields[1][0] != 'f')
        || hb_parse_identity_fields(&entry_fields[2], &entry->identity) != 0
        || hb_copy_string(entry->content_digest, sizeof(entry->content_digest), entry_fields[14]) != 0) {
      return -1;
    }
    entry->type = entry_fields[1][0];
    if (entry->type != ((index % 2U) == 0U ? 'd' : 'f')
        || entry->identity.mode != (index == 1U ? 0500U : (entry->type == 'd' ? 0500U : 0400U))
        || (entry->type == 'd' && strcmp(entry->content_digest, "-") != 0)
        || (entry->type == 'f' && (!hb_is_hex_digest(entry->content_digest)
          || entry->identity.nlink != 1U || entry->identity.size == 0U
          || entry->identity.size > HB_MAX_ENTRY_BYTES
          || total_file_bytes > HB_MAX_TOTAL_ENTRY_BYTES - entry->identity.size))) return -1;
    if (entry->type == 'f') total_file_bytes += entry->identity.size;
  }
  return 0;
}

static int hb_read_bounded_file(int fd, const struct hb_identity *opened_identity,
                                char **bytes_out, size_t *length_out) {
  struct stat before;
  struct stat after;
  struct hb_identity before_identity;
  struct hb_identity after_identity;
  char *bytes;
  size_t offset = 0;
  char trailing_byte;
  ssize_t trailing_count;
  if (fstat(fd, &before) != 0 || !S_ISREG(before.st_mode) || before.st_size <= 0
      || before.st_size > (off_t)HB_MAX_MANIFEST_BYTES || before.st_nlink != 1
      || (before.st_mode & 07777U) != 0400U) return -1;
  before_identity = hb_identity_from_stat(&before);
  if (!hb_identity_equal(opened_identity, &before_identity)) return -1;
  bytes = calloc((size_t)before.st_size + 1U, 1U);
  if (bytes == NULL || lseek(fd, 0, SEEK_SET) < 0) {
    free(bytes);
    return -1;
  }
  while (offset < (size_t)before.st_size) {
    ssize_t count = read(fd, bytes + offset, (size_t)before.st_size - offset);
    if (count < 0 && errno == EINTR) continue;
    if (count <= 0) {
      free(bytes);
      return -1;
    }
    offset += (size_t)count;
  }
  do {
    trailing_count = read(fd, &trailing_byte, 1U);
  } while (trailing_count < 0 && errno == EINTR);
  if (trailing_count != 0 || fstat(fd, &after) != 0) {
    free(bytes);
    return -1;
  }
  after_identity = hb_identity_from_stat(&after);
  if (!hb_identity_equal(&before_identity, &after_identity)) {
    free(bytes);
    return -1;
  }
  *bytes_out = bytes;
  *length_out = offset;
  return 0;
}

static int hb_open_relative(int root_fd, const char *relative, int final_directory,
                            struct hb_identity *identity_out) {
  char path[PATH_MAX];
  char *component;
  char *next;
  int current_fd = -1;
  int result_fd = -1;
  if (hb_copy_string(path, sizeof(path), relative) != 0 || relative[0] == '/'
      || strstr(relative, "..") != NULL || strstr(relative, "//") != NULL) return -1;
  current_fd = dup(root_fd);
  if (current_fd < 0 || fcntl(current_fd, F_SETFD, FD_CLOEXEC) != 0) goto cleanup;
  component = path;
  for (;;) {
    struct stat before;
    struct stat after;
    struct hb_identity before_identity;
    struct hb_identity after_identity;
    int flags;
    next = strchr(component, '/');
    if (next != NULL) *next = '\0';
    if (component[0] == '\0' || strcmp(component, ".") == 0 || strcmp(component, "..") == 0
        || fstatat(current_fd, component, &before, AT_SYMLINK_NOFOLLOW) != 0
        || S_ISLNK(before.st_mode)
        || ((next != NULL || final_directory) && !S_ISDIR(before.st_mode))
        || (next == NULL && !final_directory && !S_ISREG(before.st_mode))) goto cleanup;
    flags = O_RDONLY | O_NONBLOCK | O_NOFOLLOW | O_CLOEXEC;
    if (next != NULL || final_directory) flags |= O_DIRECTORY;
    result_fd = openat(current_fd, component, flags);
    if (result_fd < 0 || fstat(result_fd, &after) != 0) goto cleanup;
    before_identity = hb_identity_from_stat(&before);
    after_identity = hb_identity_from_stat(&after);
    if (!hb_identity_equal(&before_identity, &after_identity)) goto cleanup;
    close(current_fd);
    current_fd = -1;
    if (next == NULL) {
      *identity_out = after_identity;
      return result_fd;
    }
    current_fd = result_fd;
    result_fd = -1;
    component = next + 1;
  }

cleanup:
  if (result_fd >= 0) close(result_fd);
  if (current_fd >= 0) close(current_fd);
  return -1;
}

static void hb_close_absolute_chain(struct hb_absolute_chain *chain) {
  size_t index;
  for (index = chain->count; index > 0; index -= 1) close(chain->fds[index - 1U]);
  memset(chain, 0, sizeof(*chain));
}

static int hb_open_absolute_chain(const char *absolute, int final_directory,
                                  struct hb_absolute_chain *chain) {
  char path[PATH_MAX];
  char *component;
  char *next;
  struct stat root_status;
  size_t index = 0;
  memset(chain, 0, sizeof(*chain));
  if (!hb_is_canonical_absolute_path(absolute)
      || hb_copy_string(chain->absolute_path, sizeof(chain->absolute_path), absolute) != 0
      || hb_copy_string(path, sizeof(path), absolute + 1) != 0) return -1;
  chain->final_directory = final_directory;
  chain->fds[0] = open("/", O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
  if (chain->fds[0] < 0 || fstat(chain->fds[0], &root_status) != 0
      || !S_ISDIR(root_status.st_mode)
      || hb_copy_string(chain->components[0], sizeof(chain->components[0]), "/") != 0) {
    if (chain->fds[0] >= 0) close(chain->fds[0]);
    memset(chain, 0, sizeof(*chain));
    return -1;
  }
  chain->identities[0] = hb_identity_from_stat(&root_status);
  chain->count = 1U;
  component = path;
  for (;;) {
    struct stat before;
    struct stat after;
    struct hb_identity before_identity;
    struct hb_identity after_identity;
    int flags = O_RDONLY | O_NONBLOCK | O_NOFOLLOW | O_CLOEXEC;
    next = strchr(component, '/');
    if (next != NULL) *next = '\0';
    index = chain->count;
    if (index < HB_MAX_ANCESTRY_COMPONENTS) chain->fds[index] = -1;
    if (index >= HB_MAX_ANCESTRY_COMPONENTS || component[0] == '\0'
        || strcmp(component, ".") == 0 || strcmp(component, "..") == 0
        || hb_copy_string(chain->components[index], sizeof(chain->components[index]), component) != 0
        || fstatat(chain->fds[index - 1U], component, &before, AT_SYMLINK_NOFOLLOW) != 0
        || S_ISLNK(before.st_mode)
        || ((next != NULL || final_directory) && !S_ISDIR(before.st_mode))
        || (next == NULL && !final_directory && !S_ISREG(before.st_mode))) goto cleanup;
    if (next != NULL || final_directory) flags |= O_DIRECTORY;
    chain->fds[index] = openat(chain->fds[index - 1U], component, flags);
    if (chain->fds[index] < 0 || fstat(chain->fds[index], &after) != 0) goto cleanup;
    before_identity = hb_identity_from_stat(&before);
    after_identity = hb_identity_from_stat(&after);
    if (!hb_identity_equal(&before_identity, &after_identity)) goto cleanup;
    chain->identities[index] = after_identity;
    chain->count += 1U;
    if (next == NULL) return 0;
    component = next + 1;
  }

cleanup:
  if (index < HB_MAX_ANCESTRY_COMPONENTS && chain->fds[index] >= 0
      && index >= chain->count) close(chain->fds[index]);
  hb_close_absolute_chain(chain);
  return -1;
}

static int hb_restat_absolute_chain(const struct hb_absolute_chain *chain) {
  size_t index;
  for (index = 0; index < chain->count; index += 1) {
    struct stat status;
    struct hb_identity identity;
    if (fstat(chain->fds[index], &status) != 0) return -1;
    identity = hb_identity_from_stat(&status);
    if (!hb_identity_equal(&identity, &chain->identities[index])) return -1;
  }
  return 0;
}

static int hb_terminally_rewalk_absolute_chain(const struct hb_absolute_chain *retained) {
  struct hb_absolute_chain current;
  size_t index;
  int result = -1;
  if (hb_restat_absolute_chain(retained) != 0
      || hb_open_absolute_chain(retained->absolute_path, retained->final_directory, &current) != 0) {
    return -1;
  }
  if (current.count == retained->count
      && current.final_directory == retained->final_directory) {
    result = 0;
    for (index = 0; index < retained->count; index += 1) {
      if (strcmp(current.components[index], retained->components[index]) != 0
          || !hb_identity_equal(&current.identities[index], &retained->identities[index])) {
        result = -1;
        break;
      }
    }
  }
  hb_close_absolute_chain(&current);
  if (result != 0 || hb_restat_absolute_chain(retained) != 0) return -1;
  return 0;
}

static int hb_verify_directory_names(int directory_fd, const char *const *allowed,
                                     size_t allowed_count) {
  struct stat expected_status;
  struct stat opened_status;
  struct stat final_status;
  struct hb_identity expected_identity;
  struct hb_identity opened_identity;
  struct hb_identity final_identity;
  int duplicate_fd;
  DIR *directory;
  struct dirent *entry;
  unsigned char *seen;
  size_t seen_count = 0;
  if (fstat(directory_fd, &expected_status) != 0 || !S_ISDIR(expected_status.st_mode)) return -1;
  expected_identity = hb_identity_from_stat(&expected_status);
  duplicate_fd = openat(directory_fd, ".", O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
  if (duplicate_fd < 0 || fstat(duplicate_fd, &opened_status) != 0) {
    if (duplicate_fd >= 0) close(duplicate_fd);
    return -1;
  }
  opened_identity = hb_identity_from_stat(&opened_status);
  if (!hb_identity_equal(&expected_identity, &opened_identity)) {
    close(duplicate_fd);
    return -1;
  }
  directory = fdopendir(duplicate_fd);
  if (directory == NULL) {
    close(duplicate_fd);
    return -1;
  }
  seen = calloc(allowed_count, sizeof(*seen));
  if (seen == NULL) {
    closedir(directory);
    return -1;
  }
  errno = 0;
  while ((entry = readdir(directory)) != NULL) {
    size_t index;
    int matched = 0;
    if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0) continue;
    for (index = 0; index < allowed_count; index += 1) {
      if (strcmp(entry->d_name, allowed[index]) == 0 && seen[index] == 0U) {
        seen[index] = 1U;
        seen_count += 1U;
        matched = 1;
        break;
      }
    }
    if (!matched) {
      free(seen);
      closedir(directory);
      return -1;
    }
  }
  if (errno != 0 || seen_count != allowed_count
      || fstat(dirfd(directory), &final_status) != 0) {
    free(seen);
    closedir(directory);
    return -1;
  }
  final_identity = hb_identity_from_stat(&final_status);
  if (!hb_identity_equal(&expected_identity, &final_identity)) {
    free(seen);
    closedir(directory);
    return -1;
  }
  free(seen);
  return closedir(directory) == 0 ? 0 : -1;
}

static int hb_verify_exact_tree_names(int root_fd, const struct hb_retained_bundle *bundle) {
  static const char *const root_names[] = {"bin", "config", "lib", "native"};
  static const char *const bin_names[] = {"node"};
  static const char *const config_names[] = {"native-launch-fixture.manifest", "worker.json"};
  static const char *const lib_names[] = {"worker.js"};
  static const char *const native_names[] = {"driver.node"};
  const char *const *sets[] = {bin_names, config_names, lib_names, native_names};
  const size_t counts[] = {1U, 2U, 1U, 1U};
  const size_t directory_entry_indexes[] = {0U, 2U, 4U, 6U};
  size_t index;
  if (hb_verify_directory_names(root_fd, root_names, 4U) != 0) return -1;
  for (index = 0; index < 4U; index += 1) {
    if (hb_verify_directory_names(
          bundle->fds[directory_entry_indexes[index]],
          sets[index],
          counts[index]
        ) != 0) return -1;
  }
  return 0;
}

static void hb_init_retained_bundle(struct hb_retained_bundle *bundle) {
  size_t index;
  memset(bundle, 0, sizeof(*bundle));
  for (index = 0; index < HB_ENTRY_COUNT; index += 1) bundle->fds[index] = -1;
}

static void hb_close_retained_bundle(struct hb_retained_bundle *bundle) {
  size_t index;
  for (index = 0; index < HB_ENTRY_COUNT; index += 1) {
    if (bundle->fds[index] >= 0) close(bundle->fds[index]);
  }
  hb_init_retained_bundle(bundle);
}

static int hb_open_retained_bundle(int root_fd, const struct hb_manifest *manifest,
                                   struct hb_retained_bundle *bundle) {
  size_t index;
  hb_init_retained_bundle(bundle);
  for (index = 0; index < HB_ENTRY_COUNT; index += 1) {
    const struct hb_entry *entry = &manifest->entries[index];
    struct stat status;
    bundle->fds[index] = hb_open_relative(
      root_fd,
      entry->path,
      entry->type == 'd',
      &bundle->opened_identities[index]
    );
    if (bundle->fds[index] < 0
        || !hb_identity_equal(&bundle->opened_identities[index], &entry->identity)
        || fstat(bundle->fds[index], &status) != 0
        || (entry->type == 'd' && !S_ISDIR(status.st_mode))
        || (entry->type == 'f' && !S_ISREG(status.st_mode))) {
      hb_close_retained_bundle(bundle);
      return -1;
    }
  }
  return 0;
}

static int hb_verify_retained_bundle_pass(struct hb_retained_bundle *bundle,
                                          const struct hb_manifest *manifest,
                                          int pass,
                                          char walk_digest[65]) {
  CC_SHA256_CTX walk_context;
  unsigned char digest[CC_SHA256_DIGEST_LENGTH];
  size_t index;
  if ((pass != 1 && pass != 2) || CC_SHA256_Init(&walk_context) != 1
      || CC_SHA256_Update(&walk_context, HB_WALK_DOMAIN, (CC_LONG)strlen(HB_WALK_DOMAIN)) != 1
      || CC_SHA256_Update(&walk_context, "\n", 1U) != 1) return -1;
  for (index = 0; index < HB_ENTRY_COUNT; index += 1) {
    const struct hb_entry *entry = &manifest->entries[index];
    struct hb_identity before_identity;
    struct hb_identity after_identity;
    struct stat before_status;
    struct stat after_status;
    char content_digest[HB_DIGEST_HEX_LENGTH + 1];
    if (bundle->fds[index] < 0 || fstat(bundle->fds[index], &before_status) != 0
        || (entry->type == 'd' && !S_ISDIR(before_status.st_mode))
        || (entry->type == 'f' && !S_ISREG(before_status.st_mode))
        || (entry->type == 'f' && hb_sha256_fd(bundle->fds[index], content_digest) != 0)
        || (entry->type == 'f' && strcmp(content_digest, entry->content_digest) != 0)
        || (entry->type == 'f' && pass == 2
          && strcmp(content_digest, bundle->first_pass_content_digests[index]) != 0)
        || fstat(bundle->fds[index], &after_status) != 0) return -1;
    before_identity = hb_identity_from_stat(&before_status);
    after_identity = hb_identity_from_stat(&after_status);
    if (!hb_identity_equal(&bundle->opened_identities[index], &before_identity)
        || !hb_identity_equal(&entry->identity, &before_identity)
        || !hb_identity_equal(&before_identity, &after_identity)
        || CC_SHA256_Update(&walk_context, entry->canonical_line,
                            (CC_LONG)strlen(entry->canonical_line)) != 1
        || CC_SHA256_Update(&walk_context, "\n", 1U) != 1) return -1;
    if (entry->type == 'f' && pass == 1
        && hb_copy_string(
          bundle->first_pass_content_digests[index],
          sizeof(bundle->first_pass_content_digests[index]),
          content_digest
        ) != 0) return -1;
  }
  if (CC_SHA256_Final(digest, &walk_context) != 1) return -1;
  hb_hex(digest, sizeof(digest), walk_digest);
  return 0;
}

static int hb_rewalk_retained_bundle(int root_fd, const struct hb_manifest *manifest,
                                     const struct hb_retained_bundle *bundle) {
  size_t index;
  for (index = 0; index < HB_ENTRY_COUNT; index += 1) {
    struct hb_identity current_identity;
    int current_fd = hb_open_relative(
      root_fd,
      manifest->entries[index].path,
      manifest->entries[index].type == 'd',
      &current_identity
    );
    if (current_fd < 0
        || !hb_identity_equal(&current_identity, &bundle->opened_identities[index])) {
      if (current_fd >= 0) close(current_fd);
      return -1;
    }
    close(current_fd);
  }
  return 0;
}

static int hb_final_sweep_retained_bundle(const struct hb_manifest *manifest,
                                          const struct hb_retained_bundle *bundle) {
  size_t index;
  for (index = 0; index < HB_ENTRY_COUNT; index += 1) {
    struct stat status;
    struct hb_identity identity;
    if (bundle->fds[index] < 0 || fstat(bundle->fds[index], &status) != 0) return -1;
    identity = hb_identity_from_stat(&status);
    if (!hb_identity_equal(&identity, &bundle->opened_identities[index])
        || !hb_identity_equal(&identity, &manifest->entries[index].identity)) return -1;
  }
  return 0;
}

static int hb_root_identity_digest(const struct hb_identity *identity, char output[65]) {
  char transcript[1024];
  int length = snprintf(
    transcript,
    sizeof(transcript),
    "%s\nroot|%llu|%llu|%llu|%llu|%04llo|%llu|%llu|%llu|%lld|%lld|%lld|%lld\n",
    HB_ROOT_DOMAIN,
    (unsigned long long)identity->dev,
    (unsigned long long)identity->ino,
    (unsigned long long)identity->uid,
    (unsigned long long)identity->gid,
    (unsigned long long)identity->mode,
    (unsigned long long)identity->nlink,
    (unsigned long long)identity->size,
    (unsigned long long)identity->gen,
    (long long)identity->mtime_sec,
    (long long)identity->mtime_nsec,
    (long long)identity->ctime_sec,
    (long long)identity->ctime_nsec
  );
  if (length < 0 || (size_t)length >= sizeof(transcript)) return -1;
  return hb_sha256_bytes(transcript, (size_t)length, output);
}

static int hb_list_fds(struct proc_fdinfo **records_out, size_t *count_out) {
  int bytes = proc_pidinfo(getpid(), PROC_PIDLISTFDS, 0, NULL, 0);
  struct proc_fdinfo *records;
  int received;
  if (bytes <= 0 || bytes > (int)(1024U * sizeof(struct proc_fdinfo))) return -1;
  records = calloc((size_t)bytes + sizeof(*records), 1U);
  if (records == NULL) return -1;
  received = proc_pidinfo(getpid(), PROC_PIDLISTFDS, 0, records, bytes);
  if (received < 0 || received % (int)sizeof(*records) != 0) {
    free(records);
    return -1;
  }
  *records_out = records;
  *count_out = (size_t)received / sizeof(*records);
  return 0;
}

static int hb_close_unlisted_fds(int retained_fd) {
  struct proc_fdinfo *records = NULL;
  size_t count = 0;
  size_t index;
  if (hb_list_fds(&records, &count) != 0) return -1;
  for (index = 0; index < count; index += 1) {
    int fd = records[index].proc_fd;
    if (fd >= 3 && fd != retained_fd) {
      while (close(fd) != 0 && errno == EINTR) {}
    }
  }
  free(records);
  return 0;
}

static int hb_reopen_stdio_dev_null(void) {
  int null_fd = open("/dev/null", O_RDWR | O_CLOEXEC | O_NOFOLLOW);
  int target;
  struct stat expected;
  if (null_fd < 0 || fstat(null_fd, &expected) != 0 || !S_ISCHR(expected.st_mode)) {
    if (null_fd >= 0) close(null_fd);
    return -1;
  }
  for (target = 0; target <= 2; target += 1) {
    struct stat actual;
    if (dup2(null_fd, target) < 0 || fstat(target, &actual) != 0
        || actual.st_dev != expected.st_dev || actual.st_ino != expected.st_ino
        || actual.st_rdev != expected.st_rdev || !S_ISCHR(actual.st_mode)) {
      close(null_fd);
      return -1;
    }
  }
  if (null_fd > 2) close(null_fd);
  return 0;
}

static int hb_verify_final_fds(int report_fd, char output[65]) {
  struct proc_fdinfo *records = NULL;
  size_t count = 0;
  size_t index;
  unsigned int seen = 0U;
  static const char transcript[] =
    HB_FD_DOMAIN "\n"
    "0=dev-null\n"
    "1=dev-null\n"
    "2=dev-null\n"
    "3=report-one-shot\n";
  if (report_fd != HB_REPORT_FD || hb_list_fds(&records, &count) != 0) return -1;
  for (index = 0; index < count; index += 1) {
    int fd = records[index].proc_fd;
    if (fd < 0 || fd > HB_REPORT_FD || (seen & (1U << (unsigned int)fd)) != 0U) {
      free(records);
      return -1;
    }
    seen |= 1U << (unsigned int)fd;
  }
  free(records);
  if (seen != 0x0fU) return -1;
  return hb_sha256_bytes(transcript, sizeof(transcript) - 1U, output);
}

static int hb_compare_gid(const void *left, const void *right) {
  gid_t left_gid = *(const gid_t *)left;
  gid_t right_gid = *(const gid_t *)right;
  return left_gid < right_gid ? -1 : left_gid > right_gid ? 1 : 0;
}

static int hb_read_saved_credentials(uid_t *real_uid, uid_t *effective_uid, uid_t *saved_uid,
                                     gid_t *real_gid, gid_t *effective_gid, gid_t *saved_gid) {
  struct proc_bsdinfo info;
  int received = proc_pidinfo(getpid(), PROC_PIDTBSDINFO, 0, &info, (int)sizeof(info));
  if (received != (int)sizeof(info)) return -1;
  *real_uid = info.pbi_ruid;
  *effective_uid = info.pbi_uid;
  *saved_uid = info.pbi_svuid;
  *real_gid = info.pbi_rgid;
  *effective_gid = info.pbi_gid;
  *saved_gid = info.pbi_svgid;
  return 0;
}

static int hb_credential_observation_digest(char output[65]) {
  uid_t real_uid;
  uid_t effective_uid;
  uid_t saved_uid;
  gid_t real_gid;
  gid_t effective_gid;
  gid_t saved_gid;
  gid_t groups[HB_MAX_GROUPS];
  int group_count;
  char transcript[8192];
  size_t offset;
  int index;
  int length;
  if (hb_read_saved_credentials(
        &real_uid,
        &effective_uid,
        &saved_uid,
        &real_gid,
        &effective_gid,
        &saved_gid
      ) != 0) return -1;
  group_count = getgroups(HB_MAX_GROUPS, groups);
  if (group_count < 0 || group_count > HB_MAX_GROUPS) return -1;
  qsort(groups, (size_t)group_count, sizeof(groups[0]), hb_compare_gid);
  length = snprintf(
    transcript,
    sizeof(transcript),
    "%s\nruid=%u\neuid=%u\nsuid=%u\nrgid=%u\negid=%u\nsgid=%u\ngroups=",
    HB_CREDENTIAL_DOMAIN,
    (unsigned int)real_uid,
    (unsigned int)effective_uid,
    (unsigned int)saved_uid,
    (unsigned int)real_gid,
    (unsigned int)effective_gid,
    (unsigned int)saved_gid
  );
  if (length < 0 || (size_t)length >= sizeof(transcript)) return -1;
  offset = (size_t)length;
  for (index = 0; index < group_count; index += 1) {
    length = snprintf(transcript + offset, sizeof(transcript) - offset,
                      "%s%u", index == 0 ? "" : ",", (unsigned int)groups[index]);
    if (length < 0 || (size_t)length >= sizeof(transcript) - offset) return -1;
    offset += (size_t)length;
  }
  if (offset + 1U >= sizeof(transcript)) return -1;
  transcript[offset++] = '\n';
  transcript[offset] = '\0';
  return hb_sha256_bytes(transcript, offset, output);
}

static int hb_hash_on_disk_executable_path_object(char output[65]) {
  char executable[PROC_PIDPATHINFO_MAXSIZE];
  int length = proc_pidpath(getpid(), executable, sizeof(executable));
  struct hb_absolute_chain executable_chain;
  int fd = -1;
  struct stat before;
  struct stat after;
  struct hb_identity opened_identity;
  struct hb_identity before_identity;
  struct hb_identity after_identity;
  int result;
  if (length <= 0 || (size_t)length >= sizeof(executable)
      || !hb_is_canonical_absolute_path(executable)) return -1;
  if (hb_open_absolute_chain(executable, 0, &executable_chain) != 0) return -1;
  fd = executable_chain.fds[executable_chain.count - 1U];
  opened_identity = executable_chain.identities[executable_chain.count - 1U];
  if (fd < 0 || fstat(fd, &before) != 0 || !S_ISREG(before.st_mode) || before.st_nlink != 1) {
    hb_close_absolute_chain(&executable_chain);
    return -1;
  }
  before_identity = hb_identity_from_stat(&before);
  result = hb_sha256_fd(fd, output);
  if (result != 0 || fstat(fd, &after) != 0) {
    hb_close_absolute_chain(&executable_chain);
    return -1;
  }
  after_identity = hb_identity_from_stat(&after);
  if (!hb_identity_equal(&opened_identity, &before_identity)
      || !hb_identity_equal(&before_identity, &after_identity)) result = -1;
  if (result == 0 && hb_terminally_rewalk_absolute_chain(&executable_chain) != 0) result = -1;
  hb_close_absolute_chain(&executable_chain);
  return result;
}

static int hb_record_checksum(const struct hb_manifest *manifest,
                            const char *manifest_digest,
                            const char *on_disk_path_object_sha256,
                            const char *root_digest,
                            const char *walk_digest,
                            const char *fd_digest,
                            const char *credential_digest,
                            char output[65]) {
  char transcript[HB_MAX_RECORD_BYTES];
  int length = snprintf(
    transcript,
    sizeof(transcript),
    "%s\n"
    "version=2\n"
    "kind=darwin_native_launcher_fixture_contract_record\n"
    "record_domain=%s\n"
    "fixture_manifest_digest=%s\n"
    "native_launcher_on_disk_path_object_sha256=%s\n"
    "declared_launch_plan_digest=%s\n"
    "declared_worker_bundle_projection_digest=%s\n"
    "declared_native_evidence_digest=%s\n"
    "declared_path_plan_digest=%s\n"
    "declared_argv_digest=%s\n"
    "declared_environment_digest=%s\n"
    "declared_fd_set_digest=%s\n"
    "declared_credential_plan_digest=%s\n"
    "fixture_root_identity_digest=%s\n"
    "openat_fstatat_walk_digest=%s\n"
    "fd_enumeration_digest=%s\n"
    "credential_observation_digest=%s\n"
    "bundle_entry_count=8\n"
    "all_path_components_openat_verified=true\n"
    "all_bundle_objects_exact=true\n"
    "all_unlisted_fds_closed=true\n"
    "stdio_reopened_dev_null=true\n"
    "empty_environment=true\n"
    "retained_bundle_fds_verified=true\n"
    "double_hash_identity_pass_complete=true\n"
    "terminal_ancestry_rewalk_complete=true\n"
    "final_retained_fd_identity_sweep_complete=true\n"
    "credential_drop_executed=false\n"
    "execve_executed=false\n"
    "native_launcher_mapped_process_image_identity_bound=false\n"
    "native_fixture_record_provenance_attested=false\n"
    "child_process_custody_attested=false\n"
    "report_channel_authenticated=false\n"
    "production_attested=false\n"
    "production_ready=false\n"
    "production_blockers=%s\n",
    HB_RECORD_DOMAIN,
    HB_RECORD_DOMAIN,
    manifest_digest,
    on_disk_path_object_sha256,
    manifest->launch_plan_digest,
    manifest->worker_bundle_projection_digest,
    manifest->native_evidence_digest,
    manifest->path_plan_digest,
    manifest->argv_digest,
    manifest->environment_digest,
    manifest->fd_set_digest,
    manifest->credential_plan_digest,
    root_digest,
    walk_digest,
    fd_digest,
    credential_digest,
    HB_PRODUCTION_BLOCKERS
  );
  if (length < 0 || (size_t)length >= sizeof(transcript)) return -1;
  return hb_sha256_bytes(transcript, (size_t)length, output);
}

static int hb_write_all(int fd, const char *bytes, size_t length) {
  size_t offset = 0;
  while (offset < length) {
    ssize_t count = write(fd, bytes + offset, length - offset);
    if (count < 0 && errno == EINTR) continue;
    if (count <= 0) return -1;
    offset += (size_t)count;
  }
  return 0;
}

#if defined(HB_TEST_ONLY_PHASE_BARRIER) && HB_TEST_ONLY_PHASE_BARRIER == 1
static int hb_test_only_terminal_sweep_barrier(void) {
  static const char marker[] = "HB_TEST_ONLY_TERMINAL_SWEEP\n";
  char acknowledgement;
  ssize_t count;
  if (hb_write_all(4, marker, sizeof(marker) - 1U) != 0) return -1;
  do {
    count = read(5, &acknowledgement, 1U);
  } while (count < 0 && errno == EINTR);
  return count == 1 && acknowledgement == 'A' ? 0 : -1;
}
#endif

static int hb_write_rejection(void) {
  static const char rejection[] =
    "{\"version\":2,\"kind\":\"darwin_native_launcher_fixture_rejection\","
    "\"code\":\"fixture_rejected\"}\n";
  return hb_write_all(HB_REPORT_FD, rejection, sizeof(rejection) - 1U);
}

static int hb_write_record(const struct hb_manifest *manifest,
                           const char *manifest_digest,
                           const char *on_disk_path_object_sha256,
                           const char *root_digest,
                           const char *walk_digest,
                           const char *fd_digest,
                           const char *credential_digest,
                           const char *record_checksum) {
  char record[HB_MAX_RECORD_BYTES];
  int length = snprintf(
    record,
    sizeof(record),
    "{"
    "\"version\":2,"
    "\"kind\":\"darwin_native_launcher_fixture_contract_record\","
    "\"record_domain\":\"%s\","
    "\"fixture_manifest_digest\":\"%s\","
    "\"native_launcher_on_disk_path_object_sha256\":\"%s\","
    "\"declared_launch_plan_digest\":\"%s\","
    "\"declared_worker_bundle_projection_digest\":\"%s\","
    "\"declared_native_evidence_digest\":\"%s\","
    "\"declared_path_plan_digest\":\"%s\","
    "\"declared_argv_digest\":\"%s\","
    "\"declared_environment_digest\":\"%s\","
    "\"declared_fd_set_digest\":\"%s\","
    "\"declared_credential_plan_digest\":\"%s\","
    "\"fixture_root_identity_digest\":\"%s\","
    "\"openat_fstatat_walk_digest\":\"%s\","
    "\"fd_enumeration_digest\":\"%s\","
    "\"credential_observation_digest\":\"%s\","
    "\"bundle_entry_count\":8,"
    "\"all_path_components_openat_verified\":true,"
    "\"all_bundle_objects_exact\":true,"
    "\"all_unlisted_fds_closed\":true,"
    "\"stdio_reopened_dev_null\":true,"
    "\"empty_environment\":true,"
    "\"retained_bundle_fds_verified\":true,"
    "\"double_hash_identity_pass_complete\":true,"
    "\"terminal_ancestry_rewalk_complete\":true,"
    "\"final_retained_fd_identity_sweep_complete\":true,"
    "\"credential_drop_executed\":false,"
    "\"execve_executed\":false,"
    "\"native_launcher_mapped_process_image_identity_bound\":false,"
    "\"native_fixture_record_provenance_attested\":false,"
    "\"child_process_custody_attested\":false,"
    "\"report_channel_authenticated\":false,"
    "\"production_attested\":false,"
    "\"production_ready\":false,"
    "\"production_blockers\":["
      "\"adhoc_native_signature_not_production_qualified\","
      "\"root_owned_immutable_install_not_qualified\","
      "\"real_credential_drop_readback_hil_missing\","
      "\"negative_principal_matrix_hil_missing\","
      "\"capability_fd_projection_not_linked_into_fixture\","
      "\"privileged_launch_wire_authority_verifier_not_integrated\","
      "\"privileged_launch_provenance_persistence_not_integrated\","
      "\"standalone_native_dispatch_custodian_prebuild_missing\","
      "\"node_fixture_adapter_argv_not_executor_contract\","
      "\"production_executor_not_linked\","
      "\"fixture_mode_execve_disabled\","
      "\"root_owned_immutable_ancestry_hil_missing\","
      "\"darwin_fd_bound_exec_unavailable\","
      "\"native_launcher_mapped_process_image_identity_unbound\","
      "\"native_fixture_record_provenance_unattested\","
      "\"writable_fixture_bracketing_not_production_immutability\"],"
    "\"contract_record_checksum\":\"%s\""
    "}\n",
    HB_RECORD_DOMAIN,
    manifest_digest,
    on_disk_path_object_sha256,
    manifest->launch_plan_digest,
    manifest->worker_bundle_projection_digest,
    manifest->native_evidence_digest,
    manifest->path_plan_digest,
    manifest->argv_digest,
    manifest->environment_digest,
    manifest->fd_set_digest,
    manifest->credential_plan_digest,
    root_digest,
    walk_digest,
    fd_digest,
    credential_digest,
    record_checksum
  );
  if (length < 0 || (size_t)length >= sizeof(record)) return -1;
  return hb_write_all(HB_REPORT_FD, record, (size_t)length);
}

static int hb_verify_fixture(const char *root_path, const char *expected_manifest_digest) {
  int root_fd = -1;
  int manifest_fd = -1;
  int current_manifest_fd = -1;
  char *manifest_bytes = NULL;
  size_t manifest_length = 0;
  struct hb_manifest manifest;
  struct hb_absolute_chain root_chain;
  struct hb_retained_bundle retained_bundle;
  struct stat root_before;
  struct stat root_after;
  struct stat manifest_final_before;
  struct stat manifest_final_after;
  struct stat current_manifest_after;
  struct hb_identity root_identity_before;
  struct hb_identity root_identity_after;
  struct hb_identity opened_root_identity;
  struct hb_identity manifest_identity;
  struct hb_identity manifest_final_before_identity;
  struct hb_identity manifest_final_after_identity;
  struct hb_identity current_manifest_identity;
  struct hb_identity current_manifest_after_identity;
  char manifest_digest[65];
  char final_manifest_digest[65];
  char current_manifest_digest[65];
  char on_disk_path_object_sha256[65];
  char root_digest[65];
  char first_walk_digest[65];
  char second_walk_digest[65];
  char fd_digest[65];
  char credential_digest[65];
  char record_checksum[65];
  int result = -1;
  memset(&manifest, 0, sizeof(manifest));
  memset(&root_chain, 0, sizeof(root_chain));
  hb_init_retained_bundle(&retained_bundle);
  if (!hb_is_canonical_absolute_path(root_path) || !hb_is_hex_digest(expected_manifest_digest)
      || environ == NULL || environ[0] != NULL || getuid() == 0 || geteuid() == 0) goto cleanup;
  if (hb_open_absolute_chain(root_path, 1, &root_chain) != 0) goto cleanup;
  root_fd = root_chain.fds[root_chain.count - 1U];
  opened_root_identity = root_chain.identities[root_chain.count - 1U];
  if (root_fd < 0 || fstat(root_fd, &root_before) != 0 || !S_ISDIR(root_before.st_mode)) goto cleanup;
  root_identity_before = hb_identity_from_stat(&root_before);
  if (!hb_identity_equal(&opened_root_identity, &root_identity_before)) goto cleanup;
  manifest_fd = hb_open_relative(root_fd, HB_MANIFEST_RELATIVE, 0, &manifest_identity);
  if (manifest_fd < 0
      || hb_read_bounded_file(manifest_fd, &manifest_identity,
                              &manifest_bytes, &manifest_length) != 0
      || hb_sha256_bytes(manifest_bytes, manifest_length, manifest_digest) != 0
      || strcmp(manifest_digest, expected_manifest_digest) != 0
      || hb_parse_manifest(manifest_bytes, manifest_length, &manifest) != 0
      || strcmp(root_path, manifest.root_path) != 0
      || !hb_identity_equal(&root_identity_before, &manifest.root_identity)
      || hb_hash_on_disk_executable_path_object(on_disk_path_object_sha256) != 0
      || hb_open_retained_bundle(root_fd, &manifest, &retained_bundle) != 0
      || hb_verify_exact_tree_names(root_fd, &retained_bundle) != 0
      || hb_verify_retained_bundle_pass(
        &retained_bundle,
        &manifest,
        1,
        first_walk_digest
      ) != 0
      || hb_verify_exact_tree_names(root_fd, &retained_bundle) != 0
      || hb_verify_retained_bundle_pass(
        &retained_bundle,
        &manifest,
        2,
        second_walk_digest
      ) != 0
      || strcmp(first_walk_digest, second_walk_digest) != 0
      || hb_verify_exact_tree_names(root_fd, &retained_bundle) != 0
      || hb_credential_observation_digest(credential_digest) != 0) goto cleanup;

#if defined(HB_TEST_ONLY_PHASE_BARRIER) && HB_TEST_ONLY_PHASE_BARRIER == 1
  if (hb_test_only_terminal_sweep_barrier() != 0) goto cleanup;
#endif

  current_manifest_fd = hb_open_relative(
    root_fd,
    HB_MANIFEST_RELATIVE,
    0,
    &current_manifest_identity
  );
  if (current_manifest_fd < 0
      || !hb_identity_equal(&manifest_identity, &current_manifest_identity)
      || hb_sha256_fd(current_manifest_fd, current_manifest_digest) != 0
      || strcmp(manifest_digest, current_manifest_digest) != 0
      || fstat(current_manifest_fd, &current_manifest_after) != 0) goto cleanup;
  current_manifest_after_identity = hb_identity_from_stat(&current_manifest_after);
  if (!hb_identity_equal(&current_manifest_identity, &current_manifest_after_identity)
      || hb_rewalk_retained_bundle(root_fd, &manifest, &retained_bundle) != 0
      || hb_terminally_rewalk_absolute_chain(&root_chain) != 0
      || hb_final_sweep_retained_bundle(&manifest, &retained_bundle) != 0
      || fstat(manifest_fd, &manifest_final_before) != 0) goto cleanup;
  close(current_manifest_fd);
  current_manifest_fd = -1;
  manifest_final_before_identity = hb_identity_from_stat(&manifest_final_before);
  if (!hb_identity_equal(&manifest_identity, &manifest_final_before_identity)
      || hb_sha256_fd(manifest_fd, final_manifest_digest) != 0
      || strcmp(manifest_digest, final_manifest_digest) != 0
      || fstat(manifest_fd, &manifest_final_after) != 0) goto cleanup;
  manifest_final_after_identity = hb_identity_from_stat(&manifest_final_after);
  if (!hb_identity_equal(&manifest_final_before_identity, &manifest_final_after_identity)
      || fstat(root_fd, &root_after) != 0
      || hb_restat_absolute_chain(&root_chain) != 0) goto cleanup;
  root_identity_after = hb_identity_from_stat(&root_after);
  if (!hb_identity_equal(&root_identity_before, &root_identity_after)
      || hb_root_identity_digest(&root_identity_after, root_digest) != 0) goto cleanup;
  hb_close_retained_bundle(&retained_bundle);
  close(manifest_fd);
  manifest_fd = -1;
  hb_close_absolute_chain(&root_chain);
  root_fd = -1;
  free(manifest_bytes);
  manifest_bytes = NULL;
  if (hb_close_unlisted_fds(HB_REPORT_FD) != 0 || hb_reopen_stdio_dev_null() != 0
      || hb_verify_final_fds(HB_REPORT_FD, fd_digest) != 0
      || hb_record_checksum(
        &manifest,
        manifest_digest,
        on_disk_path_object_sha256,
        root_digest,
        second_walk_digest,
        fd_digest,
        credential_digest,
        record_checksum
      ) != 0
      || hb_write_record(
        &manifest,
        manifest_digest,
        on_disk_path_object_sha256,
        root_digest,
        second_walk_digest,
        fd_digest,
        credential_digest,
        record_checksum
      ) != 0) goto cleanup;
  result = 0;

cleanup:
  if (current_manifest_fd >= 0) close(current_manifest_fd);
  hb_close_retained_bundle(&retained_bundle);
  if (manifest_fd >= 0) close(manifest_fd);
  hb_close_absolute_chain(&root_chain);
  free(manifest_bytes);
  return result;
}

int main(int argc, char **argv) {
  int result;
  if (argc != 8 || argv == NULL
      || strcmp(argv[1], "--verify-fixture") != 0
      || strcmp(argv[2], "--root") != 0
      || strcmp(argv[4], "--manifest-sha256") != 0
      || strcmp(argv[6], "--report-fd") != 0
      || strcmp(argv[7], "3") != 0) {
    hb_write_rejection();
    return 64;
  }
  result = hb_verify_fixture(argv[3], argv[5]);
  if (result != 0) {
    hb_write_rejection();
    return 65;
  }
  return 0;
}
