#define _DARWIN_C_SOURCE 1

#if defined(HB_LIFECYCLE_CUSTODIAN_SOURCE_ONLY) == defined(HB_LIFECYCLE_CUSTODIAN_TEST_ONLY)
#error "define exactly one lifecycle custodian build gate"
#endif

#include <CommonCrypto/CommonDigest.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/un.h>

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define HB_TARGET_ROOT_FD 3
#define HB_SOURCE_ROOT_FD 4
#define HB_REQUEST_FD 5
#define HB_RESULT_FD 6
#define HB_REQUEST_MAGIC "HBLCRQ01"
#define HB_RESULT_MAGIC "HBLCRS01"
#define HB_JOURNAL_MAGIC "HBLCTXN1"
#define HB_REQUEST_VERSION 1U
#define HB_JOURNAL_VERSION 2U
#define HB_REQUEST_HEADER_BYTES 64U
#define HB_RECORD_HEADER_BYTES 44U
#define HB_JOURNAL_BYTES 192U
#define HB_RESULT_BYTES 16U
#define HB_MAX_REQUEST_BYTES (128U * 1024U)
#define HB_MAX_FILES 128U
#define HB_MAX_FILE_BYTES (512ULL * 1024ULL * 1024ULL)
#define HB_MAX_TOTAL_BYTES (512ULL * 1024ULL * 1024ULL)
#define HB_MAX_PATH_BYTES 512U
#define HB_MAX_COMPONENT_BYTES 128U
#define HB_MAX_COMPONENTS 16U
#define HB_COPY_BUFFER_BYTES 16384U
#define HB_MAX_REMOVE_DEPTH 32U
#define HB_MAX_REMOVE_ENTRIES 4096U

enum hb_operation {
  HB_OPERATION_REPLACE = 1,
  HB_OPERATION_REMOVE = 2
};

enum hb_selection {
  HB_OPTIONAL_WORKER = 1,
  HB_OPTIONAL_NATIVE = 2,
  HB_CANONICAL_ARTIFACT_VAULT = 100,
  HB_CANONICAL_BROKER = 101,
  HB_CANONICAL_CHAMELEON = 102,
  HB_CANONICAL_DETERMINISTIC = 103,
  HB_CANONICAL_PREBUILD_TRUST = 104,
  HB_CANONICAL_PRINCIPAL_ACL = 105,
  HB_CANONICAL_INSTRUMENT_CONTRACTS = 106,
  HB_CANONICAL_CHAMELEON_WORKER_RUNTIME = 107
};

enum hb_phase {
  HB_PHASE_BUILDING = 1,
  HB_PHASE_PREPARED = 2,
  HB_PHASE_BACKUP_RENAMED = 3,
  HB_PHASE_INSTALLED = 4,
  HB_PHASE_COMMITTED = 5
};

enum hb_test_crash_point {
  HB_TEST_CRASH_AFTER_STAGING_CREATE = 6,
  HB_TEST_CRASH_AFTER_BACKUP_RENAME = 7,
  HB_TEST_CRASH_AFTER_INSTALL_RENAME = 8,
  HB_TEST_CRASH_AFTER_RECOVERY = 9
};

enum hb_result_code {
  HB_RESULT_CHANGED = 0,
  HB_RESULT_ABSENT = 1,
  HB_RESULT_REJECTED = 2
};

struct hb_file_record {
  char path[HB_MAX_PATH_BYTES + 1U];
  uint16_t mode;
  uint64_t size;
  unsigned char digest[CC_SHA256_DIGEST_LENGTH];
};

struct hb_request {
  uint32_t operation;
  uint32_t selection;
  uint32_t file_count;
  uint32_t test_crash_phase;
  unsigned char plan_digest[CC_SHA256_DIGEST_LENGTH];
  struct hb_file_record files[HB_MAX_FILES];
};

struct hb_names {
  const char *parent_components[3];
  size_t parent_count;
  const char *leaf;
  char staging[160];
  char backup[160];
  char journal[160];
  char journal_temp[168];
};

struct hb_object_identity {
  uint64_t device;
  uint64_t inode;
  uint64_t generation;
  uint64_t birth_seconds;
  uint64_t birth_nanoseconds;
  uint32_t mode;
};

struct hb_journal {
  uint32_t selection;
  uint32_t phase;
  uint32_t had_existing;
  uint32_t staged_bound;
  unsigned char plan_digest[CC_SHA256_DIGEST_LENGTH];
  struct hb_object_identity original_identity;
  struct hb_object_identity staged_identity;
};

static int hb_result_capability_ready = 0;

#ifdef HB_LIFECYCLE_CUSTODIAN_TEST_ONLY
static const char *hb_test_stage = "entry";
#define HB_TEST_STAGE(value) do { hb_test_stage = (value); } while (0)
#else
#define HB_TEST_STAGE(value) do { (void)sizeof(value); } while (0)
#endif

static uint16_t hb_read_u16(const unsigned char *bytes) {
  return (uint16_t)(((uint16_t)bytes[0] << 8U) | (uint16_t)bytes[1]);
}

static uint32_t hb_read_u32(const unsigned char *bytes) {
  return ((uint32_t)bytes[0] << 24U) | ((uint32_t)bytes[1] << 16U)
    | ((uint32_t)bytes[2] << 8U) | (uint32_t)bytes[3];
}

static uint64_t hb_read_u64(const unsigned char *bytes) {
  uint64_t value = 0;
  size_t index;
  for (index = 0; index < 8U; index += 1U) value = (value << 8U) | bytes[index];
  return value;
}

static void hb_write_u32(unsigned char *bytes, uint32_t value) {
  bytes[0] = (unsigned char)(value >> 24U);
  bytes[1] = (unsigned char)(value >> 16U);
  bytes[2] = (unsigned char)(value >> 8U);
  bytes[3] = (unsigned char)value;
}

static void hb_write_u64(unsigned char *bytes, uint64_t value) {
  size_t index;
  for (index = 0; index < 8U; index += 1U) {
    bytes[7U - index] = (unsigned char)value;
    value >>= 8U;
  }
}

static int hb_write_all(int fd, const unsigned char *bytes, size_t length) {
  size_t offset = 0;
  while (offset < length) {
    ssize_t written = write(fd, bytes + offset, length - offset);
    if (written < 0 && errno == EINTR) continue;
    if (written <= 0) return -1;
    offset += (size_t)written;
  }
  return 0;
}

static int hb_pread_all(int fd, unsigned char *bytes, size_t length) {
  size_t offset = 0;
  while (offset < length) {
    ssize_t count = pread(fd, bytes + offset, length - offset, (off_t)offset);
    if (count < 0 && errno == EINTR) continue;
    if (count <= 0) return -1;
    offset += (size_t)count;
  }
  return 0;
}

static int hb_fsync(int fd) {
  int result;
  do {
    result = fsync(fd);
  } while (result != 0 && errno == EINTR);
  return result;
}

static int hb_close(int fd) {
  return close(fd);
}

static int hb_sha256_fd(int fd, unsigned char output[CC_SHA256_DIGEST_LENGTH]) {
  CC_SHA256_CTX context;
  unsigned char buffer[HB_COPY_BUFFER_BYTES];
  off_t offset = 0;
  if (CC_SHA256_Init(&context) != 1) return -1;
  for (;;) {
    ssize_t count = pread(fd, buffer, sizeof(buffer), offset);
    if (count < 0 && errno == EINTR) continue;
    if (count < 0) return -1;
    if (count == 0) break;
    if (CC_SHA256_Update(&context, buffer, (CC_LONG)count) != 1) return -1;
    offset += count;
  }
  return CC_SHA256_Final(output, &context) == 1 ? 0 : -1;
}

static int hb_component_valid(const char *value, size_t length) {
  size_t index;
  if (length == 0U || length > HB_MAX_COMPONENT_BYTES
      || (length == 1U && value[0] == '.')
      || (length == 2U && value[0] == '.' && value[1] == '.')) return 0;
  for (index = 0; index < length; index += 1U) {
    unsigned char character = (unsigned char)value[index];
    if (!((character >= 'A' && character <= 'Z')
          || (character >= 'a' && character <= 'z')
          || (character >= '0' && character <= '9')
          || character == '.' || character == '_' || character == '@'
          || character == '+' || character == '-')) return 0;
  }
  return 1;
}

static int hb_path_valid(const char *value, size_t length) {
  size_t start = 0;
  size_t components = 0;
  size_t index;
  if (length == 0U || length > HB_MAX_PATH_BYTES || value[0] == '/'
      || value[length - 1U] == '/') return 0;
  for (index = 0; index <= length; index += 1U) {
    if (index == length || value[index] == '/') {
      if (!hb_component_valid(value + start, index - start)) return 0;
      components += 1U;
      if (components > HB_MAX_COMPONENTS) return 0;
      start = index + 1U;
    } else if (value[index] == '\\' || value[index] == '\0') {
      return 0;
    }
  }
  return components > 0U;
}

static int hb_selection_valid(uint32_t selection) {
  return selection == HB_OPTIONAL_WORKER || selection == HB_OPTIONAL_NATIVE
    || (selection >= HB_CANONICAL_ARTIFACT_VAULT
      && selection <= HB_CANONICAL_CHAMELEON_WORKER_RUNTIME);
}

static int hb_mode_valid(uint32_t selection, uint16_t mode) {
  if (selection == HB_OPTIONAL_WORKER) return mode == 0444U;
  if (selection == HB_OPTIONAL_NATIVE) return mode == 0444U || mode == 0555U;
  return mode == 0644U;
}

static int hb_parse_request(struct hb_request *request) {
  struct stat status;
  int descriptor_flags = fcntl(HB_REQUEST_FD, F_GETFL);
  unsigned char *bytes = NULL;
  unsigned char digest[CC_SHA256_DIGEST_LENGTH];
  size_t offset;
  uint64_t total_bytes = 0U;
  uint32_t index;
  int result = -1;
  if (request == NULL || descriptor_flags < 0
      || (descriptor_flags & O_ACCMODE) != O_RDONLY
      || fstat(HB_REQUEST_FD, &status) != 0
      || !S_ISREG(status.st_mode) || status.st_nlink != 1
      || (status.st_mode & 0777U) != 0444U
      || status.st_size < (off_t)HB_REQUEST_HEADER_BYTES
      || status.st_size > (off_t)HB_MAX_REQUEST_BYTES) return -1;
  bytes = calloc((size_t)status.st_size, 1U);
  if (bytes == NULL || hb_pread_all(HB_REQUEST_FD, bytes, (size_t)status.st_size) != 0
      || memcmp(bytes, HB_REQUEST_MAGIC, 8U) != 0
      || hb_read_u32(bytes + 8U) != HB_REQUEST_VERSION) goto cleanup;
  memset(request, 0, sizeof(*request));
  request->operation = hb_read_u32(bytes + 12U);
  request->selection = hb_read_u32(bytes + 16U);
  request->file_count = hb_read_u32(bytes + 20U);
  request->test_crash_phase = hb_read_u32(bytes + 24U);
  if ((request->operation != HB_OPERATION_REPLACE
        && request->operation != HB_OPERATION_REMOVE)
      || !hb_selection_valid(request->selection)
      || request->file_count > HB_MAX_FILES
      || (request->operation == HB_OPERATION_REPLACE && request->file_count == 0U)
      || (request->operation == HB_OPERATION_REMOVE && request->file_count != 0U)) goto cleanup;
#ifdef HB_LIFECYCLE_CUSTODIAN_SOURCE_ONLY
  if (request->test_crash_phase != 0U) goto cleanup;
#else
  if (request->test_crash_phase > HB_TEST_CRASH_AFTER_RECOVERY) goto cleanup;
#endif
  if (CC_SHA256(bytes + HB_REQUEST_HEADER_BYTES,
      (CC_LONG)((size_t)status.st_size - HB_REQUEST_HEADER_BYTES), digest) == NULL
      || memcmp(digest, bytes + 32U, CC_SHA256_DIGEST_LENGTH) != 0) goto cleanup;
  memcpy(request->plan_digest, digest, sizeof(request->plan_digest));
  offset = HB_REQUEST_HEADER_BYTES;
  for (index = 0; index < request->file_count; index += 1U) {
    uint16_t path_length;
    struct hb_file_record *record = &request->files[index];
    if (offset + HB_RECORD_HEADER_BYTES > (size_t)status.st_size) goto cleanup;
    path_length = hb_read_u16(bytes + offset);
    record->mode = hb_read_u16(bytes + offset + 2U);
    record->size = hb_read_u64(bytes + offset + 4U);
    memcpy(record->digest, bytes + offset + 12U, CC_SHA256_DIGEST_LENGTH);
    offset += HB_RECORD_HEADER_BYTES;
    if (path_length == 0U || path_length > HB_MAX_PATH_BYTES
        || offset + path_length > (size_t)status.st_size
        || !hb_path_valid((const char *)(bytes + offset), path_length)
        || !hb_mode_valid(request->selection, record->mode)
        || record->size > HB_MAX_FILE_BYTES
        || total_bytes > HB_MAX_TOTAL_BYTES - record->size) goto cleanup;
    total_bytes += record->size;
    memcpy(record->path, bytes + offset, path_length);
    record->path[path_length] = '\0';
    if (index > 0U && strcmp(request->files[index - 1U].path, record->path) >= 0) goto cleanup;
    offset += path_length;
  }
  if (offset != (size_t)status.st_size) goto cleanup;
  result = 0;

cleanup:
  if (bytes != NULL) {
    memset(bytes, 0, (size_t)status.st_size);
    free(bytes);
  }
  return result;
}

static int hb_names_for_selection(uint32_t selection, struct hb_names *names) {
  const char *transaction_stem;
  memset(names, 0, sizeof(*names));
  if (selection == HB_OPTIONAL_WORKER || selection == HB_OPTIONAL_NATIVE) {
    names->parent_components[0] = ".hacker-bob";
    names->parent_components[1] = "optional-providers";
    names->parent_components[2] = "chameleon-ultra";
    names->parent_count = 3U;
    if (selection == HB_OPTIONAL_WORKER) {
      names->leaf = "worker-source";
      transaction_stem = "worker_source";
    } else {
      names->leaf = "darwin-arm64-native-prebuild";
      transaction_stem = "darwin_arm64_native_prebuild";
    }
  } else {
    names->parent_components[0] = "packages";
    names->parent_count = 1U;
    transaction_stem = NULL;
    switch (selection) {
      case HB_CANONICAL_ARTIFACT_VAULT: names->leaf = "bob-artifact-vault"; break;
      case HB_CANONICAL_BROKER: names->leaf = "bob-instrument-broker"; break;
      case HB_CANONICAL_CHAMELEON: names->leaf = "bob-instrument-chameleon"; break;
      case HB_CANONICAL_DETERMINISTIC: names->leaf = "bob-instrument-deterministic"; break;
      case HB_CANONICAL_PREBUILD_TRUST:
        names->leaf = "bob-instrument-native-prebuild-trust";
        break;
      case HB_CANONICAL_PRINCIPAL_ACL:
        names->leaf = "bob-instrument-principal-acl-darwin";
        break;
      case HB_CANONICAL_INSTRUMENT_CONTRACTS:
        names->leaf = "bob-instrument-contracts";
        break;
      case HB_CANONICAL_CHAMELEON_WORKER_RUNTIME:
        names->leaf = "bob-instrument-chameleon-worker-runtime";
        break;
      default: return -1;
    }
    transaction_stem = names->leaf;
  }
  if (snprintf(names->staging, sizeof(names->staging), ".staging-%s", transaction_stem)
        <= 0
      || snprintf(names->backup, sizeof(names->backup), ".backup-%s", transaction_stem)
        <= 0
      || snprintf(names->journal, sizeof(names->journal), ".transaction-%s.json",
        transaction_stem) <= 0
      || snprintf(names->journal_temp, sizeof(names->journal_temp),
        ".transaction-%s.json.tmp", transaction_stem) <= 0) return -1;
  return 0;
}

static int hb_entry_status(int parent_fd, const char *name, struct stat *status) {
  if (fstatat(parent_fd, name, status, AT_SYMLINK_NOFOLLOW) == 0) return 1;
  return errno == ENOENT ? 0 : -1;
}

static int hb_status_identity(
  const struct stat *status,
  struct hb_object_identity *identity
) {
  if (status->st_birthtimespec.tv_sec < 0 || status->st_birthtimespec.tv_nsec < 0
      || status->st_birthtimespec.tv_nsec >= 1000000000L) return -1;
  memset(identity, 0, sizeof(*identity));
  identity->device = (uint64_t)(uint32_t)status->st_dev;
  identity->inode = (uint64_t)status->st_ino;
  identity->generation = (uint64_t)status->st_gen;
  identity->birth_seconds = (uint64_t)status->st_birthtimespec.tv_sec;
  identity->birth_nanoseconds = (uint64_t)status->st_birthtimespec.tv_nsec;
  identity->mode = (uint32_t)(status->st_mode & (mode_t)(S_IFMT | 07777U));
  return 0;
}

static int hb_status_matches_identity(
  const struct stat *status,
  const struct hb_object_identity *identity
) {
  struct hb_object_identity observed;
  return hb_status_identity(status, &observed) == 0
    && observed.device == identity->device && observed.inode == identity->inode
    && observed.generation == identity->generation
    && observed.birth_seconds == identity->birth_seconds
    && observed.birth_nanoseconds == identity->birth_nanoseconds
    && observed.mode == identity->mode;
}

static int hb_entry_matches_identity(
  int parent_fd,
  const char *name,
  const struct hb_object_identity *identity
) {
  struct stat status;
  return fstatat(parent_fd, name, &status, AT_SYMLINK_NOFOLLOW) == 0
    && hb_status_matches_identity(&status, identity);
}

static int hb_entry_matches_descriptor(int parent_fd, const char *name, int descriptor) {
  struct stat at_name;
  struct stat opened;
  return fstatat(parent_fd, name, &at_name, AT_SYMLINK_NOFOLLOW) == 0
    && fstat(descriptor, &opened) == 0
    && S_ISDIR(at_name.st_mode) && S_ISDIR(opened.st_mode)
    && at_name.st_dev == opened.st_dev && at_name.st_ino == opened.st_ino;
}

static DIR *hb_directory_stream(int directory_fd) {
  int enumeration_fd = openat(directory_fd, ".",
    O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
  DIR *directory;
  if (enumeration_fd < 0) return NULL;
  directory = fdopendir(enumeration_fd);
  if (directory == NULL) (void)hb_close(enumeration_fd);
  return directory;
}

static int hb_open_parent(
  int root_fd,
  const struct hb_names *names,
  int create,
  int *parent_fd
) {
  int current = fcntl(root_fd, F_DUPFD_CLOEXEC, 32);
  size_t index;
  if (current < 0) return -1;
  for (index = 0; index < names->parent_count; index += 1U) {
    struct stat status;
    int present = hb_entry_status(current, names->parent_components[index], &status);
    int next;
    int created = 0;
    if (present < 0 || (present > 0 && !S_ISDIR(status.st_mode))) goto rejected;
    if (present == 0) {
      if (!create) {
        (void)hb_close(current);
        return 1;
      }
      if (mkdirat(current, names->parent_components[index], 0755) != 0
          || hb_fsync(current) != 0) goto rejected;
      created = 1;
    }
    next = openat(current, names->parent_components[index],
      O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (next < 0 || fstat(next, &status) != 0 || !S_ISDIR(status.st_mode)) {
      if (next >= 0) (void)hb_close(next);
      goto rejected;
    }
    if (created != 0 && (fchmod(next, 0755) != 0 || hb_fsync(next) != 0)) {
      (void)hb_close(next);
      goto rejected;
    }
    (void)hb_close(current);
    current = next;
  }
  *parent_fd = current;
  return 0;

rejected:
  (void)hb_close(current);
  return -1;
}

static int hb_remove_entry_recursive(
  int parent_fd,
  const char *name,
  size_t depth,
  size_t *remaining
) {
  struct stat status;
  struct hb_object_identity entry_identity;
  int present = hb_entry_status(parent_fd, name, &status);
  if (present <= 0) return present;
  if (remaining == NULL || *remaining == 0U || depth > HB_MAX_REMOVE_DEPTH) return -1;
  if (hb_status_identity(&status, &entry_identity) != 0) return -1;
  *remaining -= 1U;
  if (S_ISDIR(status.st_mode)) {
    int directory_fd = openat(parent_fd, name,
      O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    struct stat opened_status;
    DIR *directory;
    struct dirent *entry;
    if (directory_fd < 0 || fstat(directory_fd, &opened_status) != 0
        || !hb_status_matches_identity(&opened_status, &entry_identity)) {
      if (directory_fd >= 0) (void)hb_close(directory_fd);
      return -1;
    }
    directory = hb_directory_stream(directory_fd);
    if (directory == NULL) {
      (void)hb_close(directory_fd);
      return -1;
    }
    errno = 0;
    while ((entry = readdir(directory)) != NULL) {
      if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0) continue;
      if (!hb_component_valid(entry->d_name, strlen(entry->d_name))
          || hb_remove_entry_recursive(
            directory_fd, entry->d_name, depth + 1U, remaining) < 0) {
        (void)closedir(directory);
        (void)hb_close(directory_fd);
        return -1;
      }
      errno = 0;
    }
    if (errno != 0 || closedir(directory) != 0 || hb_fsync(directory_fd) != 0
        || !hb_entry_matches_descriptor(parent_fd, name, directory_fd)
        || !hb_entry_matches_identity(parent_fd, name, &entry_identity)
        || hb_close(directory_fd) != 0
        || unlinkat(parent_fd, name, AT_REMOVEDIR) != 0) return -1;
  } else if (!hb_entry_matches_identity(parent_fd, name, &entry_identity)
      || unlinkat(parent_fd, name, 0) != 0) {
    return -1;
  }
  return hb_fsync(parent_fd);
}

static int hb_remove_entry(int parent_fd, const char *name) {
  size_t remaining = HB_MAX_REMOVE_ENTRIES;
  return hb_remove_entry_recursive(parent_fd, name, 0U, &remaining);
}

static int hb_remove_entry_bound(
  int parent_fd,
  const char *name,
  const struct hb_object_identity *identity
) {
  if (!hb_entry_matches_identity(parent_fd, name, identity)) return -1;
  return hb_remove_entry(parent_fd, name);
}

static int hb_open_relative_file(int root_fd, const char *relative, int *output_fd) {
  char copy[HB_MAX_PATH_BYTES + 1U];
  char *cursor;
  char *separator;
  int current = fcntl(root_fd, F_DUPFD_CLOEXEC, 32);
  if (current < 0 || strlen(relative) > HB_MAX_PATH_BYTES) return -1;
  memcpy(copy, relative, strlen(relative) + 1U);
  cursor = copy;
  for (;;) {
    int next;
    separator = strchr(cursor, '/');
    if (separator == NULL) break;
    *separator = '\0';
    next = openat(current, cursor, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (next < 0) {
      (void)hb_close(current);
      return -1;
    }
    (void)hb_close(current);
    current = next;
    cursor = separator + 1;
  }
  *output_fd = openat(current, cursor, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
  (void)hb_close(current);
  return *output_fd < 0 ? -1 : 0;
}

static int hb_verify_source_file(int source_root_fd, const struct hb_file_record *record) {
  struct stat status;
  unsigned char digest[CC_SHA256_DIGEST_LENGTH];
  int file_fd;
  int result = -1;
  if (hb_open_relative_file(source_root_fd, record->path, &file_fd) != 0) return -1;
  if (fstat(file_fd, &status) == 0 && S_ISREG(status.st_mode) && status.st_nlink == 1
      && (status.st_mode & 0777U) == record->mode
      && status.st_size >= 0 && (uint64_t)status.st_size == record->size
      && hb_sha256_fd(file_fd, digest) == 0
      && memcmp(digest, record->digest, sizeof(digest)) == 0) result = 0;
  (void)hb_close(file_fd);
  return result;
}

static int hb_record_index(const struct hb_request *request, const char *path) {
  uint32_t index;
  for (index = 0; index < request->file_count; index += 1U) {
    int comparison = strcmp(request->files[index].path, path);
    if (comparison == 0) return (int)index;
    if (comparison > 0) break;
  }
  return -1;
}

static int hb_has_record_prefix(const struct hb_request *request, const char *path) {
  char prefix[HB_MAX_PATH_BYTES + 2U];
  uint32_t index;
  int length = snprintf(prefix, sizeof(prefix), "%s/", path);
  if (length <= 0 || (size_t)length >= sizeof(prefix)) return 0;
  for (index = 0; index < request->file_count; index += 1U) {
    if (strncmp(request->files[index].path, prefix, (size_t)length) == 0) return 1;
  }
  return 0;
}

static int hb_verify_source_tree_recursive(
  int source_root_fd,
  int directory_fd,
  const char *prefix,
  const struct hb_request *request,
  unsigned char seen[HB_MAX_FILES]
) {
  DIR *directory = hb_directory_stream(directory_fd);
  struct dirent *entry;
  if (directory == NULL) return -1;
  errno = 0;
  while ((entry = readdir(directory)) != NULL) {
    char relative[HB_MAX_PATH_BYTES + 1U];
    struct stat status;
    int length;
    if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0) continue;
    if (!hb_component_valid(entry->d_name, strlen(entry->d_name))) goto rejected;
    length = prefix[0] == '\0'
      ? snprintf(relative, sizeof(relative), "%s", entry->d_name)
      : snprintf(relative, sizeof(relative), "%s/%s", prefix, entry->d_name);
    if (length <= 0 || (size_t)length >= sizeof(relative)
        || fstatat(directory_fd, entry->d_name, &status, AT_SYMLINK_NOFOLLOW) != 0) goto rejected;
    if (S_ISDIR(status.st_mode)) {
      int child;
      if ((status.st_mode & 0777U) != 0755U || !hb_has_record_prefix(request, relative)) {
        goto rejected;
      }
      child = openat(directory_fd, entry->d_name,
        O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
      if (child < 0 || hb_verify_source_tree_recursive(
          source_root_fd, child, relative, request, seen) != 0
          || hb_close(child) != 0) goto rejected;
    } else if (S_ISREG(status.st_mode)) {
      int index = hb_record_index(request, relative);
      if (index < 0 || seen[index] != 0U
          || hb_verify_source_file(source_root_fd, &request->files[index]) != 0) {
        goto rejected;
      }
      seen[index] = 1U;
    } else {
      goto rejected;
    }
    errno = 0;
  }
  if (errno != 0 || closedir(directory) != 0) return -1;
  return 0;

rejected:
  (void)closedir(directory);
  return -1;
}

static int hb_verify_source_tree(int source_root_fd, const struct hb_request *request) {
  unsigned char seen[HB_MAX_FILES];
  uint32_t index;
  memset(seen, 0, sizeof(seen));
  if (hb_verify_source_tree_recursive(
      source_root_fd, source_root_fd, "", request, seen) != 0) return -1;
  for (index = 0; index < request->file_count; index += 1U) {
    if (seen[index] != 1U) return -1;
  }
  return 0;
}

static int hb_ensure_relative_parent(int root_fd, const char *relative, int *parent_fd,
  char leaf[HB_MAX_COMPONENT_BYTES + 1U]) {
  char copy[HB_MAX_PATH_BYTES + 1U];
  char *cursor;
  char *separator;
  int current = fcntl(root_fd, F_DUPFD_CLOEXEC, 32);
  if (current < 0 || strlen(relative) > HB_MAX_PATH_BYTES) return -1;
  memcpy(copy, relative, strlen(relative) + 1U);
  cursor = copy;
  for (;;) {
    int next;
    separator = strchr(cursor, '/');
    if (separator == NULL) break;
    *separator = '\0';
    next = openat(current, cursor, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (next < 0 && errno == ENOENT) {
      if (mkdirat(current, cursor, 0755) != 0 || hb_fsync(current) != 0) goto rejected;
      next = openat(current, cursor, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
      if (next >= 0 && fchmod(next, 0755) != 0) {
        (void)hb_close(next);
        goto rejected;
      }
    }
    if (next < 0) goto rejected;
    (void)hb_close(current);
    current = next;
    cursor = separator + 1;
  }
  if (strlen(cursor) > HB_MAX_COMPONENT_BYTES) goto rejected;
  memcpy(leaf, cursor, strlen(cursor) + 1U);
  *parent_fd = current;
  return 0;

rejected:
  (void)hb_close(current);
  return -1;
}

static int hb_copy_file(
  int source_root_fd,
  int staging_fd,
  const struct hb_file_record *record
) {
  unsigned char buffer[HB_COPY_BUFFER_BYTES];
  CC_SHA256_CTX digest_context;
  unsigned char digest[CC_SHA256_DIGEST_LENGTH];
  struct stat source_status;
  struct stat target_status;
  char leaf[HB_MAX_COMPONENT_BYTES + 1U];
  int source_fd = -1;
  int parent_fd = -1;
  int target_fd = -1;
  uint64_t total = 0;
  int result = -1;
  if (hb_open_relative_file(source_root_fd, record->path, &source_fd) != 0
      || fstat(source_fd, &source_status) != 0 || !S_ISREG(source_status.st_mode)
      || source_status.st_nlink != 1 || source_status.st_size < 0
      || (uint64_t)source_status.st_size != record->size
      || (source_status.st_mode & 0777U) != record->mode
      || hb_ensure_relative_parent(staging_fd, record->path, &parent_fd, leaf) != 0) {
    goto cleanup;
  }
  target_fd = openat(parent_fd, leaf,
    O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, record->mode);
  if (target_fd < 0 || CC_SHA256_Init(&digest_context) != 1) goto cleanup;
  for (;;) {
    ssize_t count = read(source_fd, buffer, sizeof(buffer));
    if (count < 0 && errno == EINTR) continue;
    if (count < 0) goto cleanup;
    if (count == 0) break;
    if (hb_write_all(target_fd, buffer, (size_t)count) != 0
        || CC_SHA256_Update(&digest_context, buffer, (CC_LONG)count) != 1) goto cleanup;
    total += (uint64_t)count;
  }
  if (CC_SHA256_Final(digest, &digest_context) != 1
      || total != record->size || memcmp(digest, record->digest, sizeof(digest)) != 0
      || fchmod(target_fd, record->mode) != 0 || hb_fsync(target_fd) != 0
      || fstat(target_fd, &target_status) != 0 || !S_ISREG(target_status.st_mode)
      || target_status.st_nlink != 1 || target_status.st_size < 0
      || (uint64_t)target_status.st_size != record->size
      || (target_status.st_mode & 0777U) != record->mode
      || hb_fsync(parent_fd) != 0) goto cleanup;
  result = 0;

cleanup:
  if (target_fd >= 0) (void)hb_close(target_fd);
  if (parent_fd >= 0) (void)hb_close(parent_fd);
  if (source_fd >= 0) (void)hb_close(source_fd);
  return result;
}

static int hb_sync_tree(int directory_fd) {
  DIR *directory = hb_directory_stream(directory_fd);
  struct dirent *entry;
  if (directory == NULL) return -1;
  errno = 0;
  while ((entry = readdir(directory)) != NULL) {
    struct stat status;
    if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0) continue;
    if (fstatat(directory_fd, entry->d_name, &status, AT_SYMLINK_NOFOLLOW) != 0) goto rejected;
    if (S_ISDIR(status.st_mode)) {
      int child = openat(directory_fd, entry->d_name,
        O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
      if (child < 0 || hb_sync_tree(child) != 0 || hb_close(child) != 0) goto rejected;
    }
    errno = 0;
  }
  if (errno != 0 || closedir(directory) != 0 || hb_fsync(directory_fd) != 0) return -1;
  return 0;

rejected:
  (void)closedir(directory);
  return -1;
}

static int hb_identity_empty(const struct hb_object_identity *identity) {
  return identity->device == 0U && identity->inode == 0U
    && identity->generation == 0U && identity->birth_seconds == 0U
    && identity->birth_nanoseconds == 0U && identity->mode == 0U;
}

static int hb_identity_valid(const struct hb_object_identity *identity) {
  uint32_t type = identity->mode & (uint32_t)S_IFMT;
  return identity->birth_nanoseconds < 1000000000ULL
    && (type == (uint32_t)S_IFDIR || type == (uint32_t)S_IFREG
      || type == (uint32_t)S_IFLNK || type == (uint32_t)S_IFIFO
      || type == (uint32_t)S_IFSOCK || type == (uint32_t)S_IFCHR
      || type == (uint32_t)S_IFBLK);
}

static void hb_encode_identity(
  unsigned char *bytes,
  const struct hb_object_identity *identity
) {
  hb_write_u64(bytes, identity->device);
  hb_write_u64(bytes + 8U, identity->inode);
  hb_write_u64(bytes + 16U, identity->generation);
  hb_write_u64(bytes + 24U, identity->birth_seconds);
  hb_write_u64(bytes + 32U, identity->birth_nanoseconds);
  hb_write_u32(bytes + 40U, identity->mode);
}

static int hb_decode_identity(
  const unsigned char *bytes,
  struct hb_object_identity *identity
) {
  if (hb_read_u32(bytes + 44U) != 0U) return -1;
  identity->device = hb_read_u64(bytes);
  identity->inode = hb_read_u64(bytes + 8U);
  identity->generation = hb_read_u64(bytes + 16U);
  identity->birth_seconds = hb_read_u64(bytes + 24U);
  identity->birth_nanoseconds = hb_read_u64(bytes + 32U);
  identity->mode = hb_read_u32(bytes + 40U);
  return 0;
}

static void hb_encode_journal(
  const struct hb_journal *journal,
  unsigned char bytes[HB_JOURNAL_BYTES]
) {
  unsigned char checksum[CC_SHA256_DIGEST_LENGTH];
  memset(bytes, 0, HB_JOURNAL_BYTES);
  memcpy(bytes, HB_JOURNAL_MAGIC, 8U);
  hb_write_u32(bytes + 8U, HB_JOURNAL_VERSION);
  hb_write_u32(bytes + 12U, journal->selection);
  hb_write_u32(bytes + 16U, journal->phase);
  hb_write_u32(bytes + 20U, journal->had_existing);
  hb_write_u32(bytes + 24U, journal->staged_bound);
  memcpy(bytes + 32U, journal->plan_digest, CC_SHA256_DIGEST_LENGTH);
  hb_encode_identity(bytes + 64U, &journal->original_identity);
  hb_encode_identity(bytes + 112U, &journal->staged_identity);
  (void)CC_SHA256(bytes, 160U, checksum);
  memcpy(bytes + 160U, checksum, sizeof(checksum));
}

static int hb_decode_journal(
  int parent_fd,
  const char *name,
  struct hb_journal *journal
) {
  unsigned char bytes[HB_JOURNAL_BYTES];
  unsigned char checksum[CC_SHA256_DIGEST_LENGTH];
  struct stat status;
  int fd = openat(parent_fd, name, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
  int result = -1;
  if (fd < 0 || fstat(fd, &status) != 0 || !S_ISREG(status.st_mode)
      || status.st_nlink != 1 || (status.st_mode & 0777U) != 0400U
      || status.st_size != (off_t)HB_JOURNAL_BYTES
      || hb_pread_all(fd, bytes, sizeof(bytes)) != 0
      || memcmp(bytes, HB_JOURNAL_MAGIC, 8U) != 0
      || hb_read_u32(bytes + 8U) != HB_JOURNAL_VERSION
      || hb_read_u32(bytes + 28U) != 0U
      || CC_SHA256(bytes, 160U, checksum) == NULL
      || memcmp(checksum, bytes + 160U, sizeof(checksum)) != 0) goto cleanup;
  journal->selection = hb_read_u32(bytes + 12U);
  journal->phase = hb_read_u32(bytes + 16U);
  journal->had_existing = hb_read_u32(bytes + 20U);
  journal->staged_bound = hb_read_u32(bytes + 24U);
  memcpy(journal->plan_digest, bytes + 32U, sizeof(journal->plan_digest));
  if (hb_decode_identity(bytes + 64U, &journal->original_identity) != 0
      || hb_decode_identity(bytes + 112U, &journal->staged_identity) != 0
      || !hb_selection_valid(journal->selection)
      || journal->phase < HB_PHASE_BUILDING || journal->phase > HB_PHASE_COMMITTED
      || journal->had_existing > 1U || journal->staged_bound > 1U
      || (journal->had_existing == 0U && !hb_identity_empty(&journal->original_identity))
      || (journal->had_existing != 0U && !hb_identity_valid(&journal->original_identity))
      || (journal->staged_bound == 0U && !hb_identity_empty(&journal->staged_identity))
      || (journal->staged_bound != 0U
        && (!hb_identity_valid(&journal->staged_identity)
          || (journal->staged_identity.mode & (uint32_t)(S_IFMT | 07777U))
            != (uint32_t)(S_IFDIR | 0755U)))
      || (journal->phase >= HB_PHASE_PREPARED && journal->staged_bound == 0U)) {
    goto cleanup;
  }
  result = 0;

cleanup:
  memset(bytes, 0, sizeof(bytes));
  if (fd >= 0) (void)hb_close(fd);
  return result;
}

static int hb_write_journal(
  int parent_fd,
  const struct hb_names *names,
  const struct hb_journal *journal
) {
  unsigned char bytes[HB_JOURNAL_BYTES];
  struct stat status;
  int fd = -1;
  int temporary_status = hb_entry_status(parent_fd, names->journal_temp, &status);
  if (temporary_status != 0) return -1;
  hb_encode_journal(journal, bytes);
  fd = openat(parent_fd, names->journal_temp,
    O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0400);
  if (fd < 0 || hb_write_all(fd, bytes, sizeof(bytes)) != 0
      || fchmod(fd, 0400) != 0 || hb_fsync(fd) != 0
      || fstat(fd, &status) != 0 || !S_ISREG(status.st_mode)
      || status.st_nlink != 1 || status.st_size != (off_t)sizeof(bytes)
      || (status.st_mode & 0777U) != 0400U) {
    memset(bytes, 0, sizeof(bytes));
    if (fd >= 0) (void)hb_close(fd);
    return -1;
  }
  if (hb_close(fd) != 0) {
    memset(bytes, 0, sizeof(bytes));
    return -1;
  }
  if (renameat(parent_fd, names->journal_temp, parent_fd, names->journal) != 0
      || hb_fsync(parent_fd) != 0) {
    memset(bytes, 0, sizeof(bytes));
    return -1;
  }
  memset(bytes, 0, sizeof(bytes));
  return 0;
}

static int hb_bound_entry_presence(
  int parent_fd,
  const char *name,
  const struct hb_object_identity *identity
) {
  struct stat status;
  int present = hb_entry_status(parent_fd, name, &status);
  if (present <= 0) return present;
  return hb_status_matches_identity(&status, identity) ? 1 : -1;
}

static int hb_remove_bound_if_present(
  int parent_fd,
  const char *name,
  const struct hb_object_identity *identity
) {
  int present = hb_bound_entry_presence(parent_fd, name, identity);
  if (present <= 0) return present;
  return hb_remove_entry_bound(parent_fd, name, identity);
}

static int hb_verify_bound_tree(
  int parent_fd,
  const char *name,
  const struct hb_object_identity *identity,
  const struct hb_request *request
) {
  struct stat status;
  int directory_fd = openat(parent_fd, name,
    O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
  int result = -1;
  if (directory_fd < 0 || fstat(directory_fd, &status) != 0
      || !hb_status_matches_identity(&status, identity)
      || hb_verify_source_tree(directory_fd, request) != 0
      || !hb_entry_matches_descriptor(parent_fd, name, directory_fd)
      || !hb_entry_matches_identity(parent_fd, name, identity)) goto cleanup;
  result = 0;

cleanup:
  if (directory_fd >= 0) (void)hb_close(directory_fd);
  return result;
}

static int hb_remove_staged_if_present(
  int parent_fd,
  const char *name,
  const struct hb_object_identity *identity,
  const struct hb_request *request
) {
  int present = hb_bound_entry_presence(parent_fd, name, identity);
  if (present <= 0) return present;
  if (request != NULL && hb_verify_bound_tree(parent_fd, name, identity, request) != 0) {
    return -1;
  }
  return hb_remove_entry_bound(parent_fd, name, identity);
}

static int hb_restore_original(
  int parent_fd,
  const struct hb_names *names,
  const struct hb_journal *journal
) {
  struct stat status;
  if (journal->had_existing == 0U
      || hb_bound_entry_presence(parent_fd, names->backup,
        &journal->original_identity) != 1
      || hb_entry_status(parent_fd, names->leaf, &status) != 0
      || renameat(parent_fd, names->backup, parent_fd, names->leaf) != 0
      || hb_fsync(parent_fd) != 0
      || !hb_entry_matches_identity(parent_fd, names->leaf,
        &journal->original_identity)) return -1;
  return 0;
}

static int hb_recover_transaction(
  int parent_fd,
  const struct hb_names *names,
  uint32_t selection,
  const unsigned char *expected_plan_digest,
  const struct hb_request *expected_request,
  int allow_orphan_cleanup
) {
  struct stat status;
  struct hb_journal journal;
  int journal_present = hb_entry_status(parent_fd, names->journal, &status);
  int temp_present = hb_entry_status(parent_fd, names->journal_temp, &status);
  int staging_present;
  int backup_present;
  int leaf_present;
  if (journal_present < 0 || temp_present < 0) return -1;
  if (journal_present == 0 && temp_present > 0) {
    if (hb_decode_journal(parent_fd, names->journal_temp, &journal) != 0
        || renameat(parent_fd, names->journal_temp, parent_fd, names->journal) != 0
        || hb_fsync(parent_fd) != 0) return -1;
    journal_present = 1;
  } else if (journal_present > 0 && temp_present > 0) {
    if (hb_remove_entry(parent_fd, names->journal_temp) < 0) return -1;
  }
  staging_present = hb_entry_status(parent_fd, names->staging, &status);
  backup_present = hb_entry_status(parent_fd, names->backup, &status);
  leaf_present = hb_entry_status(parent_fd, names->leaf, &status);
  if (staging_present < 0 || backup_present < 0 || leaf_present < 0) return -1;
  if (journal_present == 0) {
    if (staging_present == 0 && backup_present == 0) return 0;
    if (!allow_orphan_cleanup) return -1;
    if (hb_remove_entry(parent_fd, names->staging) < 0
        || hb_remove_entry(parent_fd, names->backup) < 0) return -1;
    return 0;
  }
  if (hb_decode_journal(parent_fd, names->journal, &journal) != 0
      || journal.selection != selection
      || (expected_plan_digest != NULL
        && memcmp(journal.plan_digest, expected_plan_digest,
          CC_SHA256_DIGEST_LENGTH) != 0)) return -1;
  if (journal.phase == HB_PHASE_BUILDING) {
    if (backup_present > 0
        || (staging_present > 0 && (journal.staged_bound == 0U
          || hb_remove_staged_if_present(parent_fd, names->staging,
            &journal.staged_identity, expected_request) != 0))) return -1;
  } else if (journal.phase == HB_PHASE_PREPARED) {
    if (journal.had_existing != 0U) {
      if (backup_present > 0) {
        if (!hb_entry_matches_identity(parent_fd, names->backup,
              &journal.original_identity)
            || leaf_present > 0
            || hb_remove_staged_if_present(parent_fd, names->staging,
              &journal.staged_identity, expected_request) < 0
            || hb_restore_original(parent_fd, names, &journal) != 0) return -1;
      } else if (leaf_present == 0
          || !hb_entry_matches_identity(parent_fd, names->leaf,
            &journal.original_identity)
          || hb_remove_staged_if_present(parent_fd, names->staging,
            &journal.staged_identity, expected_request) < 0) {
        return -1;
      }
    } else if (backup_present > 0 || leaf_present > 0
        || hb_remove_staged_if_present(parent_fd, names->staging,
          &journal.staged_identity, expected_request) < 0) {
      return -1;
    }
  } else if (journal.phase == HB_PHASE_BACKUP_RENAMED) {
    if (journal.had_existing != 0U) {
      if (backup_present > 0) {
        if (!hb_entry_matches_identity(parent_fd, names->backup,
              &journal.original_identity)) return -1;
        if (leaf_present > 0 && (!hb_entry_matches_identity(parent_fd, names->leaf,
              &journal.staged_identity)
            || hb_remove_staged_if_present(parent_fd, names->leaf,
              &journal.staged_identity, expected_request) != 0)) return -1;
        if (hb_remove_staged_if_present(parent_fd, names->staging,
              &journal.staged_identity, expected_request) < 0
            || hb_restore_original(parent_fd, names, &journal) != 0) return -1;
      } else if (leaf_present == 0
          || !hb_entry_matches_identity(parent_fd, names->leaf,
            &journal.original_identity)
          || hb_remove_staged_if_present(parent_fd, names->staging,
            &journal.staged_identity, expected_request) < 0) {
        return -1;
      }
    } else {
      if (backup_present > 0 || (staging_present > 0 && leaf_present > 0)) return -1;
      if (staging_present > 0) {
        if (hb_remove_staged_if_present(parent_fd, names->staging,
            &journal.staged_identity, expected_request) != 0) return -1;
      } else if (leaf_present > 0
          && hb_remove_staged_if_present(parent_fd, names->leaf,
            &journal.staged_identity, expected_request) != 0) {
        return -1;
      }
    }
  } else {
    if (leaf_present == 0 || !hb_entry_matches_identity(parent_fd, names->leaf,
          &journal.staged_identity)
        || (expected_request != NULL && hb_verify_bound_tree(parent_fd, names->leaf,
          &journal.staged_identity, expected_request) != 0)
        || staging_present > 0) return -1;
    if (journal.had_existing != 0U) {
      if (backup_present > 0 && hb_remove_entry_bound(parent_fd, names->backup,
          &journal.original_identity) != 0) return -1;
    } else if (backup_present > 0) {
      return -1;
    }
  }
  if (hb_remove_entry(parent_fd, names->journal) < 0
      || hb_remove_entry(parent_fd, names->journal_temp) < 0) return -1;
  return hb_fsync(parent_fd);
}

static void hb_maybe_crash(const struct hb_request *request, uint32_t phase) {
#ifdef HB_LIFECYCLE_CUSTODIAN_TEST_ONLY
  if (request->test_crash_phase == phase) _exit((int)(90U + phase));
#else
  (void)request;
  (void)phase;
#endif
}

static int hb_replace(
  int parent_fd,
  const struct hb_names *names,
  const struct hb_request *request
) {
  struct stat status;
  struct hb_journal journal;
  int leaf_present;
  int staging_fd = -1;
  uint32_t index;
  HB_TEST_STAGE("replace_recover");
  if (hb_recover_transaction(
      parent_fd, names, request->selection, request->plan_digest, request, 0) != 0) return -1;
  hb_maybe_crash(request, HB_TEST_CRASH_AFTER_RECOVERY);
  if (hb_verify_source_tree(HB_SOURCE_ROOT_FD, request) != 0) return -1;
  HB_TEST_STAGE("replace_leaf_status");
  leaf_present = hb_entry_status(parent_fd, names->leaf, &status);
  if (leaf_present < 0) return -1;
  memset(&journal, 0, sizeof(journal));
  journal.selection = request->selection;
  journal.phase = HB_PHASE_BUILDING;
  journal.had_existing = leaf_present > 0 ? 1U : 0U;
  if (leaf_present > 0) {
    if (hb_status_identity(&status, &journal.original_identity) != 0) return -1;
  }
  if (hb_entry_status(parent_fd, names->staging, &status) != 0
      || hb_entry_status(parent_fd, names->backup, &status) != 0) return -1;
  memcpy(journal.plan_digest, request->plan_digest, sizeof(journal.plan_digest));
  HB_TEST_STAGE("replace_building_journal");
  if (hb_write_journal(parent_fd, names, &journal) != 0) return -1;
  hb_maybe_crash(request, HB_PHASE_BUILDING);
  HB_TEST_STAGE("replace_staging_create");
  if (mkdirat(parent_fd, names->staging, 0755) != 0
      || (staging_fd = openat(parent_fd, names->staging,
        O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)) < 0
      || fchmod(staging_fd, 0755) != 0 || hb_fsync(staging_fd) != 0
      || hb_fsync(parent_fd) != 0
      || !hb_entry_matches_descriptor(parent_fd, names->staging, staging_fd)
      || fstat(staging_fd, &status) != 0) return -1;
  hb_maybe_crash(request, HB_TEST_CRASH_AFTER_STAGING_CREATE);
  journal.staged_bound = 1U;
  if (hb_status_identity(&status, &journal.staged_identity) != 0) return -1;
  HB_TEST_STAGE("replace_staging_identity_journal");
  if (hb_write_journal(parent_fd, names, &journal) != 0) return -1;
  for (index = 0; index < request->file_count; index += 1U) {
    HB_TEST_STAGE("replace_copy_file");
    if (hb_copy_file(HB_SOURCE_ROOT_FD, staging_fd, &request->files[index]) != 0) return -1;
  }
  HB_TEST_STAGE("replace_post_copy_verify");
  if (hb_verify_source_tree(HB_SOURCE_ROOT_FD, request) != 0
      || hb_verify_source_tree(staging_fd, request) != 0
      || hb_sync_tree(staging_fd) != 0
      || !hb_entry_matches_descriptor(parent_fd, names->staging, staging_fd)) return -1;
  journal.phase = HB_PHASE_PREPARED;
  HB_TEST_STAGE("replace_prepared_journal");
  if (hb_write_journal(parent_fd, names, &journal) != 0) return -1;
  hb_maybe_crash(request, HB_PHASE_PREPARED);
  HB_TEST_STAGE("replace_backup_rename");
  if (!hb_entry_matches_descriptor(parent_fd, names->staging, staging_fd)
      || hb_verify_source_tree(staging_fd, request) != 0) return -1;
  if (leaf_present > 0) {
    if (!hb_entry_matches_identity(parent_fd, names->leaf,
          &journal.original_identity)
        || renameat(parent_fd, names->leaf, parent_fd, names->backup) != 0
        || hb_fsync(parent_fd) != 0
        || !hb_entry_matches_identity(parent_fd, names->backup,
          &journal.original_identity)) return -1;
  } else if (hb_entry_status(parent_fd, names->leaf, &status) != 0) {
    return -1;
  }
  hb_maybe_crash(request, HB_TEST_CRASH_AFTER_BACKUP_RENAME);
  journal.phase = HB_PHASE_BACKUP_RENAMED;
  HB_TEST_STAGE("replace_backup_journal");
  if (hb_write_journal(parent_fd, names, &journal) != 0) return -1;
  hb_maybe_crash(request, HB_PHASE_BACKUP_RENAMED);
  HB_TEST_STAGE("replace_install_rename");
  if (!hb_entry_matches_descriptor(parent_fd, names->staging, staging_fd)
      || (journal.had_existing != 0U
        && !hb_entry_matches_identity(parent_fd, names->backup,
          &journal.original_identity))
      || (journal.had_existing == 0U
        && hb_entry_status(parent_fd, names->backup, &status) != 0)
      || hb_entry_status(parent_fd, names->leaf, &status) != 0
      || renameat(parent_fd, names->staging, parent_fd, names->leaf) != 0
      || hb_fsync(parent_fd) != 0
      || !hb_entry_matches_descriptor(parent_fd, names->leaf, staging_fd)
      || hb_verify_source_tree(staging_fd, request) != 0
      || hb_sync_tree(staging_fd) != 0 || hb_close(staging_fd) != 0) return -1;
  hb_maybe_crash(request, HB_TEST_CRASH_AFTER_INSTALL_RENAME);
  journal.phase = HB_PHASE_INSTALLED;
  HB_TEST_STAGE("replace_installed_journal");
  if (hb_write_journal(parent_fd, names, &journal) != 0) return -1;
  hb_maybe_crash(request, HB_PHASE_INSTALLED);
  journal.phase = HB_PHASE_COMMITTED;
  HB_TEST_STAGE("replace_committed_journal");
  if (hb_write_journal(parent_fd, names, &journal) != 0) return -1;
  hb_maybe_crash(request, HB_PHASE_COMMITTED);
  HB_TEST_STAGE("replace_cleanup");
  if ((journal.had_existing != 0U && hb_remove_bound_if_present(
        parent_fd, names->backup, &journal.original_identity) < 0)
      || (journal.had_existing == 0U
        && hb_entry_status(parent_fd, names->backup, &status) != 0)
      || hb_remove_entry(parent_fd, names->journal) < 0
      || hb_remove_entry(parent_fd, names->journal_temp) < 0
      || hb_fsync(parent_fd) != 0) return -1;
  return 0;
}

static int hb_remove(int parent_fd, const struct hb_names *names, uint32_t selection) {
  struct stat status;
  int had_owned_artifact = 0;
  int present;
  const char *owned_names[5] = {
    names->leaf,
    names->staging,
    names->backup,
    names->journal,
    names->journal_temp
  };
  size_t index;
  for (index = 0; index < 5U; index += 1U) {
    int artifact_status = hb_entry_status(parent_fd, owned_names[index], &status);
    if (artifact_status < 0) return -1;
    if (artifact_status > 0) had_owned_artifact = 1;
  }
  if (hb_recover_transaction(parent_fd, names, selection, NULL, NULL, 1) != 0) return -1;
  present = hb_entry_status(parent_fd, names->leaf, &status);
  if (present < 0) return -1;
  if (present > 0 && hb_remove_entry(parent_fd, names->leaf) < 0) return -1;
  if (hb_remove_entry(parent_fd, names->staging) < 0
      || hb_remove_entry(parent_fd, names->backup) < 0
      || hb_remove_entry(parent_fd, names->journal) < 0
      || hb_remove_entry(parent_fd, names->journal_temp) < 0
      || hb_fsync(parent_fd) != 0) return -1;
  return had_owned_artifact != 0 ? HB_RESULT_CHANGED : HB_RESULT_ABSENT;
}

static int hb_same_object(const struct stat *left, const struct stat *right) {
  return left->st_dev == right->st_dev && left->st_ino == right->st_ino;
}

static int hb_prepare_result_capability(void) {
  struct stat status;
  struct sockaddr_un local_address;
  struct sockaddr_un peer_address;
  socklen_t local_length = (socklen_t)sizeof(local_address);
  socklen_t peer_length = (socklen_t)sizeof(peer_address);
  socklen_t type_length;
  int socket_type = 0;
  int no_sigpipe = 1;
  if (hb_result_capability_ready != 0) return 0;
  type_length = (socklen_t)sizeof(socket_type);
  memset(&local_address, 0, sizeof(local_address));
  memset(&peer_address, 0, sizeof(peer_address));
  if (fcntl(HB_RESULT_FD, F_GETFL) != O_RDWR
      || fcntl(HB_RESULT_FD, F_GETFD) != 0
      || fstat(HB_RESULT_FD, &status) != 0 || !S_ISSOCK(status.st_mode)
      || getsockopt(HB_RESULT_FD, SOL_SOCKET, SO_TYPE, &socket_type, &type_length) != 0
      || type_length != (socklen_t)sizeof(socket_type) || socket_type != SOCK_STREAM
      || getsockname(HB_RESULT_FD, (struct sockaddr *)&local_address, &local_length) != 0
      || local_length < (socklen_t)sizeof(local_address.sun_family)
      || local_address.sun_family != AF_UNIX
      || getpeername(HB_RESULT_FD, (struct sockaddr *)&peer_address, &peer_length) != 0
      || peer_length < (socklen_t)sizeof(peer_address.sun_family)
      || peer_address.sun_family != AF_UNIX
      || setsockopt(HB_RESULT_FD, SOL_SOCKET, SO_NOSIGPIPE,
        &no_sigpipe, (socklen_t)sizeof(no_sigpipe)) != 0
      || shutdown(HB_RESULT_FD, SHUT_RD) != 0) return -1;
  hb_result_capability_ready = 1;
  return 0;
}

static int hb_validate_fixed_descriptors(void) {
  struct stat target;
  struct stat source;
  struct stat request;
  struct stat result;
  if (hb_result_capability_ready == 0
      || fcntl(HB_TARGET_ROOT_FD, F_GETFL) != O_RDONLY
      || fcntl(HB_SOURCE_ROOT_FD, F_GETFL) != O_RDONLY
      || fcntl(HB_REQUEST_FD, F_GETFL) != O_RDONLY
      || fcntl(HB_RESULT_FD, F_GETFL) != O_RDWR
      || fcntl(HB_TARGET_ROOT_FD, F_GETFD) != 0
      || fcntl(HB_SOURCE_ROOT_FD, F_GETFD) != 0
      || fcntl(HB_REQUEST_FD, F_GETFD) != 0
      || fcntl(HB_RESULT_FD, F_GETFD) != 0
      || fstat(HB_TARGET_ROOT_FD, &target) != 0 || !S_ISDIR(target.st_mode)
      || fstat(HB_SOURCE_ROOT_FD, &source) != 0 || !S_ISDIR(source.st_mode)
      || fstat(HB_REQUEST_FD, &request) != 0 || !S_ISREG(request.st_mode)
      || request.st_nlink != 1 || (request.st_mode & 0777U) != 0444U
      || fstat(HB_RESULT_FD, &result) != 0 || !S_ISSOCK(result.st_mode)
      || hb_same_object(&target, &source) || hb_same_object(&target, &request)
      || hb_same_object(&target, &result) || hb_same_object(&source, &request)
      || hb_same_object(&source, &result) || hb_same_object(&request, &result)) return -1;
  return 0;
}

__attribute__((unused))
static int hb_execute(void) {
  struct hb_request request;
  struct hb_names names;
  int parent_fd = -1;
  int result = HB_RESULT_REJECTED;
  HB_TEST_STAGE("prepare_result");
  if (hb_prepare_result_capability() != 0) goto complete;
  HB_TEST_STAGE("validate_descriptors");
  if (hb_validate_fixed_descriptors() != 0) goto complete;
  HB_TEST_STAGE("parse_request");
  if (hb_parse_request(&request) != 0) goto complete;
  HB_TEST_STAGE("selection_names");
  if (hb_names_for_selection(request.selection, &names) != 0) goto complete;
  if (request.operation == HB_OPERATION_REPLACE) {
    HB_TEST_STAGE("preverify_source");
    if (hb_verify_source_tree(HB_SOURCE_ROOT_FD, &request) != 0) goto complete;
    HB_TEST_STAGE("open_target_parent");
    if (hb_open_parent(HB_TARGET_ROOT_FD, &names, 1, &parent_fd) != 0) goto complete;
    HB_TEST_STAGE("replace");
    if (hb_replace(parent_fd, &names, &request) != 0) goto complete;
    result = HB_RESULT_CHANGED;
  } else {
    int opened = hb_open_parent(HB_TARGET_ROOT_FD, &names, 0, &parent_fd);
    if (opened != 0) {
      result = opened > 0 ? HB_RESULT_ABSENT : HB_RESULT_REJECTED;
      goto complete;
    }
    result = hb_remove(parent_fd, &names, request.selection);
    if (result < 0) result = HB_RESULT_REJECTED;
  }

complete:
  if (parent_fd >= 0) (void)hb_close(parent_fd);
  return result;
}

#ifdef HB_LIFECYCLE_CUSTODIAN_TEST_ONLY
static int hb_write_result(int code) {
  unsigned char bytes[HB_RESULT_BYTES];
  memset(bytes, 0, sizeof(bytes));
  memcpy(bytes, HB_RESULT_MAGIC, 8U);
  hb_write_u32(bytes + 8U, HB_REQUEST_VERSION);
  hb_write_u32(bytes + 12U, (uint32_t)code);
  return hb_write_all(HB_RESULT_FD, bytes, sizeof(bytes));
}

int main(int argc, char **argv) {
  int result;
  if (argc != 2 || strcmp(argv[1], "--test-only-lifecycle-custodian-v1") != 0) return 64;
  result = hb_execute();
  if (result == HB_RESULT_REJECTED) (void)dprintf(STDERR_FILENO, "%s\n", hb_test_stage);
  if (hb_result_capability_ready == 0) return 67;
  if (hb_write_result(result) != 0) return 66;
  return result == HB_RESULT_REJECTED ? 65 : 0;
}
#endif
