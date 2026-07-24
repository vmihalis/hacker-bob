#ifndef HACKER_BOB_TRUSTED_CLOCK_PROTOCOL_H
#define HACKER_BOB_TRUSTED_CLOCK_PROTOCOL_H

#include <stddef.h>
#include <stdint.h>

// This checked-in header is intentionally unprovisioned. A future signed native
// release must replace it with a manifest-derived header whose bytes are covered
// by the release and loaded-image attestations. Command-line defines are not an
// enrollment mechanism.
enum {
  HB_CLOCK_SOURCE_VERSION = 1,
  HB_CLOCK_REQUEST_TYPE = 1,
  HB_CLOCK_RESPONSE_TYPE = 2,
  HB_CLOCK_REQUEST_BYTES = 64,
  HB_CLOCK_RESPONSE_BYTES = 232,
  HB_CLOCK_REQUEST_ID_BYTES = 16,
  HB_CLOCK_CHALLENGE_BYTES = 32,
  HB_CLOCK_DIGEST_BYTES = 32,
  HB_CLOCK_MAX_SAMPLES_PER_CONNECTION = 1,
  HB_CLOCK_IO_TIMEOUT_SECONDS = 2,
  HB_CLOCK_SOURCE_PROVISIONED = 0,
};

static const char HB_CLOCK_SERVICE_ID[] =
    "io.hacker-bob.physical.trusted-clockd";
static const char HB_CLOCK_CLIENT_ID[] =
    "io.hacker-bob.physical.trusted-clock-client";
static const char HB_CLOCK_SERVICE_PRINCIPAL[] = "_hackerbobclock";
static const char HB_CLOCK_LAUNCHD_LABEL[] =
    "io.hacker-bob.physical.trusted-clockd";
static const char HB_CLOCK_LAUNCHD_SOCKET_NAME[] = "TrustedClockSocket";
static const char HB_CLOCK_SOCKET_PATH[] =
    "/private/var/run/hacker-bob/physical-trusted-clock-v1.sock";
static const char HB_CLOCK_BOOT_SESSION_SYSCTL[] = "kern.bootsessionuuid";

// UNPROVISIONED makes both requirements impossible for a qualified release.
// Exact real SecRequirement bytes and their digests belong in a signed v3 or
// separate trusted-clock native release envelope, never in runtime arguments.
static const char HB_CLOCK_SERVICE_REQUIREMENT[] =
    "anchor apple generic and identifier \"io.hacker-bob.physical.trusted-clockd\" "
    "and certificate leaf[subject.OU] = \"UNPROVISIONED\"";
static const char HB_CLOCK_CLIENT_REQUIREMENT[] =
    "anchor apple generic and identifier \"io.hacker-bob.physical.trusted-clock-client\" "
    "and certificate leaf[subject.OU] = \"UNPROVISIONED\"";

static const uint8_t HB_CLOCK_REQUEST_MAGIC[8] = {
    0x48, 0x42, 0x43, 0x4c, 0x4b, 0x31, 0x00, 0x00,
};
static const uint8_t HB_CLOCK_RESPONSE_MAGIC[8] = {
    0x48, 0x42, 0x43, 0x4c, 0x4b, 0x31, 0x52, 0x00,
};

static const char HB_CLOCK_CHALLENGE_DIGEST_DOMAIN[] =
    "hacker-bob/darwin-trusted-clock-challenge/v1";
static const char HB_CLOCK_BOOT_EPOCH_DIGEST_DOMAIN[] =
    "hacker-bob/darwin-trusted-clock-boot-epoch/v1";
static const char HB_CLOCK_SAMPLE_DIGEST_DOMAIN[] =
    "hacker-bob/darwin-trusted-clock-source-sample/v1";

// These zero values are also intentionally unusable. The future generated
// enrollment header must provide distinct measured identities and an exact
// enrollment digest under the signed release policy.
static const uint8_t HB_CLOCK_SERVICE_IDENTITY_DIGEST[HB_CLOCK_DIGEST_BYTES] = {0};
static const uint8_t HB_CLOCK_CLIENT_IDENTITY_DIGEST[HB_CLOCK_DIGEST_BYTES] = {0};
static const uint8_t HB_CLOCK_ENROLLMENT_DIGEST[HB_CLOCK_DIGEST_BYTES] = {0};
static const uint32_t HB_CLOCK_SERVICE_UID = UINT32_MAX;
static const uint32_t HB_CLOCK_SERVICE_GID = UINT32_MAX;
static const uint32_t HB_CLOCK_CLIENT_UID = UINT32_MAX;
static const uint32_t HB_CLOCK_CLIENT_GID = UINT32_MAX;

typedef struct hb_clock_source_sample {
  uint64_t monotonic_ns;
  uint8_t request_id[HB_CLOCK_REQUEST_ID_BYTES];
  uint8_t challenge_digest[HB_CLOCK_DIGEST_BYTES];
  uint8_t boot_epoch_digest[HB_CLOCK_DIGEST_BYTES];
  uint8_t service_identity_digest[HB_CLOCK_DIGEST_BYTES];
  uint8_t client_identity_digest[HB_CLOCK_DIGEST_BYTES];
  uint8_t enrollment_digest[HB_CLOCK_DIGEST_BYTES];
  uint8_t source_sample_digest[HB_CLOCK_DIGEST_BYTES];
} hb_clock_source_sample;

#ifdef __cplusplus
extern "C" {
#endif

int hb_trusted_clock_sample(hb_clock_source_sample* output);

#ifdef __cplusplus
}
#endif

#endif
