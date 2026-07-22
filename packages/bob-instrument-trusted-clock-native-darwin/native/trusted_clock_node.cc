#include "trusted_clock_protocol.h"

#include <errno.h>
#include <node_api.h>
#include <stdint.h>
#include <string.h>

#include <array>
#include <atomic>
#include <string>

namespace {

std::atomic<bool> g_sample_consumed{false};

void SecureZero(void* bytes, size_t length) {
  volatile uint8_t* cursor = static_cast<volatile uint8_t*>(bytes);
  for (size_t index = 0; index < length; ++index) cursor[index] = 0;
}

class ScopedSampleScrub {
 public:
  explicit ScopedSampleScrub(hb_clock_source_sample* sample) : sample_(sample) {}
  ScopedSampleScrub(const ScopedSampleScrub&) = delete;
  ScopedSampleScrub& operator=(const ScopedSampleScrub&) = delete;
  ~ScopedSampleScrub() {
    if (sample_ != nullptr) SecureZero(sample_, sizeof(*sample_));
  }

 private:
  hb_clock_source_sample* sample_;
};

bool DefineDataProperty(napi_env env, napi_value object, const char* name,
                        napi_value value) {
  const napi_property_descriptor descriptor = {
      name, nullptr, nullptr, nullptr, nullptr, value, napi_enumerable, nullptr};
  return napi_define_properties(env, object, 1, &descriptor) == napi_ok;
}

void ThrowCode(napi_env env, const char* code) {
  napi_value message;
  napi_value error;
  napi_value code_value;
  if (napi_create_string_utf8(env, "Darwin trusted-clock native sample failed",
                              NAPI_AUTO_LENGTH, &message) != napi_ok
      || napi_create_error(env, nullptr, message, &error) != napi_ok
      || napi_create_string_utf8(env, code, NAPI_AUTO_LENGTH, &code_value) != napi_ok
      || !DefineDataProperty(env, error, "code", code_value)
      || napi_throw(env, error) != napi_ok) {
    napi_throw_error(env, code, "Darwin trusted-clock native sample failed");
  }
}

std::string HexBytes(const uint8_t* bytes, size_t length) {
  static constexpr char kHex[] = "0123456789abcdef";
  std::string output(length * 2U, '0');
  for (size_t index = 0; index < length; ++index) {
    output[index * 2U] = kHex[bytes[index] >> 4U];
    output[index * 2U + 1U] = kHex[bytes[index] & 0x0fU];
  }
  return output;
}

bool SetString(napi_env env, napi_value object, const char* name,
               const std::string& value) {
  napi_value encoded;
  return napi_create_string_utf8(env, value.data(), value.size(), &encoded) == napi_ok
      && DefineDataProperty(env, object, name, encoded);
}

bool SetCString(napi_env env, napi_value object, const char* name,
                const char* value) {
  napi_value encoded;
  return napi_create_string_utf8(env, value, NAPI_AUTO_LENGTH, &encoded) == napi_ok
      && DefineDataProperty(env, object, name, encoded);
}

bool SetUint32(napi_env env, napi_value object, const char* name,
               uint32_t value) {
  napi_value encoded;
  return napi_create_uint32(env, value, &encoded) == napi_ok
      && DefineDataProperty(env, object, name, encoded);
}

const char* StatusCode(int status) {
  switch (status) {
    case ENOTSUP:
      return "darwin_trusted_clock_native_unprovisioned";
    case ENOTCONN:
      return "darwin_trusted_clock_native_service_unavailable";
    case EPROTO:
      return "darwin_trusted_clock_native_protocol_rejected";
    default:
      return "darwin_trusted_clock_native_sample_failed";
  }
}

napi_value SampleTrustedClockNative(napi_env env, napi_callback_info info) {
  size_t argc = 0;
  if (napi_get_cb_info(env, info, &argc, nullptr, nullptr, nullptr) != napi_ok
      || argc != 0) {
    g_sample_consumed.store(true, std::memory_order_release);
    ThrowCode(env, "darwin_trusted_clock_native_argument_injection");
    return nullptr;
  }
  if (g_sample_consumed.exchange(true, std::memory_order_acq_rel)) {
    ThrowCode(env, "darwin_trusted_clock_native_sample_consumed");
    return nullptr;
  }
  hb_clock_source_sample sample{};
  ScopedSampleScrub scrub(&sample);
  const int status = hb_trusted_clock_sample(&sample);
  if (status != 0) {
    ThrowCode(env, StatusCode(status));
    return nullptr;
  }

  napi_value output;
  if (napi_create_object(env, &output) != napi_ok
      || !SetUint32(env, output, "version", HB_CLOCK_SOURCE_VERSION)
      || !SetCString(env, output, "source", "mach_continuous_time_v1")
      || !SetString(env, output, "monotonic_ns",
                    std::to_string(sample.monotonic_ns))
      || !SetString(env, output, "request_id",
                    HexBytes(sample.request_id, HB_CLOCK_REQUEST_ID_BYTES))
      || !SetString(env, output, "challenge_digest",
                    HexBytes(sample.challenge_digest, HB_CLOCK_DIGEST_BYTES))
      || !SetString(env, output, "boot_epoch_digest",
                    HexBytes(sample.boot_epoch_digest, HB_CLOCK_DIGEST_BYTES))
      || !SetString(env, output, "service_identity_digest",
                    HexBytes(sample.service_identity_digest, HB_CLOCK_DIGEST_BYTES))
      || !SetString(env, output, "client_identity_digest",
                    HexBytes(sample.client_identity_digest, HB_CLOCK_DIGEST_BYTES))
      || !SetString(env, output, "enrollment_digest",
                    HexBytes(sample.enrollment_digest, HB_CLOCK_DIGEST_BYTES))
      || !SetString(env, output, "source_sample_digest",
                    HexBytes(sample.source_sample_digest, HB_CLOCK_DIGEST_BYTES))
      || napi_object_freeze(env, output) != napi_ok) {
    ThrowCode(env, "darwin_trusted_clock_native_projection_failed");
    return nullptr;
  }
  return output;
}

napi_value Initialize(napi_env env, napi_value exports) {
  napi_value sample_function;
  if (napi_create_function(env, "sampleTrustedClockNative", NAPI_AUTO_LENGTH,
                           SampleTrustedClockNative, nullptr,
                           &sample_function) != napi_ok
      || !DefineDataProperty(env, exports, "sampleTrustedClockNative",
                             sample_function)) {
    ThrowCode(env, "darwin_trusted_clock_native_initialize_failed");
    return nullptr;
  }
  return exports;
}

}  // namespace

NAPI_MODULE(NODE_GYP_MODULE_NAME, Initialize)
