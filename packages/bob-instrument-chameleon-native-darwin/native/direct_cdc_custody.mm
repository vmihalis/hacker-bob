#include <node_api.h>

#import <Foundation/Foundation.h>
#import <IOUSBHost/IOUSBHost.h>
#import <Security/SecTask.h>

#include <CommonCrypto/CommonDigest.h>
#include <IOKit/IOKitLib.h>
#include <libkern/OSByteOrder.h>
#include <unistd.h>

#include <algorithm>
#include <array>
#include <cctype>
#include <cmath>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <memory>
#include <mutex>
#include <string>
#include <vector>

namespace {

constexpr uint32_t kVersion = 1;
constexpr const char* kPrimitive = "darwin_iousbhost_cdc_acm_exact_v1";
constexpr const char* kRejected = "darwin_direct_cdc_custody_rejected";
constexpr const char* kOpenRejected = "darwin_direct_cdc_open_rejected";
constexpr const char* kTransactionAmbiguous =
    "darwin_direct_cdc_transaction_ambiguous";
constexpr const char* kRealDisabled = "darwin_direct_cdc_real_open_disabled";
constexpr const char* kTicketDomain =
    "hacker-bob/chameleon-darwin-direct-cdc-launch-ticket/v1";
constexpr const char* kInterfaceDomain =
    "hacker-bob/chameleon-darwin-direct-cdc-interface-descriptor-set/v1";
constexpr const char* kBulkOutDomain =
    "hacker-bob/chameleon-darwin-direct-cdc-bulk_out-descriptor/v1";
constexpr const char* kBulkInDomain =
    "hacker-bob/chameleon-darwin-direct-cdc-bulk_in-descriptor/v1";
constexpr const char* kEnrollmentDomain =
    "hacker-bob/chameleon-darwin-direct-cdc-enrollment/v1";
constexpr const char* kControlRequestDomain =
    "hacker-bob/chameleon-darwin-direct-cdc-control-request/v1";
constexpr size_t kMaximumDescriptorSetBytes = 4096;
constexpr size_t kMinimumFrameBytes = 10;
constexpr size_t kMaximumFrameBytes = 16 * 1024;
constexpr uint32_t kMaximumTimeoutMs = 1000;
constexpr unsigned char kSof = 0x11;
constexpr unsigned char kSofLrc = 0xef;
constexpr napi_type_tag kDirectHandleTypeTag = {
    0x819f41c8d83c4a2bULL,
    0xb375e6f29a1d0c47ULL,
};

static_assert(IOUSBHostObjectInitOptionsDeviceCapture == 1,
              "IOUSBHost DeviceCapture option changed");
static_assert(IOUSBHostObjectInitOptionsDeviceSeize == 2,
              "IOUSBHost DeviceSeize option changed");
static_assert(IOUSBHostAbortOptionSynchronous == 1,
              "IOUSBHost synchronous abort option changed");
static_assert(sizeof(IOUSBDeviceRequest) == 8,
              "USB setup request must remain exactly eight bytes");

void SecureZero(void* value, size_t length) {
  volatile unsigned char* cursor = static_cast<volatile unsigned char*>(value);
  while (length > 0) {
    *cursor = 0;
    ++cursor;
    --length;
  }
}

void ZeroVector(std::vector<unsigned char>* value) {
  if (value != nullptr && !value->empty()) {
    SecureZero(value->data(), value->size());
    value->clear();
    value->shrink_to_fit();
  }
}

void ZeroString(std::string* value) {
  if (value != nullptr && !value->empty()) {
    SecureZero(value->data(), value->size());
    value->clear();
  }
}

struct OpenConfig {
  std::string capture_mode;
  std::string authorization_mode;
  std::string ticket_id;
  std::string ticket_nonce;
  std::string expires_monotonic_ns;
  uint32_t worker_uid = 0;
  uint32_t worker_gid = 0;
  bool vm_device_access_entitlement = false;
  bool io_service_authorized = false;
  std::string dedicated_principal_digest;
  std::string worker_code_identity_digest;
  std::string launch_ticket_digest;
  uint32_t vendor_id = 0;
  uint32_t product_id = 0;
  uint32_t location_id = 0;
  std::string serial_number_digest;
  uint32_t configuration_value = 0;
  uint32_t control_interface_number = 0;
  uint32_t data_interface_number = 0;
  std::vector<unsigned char> device_descriptor;
  std::vector<unsigned char> interface_descriptor_set;
  std::vector<unsigned char> control_interface_descriptor;
  std::vector<unsigned char> data_interface_descriptor;
  std::vector<unsigned char> bulk_out_descriptor;
  std::vector<unsigned char> bulk_in_descriptor;
  std::string interface_descriptor_digest;
  std::string bulk_out_descriptor_digest;
  std::string bulk_in_descriptor_digest;
  std::string enrollment_digest;
  uint32_t connection_generation = 0;
  uint8_t bulk_out_address = 0;
  uint8_t bulk_in_address = 0;

  ~OpenConfig() {
    ZeroString(&ticket_id);
    ZeroString(&ticket_nonce);
    ZeroString(&dedicated_principal_digest);
    ZeroString(&worker_code_identity_digest);
    ZeroString(&launch_ticket_digest);
    ZeroString(&serial_number_digest);
    ZeroVector(&device_descriptor);
    ZeroVector(&interface_descriptor_set);
    ZeroVector(&control_interface_descriptor);
    ZeroVector(&data_interface_descriptor);
    ZeroVector(&bulk_out_descriptor);
    ZeroVector(&bulk_in_descriptor);
    ZeroString(&interface_descriptor_digest);
    ZeroString(&bulk_out_descriptor_digest);
    ZeroString(&bulk_in_descriptor_digest);
    ZeroString(&enrollment_digest);
  }
};

struct DirectState {
  std::mutex mutex;
  uint32_t generation = 0;
  bool transaction_used = false;
  bool destroyed = false;
  bool quarantined = false;
  uint8_t bulk_out_address = 0;
  uint8_t bulk_in_address = 0;

  ~DirectState() {
    std::lock_guard<std::mutex> lock(mutex);
    destroyed = true;
    quarantined = true;
    bulk_out_address = 0;
    bulk_in_address = 0;
  }
};

struct HandleBox {
  std::shared_ptr<DirectState> state;
};

bool DefineProperty(napi_env env, napi_value object, const char* name,
                    napi_value value) {
  const napi_property_descriptor descriptor = {
      name, nullptr, nullptr, nullptr, nullptr, value, napi_enumerable, nullptr};
  return napi_define_properties(env, object, 1, &descriptor) == napi_ok;
}

void ThrowCode(napi_env env, const char* code) {
  napi_value message;
  napi_value error;
  napi_value code_value;
  if (napi_create_string_utf8(env, "Darwin direct CDC custody was rejected",
                              NAPI_AUTO_LENGTH, &message) != napi_ok ||
      napi_create_error(env, nullptr, message, &error) != napi_ok ||
      napi_create_string_utf8(env, code, NAPI_AUTO_LENGTH, &code_value) != napi_ok ||
      !DefineProperty(env, error, "code", code_value)) {
    napi_throw_error(env, code, "Darwin direct CDC custody was rejected");
    return;
  }
  napi_throw(env, error);
}

bool IsObject(napi_env env, napi_value value) {
  napi_valuetype type = napi_undefined;
  return napi_typeof(env, value, &type) == napi_ok && type == napi_object;
}

bool HasExactKeys(napi_env env, napi_value value,
                  const std::vector<const char*>& expected) {
  if (!IsObject(env, value)) return false;
  napi_value keys;
  if (napi_get_all_property_names(env, value, napi_key_own_only,
                                  napi_key_enumerable,
                                  napi_key_numbers_to_strings, &keys) != napi_ok) {
    return false;
  }
  uint32_t length = 0;
  if (napi_get_array_length(env, keys, &length) != napi_ok ||
      length != expected.size()) {
    return false;
  }
  std::vector<bool> seen(expected.size(), false);
  for (uint32_t index = 0; index < length; ++index) {
    napi_value key;
    size_t bytes = 0;
    if (napi_get_element(env, keys, index, &key) != napi_ok ||
        napi_get_value_string_utf8(env, key, nullptr, 0, &bytes) != napi_ok ||
        bytes == 0 || bytes > 128) {
      return false;
    }
    std::string name(bytes, '\0');
    size_t copied = 0;
    if (napi_get_value_string_utf8(env, key, name.data(), bytes + 1, &copied) !=
            napi_ok ||
        copied != bytes) {
      return false;
    }
    bool matched = false;
    for (size_t expected_index = 0; expected_index < expected.size();
         ++expected_index) {
      if (!seen[expected_index] && name == expected[expected_index]) {
        seen[expected_index] = true;
        matched = true;
        break;
      }
    }
    ZeroString(&name);
    if (!matched) return false;
  }
  return std::all_of(seen.begin(), seen.end(), [](bool value) { return value; });
}

bool GetNamed(napi_env env, napi_value object, const char* name,
              napi_value* output) {
  napi_value key;
  bool has = false;
  return napi_create_string_utf8(env, name, NAPI_AUTO_LENGTH, &key) == napi_ok &&
         napi_has_own_property(env, object, key, &has) == napi_ok &&
         has && napi_get_named_property(env, object, name, output) == napi_ok;
}

bool ReadBool(napi_env env, napi_value object, const char* name, bool* output) {
  napi_value value;
  napi_valuetype type = napi_undefined;
  return GetNamed(env, object, name, &value) &&
         napi_typeof(env, value, &type) == napi_ok && type == napi_boolean &&
         napi_get_value_bool(env, value, output) == napi_ok;
}

bool ReadExactUint32Value(napi_env env, napi_value value, uint32_t* output) {
  napi_valuetype type = napi_undefined;
  double decoded = 0;
  if (napi_typeof(env, value, &type) != napi_ok || type != napi_number ||
      napi_get_value_double(env, value, &decoded) != napi_ok ||
      !std::isfinite(decoded) || std::trunc(decoded) != decoded || decoded < 0 ||
      decoded > static_cast<double>(UINT32_MAX)) {
    return false;
  }
  *output = static_cast<uint32_t>(decoded);
  return true;
}

bool ReadUint32(napi_env env, napi_value object, const char* name,
                uint32_t* output) {
  napi_value value;
  return GetNamed(env, object, name, &value) &&
         ReadExactUint32Value(env, value, output);
}

bool ReadString(napi_env env, napi_value object, const char* name,
                size_t maximum, std::string* output) {
  napi_value value;
  napi_valuetype type = napi_undefined;
  size_t length = 0;
  if (!GetNamed(env, object, name, &value) ||
      napi_typeof(env, value, &type) != napi_ok || type != napi_string ||
      napi_get_value_string_utf8(env, value, nullptr, 0, &length) != napi_ok ||
      length == 0 || length > maximum) {
    return false;
  }
  output->assign(length, '\0');
  size_t copied = 0;
  if (napi_get_value_string_utf8(env, value, output->data(), length + 1,
                                 &copied) != napi_ok ||
      copied != length || output->find('\0') != std::string::npos) {
    ZeroString(output);
    return false;
  }
  return true;
}

bool ReadBuffer(napi_env env, napi_value object, const char* name,
                size_t minimum, size_t maximum,
                std::vector<unsigned char>* output) {
  napi_value value;
  bool is_buffer = false;
  void* data = nullptr;
  size_t length = 0;
  if (!GetNamed(env, object, name, &value) ||
      napi_is_buffer(env, value, &is_buffer) != napi_ok || !is_buffer ||
      napi_get_buffer_info(env, value, &data, &length) != napi_ok ||
      data == nullptr || length < minimum || length > maximum) {
    return false;
  }
  const auto* bytes = static_cast<const unsigned char*>(data);
  output->assign(bytes, bytes + length);
  return true;
}

bool IsDigest(const std::string& value) {
  if (value.size() != 64) return false;
  return std::all_of(value.begin(), value.end(), [](unsigned char byte) {
    return (byte >= '0' && byte <= '9') || (byte >= 'a' && byte <= 'f');
  });
}

bool IsIdentifier(const std::string& value) {
  if (value.empty() || value.size() > 128 || value[0] < 'a' || value[0] > 'z') {
    return false;
  }
  return std::all_of(value.begin() + 1, value.end(), [](unsigned char byte) {
    return std::islower(byte) || std::isdigit(byte) || byte == '.' || byte == '_' ||
           byte == '-';
  });
}

bool IsNonce(const std::string& value) {
  if (value.size() < 22 || value.size() > 128) return false;
  return std::all_of(value.begin(), value.end(), [](unsigned char byte) {
    return std::isalnum(byte) || byte == '_' || byte == '-';
  });
}

bool IsPositiveDecimal(const std::string& value) {
  if (value.empty() || value.size() > 40 || value == "0" ||
      (value.size() > 1 && value[0] == '0')) {
    return false;
  }
  return std::all_of(value.begin(), value.end(), [](unsigned char byte) {
    return std::isdigit(byte);
  });
}

std::string Uint32String(uint32_t value) { return std::to_string(value); }

std::string BoolString(bool value) { return value ? "true" : "false"; }

std::string FramedDigest(
    const char* domain,
    const std::vector<std::vector<unsigned char>>& fields) {
  CC_SHA256_CTX context;
  CC_SHA256_Init(&context);
  CC_SHA256_Update(&context, domain, static_cast<CC_LONG>(std::strlen(domain)));
  for (const auto& field : fields) {
    uint64_t length = field.size();
    unsigned char encoded[8];
    for (size_t index = 0; index < 8; ++index) {
      encoded[7 - index] = static_cast<unsigned char>(length & 0xff);
      length >>= 8;
    }
    CC_SHA256_Update(&context, encoded, sizeof(encoded));
    if (!field.empty()) {
      CC_SHA256_Update(&context, field.data(), static_cast<CC_LONG>(field.size()));
    }
    SecureZero(encoded, sizeof(encoded));
  }
  unsigned char digest[CC_SHA256_DIGEST_LENGTH];
  CC_SHA256_Final(digest, &context);
  static constexpr char kHex[] = "0123456789abcdef";
  std::string output(CC_SHA256_DIGEST_LENGTH * 2, '0');
  for (size_t index = 0; index < CC_SHA256_DIGEST_LENGTH; ++index) {
    output[index * 2] = kHex[digest[index] >> 4];
    output[index * 2 + 1] = kHex[digest[index] & 0x0f];
  }
  SecureZero(digest, sizeof(digest));
  SecureZero(&context, sizeof(context));
  return output;
}

std::vector<unsigned char> Bytes(const std::string& value) {
  return std::vector<unsigned char>(value.begin(), value.end());
}

uint16_t ReadLittle16(const std::vector<unsigned char>& value, size_t offset) {
  return static_cast<uint16_t>(value[offset]) |
         (static_cast<uint16_t>(value[offset + 1]) << 8);
}

bool SameBytes(const std::vector<unsigned char>& left, size_t offset,
               size_t length, const std::vector<unsigned char>& right) {
  return right.size() == length && offset + length <= left.size() &&
         std::equal(right.begin(), right.end(), left.begin() + offset);
}

bool ValidateDeviceDescriptor(const OpenConfig& config) {
  const auto& value = config.device_descriptor;
  return value.size() == 18 && value[0] == 18 && value[1] == 1 &&
         ReadLittle16(value, 8) == config.vendor_id &&
         ReadLittle16(value, 10) == config.product_id && value[16] != 0 &&
         value[17] != 0;
}

bool ValidateInterfaceDescriptor(const std::vector<unsigned char>& value,
                                 uint32_t number, bool control) {
  if (value.size() != 9 || value[0] != 9 || value[1] != 4 ||
      value[2] != number || value[3] != 0) {
    return false;
  }
  if (control) return value[5] == 0x02 && value[6] == 0x02;
  return value[4] == 2 && value[5] == 0x0a;
}

bool ValidateBulkEndpoint(const std::vector<unsigned char>& value, bool input,
                          uint8_t* address) {
  if (value.size() != 7 || value[0] != 7 || value[1] != 5 ||
      (value[2] & 0x80) != (input ? 0x80 : 0) || (value[2] & 0x0f) == 0 ||
      (value[3] & 0x03) != 0x02) {
    return false;
  }
  const uint16_t maximum_packet = ReadLittle16(value, 4) & 0x07ff;
  if (maximum_packet == 0 || maximum_packet > 1024) return false;
  *address = value[2];
  return true;
}

bool ValidateDescriptorSet(const OpenConfig& config) {
  const auto& bytes = config.interface_descriptor_set;
  if (bytes.size() < 9 || bytes[0] != 9 || bytes[1] != 2 ||
      ReadLittle16(bytes, 2) != bytes.size() ||
      bytes[5] != config.configuration_value) {
    return false;
  }
  size_t offset = 0;
  int current_interface = -1;
  uint32_t control_matches = 0;
  uint32_t data_matches = 0;
  uint32_t out_matches = 0;
  uint32_t in_matches = 0;
  while (offset < bytes.size()) {
    const size_t length = bytes[offset];
    if (length < 2 || offset + length > bytes.size()) return false;
    const unsigned char type = bytes[offset + 1];
    if (type == 4 && length == 9) {
      current_interface = bytes[offset + 2];
      if (SameBytes(bytes, offset, length, config.control_interface_descriptor)) {
        ++control_matches;
      }
      if (SameBytes(bytes, offset, length, config.data_interface_descriptor)) {
        ++data_matches;
      }
    } else if (type == 5 && length == 7 &&
               current_interface ==
                   static_cast<int>(config.data_interface_number)) {
      if (SameBytes(bytes, offset, length, config.bulk_out_descriptor)) ++out_matches;
      if (SameBytes(bytes, offset, length, config.bulk_in_descriptor)) ++in_matches;
    }
    offset += length;
  }
  return offset == bytes.size() && control_matches == 1 && data_matches == 1 &&
         out_matches == 1 && in_matches == 1;
}

std::array<unsigned char, 8> BuildControlRequestBytes(uint32_t interface_number) {
  std::array<unsigned char, 8> value = {};
  value[0] = IOUSBHostDeviceRequestType(
      kIOUSBDeviceRequestDirectionValueOut,
      kIOUSBDeviceRequestTypeValueClass,
      kIOUSBDeviceRequestRecipientValueInterface);
  value[1] = 0x22;
  value[4] = static_cast<unsigned char>(interface_number & 0xff);
  value[5] = static_cast<unsigned char>((interface_number >> 8) & 0xff);
  return value;
}

IOUSBDeviceRequest BuildControlRequest(uint32_t interface_number) {
  IOUSBDeviceRequest request = {};
  request.bmRequestType = IOUSBHostDeviceRequestType(
      kIOUSBDeviceRequestDirectionValueOut,
      kIOUSBDeviceRequestTypeValueClass,
      kIOUSBDeviceRequestRecipientValueInterface);
  request.bRequest = 0x22;
  request.wValue = OSSwapHostToLittleInt16(0);
  request.wIndex = OSSwapHostToLittleInt16(
      static_cast<uint16_t>(interface_number));
  request.wLength = OSSwapHostToLittleInt16(0);
  return request;
}

// Compile-time SDK-backed successor skeleton. None of these helpers is exposed
// through N-API and the fixture path never calls them. The future privileged
// worker must obtain the exact io_service_t internally from a launch-ticket
// bound matcher; no raw service or pipe handle crosses the JS boundary.
__attribute__((unused)) bool HasVmDeviceAccessEntitlement() {
  SecTaskRef task = SecTaskCreateFromSelf(kCFAllocatorDefault);
  if (task == nullptr) return false;
  CFErrorRef error = nullptr;
  CFTypeRef value = SecTaskCopyValueForEntitlement(
      task, CFSTR("com.apple.vm.device-access"), &error);
  const bool accepted = value != nullptr && CFGetTypeID(value) == CFBooleanGetTypeID() &&
                        CFBooleanGetValue(static_cast<CFBooleanRef>(value));
  if (value != nullptr) CFRelease(value);
  if (error != nullptr) CFRelease(error);
  CFRelease(task);
  return accepted;
}

__attribute__((unused)) IOUSBHostDevice* CaptureAuthorizedDevice(
    io_service_t service, bool use_capture, NSError** error) {
  const bool root = geteuid() == 0 && getuid() == 0;
  if (!root) {
    if (!HasVmDeviceAccessEntitlement() ||
        IOServiceAuthorize(service, kIOServiceInteractionAllowed) !=
            kIOReturnSuccess) {
      return nil;
    }
  }
  const IOUSBHostObjectInitOptions option =
      use_capture ? IOUSBHostObjectInitOptionsDeviceCapture
                  : IOUSBHostObjectInitOptionsDeviceSeize;
  return [[IOUSBHostDevice alloc] initWithIOService:service
                                            options:option
                                              queue:nil
                                              error:error
                                    interestHandler:nil];
}

__attribute__((unused)) bool SetControlLineLowBeforeBindingBulk(
    IOUSBHostInterface* control_interface,
    IOUSBHostInterface* data_interface,
    uint8_t control_interface_number,
    uint8_t bulk_out_address,
    uint8_t bulk_in_address,
    IOUSBHostPipe** bulk_out,
    IOUSBHostPipe** bulk_in,
    NSError** error) {
  const IOUSBDeviceRequest request =
      BuildControlRequest(control_interface_number);
  if (![control_interface sendDeviceRequest:request error:error]) return false;
  *bulk_out = [data_interface copyPipeWithAddress:bulk_out_address error:error];
  if (*bulk_out == nil) return false;
  *bulk_in = [data_interface copyPipeWithAddress:bulk_in_address error:error];
  return *bulk_in != nil;
}

__attribute__((unused)) void AbortAndDestroySynchronously(
    IOUSBHostPipe* bulk_out,
    IOUSBHostPipe* bulk_in,
    IOUSBHostInterface* control_interface,
    IOUSBHostInterface* data_interface,
    IOUSBHostDevice* device) {
  NSError* ignored = nil;
  if (bulk_out != nil) {
    [bulk_out abortWithOption:IOUSBHostAbortOptionSynchronous error:&ignored];
  }
  ignored = nil;
  if (bulk_in != nil) {
    [bulk_in abortWithOption:IOUSBHostAbortOptionSynchronous error:&ignored];
  }
  [data_interface destroy];
  [control_interface destroy];
  [device destroy];
}

bool ReadOpenConfig(napi_env env, napi_value value, OpenConfig* config) {
  static const std::vector<const char*> kFields = {
      "authorization_mode",
      "bulk_in_endpoint_descriptor_bytes",
      "bulk_in_endpoint_descriptor_digest",
      "bulk_out_endpoint_descriptor_bytes",
      "bulk_out_endpoint_descriptor_digest",
      "capture_mode",
      "configuration_value",
      "connection_generation",
      "control_interface_descriptor_bytes",
      "control_interface_number",
      "data_interface_descriptor_bytes",
      "data_interface_number",
      "dedicated_principal_digest",
      "device_descriptor_bytes",
      "enrollment_digest",
      "expires_monotonic_ns",
      "fixture_only",
      "interface_descriptor_digest",
      "interface_descriptor_set_bytes",
      "io_service_authorized",
      "launch_ticket_digest",
      "location_id",
      "product_id",
      "serial_number_digest",
      "ticket_id",
      "ticket_nonce",
      "vendor_id",
      "version",
      "vm_device_access_entitlement",
      "worker_code_identity_digest",
      "worker_gid",
      "worker_uid",
  };
  uint32_t version = 0;
  bool fixture_only = false;
  if (!HasExactKeys(env, value, kFields) ||
      !ReadUint32(env, value, "version", &version) || version != kVersion ||
      !ReadBool(env, value, "fixture_only", &fixture_only) || !fixture_only ||
      !ReadString(env, value, "capture_mode", 32, &config->capture_mode) ||
      !ReadString(env, value, "authorization_mode", 64,
                  &config->authorization_mode) ||
      !ReadString(env, value, "ticket_id", 128, &config->ticket_id) ||
      !ReadString(env, value, "ticket_nonce", 128, &config->ticket_nonce) ||
      !ReadString(env, value, "expires_monotonic_ns", 40,
                  &config->expires_monotonic_ns) ||
      !ReadUint32(env, value, "worker_uid", &config->worker_uid) ||
      !ReadUint32(env, value, "worker_gid", &config->worker_gid) ||
      !ReadBool(env, value, "vm_device_access_entitlement",
                &config->vm_device_access_entitlement) ||
      !ReadBool(env, value, "io_service_authorized",
                &config->io_service_authorized) ||
      !ReadString(env, value, "dedicated_principal_digest", 64,
                  &config->dedicated_principal_digest) ||
      !ReadString(env, value, "worker_code_identity_digest", 64,
                  &config->worker_code_identity_digest) ||
      !ReadString(env, value, "launch_ticket_digest", 64,
                  &config->launch_ticket_digest) ||
      !ReadUint32(env, value, "vendor_id", &config->vendor_id) ||
      !ReadUint32(env, value, "product_id", &config->product_id) ||
      !ReadUint32(env, value, "location_id", &config->location_id) ||
      !ReadString(env, value, "serial_number_digest", 64,
                  &config->serial_number_digest) ||
      !ReadUint32(env, value, "configuration_value",
                  &config->configuration_value) ||
      !ReadUint32(env, value, "control_interface_number",
                  &config->control_interface_number) ||
      !ReadUint32(env, value, "data_interface_number",
                  &config->data_interface_number) ||
      !ReadBuffer(env, value, "device_descriptor_bytes", 18, 18,
                  &config->device_descriptor) ||
      !ReadBuffer(env, value, "interface_descriptor_set_bytes", 9,
                  kMaximumDescriptorSetBytes,
                  &config->interface_descriptor_set) ||
      !ReadBuffer(env, value, "control_interface_descriptor_bytes", 9, 9,
                  &config->control_interface_descriptor) ||
      !ReadBuffer(env, value, "data_interface_descriptor_bytes", 9, 9,
                  &config->data_interface_descriptor) ||
      !ReadBuffer(env, value, "bulk_out_endpoint_descriptor_bytes", 7, 7,
                  &config->bulk_out_descriptor) ||
      !ReadBuffer(env, value, "bulk_in_endpoint_descriptor_bytes", 7, 7,
                  &config->bulk_in_descriptor) ||
      !ReadString(env, value, "interface_descriptor_digest", 64,
                  &config->interface_descriptor_digest) ||
      !ReadString(env, value, "bulk_out_endpoint_descriptor_digest", 64,
                  &config->bulk_out_descriptor_digest) ||
      !ReadString(env, value, "bulk_in_endpoint_descriptor_digest", 64,
                  &config->bulk_in_descriptor_digest) ||
      !ReadString(env, value, "enrollment_digest", 64,
                  &config->enrollment_digest) ||
      !ReadUint32(env, value, "connection_generation",
                  &config->connection_generation)) {
    return false;
  }
  return true;
}

bool ValidateConfig(OpenConfig* config) {
  const char* fixture = std::getenv("BOB_CHAMELEON_DARWIN_DIRECT_CDC_FIXTURE");
  const uid_t real_uid = getuid();
  const uid_t effective_uid = geteuid();
  const gid_t real_gid = getgid();
  const gid_t effective_gid = getegid();
  const bool entitlement_mode =
      config->authorization_mode == "entitlement_and_ioservice_authorize";
  if (fixture == nullptr || std::strcmp(fixture, "1") != 0 ||
      (config->capture_mode != "device_capture" &&
       config->capture_mode != "device_seize") ||
      (!entitlement_mode && config->authorization_mode != "root") ||
      real_uid != effective_uid || real_gid != effective_gid ||
      config->worker_uid != real_uid || config->worker_uid != effective_uid ||
      config->worker_gid != real_gid || config->worker_gid != effective_gid ||
      (entitlement_mode &&
       (config->worker_uid == 0 || !config->vm_device_access_entitlement ||
        !config->io_service_authorized)) ||
      (!entitlement_mode &&
       (config->worker_uid != 0 || config->vm_device_access_entitlement ||
        config->io_service_authorized)) ||
      !IsIdentifier(config->ticket_id) || !IsNonce(config->ticket_nonce) ||
      !IsPositiveDecimal(config->expires_monotonic_ns) ||
      !IsDigest(config->dedicated_principal_digest) ||
      !IsDigest(config->worker_code_identity_digest) ||
      !IsDigest(config->launch_ticket_digest) || config->vendor_id == 0 ||
      config->vendor_id > 0xffff || config->product_id == 0 ||
      config->product_id > 0xffff || !IsDigest(config->serial_number_digest) ||
      config->configuration_value == 0 || config->configuration_value > 0xff ||
      config->control_interface_number > 0xff ||
      config->data_interface_number > 0xff ||
      config->control_interface_number == config->data_interface_number ||
      config->connection_generation == 0 ||
      !ValidateDeviceDescriptor(*config) ||
      !ValidateInterfaceDescriptor(config->control_interface_descriptor,
                                   config->control_interface_number, true) ||
      !ValidateInterfaceDescriptor(config->data_interface_descriptor,
                                   config->data_interface_number, false) ||
      !ValidateBulkEndpoint(config->bulk_out_descriptor, false,
                            &config->bulk_out_address) ||
      !ValidateBulkEndpoint(config->bulk_in_descriptor, true,
                            &config->bulk_in_address) ||
      !ValidateDescriptorSet(*config)) {
    return false;
  }

  std::string ticket_digest = FramedDigest(
      kTicketDomain,
      {Bytes(config->ticket_id), Bytes(config->ticket_nonce),
       Bytes(config->expires_monotonic_ns), Bytes(config->capture_mode),
       Bytes(config->authorization_mode), Bytes(Uint32String(config->worker_uid)),
       Bytes(Uint32String(config->worker_gid)),
       Bytes(BoolString(config->vm_device_access_entitlement)),
       Bytes(BoolString(config->io_service_authorized)),
       Bytes(config->dedicated_principal_digest),
       Bytes(config->worker_code_identity_digest)});
  std::string interface_digest =
      FramedDigest(kInterfaceDomain, {config->interface_descriptor_set});
  std::string out_digest =
      FramedDigest(kBulkOutDomain, {config->bulk_out_descriptor});
  std::string in_digest =
      FramedDigest(kBulkInDomain, {config->bulk_in_descriptor});
  std::string enrollment_digest = FramedDigest(
      kEnrollmentDomain,
      {Bytes(Uint32String(config->vendor_id)),
       Bytes(Uint32String(config->product_id)),
       Bytes(Uint32String(config->location_id)), Bytes(config->serial_number_digest),
       Bytes(Uint32String(config->configuration_value)),
       Bytes(Uint32String(config->control_interface_number)),
       Bytes(Uint32String(config->data_interface_number)), Bytes(interface_digest),
       Bytes(out_digest), Bytes(in_digest)});
  const bool accepted = ticket_digest == config->launch_ticket_digest &&
                        interface_digest == config->interface_descriptor_digest &&
                        out_digest == config->bulk_out_descriptor_digest &&
                        in_digest == config->bulk_in_descriptor_digest &&
                        enrollment_digest == config->enrollment_digest;
  ZeroString(&ticket_digest);
  ZeroString(&interface_digest);
  ZeroString(&out_digest);
  ZeroString(&in_digest);
  ZeroString(&enrollment_digest);
  return accepted;
}

bool SetString(napi_env env, napi_value object, const char* name,
               const std::string& value) {
  napi_value encoded;
  return napi_create_string_utf8(env, value.data(), value.size(), &encoded) == napi_ok &&
         DefineProperty(env, object, name, encoded);
}

bool SetCString(napi_env env, napi_value object, const char* name,
                const char* value) {
  napi_value encoded;
  return napi_create_string_utf8(env, value, NAPI_AUTO_LENGTH, &encoded) == napi_ok &&
         DefineProperty(env, object, name, encoded);
}

bool SetBool(napi_env env, napi_value object, const char* name, bool value) {
  napi_value encoded;
  return napi_get_boolean(env, value, &encoded) == napi_ok &&
         DefineProperty(env, object, name, encoded);
}

bool SetUint32(napi_env env, napi_value object, const char* name, uint32_t value) {
  napi_value encoded;
  return napi_create_uint32(env, value, &encoded) == napi_ok &&
         DefineProperty(env, object, name, encoded);
}

void FinalizeHandle(napi_env, void* data, void*) {
  auto* box = static_cast<HandleBox*>(data);
  if (box == nullptr) return;
  if (box->state) {
    std::lock_guard<std::mutex> lock(box->state->mutex);
    box->state->destroyed = true;
    box->state->quarantined = true;
    box->state->bulk_out_address = 0;
    box->state->bulk_in_address = 0;
  }
  delete box;
}

bool GetHandle(napi_env env, napi_value value,
               std::shared_ptr<DirectState>* output) {
  napi_valuetype type = napi_undefined;
  bool tagged = false;
  void* raw = nullptr;
  if (napi_typeof(env, value, &type) != napi_ok || type != napi_object ||
      napi_check_object_type_tag(env, value, &kDirectHandleTypeTag, &tagged) !=
          napi_ok ||
      !tagged || napi_unwrap(env, value, &raw) != napi_ok || raw == nullptr) {
    return false;
  }
  auto* box = static_cast<HandleBox*>(raw);
  if (!box->state) return false;
  *output = box->state;
  return true;
}

void QuarantineState(const std::shared_ptr<DirectState>& state) {
  std::lock_guard<std::mutex> lock(state->mutex);
  state->destroyed = true;
  state->quarantined = true;
  state->bulk_out_address = 0;
  state->bulk_in_address = 0;
}

napi_value OpenFixtureExact(napi_env env, napi_callback_info info) {
  size_t argc = 1;
  napi_value args[1];
  if (napi_get_cb_info(env, info, &argc, args, nullptr, nullptr) != napi_ok ||
      argc != 1 || !IsObject(env, args[0])) {
    ThrowCode(env, kOpenRejected);
    return nullptr;
  }
  bool fixture_only = false;
  if (!ReadBool(env, args[0], "fixture_only", &fixture_only)) {
    ThrowCode(env, kOpenRejected);
    return nullptr;
  }
  if (!fixture_only) {
    ThrowCode(env, kRealDisabled);
    return nullptr;
  }
  OpenConfig config;
  if (!ReadOpenConfig(env, args[0], &config) || !ValidateConfig(&config)) {
    ThrowCode(env, kOpenRejected);
    return nullptr;
  }
  const auto request_bytes =
      BuildControlRequestBytes(config.control_interface_number);
  if (request_bytes[0] != 0x21 || request_bytes[1] != 0x22 ||
      request_bytes[2] != 0 || request_bytes[3] != 0 ||
      request_bytes[6] != 0 || request_bytes[7] != 0) {
    ThrowCode(env, kOpenRejected);
    return nullptr;
  }
  const std::vector<unsigned char> request_vector(request_bytes.begin(),
                                                   request_bytes.end());
  const std::string request_digest =
      FramedDigest(kControlRequestDomain, {request_vector});

  napi_value output;
  napi_value attestation;
  if (napi_create_object(env, &output) != napi_ok ||
      napi_create_object(env, &attestation) != napi_ok) {
    ThrowCode(env, kOpenRejected);
    return nullptr;
  }
  const bool capture = config.capture_mode == "device_capture";
  const bool entitlement =
      config.authorization_mode == "entitlement_and_ioservice_authorize";
  bool set = SetUint32(env, attestation, "version", kVersion) &&
             SetCString(env, attestation, "primitive", kPrimitive) &&
             SetBool(env, attestation, "fixture_only", true) &&
             SetBool(env, attestation, "production_ready", false) &&
             SetCString(env, attestation, "sdk_framework", "IOUSBHost") &&
             SetBool(env, attestation, "sdk_contract_compile_time_backed", true) &&
             SetString(env, attestation, "capture_mode", config.capture_mode) &&
             SetBool(env, attestation,
                     "device_capture_terminates_clients_and_drivers", capture) &&
             SetBool(env, attestation, "device_seize_requests_owner_close", !capture) &&
             SetString(env, attestation, "privilege_gate_mode",
                       config.authorization_mode) &&
             SetBool(env, attestation, "entitlement_required", entitlement) &&
             SetBool(env, attestation, "io_service_authorize_required", entitlement) &&
             SetBool(env, attestation, "root_qualified", !entitlement) &&
             SetBool(env, attestation, "vm_device_access_entitlement",
                     config.vm_device_access_entitlement) &&
             SetString(env, attestation, "launch_ticket_digest",
                       config.launch_ticket_digest) &&
             SetString(env, attestation, "enrollment_digest",
                       config.enrollment_digest) &&
             SetString(env, attestation, "interface_descriptor_digest",
                       config.interface_descriptor_digest) &&
             SetString(env, attestation, "bulk_out_endpoint_descriptor_digest",
                       config.bulk_out_descriptor_digest) &&
             SetString(env, attestation, "bulk_in_endpoint_descriptor_digest",
                       config.bulk_in_descriptor_digest) &&
             SetUint32(env, attestation, "connection_generation",
                       config.connection_generation) &&
             SetBool(env, attestation, "exclusive_ownership_required", true) &&
             SetUint32(env, attestation, "cdc_request_type", request_bytes[0]) &&
             SetUint32(env, attestation, "cdc_request", request_bytes[1]) &&
             SetUint32(env, attestation, "cdc_value", 0) &&
             SetUint32(env, attestation, "cdc_index",
                       config.control_interface_number) &&
             SetUint32(env, attestation, "cdc_length", 0) &&
             SetString(env, attestation, "cdc_control_request_digest",
                       request_digest) &&
             SetBool(env, attestation,
                     "control_line_state_applied_before_bulk", true) &&
             SetUint32(env, attestation, "bulk_out_address",
                       config.bulk_out_address) &&
             SetUint32(env, attestation, "bulk_in_address",
                       config.bulk_in_address) &&
             SetCString(env, attestation, "phase",
                        "bulk_endpoints_bound_after_control_line_low");
  if (!set) {
    ThrowCode(env, kOpenRejected);
    return nullptr;
  }

  auto state = std::make_shared<DirectState>();
  state->generation = config.connection_generation;
  state->bulk_out_address = config.bulk_out_address;
  state->bulk_in_address = config.bulk_in_address;
  auto* box = new HandleBox{state};
  napi_value token;
  if (napi_create_object(env, &token) != napi_ok) {
    delete box;
    ThrowCode(env, kOpenRejected);
    return nullptr;
  }
  if (napi_wrap(env, token, box, FinalizeHandle, nullptr, nullptr) != napi_ok) {
    delete box;
    ThrowCode(env, kOpenRejected);
    return nullptr;
  }
  if (napi_type_tag_object(env, token, &kDirectHandleTypeTag) != napi_ok) {
    void* removed = nullptr;
    if (napi_remove_wrap(env, token, &removed) == napi_ok && removed != nullptr) {
      delete static_cast<HandleBox*>(removed);
    }
    ThrowCode(env, kOpenRejected);
    return nullptr;
  }
  if (!DefineProperty(env, output, "handle", token) ||
      !DefineProperty(env, output, "attestation", attestation)) {
    {
      std::lock_guard<std::mutex> lock(state->mutex);
      state->destroyed = true;
      state->quarantined = true;
    }
    ThrowCode(env, kOpenRejected);
    return nullptr;
  }
  return output;
}

unsigned char CalculateLrc(const unsigned char* bytes, size_t length) {
  unsigned int sum = 0;
  for (size_t index = 0; index < length; ++index) {
    sum = (sum + bytes[index]) & 0xff;
  }
  return static_cast<unsigned char>((0U - sum) & 0xff);
}

uint16_t ReadBig16(const std::vector<unsigned char>& value, size_t offset) {
  return static_cast<uint16_t>((static_cast<uint16_t>(value[offset]) << 8) |
                               value[offset + 1]);
}

bool ValidFrame(const std::vector<unsigned char>& frame, bool request) {
  if (frame.size() < kMinimumFrameBytes || frame.size() > kMaximumFrameBytes ||
      frame[0] != kSof || frame[1] != kSofLrc ||
      (request && ReadBig16(frame, 4) != 0) ||
      CalculateLrc(&frame[2], 6) != frame[8] ||
      static_cast<size_t>(ReadBig16(frame, 6)) + kMinimumFrameBytes !=
          frame.size()) {
    return false;
  }
  return CalculateLrc(&frame[9], frame.size() - kMinimumFrameBytes) ==
         frame.back();
}

napi_value TransactFixtureExact(napi_env env, napi_callback_info info) {
  size_t argc = 8;
  napi_value args[8] = {};
  if (napi_get_cb_info(env, info, &argc, args, nullptr, nullptr) != napi_ok) {
    ThrowCode(env, kTransactionAmbiguous);
    return nullptr;
  }
  std::shared_ptr<DirectState> state;
  uint32_t generation = 0;
  uint32_t sequence = 0;
  uint32_t maximum_response = 0;
  uint32_t timeout_ms = 0;
  bool request_is_buffer = false;
  bool response_is_buffer = false;
  void* request_data = nullptr;
  void* response_data = nullptr;
  size_t request_length = 0;
  size_t response_length = 0;
  if (argc < 1 || !GetHandle(env, args[0], &state)) {
    ThrowCode(env, kTransactionAmbiguous);
    return nullptr;
  }
  const auto quarantine_and_throw = [&]() -> napi_value {
    QuarantineState(state);
    ThrowCode(env, kTransactionAmbiguous);
    return nullptr;
  };
  if (argc != 7 || !ReadExactUint32Value(env, args[1], &generation) ||
      !ReadExactUint32Value(env, args[2], &sequence) ||
      napi_is_buffer(env, args[3], &request_is_buffer) != napi_ok ||
      !request_is_buffer ||
      napi_get_buffer_info(env, args[3], &request_data, &request_length) != napi_ok ||
      napi_is_buffer(env, args[4], &response_is_buffer) != napi_ok ||
      !response_is_buffer ||
      napi_get_buffer_info(env, args[4], &response_data, &response_length) != napi_ok ||
      !ReadExactUint32Value(env, args[5], &maximum_response) ||
      !ReadExactUint32Value(env, args[6], &timeout_ms) ||
      request_data == nullptr || response_data == nullptr ||
      request_length < kMinimumFrameBytes || request_length > kMaximumFrameBytes ||
      response_length < kMinimumFrameBytes || response_length > maximum_response ||
      maximum_response < kMinimumFrameBytes ||
      maximum_response > kMaximumFrameBytes || timeout_ms == 0 ||
      timeout_ms > kMaximumTimeoutMs || sequence != 1) {
    return quarantine_and_throw();
  }
  const auto* request_bytes = static_cast<const unsigned char*>(request_data);
  const auto* response_bytes = static_cast<const unsigned char*>(response_data);
  std::vector<unsigned char> request(request_bytes, request_bytes + request_length);
  std::vector<unsigned char> response(response_bytes, response_bytes + response_length);
  bool accepted = ValidFrame(request, true) && ValidFrame(response, false) &&
                  ReadBig16(request, 2) == ReadBig16(response, 2);
  {
    std::lock_guard<std::mutex> lock(state->mutex);
    if (state->destroyed || state->quarantined || state->transaction_used ||
        state->generation != generation) {
      accepted = false;
    }
    if (accepted) {
      state->transaction_used = true;
    } else {
      state->destroyed = true;
      state->quarantined = true;
      state->bulk_out_address = 0;
      state->bulk_in_address = 0;
    }
  }
  ZeroVector(&request);
  if (!accepted) {
    ZeroVector(&response);
    return quarantine_and_throw();
  }
  napi_value output;
  if (napi_create_buffer_copy(env, response.size(), response.data(), nullptr,
                              &output) != napi_ok) {
    {
      std::lock_guard<std::mutex> lock(state->mutex);
      state->destroyed = true;
      state->quarantined = true;
    }
    ZeroVector(&response);
    return quarantine_and_throw();
  }
  ZeroVector(&response);
  return output;
}

napi_value DestroyState(napi_env env, napi_callback_info info, bool quarantine) {
  size_t argc = 3;
  napi_value args[3] = {};
  std::shared_ptr<DirectState> state;
  uint32_t generation = 0;
  if (napi_get_cb_info(env, info, &argc, args, nullptr, nullptr) != napi_ok) {
    ThrowCode(env, kRejected);
    return nullptr;
  }
  if (argc < 1 || !GetHandle(env, args[0], &state)) {
    ThrowCode(env, kRejected);
    return nullptr;
  }
  if (argc != 2 || !ReadExactUint32Value(env, args[1], &generation)) {
    QuarantineState(state);
    ThrowCode(env, kRejected);
    return nullptr;
  }
  bool accepted = true;
  {
    std::lock_guard<std::mutex> lock(state->mutex);
    if (state->destroyed || state->quarantined ||
        state->generation != generation ||
        (!quarantine && !state->transaction_used)) {
      state->destroyed = true;
      state->quarantined = true;
      state->bulk_out_address = 0;
      state->bulk_in_address = 0;
      accepted = false;
    } else {
      state->destroyed = true;
      state->quarantined = state->quarantined || quarantine;
      state->bulk_out_address = 0;
      state->bulk_in_address = 0;
    }
  }
  if (!accepted) {
    ThrowCode(env, kRejected);
    return nullptr;
  }
  napi_value result;
  napi_get_boolean(env, true, &result);
  return result;
}

napi_value AbortDestroyExact(napi_env env, napi_callback_info info) {
  return DestroyState(env, info, true);
}

napi_value DestroyExact(napi_env env, napi_callback_info info) {
  return DestroyState(env, info, false);
}

napi_value Initialize(napi_env env, napi_value exports) {
  const napi_property_descriptor descriptors[] = {
      {"openFixtureExact", nullptr, OpenFixtureExact, nullptr, nullptr, nullptr,
       napi_enumerable, nullptr},
      {"transactFixtureExact", nullptr, TransactFixtureExact, nullptr, nullptr,
       nullptr, napi_enumerable, nullptr},
      {"abortDestroyExact", nullptr, AbortDestroyExact, nullptr, nullptr, nullptr,
       napi_enumerable, nullptr},
      {"destroyExact", nullptr, DestroyExact, nullptr, nullptr, nullptr,
       napi_enumerable, nullptr},
  };
  if (napi_define_properties(env, exports,
                             sizeof(descriptors) / sizeof(descriptors[0]),
                             descriptors) != napi_ok) {
    ThrowCode(env, kRejected);
    return nullptr;
  }
  return exports;
}

}  // namespace

NAPI_MODULE(NODE_GYP_MODULE_NAME, Initialize)
