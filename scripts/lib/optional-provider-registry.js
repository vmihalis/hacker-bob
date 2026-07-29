"use strict";

const {
  NATIVE_PREBUILD_REQUIRED_COMPONENTS_V2,
} = require("../../packages/bob-instrument-native-prebuild-trust/lib/release-trust-v2.js");

const OPTIONAL_PROVIDER_REGISTRY_VERSION = 1;
const OPTIONAL_PROVIDER_OWNED_ROOT = ".hacker-bob/optional-providers";
const OPTIONAL_PROVIDER_STATUS_VALUES = Object.freeze([
  "absent",
  "unsupported_host",
  "installed_unqualified",
  "qualified_diagnostic",
  "blocked",
]);

function frozenRecord(value) {
  return Object.freeze(value);
}

const CHAMELEON_WORKER_DEPENDENCIES = frozenRecord({
  "@hacker-bob/instrument-chameleon-worker-runtime": "0.0.0-development",
});
const EMPTY_DEPENDENCIES = frozenRecord({});

const CHAMELEON_WORKER_CLOSURE_PACKAGES = Object.freeze([
  frozenRecord({
    package_id: "chameleon_worker_runtime",
    package_name: "@hacker-bob/instrument-chameleon-worker-runtime",
    package_version: "0.0.0-development",
    package_root: "worker/node_modules/@hacker-bob/instrument-chameleon-worker-runtime",
    expected_main: "lib/codec.js",
    expected_files: Object.freeze(["lib/**/*.js"]),
    expected_exports: frozenRecord({
      ".": "./lib/codec.js",
      "./codec": "./lib/codec.js",
      "./compiled-provider-command": "./lib/compiled-provider-command.js",
      "./hf14a-probe-compiler": "./lib/hf14a-probe-compiler.js",
      "./rf-off-usb-execution-port": "./lib/rf-off-usb-execution-port.js",
      "./usb-cdc-custody": "./lib/usb-cdc-custody.js",
    }),
    expected_dependencies: EMPTY_DEPENDENCIES,
  }),
  frozenRecord({
    package_id: "worker",
    package_name: "@hacker-bob/instrument-chameleon-worker",
    package_version: "0.0.0-development",
    package_root: "worker",
    expected_main: "lib/serialport-usb-cdc-driver.js",
    expected_files: Object.freeze(["lib/**/*.js", "README.md"]),
    expected_exports: frozenRecord({
      ".": "./lib/serialport-usb-cdc-driver.js",
      "./serialport-usb-cdc-driver": "./lib/serialport-usb-cdc-driver.js",
    }),
    expected_dependencies: CHAMELEON_WORKER_DEPENDENCIES,
  }),
]);

const OPTIONAL_PROVIDER_REGISTRY = Object.freeze([
  frozenRecord({
    version: OPTIONAL_PROVIDER_REGISTRY_VERSION,
    provider_id: "chameleon_ultra",
    activation_policy: "never_automatic",
    installation_policy: "explicit_operator_only",
    owned_root: `${OPTIONAL_PROVIDER_OWNED_ROOT}/chameleon-ultra`,
    packages: Object.freeze([
      frozenRecord({
        package_id: "worker_source",
        package_name: "@hacker-bob/instrument-chameleon-worker",
        package_version: "0.0.0-development",
        version_policy: "registry_exact",
        owned_subdirectory: "worker-source",
        surface_policy: "signed_javascript_worker_closure_v1",
        signed_release_required: true,
        target_os: "any",
        target_architecture: "any",
        node_major: 20,
        napi_version: null,
        expected_main: "lib/serialport-usb-cdc-driver.js",
        expected_closure_entrypoint: "worker/lib/serialport-usb-cdc-driver.js",
        expected_closure_packages: CHAMELEON_WORKER_CLOSURE_PACKAGES,
        expected_closure_package_ids: Object.freeze(
          CHAMELEON_WORKER_CLOSURE_PACKAGES.map((record) => record.package_id),
        ),
        expected_dependencies: CHAMELEON_WORKER_DEPENDENCIES,
        required_component_ids: Object.freeze([]),
        required_signed_schema_artifact_count: 0,
        required_component_install_modes: frozenRecord({}),
      }),
      frozenRecord({
        package_id: "darwin_arm64_native_prebuild",
        package_name: "@hacker-bob/instrument-native-prebuild-darwin-arm64",
        package_version: null,
        version_policy: "signed_manifest_exact",
        owned_subdirectory: "darwin-arm64-native-prebuild",
        surface_policy: "signed_native_prebuild_v2",
        signed_release_required: true,
        target_os: "darwin",
        target_architecture: "arm64",
        node_major: 20,
        napi_version: 9,
        expected_main: null,
        expected_dependencies: frozenRecord({}),
        required_component_ids: Object.freeze([...NATIVE_PREBUILD_REQUIRED_COMPONENTS_V2]),
        required_signed_schema_artifact_count: 28,
        required_component_install_modes: frozenRecord({
          native_ipc_acceptor: 0o444,
          chameleon_cdc_custody: 0o444,
          safety_watchdog: 0o555,
          privileged_launcher: 0o555,
          lifecycle_custodian: 0o555,
          native_dispatch_custodian: 0o555,
        }),
      }),
    ]),
  }),
]);

function registryError() {
  const error = new Error("Optional provider registry selection was rejected");
  error.code = "optional_provider_registry_rejected";
  return error;
}

function getOptionalProvider(providerId) {
  if (typeof providerId !== "string") throw registryError();
  const provider = OPTIONAL_PROVIDER_REGISTRY.find((entry) => entry.provider_id === providerId);
  if (!provider) throw registryError();
  return provider;
}

function getOptionalProviderPackage(providerId, packageId) {
  if (typeof packageId !== "string") throw registryError();
  const provider = getOptionalProvider(providerId);
  const packageRecord = provider.packages.find((entry) => entry.package_id === packageId);
  if (!packageRecord) throw registryError();
  return frozenRecord({ provider, package: packageRecord });
}

function optionalProviderOwnedRoots() {
  return Object.freeze(OPTIONAL_PROVIDER_REGISTRY.map((provider) => provider.owned_root));
}

module.exports = {
  OPTIONAL_PROVIDER_OWNED_ROOT,
  OPTIONAL_PROVIDER_REGISTRY,
  OPTIONAL_PROVIDER_REGISTRY_VERSION,
  OPTIONAL_PROVIDER_STATUS_VALUES,
  getOptionalProvider,
  getOptionalProviderPackage,
  optionalProviderOwnedRoots,
};
