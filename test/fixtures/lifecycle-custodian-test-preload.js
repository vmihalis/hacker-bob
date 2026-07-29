"use strict";

// Preloaded via NODE_OPTIONS into child processes that run the installer under
// test. The double it installs drives a Darwin/arm64-only native fixture, so on
// every other host leave the real wrapper in place: that wrapper reports the
// custodian unavailable, which is precisely the path the installer takes there.
// Enrolling unconditionally aborted the child before the CLI under test ran.
const {
  installLifecycleCustodianTestDouble,
  lifecycleCustodianTestDoubleSupported,
} = require("./lifecycle-custodian-test-port.js");

if (lifecycleCustodianTestDoubleSupported()) installLifecycleCustodianTestDouble();
