"use strict";

const releaseTrust = require("./release-trust");
const doctor = require("./doctor");
const releaseTrustV2 = require("./release-trust-v2");
const doctorV2 = require("./doctor-v2");
const javascriptWorkerClosure = require("./javascript-worker-closure");

module.exports = Object.freeze({
  ...releaseTrust,
  ...doctor,
  ...releaseTrustV2,
  ...doctorV2,
  ...javascriptWorkerClosure,
});
