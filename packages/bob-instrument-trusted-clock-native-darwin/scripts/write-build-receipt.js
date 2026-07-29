"use strict";

const fs = require("node:fs");
const path = require("node:path");

const {
  DARWIN_TRUSTED_CLOCK_LOCAL_BUILD_RECEIPT_PATH,
  _canonicalJsonForBuildReceipt,
  createDarwinTrustedClockLocalBuildReceipt,
} = require("../lib/native-build-contract.js");

const ROOT = path.resolve(__dirname, "..");
const receipt = createDarwinTrustedClockLocalBuildReceipt(ROOT);
const encoded = Buffer.from(`${_canonicalJsonForBuildReceipt(receipt)}\n`, "utf8");
const destination = path.join(ROOT, DARWIN_TRUSTED_CLOCK_LOCAL_BUILD_RECEIPT_PATH);
const directory = path.dirname(destination);
const temporary = path.join(directory, `.trusted-clock-build-receipt-${process.pid}.tmp`);
let descriptor = -1;
let directoryDescriptor = -1;

try {
  descriptor = fs.openSync(
    temporary,
    fs.constants.O_WRONLY | fs.constants.O_CREAT | fs.constants.O_EXCL
      | (fs.constants.O_NOFOLLOW || 0) | (fs.constants.O_CLOEXEC || 0),
    0o600,
  );
  let offset = 0;
  while (offset < encoded.length) {
    offset += fs.writeSync(descriptor, encoded, offset, encoded.length - offset);
  }
  fs.fsyncSync(descriptor);
  fs.closeSync(descriptor);
  descriptor = -1;
  fs.renameSync(temporary, destination);
  directoryDescriptor = fs.openSync(
    directory,
    fs.constants.O_RDONLY | (fs.constants.O_CLOEXEC || 0),
  );
  fs.fsyncSync(directoryDescriptor);
} finally {
  encoded.fill(0);
  if (descriptor >= 0) fs.closeSync(descriptor);
  if (directoryDescriptor >= 0) fs.closeSync(directoryDescriptor);
  try {
    fs.unlinkSync(temporary);
  } catch (error) {
    if (error?.code !== "ENOENT") throw error;
  }
}

