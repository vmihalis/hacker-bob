"use strict";

const SEVERITY_VALUES = ["critical", "high", "medium", "low", "info"];
const CHAIN_FAMILY_VALUES = ["evm", "svm", "aptos", "sui", "substrate", "cosmwasm"];
const VERIFICATION_ROUND_VALUES = ["brutalist", "balanced", "final"];

module.exports = {
  CHAIN_FAMILY_VALUES,
  SEVERITY_VALUES,
  VERIFICATION_ROUND_VALUES,
};
