"use strict";

const SVM_CLUSTER_VALUES = ["mainnet-beta", "devnet", "testnet"];
const APTOS_NETWORK_VALUES = ["mainnet", "testnet", "devnet"];
const SUI_NETWORK_VALUES = ["mainnet", "testnet", "devnet", "localnet"];
const SUBSTRATE_NETWORK_VALUES = [
  "polkadot",
  "kusama",
  "astar",
  "shiden",
  "rococo",
  "westend",
  "localnet",
];
const COSMWASM_NETWORK_VALUES = [
  "osmosis",
  "juno",
  "neutron",
  "archway",
  "sei",
  "stargaze",
  "terra",
  "kava",
  "localnet",
];
const CHAIN_ATTEMPT_OUTCOME_VALUES = ["confirmed", "denied", "blocked", "inconclusive", "not_applicable"];
const CHAIN_ATTEMPT_TERMINAL_OUTCOME_VALUES = ["confirmed", "denied", "blocked", "not_applicable"];

module.exports = {
  APTOS_NETWORK_VALUES,
  CHAIN_ATTEMPT_OUTCOME_VALUES,
  CHAIN_ATTEMPT_TERMINAL_OUTCOME_VALUES,
  COSMWASM_NETWORK_VALUES,
  SUBSTRATE_NETWORK_VALUES,
  SUI_NETWORK_VALUES,
  SVM_CLUSTER_VALUES,
};
