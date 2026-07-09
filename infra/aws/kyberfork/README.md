# kyberfork — smart-contract target (the deterministic anchor). IaC.

An `anvil` (Foundry) JSON-RPC node serving a fork of **already-public** Ethereum mainnet state
at **block 17,050,000**, running the real open-source `KyberNetwork/ks-elastic-sc-legacy`
contracts (Kyber Network — Vietnamese-founded). We own the fork; the vuln is real pre-patch
bytecode, pre-validated to reach SUBMIT against the public `one-hundred-proof/kyberswap-exploit`
PoC at the identical block.

- **Build-time** (machine WITH egress, never the microVM):
  `anvil --fork-url $ARCHIVE_RPC --fork-block-number 17050000 --dump-state kyberswap-fork.json`
  → a self-contained snapshot of public historical state.
- **Runtime:** `anvil --load-state` onto an EC2/Fargate node **inside** the no-IGW/no-NAT VPC,
  private DNS `kyberfork.internal:8545`, **zero runtime egress**.

Spec: `aabw-2026/projects/06-aws-glassbox/KYBERFORK-SPEC.md`. TODO(build-day): author the stack.

**BRIGHT LINE:** scope = `kyberfork.internal` ONLY — never a live/archive RPC, Etherscan,
kyberswap.com, Kyber's live mainnet, real mainnet, or the Immunefi submission path.
