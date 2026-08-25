# Blockchain severance seam

This inventory is the post-N1, pre-DIP structural-debt baseline for the blockchain plane. It is generated from the checker’s current AST walk and is expected only to shrink in later hypergraph nodes.

## Edge inventory

| # | Edge | Baseline rationale |
|---:|---|---|
| 1 | `mcp/core/invariant-runner.js:1111` -> `../domains/blockchain/smart-contracts/evm-client.js` | Existing pre-DIP core-to-blockchain dependency; recorded so new edges fail closed. |
| 2 | `mcp/core/invariant-runner.js:1014` -> `../domains/blockchain/smart-contracts/evm-rpc-pool.js` | Existing pre-DIP core-to-blockchain dependency; recorded so new edges fail closed. |
| 3 | `mcp/core/session/assignment-brief.js:66` -> `../../domains/blockchain/smart-contracts/evm-rpc-pool.js` | Existing pre-DIP core-to-blockchain dependency; recorded so new edges fail closed. |
| 4 | `mcp/core/session/session-authority.js:31` -> `../../domains/blockchain/chain-tool-identity.js` | Existing pre-DIP core-to-blockchain dependency; recorded so new edges fail closed. |
| 6 | `mcp/tools/finalize-node.js:76` -> `../domains/blockchain/contract-target.js` | Existing pre-DIP core-to-blockchain dependency; recorded so new edges fail closed. |
| 7 | `mcp/tools/index.js:48` -> `./blockchain/anchor-run.js` | Existing pre-DIP core-to-blockchain dependency; recorded so new edges fail closed. |
| 8 | `mcp/tools/index.js:50` -> `./blockchain/aptos-fetch-module.js` | Existing pre-DIP core-to-blockchain dependency; recorded so new edges fail closed. |
| 9 | `mcp/tools/index.js:49` -> `./blockchain/aptos-fetch-resource.js` | Existing pre-DIP core-to-blockchain dependency; recorded so new edges fail closed. |
| 10 | `mcp/tools/index.js:51` -> `./blockchain/aptos-run.js` | Existing pre-DIP core-to-blockchain dependency; recorded so new edges fail closed. |
| 11 | `mcp/tools/index.js:59` -> `./blockchain/cosmwasm-fetch-contract.js` | Existing pre-DIP core-to-blockchain dependency; recorded so new edges fail closed. |
| 12 | `mcp/tools/index.js:58` -> `./blockchain/cosmwasm-run.js` | Existing pre-DIP core-to-blockchain dependency; recorded so new edges fail closed. |
| 13 | `mcp/tools/index.js:60` -> `./blockchain/cosmwasm-smart-query.js` | Existing pre-DIP core-to-blockchain dependency; recorded so new edges fail closed. |
| 14 | `mcp/tools/index.js:40` -> `./blockchain/evm-call.js` | Existing pre-DIP core-to-blockchain dependency; recorded so new edges fail closed. |
| 15 | `mcp/tools/index.js:42` -> `./blockchain/evm-fetch-source.js` | Existing pre-DIP core-to-blockchain dependency; recorded so new edges fail closed. |
| 16 | `mcp/tools/index.js:43` -> `./blockchain/evm-role-table.js` | Existing pre-DIP core-to-blockchain dependency; recorded so new edges fail closed. |
| 17 | `mcp/tools/index.js:41` -> `./blockchain/evm-storage-read.js` | Existing pre-DIP core-to-blockchain dependency; recorded so new edges fail closed. |
| 18 | `mcp/tools/index.js:44` -> `./blockchain/foundry-run.js` | Existing pre-DIP core-to-blockchain dependency; recorded so new edges fail closed. |
| 19 | `mcp/tools/index.js:45` -> `./blockchain/halmos-run.js` | Existing pre-DIP core-to-blockchain dependency; recorded so new edges fail closed. |
| 20 | `mcp/tools/index.js:28` -> `./blockchain/init-contract-session.js` | Existing pre-DIP core-to-blockchain dependency; recorded so new edges fail closed. |
| 21 | `mcp/tools/index.js:36` -> `./blockchain/read-invariant-runs.js` | Existing pre-DIP core-to-blockchain dependency; recorded so new edges fail closed. |
| 22 | `mcp/tools/index.js:35` -> `./blockchain/run-invariant-for-finding.js` | Existing pre-DIP core-to-blockchain dependency; recorded so new edges fail closed. |
| 23 | `mcp/tools/index.js:57` -> `./blockchain/substrate-fetch-runtime.js` | Existing pre-DIP core-to-blockchain dependency; recorded so new edges fail closed. |
| 24 | `mcp/tools/index.js:56` -> `./blockchain/substrate-fetch-storage.js` | Existing pre-DIP core-to-blockchain dependency; recorded so new edges fail closed. |
| 25 | `mcp/tools/index.js:55` -> `./blockchain/substrate-run.js` | Existing pre-DIP core-to-blockchain dependency; recorded so new edges fail closed. |
| 26 | `mcp/tools/index.js:34` -> `./blockchain/suggest-invariants.js` | Existing pre-DIP core-to-blockchain dependency; recorded so new edges fail closed. |
| 27 | `mcp/tools/index.js:52` -> `./blockchain/sui-fetch-object.js` | Existing pre-DIP core-to-blockchain dependency; recorded so new edges fail closed. |
| 28 | `mcp/tools/index.js:53` -> `./blockchain/sui-fetch-package.js` | Existing pre-DIP core-to-blockchain dependency; recorded so new edges fail closed. |
| 29 | `mcp/tools/index.js:54` -> `./blockchain/sui-run.js` | Existing pre-DIP core-to-blockchain dependency; recorded so new edges fail closed. |
| 30 | `mcp/tools/index.js:46` -> `./blockchain/svm-fetch-account.js` | Existing pre-DIP core-to-blockchain dependency; recorded so new edges fail closed. |
| 31 | `mcp/tools/index.js:47` -> `./blockchain/svm-fetch-program.js` | Existing pre-DIP core-to-blockchain dependency; recorded so new edges fail closed. |
| 32 | `mcp/tools/index.js:64` -> `./blockchain/verify-invariant-differential.js` | Existing pre-DIP core-to-blockchain dependency; recorded so new edges fail closed. |
| 33 | `mcp/tools/init-session.js:8` -> `../domains/blockchain/contract-target.js` | Existing pre-DIP core-to-blockchain dependency; recorded so new edges fail closed. |
| 34 | `mcp/tools/repo/init-repo-session.js:7` -> `../../domains/blockchain/contract-target.js` | Existing pre-DIP core-to-blockchain dependency; recorded so new edges fail closed. |
