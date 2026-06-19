# `stigmergy-coherence` fixture corpus

This directory anchors the FP-rate budget for Y-P14c
(`check:stigmergy-coherence`). The canonical 6-pair corpus is the live
manifest itself (`mcp/lib/stigmergic-producers.js` paired with
`mcp/lib/stigmergic-consumers.js`); synthetic drift fixtures are
constructed inline in `test/stigmergy-coherence.test.js` (drift kinds
(i)–(iv)).

Threshold (Y-P14c): ≤2% false-positive rate on the curated corpus.

Add new fixture subdirectories here only if a drift kind can NOT be
expressed synthetically inline. Each fixture subdirectory MUST be
referenced by an explicit test assertion in
`test/stigmergy-coherence.test.js` so the FP-rate budget remains
auditable.
