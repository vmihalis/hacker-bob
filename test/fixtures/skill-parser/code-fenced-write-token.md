---
name: code-fenced-write-token
description: TRUE NEGATIVE — write-tool token appears INSIDE a fenced code block, so the structural-containment dimension correctly ignores it.
---

# Code-Fenced Token Fixture (TRUE NEGATIVE)

## STATE: REPORT

Example payload shape (do NOT call directly from this state):

```json
{
  "tool": "bob_write_chain_attempt",
  "args": { "target_domain": "example.com" }
}
```

This block contains the canonical write-tool prefix only inside a
fenced code block, so D1 must NOT fire. There are zero write-tool
tokens outside code blocks in this STATE.
