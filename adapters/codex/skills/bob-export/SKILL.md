---
name: bob-export
description: Create a Hacker Bob post-release improvement bundle for the currently installed Bob version.
---

# Hacker Bob Export

Use this when the operator asks to create a post-release improvement bundle from Codex.

Run from the project root. The command has no v1 flags:
```bash
node -e "const exporter=require('./mcp/lib/bob-export.js'); const result=exporter.exportBobReleaseBundle({ projectDir: process.cwd() }); process.stdout.write(exporter.renderExportResult(result));"
```

Report the helper output exactly. This workflow exports telemetry and session summaries for improving Hacker Bob; it does not evaluate, resume sessions, or interact with targets.
