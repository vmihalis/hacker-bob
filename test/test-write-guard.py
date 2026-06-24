#!/usr/bin/env python3
"""Unit tests for session-write-guard.sh hook."""
import json
import os
import subprocess
import sys

HOOK = os.path.join(os.path.dirname(__file__), "..", ".claude", "hooks", "session-write-guard.sh")
KIMI_HOOK = os.path.join(os.path.dirname(__file__), "..", "adapters", "kimi", "hooks", "session-write-guard.sh")
# The Claude and Kimi write guards must enforce IDENTICAL policy (no split-brain).
# Both parse the same PreToolUse envelope, so the same cases run against both.
HOOKS = [("claude", HOOK), ("kimi", KIMI_HOOK)]
HOME = os.path.expanduser("~")
SESSION = f"{HOME}/hacker-bob-sessions/example.com"

TESTS = [
    # (description, payload, expected_exit_code)

    # --- Write tool tests ---
    ("Write to MCP-owned brutalist.json → block",
     {"tool_input": {"file_path": f"{SESSION}/brutalist.json", "content": "test"}},
     2),
    ("Write to MCP-owned grade.md → block",
     {"tool_input": {"file_path": f"{SESSION}/grade.md", "content": "test"}},
     2),
    ("Write to MCP-owned findings.jsonl → block",
     {"tool_input": {"file_path": f"{SESSION}/findings.jsonl", "content": "test"}},
     2),
    ("Write to MCP-owned coverage.jsonl → block",
     {"tool_input": {"file_path": f"{SESSION}/coverage.jsonl", "content": "test"}},
     2),
    ("Write to MCP-owned technique-attempts.jsonl → block",
     {"tool_input": {"file_path": f"{SESSION}/technique-attempts.jsonl", "content": "test"}},
     2),
    ("Write to MCP-owned technique-pack-reads.jsonl → block",
     {"tool_input": {"file_path": f"{SESSION}/technique-pack-reads.jsonl", "content": "test"}},
     2),
    ("Write to MCP-owned chain-attempts.jsonl → block",
     {"tool_input": {"file_path": f"{SESSION}/chain-attempts.jsonl", "content": "test"}},
     2),
    ("Write to MCP-owned diff-impact.json → block",
     {"tool_input": {"file_path": f"{SESSION}/diff-impact.json", "content": "test"}},
     2),
    ("Write to MCP-owned evidence-packs.json → block",
     {"tool_input": {"file_path": f"{SESSION}/evidence-packs.json", "content": "test"}},
     2),
    ("Write to MCP-owned pipeline-events.jsonl → block",
     {"tool_input": {"file_path": f"{SESSION}/pipeline-events.jsonl", "content": "test"}},
     2),
    ("Write to MCP-owned http-audit.jsonl → block",
     {"tool_input": {"file_path": f"{SESSION}/http-audit.jsonl", "content": "test"}},
     2),
    ("Write to MCP-owned traffic.jsonl → block",
     {"tool_input": {"file_path": f"{SESSION}/traffic.jsonl", "content": "test"}},
     2),
    ("Write to MCP-owned public-intel.json → block",
     {"tool_input": {"file_path": f"{SESSION}/public-intel.json", "content": "test"}},
     2),
    ("Write to MCP-owned handoff signing key → block",
     {"tool_input": {"file_path": f"{SESSION}/.handoff-signing-key.json", "content": "test"}},
     2),
    ("Write to MCP-owned surface-routes.json → block",
     {"tool_input": {"file_path": f"{SESSION}/surface-routes.json", "content": "test"}},
     2),
    ("Write to MCP-owned repo-inventory.json → block",
     {"tool_input": {"file_path": f"{SESSION}/repo-inventory.json", "content": "test"}},
     2),
    ("Write to MCP-owned repo-checks.jsonl → block",
     {"tool_input": {"file_path": f"{SESSION}/repo-checks.jsonl", "content": "test"}},
     2),
    ("Write to MCP-owned repo-env.json → block",
     {"tool_input": {"file_path": f"{SESSION}/repo-env.json", "content": "test"}},
     2),
    ("Write to MCP-owned Dockerfile.bob → block",
     {"tool_input": {"file_path": f"{SESSION}/Dockerfile.bob", "content": "test"}},
     2),
    ("Write to MCP-owned repo-command-runs.jsonl → block",
     {"tool_input": {"file_path": f"{SESSION}/repo-command-runs.jsonl", "content": "test"}},
     2),
    ("Write to MCP-owned offensive-runs.jsonl → block",
     {"tool_input": {"file_path": f"{SESSION}/offensive-runs.jsonl", "content": "test"}},
     2),
    ("Write to MCP-owned static-artifacts.jsonl → block",
     {"tool_input": {"file_path": f"{SESSION}/static-artifacts.jsonl", "content": "test"}},
     2),
    ("Write to MCP-owned static-imports artifact → block",
     {"tool_input": {"file_path": f"{SESSION}/static-imports/SA-1.txt", "content": "test"}},
     2),
    ("Write to MCP-owned static-analysis-results.jsonl → block",
     {"tool_input": {"file_path": f"{SESSION}/static-analysis-results.jsonl", "content": "test"}},
     2),
    ("Write to MCP-owned static-analysis-index.jsonl → block",
     {"tool_input": {"file_path": f"{SESSION}/static-analysis-index.jsonl", "content": "test"}},
     2),
    ("Write to MCP-owned handoff-w1-a2.json → block",
     {"tool_input": {"file_path": f"{SESSION}/handoff-w1-a2.json", "content": "test"}},
     2),
    ("Write to MCP-owned state.json → block",
     {"tool_input": {"file_path": f"{SESSION}/state.json", "content": "test"}},
     2),
    ("Write to audit-graded report.md → block",
     {"tool_input": {"file_path": f"{SESSION}/report.md", "content": "test"}},
     2),
    ("Write to audit-graded chains.md → block",
     {"tool_input": {"file_path": f"{SESSION}/chains.md", "content": "test"}},
     2),
    ("Write to agent-owned attack_surface.json → allow",
     {"tool_input": {"file_path": f"{SESSION}/attack_surface.json", "content": "test"}},
     0),
    ("Write to agent-owned surface-discovery-summary.json → allow",
     {"tool_input": {"file_path": f"{SESSION}/surface-discovery-summary.json", "content": "test"}},
     0),
    ("Write to agent-owned deep-summary.json → allow",
     {"tool_input": {"file_path": f"{SESSION}/deep-summary.json", "content": "test"}},
     0),
    ("Write to MCP-owned surface-leads.json → block",
     {"tool_input": {"file_path": f"{SESSION}/surface-leads.json", "content": "test"}},
     2),
    ("Write to agent-owned subdomains.txt → allow",
     {"tool_input": {"file_path": f"{SESSION}/subdomains.txt", "content": "test"}},
     0),
    ("Write outside session dir → allow",
     {"tool_input": {"file_path": "/tmp/anything.json", "content": "test"}},
     0),

    # --- Bash redirect tests ---
    ("Bash > to MCP-owned grade.md → block",
     {"tool_input": {"command": f"echo test > {SESSION}/grade.md"}},
     2),
    ("Bash >> to MCP-owned findings.md → block",
     {"tool_input": {"command": f"cat data >> {SESSION}/findings.md"}},
     2),
    ("Bash >> to MCP-owned coverage.jsonl → block",
     {"tool_input": {"command": f"cat data >> {SESSION}/coverage.jsonl"}},
     2),
    ("Bash >> to MCP-owned technique-attempts.jsonl → block",
     {"tool_input": {"command": f"cat data >> {SESSION}/technique-attempts.jsonl"}},
     2),
    ("Bash >> to MCP-owned technique-pack-reads.jsonl → block",
     {"tool_input": {"command": f"cat data >> {SESSION}/technique-pack-reads.jsonl"}},
     2),
    ("Bash >> to MCP-owned chain-attempts.jsonl → block",
     {"tool_input": {"command": f"cat data >> {SESSION}/chain-attempts.jsonl"}},
     2),
    ("Bash > to MCP-owned diff-impact.json → block",
     {"tool_input": {"command": f"echo data > {SESSION}/diff-impact.json"}},
     2),
    ("Bash > to MCP-owned evidence-packs.md → block",
     {"tool_input": {"command": f"echo data > {SESSION}/evidence-packs.md"}},
     2),
    ("Bash >> to MCP-owned traffic.jsonl → block",
     {"tool_input": {"command": f"cat data >> {SESSION}/traffic.jsonl"}},
     2),
    ("Bash > to MCP-owned repo-inventory.json → block",
     {"tool_input": {"command": f"echo '{{}}' > {SESSION}/repo-inventory.json"}},
     2),
    ("Bash >> to MCP-owned repo-checks.jsonl → block",
     {"tool_input": {"command": f"cat data >> {SESSION}/repo-checks.jsonl"}},
     2),
    ("Bash > to MCP-owned repo-env.json → block",
     {"tool_input": {"command": f"echo '{{}}' > {SESSION}/repo-env.json"}},
     2),
    ("Bash > to MCP-owned Dockerfile.bob → block",
     {"tool_input": {"command": f"echo FROM scratch > {SESSION}/Dockerfile.bob"}},
     2),
    ("Bash >> to MCP-owned repo-command-runs.jsonl → block",
     {"tool_input": {"command": f"cat data >> {SESSION}/repo-command-runs.jsonl"}},
     2),
    ("Bash >> to MCP-owned offensive-runs.jsonl → block",
     {"tool_input": {"command": f"cat data >> {SESSION}/offensive-runs.jsonl"}},
     2),
    ("Bash cd-then-relative-redirect to offensive-runs.jsonl → block",
     {"tool_input": {"command": f"cd {SESSION} && printf '{{}}' >> offensive-runs.jsonl"}},
     2),
    ("Bash cd-dashdash-then-relative-redirect to offensive-runs.jsonl → block",
     {"tool_input": {"command": f"cd -- {SESSION} && printf '{{}}' >> offensive-runs.jsonl"}},
     2),
    ("Bash cd-then-relative-redirect to repo-command-runs.jsonl → block",
     {"tool_input": {"command": f"cd {SESSION} && echo data >> repo-command-runs.jsonl"}},
     2),
    ("Bash cd-then-relative-redirect to allowed notes.txt → allow",
     {"tool_input": {"command": f"cd {SESSION} && echo hi >> notes.txt"}},
     0),
    ("Bash > to MCP-owned static-scan-results.jsonl → block",
     {"tool_input": {"command": f"echo data > {SESSION}/static-scan-results.jsonl"}},
     2),
    ("Bash > to MCP-owned static-analysis-results.jsonl → block",
     {"tool_input": {"command": f"echo data > {SESSION}/static-analysis-results.jsonl"}},
     2),
    ("Bash > to MCP-owned static-analysis-index.jsonl → block",
     {"tool_input": {"command": f"echo data > {SESSION}/static-analysis-index.jsonl"}},
     2),
    ("Bash > to MCP-owned static-imports artifact → block",
     {"tool_input": {"command": f"echo data > {SESSION}/static-imports/SA-1.txt"}},
     2),
    ("Bash tee to MCP-owned brutalist.json → block",
     {"tool_input": {"command": f"echo data | tee {SESSION}/brutalist.json"}},
     2),
    ("Bash > to agent-owned .txt → allow",
     {"tool_input": {"command": f"echo test > {SESSION}/subdomains.txt"}},
     0),
    ("Bash > to agent-owned compact surface-discovery JSON → allow",
     {"tool_input": {"command": f"echo '{{}}' > {SESSION}/surface-discovery-summary.json"}},
     0),
    ("Bash no redirects → allow",
     {"tool_input": {"command": "ls -la /tmp"}},
     0),
    ("Bash rm MCP-owned signing key → block",
     {"tool_input": {"command": f"rm {SESSION}/.handoff-signing-key.json"}},
     2),
    ("Bash chmod MCP-owned signing key → block",
     {"tool_input": {"command": f"chmod 644 {SESSION}/.handoff-signing-key.json"}},
     2),

    # --- Inline script tests ---
    ("python3 -c open() to MCP-owned → block",
     {"tool_input": {"command": f"python3 -c \"open('{SESSION}/brutalist.json','w').write('{{}}')\""}},
     2),
    ("python3 -c open() to audit-graded report.md → block",
     {"tool_input": {"command": f"python3 -c \"open('{SESSION}/report.md','w').write('test')\""}},
     2),
    ("python3 -c open() to agent-writable subdomains.txt → allow",
     {"tool_input": {"command": f"python3 -c \"open('{SESSION}/subdomains.txt','w').write('x')\""}},
     0),
    ("python3 heredoc open() to MCP-owned → block",
     {"tool_input": {"command": f"python3 - <<'PY'\nwith open('{SESSION}/grade.json','w') as f:\n    f.write('{{}}')\nPY"}},
     2),
    ("node -e writeFile to MCP-owned → block",
     {"tool_input": {"command": f"node -e \"require('fs').writeFileSync(open('{SESSION}/state.json','w'))\""}},
     2),
    ("python3 -c without file write → allow",
     {"tool_input": {"command": "python3 -c \"print(42)\""}},
     0),

    # --- Escaped quotes and pathlib edge cases ---
    ("python3 -c with escaped inner quotes → block",
     {"tool_input": {"command": f"python3 -c \"import json; f=open('{SESSION}/state.json','w'); json.dump({{}},f); f.close()\""}},
     2),
    ("pathlib Path().write_text() to MCP-owned → block",
     {"tool_input": {"command": f"python3 -c \"from pathlib import Path; Path('{SESSION}/brutalist.json').write_text('{{}}')\""}},
     2),
    ("pathlib Path().write_text() to audit-graded report.md → block",
     {"tool_input": {"command": f"python3 -c \"from pathlib import Path; Path('{SESSION}/report.md').write_text('test')\""}},
     2),
    ("open() outside session dir → allow",
     {"tool_input": {"command": "python3 -c \"open('/tmp/test.json','w').write('test')\""}},
     0),
    ("Bash with open() in echo string (not a real write) → allow",
     {"tool_input": {"command": "echo \"open('/tmp/test.json','w')\""}},
     0),

    # --- shlex.split ValueError must block, not silently allow ---
    ("Bash with unterminated quote blocks (shlex ValueError)",
     {"tool_input": {"command": f"rm '{SESSION}/findings.jsonl"}},
     2),

    # --- regex parity: paths.js .source compiled under Python re ---
    # The manifest's exported handoff pattern is the paths.js .source
    # (^handoff-w[1-9][0-9]*-a[1-9][0-9]*\.json$). Prove Python re matches it.
    ("Write to audit-graded handoff-w1-a1.json → block",
     {"tool_input": {"file_path": f"{SESSION}/handoff-w1-a1.json", "content": "x"}},
     2),
    ("Write to audit-graded handoff-w1-a1.md → block",
     {"tool_input": {"file_path": f"{SESSION}/handoff-w1-a1.md", "content": "x"}},
     2),
    # Boundary: the stricter [1-9][0-9]* form rejects w0/a0. It then falls
    # through to default-block anyway (unknown file in session dir), so the
    # observable verdict is still block — assert it so the semantics are pinned.
    ("Write to handoff-w0-a1.json → block (default-block; pattern rejects w0)",
     {"tool_input": {"file_path": f"{SESSION}/handoff-w0-a1.json", "content": "x"}},
     2),
    # The agent-writable *.txt pattern (^.*\.txt$) must compile under re and
    # ALLOW a plain scratch .txt at the session root.
    ("Write to agent-writable foo.txt → allow",
     {"tool_input": {"file_path": f"{SESSION}/foo.txt", "content": "x"}},
     0),
    # Audit-graded RELATIVE DIR prefix — a file under verification-attempts/
    # blocks regardless of basename (parity with isAuditGradedPath).
    ("Write under audit-graded verification-attempts/ → block",
     {"tool_input": {"file_path": f"{SESSION}/verification-attempts/round-1.json", "content": "x"}},
     2),

    # --- Heredoc bodies must not trip the shlex fail-closed guard. ---
    # The discovery scripts' canonical step-6 JS-analysis heredoc embeds
    # r'https?://[^\s"\'<>]+...', whose \' unbalances shlex's quote counter and
    # used to fail-closed-block the framework's OWN shipped script. A heredoc
    # whose body breaks shlex but writes ONLY scratch files must be ALLOWED —
    # the body is inert stdin and carries no shell-level write target.
    ("heredoc w/ quote-breaking regex, writes scratch .txt → allow",
     {"tool_input": {"command":
        "python3 - <<'PY'\n"
        "import re\n"
        "hits = re.findall(r'a\\'b', open('/tmp/c').read())\n"
        f"open('{SESSION}/subdomains.txt','w').write('ok')\n"
        "PY"}},
     0),
    # The heredoc strip must not open a hole: an inline write to an MCP-owned
    # file from inside such a heredoc is still caught by the full-command regex.
    ("heredoc w/ quote-breaking regex, inline-writes MCP-owned grade.json → block",
     {"tool_input": {"command":
        "python3 - <<'PY'\n"
        "import re\n"
        "hits = re.findall(r'a\\'b', 'x')\n"
        f"open('{SESSION}/grade.json','w').write('x')\n"
        "PY"}},
     2),

    # --- Command-aware payload separation: data is not a write. ---
    # A write-call STRING echoed/heredoc'd to a data consumer is inert -> ALLOW.
    ("echo of an open(...,'w') string is data, not a write → allow",
     {"tool_input": {"command": f"echo \"open('{SESSION}/grade.md','w')\""}},
     0),
    ("cat heredoc body containing an open(...,'w') string is data → allow",
     {"tool_input": {"command": f"cat <<'EOF'\nopen('{SESSION}/grade.json','w').write('x')\nEOF"}},
     0),
    # A read-mode open of a session file is not a write -> ALLOW (precision).
    ("read-mode open of a session file is not a write → allow",
     {"tool_input": {"command":
        "python3 - <<'PY'\n"
        "import re\n"
        "hits = re.findall(r'a\\'b', 'x')\n"
        f"data = open('{SESSION}/grade.md').read()\n"
        "PY"}},
     0),
    # A genuine rm inside a SHELL heredoc body is re-analyzed recursively → block.
    ("bash heredoc body that rm's a blocked file → block (shell recursion)",
     {"tool_input": {"command": f"bash <<'EOF'\nrm {SESSION}/findings.jsonl\nEOF"}},
     2),
    # A '>' that appears only as DATA inside -c interpreter source → allow.
    ("redirect-looking text inside python3 -c is data → allow",
     {"tool_input": {"command": f"python3 -c \"print('a > {SESSION}/grade.md')\""}},
     0),

    # --- Hardening: naive shell write primitives beyond rm/mv/cp. ---
    ("truncate of MCP-owned state.json → block",
     {"tool_input": {"command": f"truncate -s 0 {SESSION}/state.json"}},
     2),
    ("dd of= MCP-owned state.json → block",
     {"tool_input": {"command": f"dd if=/tmp/src of={SESSION}/state.json"}},
     2),
    ("sed -i of MCP-owned state.json → block",
     {"tool_input": {"command": f"sed -i.bak 's/a/b/' {SESSION}/state.json"}},
     2),
    ("install over audit-graded report.md → block",
     {"tool_input": {"command": f"install /tmp/src {SESSION}/report.md"}},
     2),
    ("ln -sf over MCP-owned state.json → block",
     {"tool_input": {"command": f"ln -sf /tmp/src {SESSION}/state.json"}},
     2),
    ("truncate of agent-writable scratch .txt → allow",
     {"tool_input": {"command": f"truncate -s 0 {SESSION}/subdomains.txt"}},
     0),
    # --- Hardening: interpreter write idioms beyond open(...,'w'). ---
    ("python os.system shell-redirect to grade.md → block (recursed as shell)",
     {"tool_input": {"command": f"python3 -c \"import os; os.system('echo x > {SESSION}/grade.md')\""}},
     2),
    ("python shutil.copy onto audit-graded report.md → block",
     {"tool_input": {"command": f"python3 -c \"import shutil; shutil.copy('/tmp/s','{SESSION}/report.md')\""}},
     2),
    ("python os.replace onto MCP-owned state.json → block",
     {"tool_input": {"command": f"python3 -c \"import os; os.replace('/tmp/s','{SESSION}/state.json')\""}},
     2),
    ("ruby File.write of MCP-owned state.json → block",
     {"tool_input": {"command": f"ruby -e \"File.write('{SESSION}/state.json','x')\""}},
     2),
    # --- Hardening: a shell interpreter's -c body is recursed as shell. ---
    ("sh -c with a nested redirect to state.json → block",
     {"tool_input": {"command": f"sh -c 'echo x > {SESSION}/state.json'"}},
     2),
    # --- FP fix: a command-substitution redirect target is dynamic, not a
    # captured fragment, so a timestamped scratch .txt is allowed. ---
    ("redirect to a $(date)-timestamped scratch .txt → allow",
     {"tool_input": {"command": f"echo x > \"{SESSION}/probe-$(date +%s).txt\""}},
     0),

    # --- pathlib variable-join writes: `(session / "name").write_text(...)`. ---
    # The leaking idiom: a literal-path WRITE_OP_RE matched a `write_text` but NOT
    # the variable-join form the discovery prompt actually uses. The join EXPR is
    # runtime-dynamic; the joined string LITERAL is session-RELATIVE and is resolved
    # against SESSIONS_ROOT, so MCP-owned basenames BLOCK and agent-writable ALLOW.
    ("variable-join (session / surface-leads.json).write_text → block (the leaking form)",
     {"tool_input": {"command":
        "python3 - <<'PY'\n"
        "import pathlib\n"
        "session = pathlib.Path('/x')\n"
        "(session / \"surface-leads.json\").write_text('{}')\n"
        "PY"}},
     2),
    ("variable-join (session / surface-leads.json).write_bytes → block",
     {"tool_input": {"command":
        "python3 - <<'PY'\n"
        "import pathlib\n"
        "session = pathlib.Path('/x')\n"
        "(session / \"surface-leads.json\").write_bytes(b'x')\n"
        "PY"}},
     2),
    ("assigned-then-write p = session / state.json; p.write_text → block",
     {"tool_input": {"command":
        "python3 - <<'PY'\n"
        "import pathlib\n"
        "session = pathlib.Path('/x')\n"
        "p = session / \"state.json\"\n"
        "p.write_text('{}')\n"
        "PY"}},
     2),
    # NEAR-MISS: agent-writable basename via the same join form must still ALLOW
    # (proves the fix is not over-broad — check_file's is_agent_allowed runs first).
    ("variable-join (session / deep-summary.json).write_text → allow (agent-writable)",
     {"tool_input": {"command":
        "python3 - <<'PY'\n"
        "import pathlib\n"
        "session = pathlib.Path('/x')\n"
        "(session / \"deep-summary.json\").write_text('{}')\n"
        "PY"}},
     0),
    ("variable-join (session / subdomains.txt).write_text → allow (matches ^.*\\.txt$)",
     {"tool_input": {"command":
        "python3 - <<'PY'\n"
        "import pathlib\n"
        "session = pathlib.Path('/x')\n"
        "(session / \"subdomains.txt\").write_text('x')\n"
        "PY"}},
     0),
    # NEAR-MISS: read-side join must ALLOW — the verb anchor excludes read_text.
    ("variable-join read-side (session / surface-leads.json).read_text → allow",
     {"tool_input": {"command":
        "python3 - <<'PY'\n"
        "import pathlib\n"
        "session = pathlib.Path('/x')\n"
        "data = (session / \"surface-leads.json\").read_text()\n"
        "PY"}},
     0),
    # NEAR-MISS: the shipped cname read-then-write idiom (agent-writable .txt
    # basename, read on the same join expr) must ALLOW.
    ("variable-join cname_records.txt read-then-write idiom → allow",
     {"tool_input": {"command":
        "python3 - <<'PY'\n"
        "import pathlib\n"
        "session = pathlib.Path('/x')\n"
        "(session / \"cname_records.txt\").write_text(\"\\n\".join(sorted(set((session / \"cname_records.txt\").read_text().splitlines()))) + \"\\n\")\n"
        "PY"}},
     0),
    # --- NON-SESSION join base must ALLOW (the false-positive fix). ---
    # The THREAT is writing an MCP-owned basename to the SESSION dir. A join whose
    # BASE is a LITERAL / non-session path resolves to its REAL location (outside any
    # session root), so an MCP-owned-LOOKING basename there is NOT a session write.
    # (a) literal base Path('/tmp') joined with an MCP-owned basename → allow.
    ("variable-join (Path('/tmp') / findings.jsonl).write_text → allow (non-session base)",
     {"tool_input": {"command":
        "python3 - <<'PY'\n"
        "import pathlib\n"
        "tmp = pathlib.Path('/tmp')\n"
        "(tmp / \"findings.jsonl\").write_text('x')\n"
        "PY"}},
     0),
    # (b) assigned-then-write with a non-session base var → allow.
    ("assigned-then-write p = tmp / findings.jsonl (non-session base) → allow",
     {"tool_input": {"command":
        "python3 - <<'PY'\n"
        "import pathlib\n"
        "tmp = pathlib.Path('/tmp')\n"
        "p = tmp / \"findings.jsonl\"\n"
        "p.write_text('x')\n"
        "PY"}},
     0),
    # (c) relative literal base Path('reports') joined with audit-graded report.md → allow.
    ("variable-join (Path('reports') / report.md).write_text → allow (relative non-session base)",
     {"tool_input": {"command":
        "python3 - <<'PY'\n"
        "import pathlib\n"
        "out = pathlib.Path('reports')\n"
        "(out / \"report.md\").write_text('x')\n"
        "PY"}},
     0),
]


def main():
    import tempfile
    import shutil

    passed = 0
    failed = 0

    def record(ok, desc, expected, got, stderr):
        nonlocal passed, failed
        status = "\033[32mPASS\033[0m" if ok else "\033[31mFAIL\033[0m"
        print(f"  {status}: {desc}")
        if not ok:
            print(f"         expected exit {expected}, got {got}")
            if stderr.strip():
                print(f"         stderr: {stderr.strip()}")
            failed += 1
        else:
            passed += 1

    for adapter, hook in HOOKS:
        print(f"\n=== {adapter} write guard ===")
        for desc, payload, expected in TESTS:
            result = subprocess.run(
                ["bash", hook],
                input=json.dumps(payload),
                capture_output=True,
                text=True,
            )
            record(result.returncode == expected, f"[{adapter}] {desc}",
                   expected, result.returncode, result.stderr)

        # Liveness 1: a missing/unreadable manifest must FAIL CLOSED (block). The
        # hook sets WRITE_GUARD_TABLES_FILE to "$(dirname "$0")/write-guard-tables.json",
        # so copy the hook into a temp dir with NO manifest beside it.
        with tempfile.TemporaryDirectory() as tmp:
            hook_copy = os.path.join(tmp, "session-write-guard.sh")
            shutil.copyfile(hook, hook_copy)
            live = subprocess.run(
                ["bash", hook_copy],
                input=json.dumps(
                    {"tool_input": {"file_path": f"{SESSION}/anything.json", "content": "x"}}
                ),
                capture_output=True,
                text=True,
            )
            record(live.returncode == 2, f"[{adapter}] Manifest missing -> fail closed (block)",
                   2, live.returncode, live.stderr)

        # Liveness 2: a structurally-WRONG manifest (valid JSON, missing a key)
        # must ALSO fail closed with exit 2 — KeyError must not leak an unhandled
        # exit 1 that a host could treat as a framework error and fail open.
        with tempfile.TemporaryDirectory() as tmp:
            hook_copy = os.path.join(tmp, "session-write-guard.sh")
            shutil.copyfile(hook, hook_copy)
            with open(os.path.join(tmp, "write-guard-tables.json"), "w", encoding="utf-8") as fh:
                json.dump({"audit_graded_basenames": ["report.md"]}, fh)  # missing other keys
            live = subprocess.run(
                ["bash", hook_copy],
                input=json.dumps(
                    {"tool_input": {"file_path": f"{SESSION}/anything.json", "content": "x"}}
                ),
                capture_output=True,
                text=True,
            )
            record(live.returncode == 2, f"[{adapter}] Manifest incomplete (missing key) -> fail closed (block)",
                   2, live.returncode, live.stderr)

    print(f"\n  {passed}/{passed + failed} passed")
    return 0 if failed == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
