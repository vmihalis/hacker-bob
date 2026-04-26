#!/usr/bin/env python3
"""Unit tests for session-write-guard.sh hook."""
import json
import os
import subprocess
import sys

HOOK = os.path.join(os.path.dirname(__file__), "..", ".claude", "hooks", "session-write-guard.sh")
HOME = os.path.expanduser("~")
SESSION = f"{HOME}/bounty-agent-sessions/example.com"

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
    ("Write to MCP-owned static-artifacts.jsonl → block",
     {"tool_input": {"file_path": f"{SESSION}/static-artifacts.jsonl", "content": "test"}},
     2),
    ("Write to MCP-owned static-imports artifact → block",
     {"tool_input": {"file_path": f"{SESSION}/static-imports/SA-1.txt", "content": "test"}},
     2),
    ("Write to MCP-owned handoff-w1-a2.json → block",
     {"tool_input": {"file_path": f"{SESSION}/handoff-w1-a2.json", "content": "test"}},
     2),
    ("Write to MCP-owned state.json → block",
     {"tool_input": {"file_path": f"{SESSION}/state.json", "content": "test"}},
     2),
    ("Write to agent-owned report.md → allow",
     {"tool_input": {"file_path": f"{SESSION}/report.md", "content": "test"}},
     0),
    ("Write to agent-owned chains.md → allow",
     {"tool_input": {"file_path": f"{SESSION}/chains.md", "content": "test"}},
     0),
    ("Write to agent-owned attack_surface.json → allow",
     {"tool_input": {"file_path": f"{SESSION}/attack_surface.json", "content": "test"}},
     0),
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
    ("Bash >> to MCP-owned traffic.jsonl → block",
     {"tool_input": {"command": f"cat data >> {SESSION}/traffic.jsonl"}},
     2),
    ("Bash > to MCP-owned static-scan-results.jsonl → block",
     {"tool_input": {"command": f"echo data > {SESSION}/static-scan-results.jsonl"}},
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
    ("Bash no redirects → allow",
     {"tool_input": {"command": "ls -la /tmp"}},
     0),

    # --- Inline script tests ---
    ("python3 -c open() to MCP-owned → block",
     {"tool_input": {"command": f"python3 -c \"open('{SESSION}/brutalist.json','w').write('{{}}')\""}},
     2),
    ("python3 -c open() to agent-owned → allow",
     {"tool_input": {"command": f"python3 -c \"open('{SESSION}/report.md','w').write('test')\""}},
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
    ("pathlib Path().write_text() to agent-owned → allow",
     {"tool_input": {"command": f"python3 -c \"from pathlib import Path; Path('{SESSION}/report.md').write_text('test')\""}},
     0),
    ("open() outside session dir → allow",
     {"tool_input": {"command": "python3 -c \"open('/tmp/test.json','w').write('test')\""}},
     0),
    ("Bash with open() in echo string (not a real write) → allow",
     {"tool_input": {"command": "echo \"open('/tmp/test.json','w')\""}},
     0),
]


def main():
    passed = 0
    failed = 0

    for desc, payload, expected in TESTS:
        result = subprocess.run(
            ["bash", HOOK],
            input=json.dumps(payload),
            capture_output=True,
            text=True,
        )
        ok = result.returncode == expected
        status = "\033[32mPASS\033[0m" if ok else "\033[31mFAIL\033[0m"
        print(f"  {status}: {desc}")
        if not ok:
            print(f"         expected exit {expected}, got {result.returncode}")
            if result.stderr.strip():
                print(f"         stderr: {result.stderr.strip()}")
            failed += 1
        else:
            passed += 1

    print(f"\n  {passed}/{passed + failed} passed")
    return 0 if failed == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
