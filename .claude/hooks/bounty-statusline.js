#!/usr/bin/env node
// Bounty status line — model, context bar, active hunt status

const fs = require('fs');
const path = require('path');
const os = require('os');

let input = '';
const stdinTimeout = setTimeout(() => process.exit(0), 3000);
process.stdin.setEncoding('utf8');
process.stdin.on('data', chunk => input += chunk);
process.stdin.on('end', () => {
  clearTimeout(stdinTimeout);
  try {
    const data = JSON.parse(input);
    const model = data.model?.display_name || 'Claude';
    const dir = path.basename(data.workspace?.current_dir || process.cwd());
    const remaining = data.context_window?.remaining_percentage;

    // Context bar
    const AUTO_COMPACT_BUFFER_PCT = 16.5;
    let ctx = '';
    if (remaining != null) {
      const usableRemaining = Math.max(0, ((remaining - AUTO_COMPACT_BUFFER_PCT) / (100 - AUTO_COMPACT_BUFFER_PCT)) * 100);
      const used = Math.max(0, Math.min(100, Math.round(100 - usableRemaining)));
      const filled = Math.floor(used / 10);
      const bar = '█'.repeat(filled) + '░'.repeat(10 - filled);
      if (used < 50) ctx = ` \x1b[32m${bar} ${used}%\x1b[0m`;
      else if (used < 65) ctx = ` \x1b[33m${bar} ${used}%\x1b[0m`;
      else if (used < 80) ctx = ` \x1b[38;5;208m${bar} ${used}%\x1b[0m`;
      else ctx = ` \x1b[5;31m${bar} ${used}%\x1b[0m`;
    }

    // Bounty session status
    let bounty = '';
    const sessDir = path.join(os.homedir(), 'bounty-agent-sessions');
    try {
      const dirs = fs.readdirSync(sessDir)
        .map(d => {
          const f = path.join(sessDir, d, 'state.json');
          try { return { dir: d, mtime: fs.statSync(f).mtimeMs, state: JSON.parse(fs.readFileSync(f, 'utf8')) }; }
          catch { return null; }
        })
        .filter(Boolean)
        .sort((a, b) => b.mtime - a.mtime);

      if (dirs.length > 0) {
        const s = dirs[0].state;
        const phase = s.phase || '?';
        const wave = s.hunt_wave || 0;
        const findings = s.total_findings || 0;
        const target = s.target || dirs[0].dir;

        const waveStr = phase === 'HUNT' ? ` W${wave}` : '';
        const findingsStr = findings > 0 ? ` \x1b[32m${findings}f\x1b[0m` : '';
        bounty = ` │ \x1b[1m${phase}${waveStr}\x1b[0m${findingsStr} │ ${target}`;
      }
    } catch {}

    // Rate limit warning
    let rate = '';
    const fiveHr = data.rate_limits?.five_hour?.used_percentage;
    const sevenDay = data.rate_limits?.seven_day?.used_percentage;
    const worst = Math.max(fiveHr || 0, sevenDay || 0);
    if (worst >= 80) rate = ` \x1b[5;31m⚠ Rate ${Math.round(worst)}%\x1b[0m`;
    else if (worst >= 60) rate = ` \x1b[33m⚠ Rate ${Math.round(worst)}%\x1b[0m`;

    process.stdout.write(`\x1b[2m${model}\x1b[0m │ \x1b[2m${dir}\x1b[0m${bounty}${ctx}${rate}`);
  } catch {}
});
