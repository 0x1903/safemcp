#!/usr/bin/env node
// Records a real `safemcp --live` run against examples/demo-config.json as an asciicast,
// then renders it to docs/demo.svg (animated, shown at the top of the README).
//
//   node scripts/demo.js
import { execFileSync } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const root = path.join(path.dirname(fileURLToPath(import.meta.url)), '..');
const command = 'npx safemcp --file demo-config.json --live';

// Fresh pin store so the run looks like a first scan.
const home = fs.mkdtempSync(path.join(os.tmpdir(), 'safemcp-demo-'));
// Private copy (mode 600) so the demo isn't dominated by the file-permission finding.
const config = path.join(home, 'demo-config.json');
fs.copyFileSync(path.join(root, 'examples', 'demo-config.json'), config);
fs.chmodSync(config, 0o600);
const width = 100;
let output;
try {
  output = execFileSync(process.execPath, ['bin/safemcp.js', '--file', config, '--live', '--timeout', '60'], {
    cwd: root,
    env: { ...process.env, FORCE_COLOR: '1', COLUMNS: String(width - 4), SAFEMCP_HOME: home },
    encoding: 'utf8',
  });
} catch (e) {
  output = e.stdout; // non-zero exit is fine, the report is what we want
}
output = output.replace(/\S*demo-config\.json/, '~/demo-config.json');

const lines = output.replace(/\n+$/, '').split('\n');
const events = [];
let t = 0.5;
const emit = (text, delay) => {
  t += delay;
  events.push([Number(t.toFixed(3)), 'o', text]);
};

emit('\x1b[1;32m$\x1b[0m ', 0);
for (const ch of command) emit(ch, 0.045 + Math.random() * 0.04);
emit('\r\n', 0.5);
for (let i = 1; i <= 3; i++) emit(`\r\x1b[2K\x1b[2mconnecting to servers ${i}/3…\x1b[0m`, 0.45);
emit('\r\x1b[2K', 0.4);
for (const line of lines) emit(line + '\r\n', line.trim() ? 0.05 : 0.15);
emit('', 5);

const cast = process.env.DEMO_CAST || path.join(home, 'demo.cast');
const header = { version: 2, width, height: lines.length + 3, env: { TERM: 'xterm-256color' } };
fs.writeFileSync(cast, [header, ...events].map((e) => JSON.stringify(e)).join('\n') + '\n');

fs.mkdirSync(path.join(root, 'docs'), { recursive: true });
execFileSync('npx', ['-y', 'svg-term-cli@2.1.1', '--in', cast, '--out', path.join(root, 'docs', 'demo.svg'), '--window', '--no-cursor', '--padding', '18', '--term', 'xresources', '--profile', 'scripts/demo-theme.Xresources'], {
  cwd: root, // svg-term resolves --profile against cwd, so it must be relative
  stdio: 'inherit',
});
console.log(`wrote docs/demo.svg (${lines.length} lines, ${t.toFixed(1)}s)`);
