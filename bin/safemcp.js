#!/usr/bin/env node
import { readFileSync } from 'node:fs';
import { scan, addLive } from '../src/scan.js';
import { printReport } from '../src/report.js';
import { SEVERITIES } from '../src/rules.js';

const { version } = JSON.parse(readFileSync(new URL('../package.json', import.meta.url), 'utf8'));

const HELP = `safemcp v${version} — scan MCP server configs for security risks

Usage: safemcp [scan] [options]

Options:
  -f, --file <path>      Scan a specific config file (repeatable). Default: auto-detect
                         Claude Desktop, Claude Code (incl. installed plugins), Cursor,
                         VS Code and Windsurf configs.
  -d, --dir <path>       Recursively scan every MCP config under a folder (repeatable)
      --live             Also start/connect to each server, list its tools and check them
                         for tool poisoning, shadowing and rug pulls. This RUNS the
                         configured servers, exactly as your AI client would.
      --tools-file <p>   Check a saved tools/list JSON response offline (repeatable)
      --timeout <sec>    Per-server timeout for --live (default 20)
      --no-pin           Don't record tool fingerprints (~/.safemcp/pins.json) in --live
      --json             Print machine-readable JSON
      --fail-on <sev>    Exit with code 1 if any finding is at or above <sev>
                         (critical | high | medium | low). Useful in CI.
  -h, --help             Show this help
  -v, --version          Show version

Secrets are always masked in output.`;

function parseArgs(argv) {
  const opts = { files: [], dirs: [], toolsFiles: [], json: false, failOn: null, live: false, pin: true, timeout: 20 };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === 'scan') continue;
    else if (a === '-h' || a === '--help') opts.help = true;
    else if (a === '-v' || a === '--version') opts.version = true;
    else if (a === '--json') opts.json = true;
    else if (a === '-f' || a === '--file') opts.files.push(argv[++i]);
    else if (a === '-d' || a === '--dir') opts.dirs.push(argv[++i]);
    else if (a === '--fail-on') opts.failOn = argv[++i];
    else if (a === '--live') opts.live = true;
    else if (a === '--no-pin') opts.pin = false;
    else if (a === '--tools-file') opts.toolsFiles.push(argv[++i]);
    else if (a === '--timeout') opts.timeout = Number(argv[++i]);
    else throw new Error(`Unknown option: ${a}`);
  }
  if (opts.failOn && !SEVERITIES.includes(opts.failOn)) {
    throw new Error(`--fail-on must be one of: ${SEVERITIES.join(', ')}`);
  }
  if (!(opts.timeout > 0)) throw new Error('--timeout must be a positive number of seconds');
  return opts;
}

let opts;
try {
  opts = parseArgs(process.argv.slice(2));
} catch (e) {
  console.error(`${e.message}\n\n${HELP}`);
  process.exit(2);
}

if (opts.help) {
  console.log(HELP);
  process.exit(0);
}
if (opts.version) {
  console.log(version);
  process.exit(0);
}

let result = scan({ files: opts.files, dirs: opts.dirs, toolsFiles: opts.toolsFiles });

if (opts.live) {
  const progress = process.stderr.isTTY && !opts.json;
  result = await addLive(result, {
    timeoutMs: opts.timeout * 1000,
    pin: opts.pin,
    onProgress: progress ? (n, total, name) => process.stderr.write(`\r\x1b[2Kconnecting to servers ${n}/${total} (${name})`) : null,
  });
  if (progress) process.stderr.write('\r\x1b[2K');
}

if (opts.json) {
  // Raw server definitions may contain secrets; JSON output only carries masked findings.
  const configs = result.configs.map(({ client, file, error, fileFindings, servers }) => ({
    client,
    file,
    error,
    fileFindings,
    servers: servers.map(({ name, scope, live, findings }) => ({ name, scope, live, findings })),
  }));
  console.log(JSON.stringify({ ...result, configs }, null, 2));
} else {
  printReport(result, { version });
}

if (opts.failOn) {
  const threshold = SEVERITIES.indexOf(opts.failOn);
  const failed = SEVERITIES.slice(0, threshold + 1).some((sev) => result.counts[sev] > 0);
  process.exit(failed ? 1 : 0);
}
