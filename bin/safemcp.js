#!/usr/bin/env node
import { readFileSync } from 'node:fs';
import { scan, addLive } from '../src/scan.js';
import { printReport } from '../src/report.js';
import { SEVERITIES } from '../src/rules.js';
import { planPins, applyPins, checkPins } from '../src/pin.js';
import { tildify } from '../src/discover.js';
import { loadPins, savePins, pendingPins, acceptPins } from '../src/pins.js';

const { version } = JSON.parse(readFileSync(new URL('../package.json', import.meta.url), 'utf8'));

const HELP = `safemcp v${version} — scan MCP server configs for security risks

Usage: safemcp [scan] [options]
       safemcp pin [--write] [--file <path>] [--dir <path>]
       safemcp pin --check [--file <path>] [--dir <path>]
       safemcp accept [<server>...] [--all]

Commands:
  scan (default)         Check MCP servers, agent settings and instruction files
  pin                    Pin unpinned MCP packages (npx/uvx/pnpm dlx/pipx run, git sources) to
                         the exact version that is current now. Shows the plan; add --write to
                         apply it (a .safemcp-bak copy of each changed file is kept).
  pin --check            For pinned packages: is there a newer release, and does it show
                         supply-chain warning signs (new install script, lost provenance,
                         different publisher, very fresh, size jump)? Exits 1 on high signals.
  accept                 After reviewing a TP007/TP008 change from --live, accept the server's
                         new tool definitions as the baseline. Without arguments, lists what
                         is waiting. Until accepted, the change is reported on every --live scan.

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
  const opts = { command: 'scan', servers: [], files: [], dirs: [], toolsFiles: [], json: false, failOn: null, live: false, pin: true, timeout: 20, write: false };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === 'scan' && i === 0) continue;
    else if (a === 'pin' && i === 0) opts.command = 'pin';
    else if (a === '--write') opts.write = true;
    else if (a === 'accept' && i === 0) opts.command = 'accept';
    else if (a === '--all' && opts.command === 'accept') opts.all = true;
    else if (opts.command === 'accept' && !a.startsWith('-')) opts.servers.push(a);
    else if (a === '--check') opts.check = true;
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

if (opts.command === 'pin') {
  await pin(opts);
  process.exit(0);
}
if (opts.command === 'accept') {
  accept(opts);
  process.exit(process.exitCode || 0);
}

function accept({ servers, all, json }) {
  const pins = loadPins();
  const pending = pendingPins(pins);
  if (!servers.length && !all) {
    if (json) console.log(JSON.stringify(pending, null, 2));
    else if (!pending.length) console.log('\nNothing to accept: no tool changes are waiting for review.\n');
    else {
      console.log('\nTool changes waiting for review (see `safemcp --live` for what changed):\n');
      for (const p of pending) console.log(`  ${p.server}: ${p.tools.join(', ')}  (${tildify(p.key.slice(0, p.key.indexOf('#')))})`);
      console.log('\nRun `safemcp accept <server>` for each one you have reviewed, or `safemcp accept --all`.\n');
    }
    return;
  }
  const unknown = servers.filter((s) => !pending.some((p) => p.server === s));
  const accepted = acceptPins(pins, all ? null : servers);
  savePins(pins);
  if (json) console.log(JSON.stringify({ accepted, unknown }, null, 2));
  else {
    console.log();
    for (const a of accepted) console.log(`  \u2713 ${a.server}: accepted ${a.tools.join(', ')}`);
    for (const s of unknown) console.log(`  ${s}: nothing waiting (run \`safemcp accept\` to list)`);
    console.log();
  }
  if (unknown.length) process.exitCode = 1;
}

async function pin({ files, dirs, write, json, check }) {
  const { configs } = scan({ files, dirs });
  if (check) return pinCheck(configs.filter((c) => c.kind === 'mcp'), json);
  const plan = await planPins(configs.filter((c) => c.kind === 'mcp'));
  const written = write ? applyPins(plan) : [];
  if (json) {
    console.log(JSON.stringify({ plan, written }, null, 2));
    return;
  }
  if (!plan.length) {
    console.log('\nAll MCP packages are already pinned. Nothing to do.\n');
    return;
  }
  console.log();
  for (const file of [...new Set(plan.map((p) => p.file))]) {
    console.log(tildify(file));
    for (const p of plan.filter((x) => x.file === file)) {
      const name = p.scope ? `${p.server} (${p.scope})` : p.server;
      console.log(p.to ? `  ${name}: ${p.from}  \u2192  ${p.to}` : `  ${name}: ${p.from}  \u2014 skipped: ${p.error}`);
    }
  }
  const ok = plan.filter((p) => p.to).length;
  console.log();
  if (write) console.log(`Pinned ${ok} package(s) in ${written.length} file(s). Backups: <file>.safemcp-bak. Restart your AI client to apply.`);
  else console.log(`${ok} package(s) can be pinned. Run \`safemcp pin --write\` to apply (backups are kept).`);
  console.log('Pinning freezes today\'s version — review it, and re-run this after updating on purpose.\n');
}

async function pinCheck(configs, json) {
  const results = await checkPins(configs);
  const risky = results.some((r) => r.signals.some((s) => s.severity === 'high'));
  if (json) {
    console.log(JSON.stringify(results, null, 2));
  } else if (!results.length) {
    console.log('\nNo pinned MCP packages found. Run `safemcp pin` first.\n');
  } else {
    console.log();
    const mark = { high: '\u2716', medium: '\u26A0', low: '\u00B7' };
    for (const r of results) {
      const name = r.scope ? `${r.server} (${r.scope})` : r.server;
      if (r.error) console.log(`  ${name}: could not check (${r.error})`);
      else if (!r.latest) console.log(`  \u2713 ${name}: ${r.current} is the latest`);
      else {
        const when = r.released ? ` (released ${r.released.slice(0, 10)})` : '';
        console.log(`  \u2191 ${name}: ${r.current} \u2192 ${r.latest}${when}`);
        for (const s of r.signals) console.log(`      ${mark[s.severity]} ${s.severity.toUpperCase()} ${s.title}: ${s.detail}`);
        if (!r.signals.length) console.log('      no warning signs in the registry metadata');
      }
    }
    console.log();
    const updates = results.filter((r) => r.latest).length;
    if (updates) console.log(`${updates} update(s) available. Review them, then update the pinned version in your config (or re-run \`safemcp pin\` after unpinning).`);
    if (risky) console.log('High-risk signals found: do not update until you have checked what changed.');
    console.log();
  }
  if (risky) process.exitCode = 1;
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
