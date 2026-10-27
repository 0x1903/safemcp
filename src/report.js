import { tildify } from './discover.js';

const useColor = process.env.FORCE_COLOR ? process.env.FORCE_COLOR !== '0' : process.stdout.isTTY && !process.env.NO_COLOR;
const paint = (code) => (s) => (useColor ? `\x1b[${code}m${s}\x1b[0m` : String(s));
const c = {
  bold: paint(1),
  dim: paint(2),
  red: paint(31),
  green: paint(32),
  yellow: paint(33),
  blue: paint(34),
  magenta: paint(35),
  cyan: paint(36),
};

const SEV_STYLE = {
  critical: (s) => c.bold(c.magenta(s)),
  high: c.red,
  medium: c.yellow,
  low: c.blue,
};

function badge(sev) {
  return SEV_STYLE[sev](sev.toUpperCase().padEnd(8));
}

const termWidth = () => Math.max(60, process.stdout.columns || Number(process.env.COLUMNS) || 100);

// Word-wraps text to the terminal width, continuing lines at the same indent.
function wrap(text, indent, style = (s) => s) {
  const max = termWidth() - indent.length;
  const lines = [];
  let line = '';
  for (const word of String(text).split(' ')) {
    if (line && line.length + 1 + word.length > max) {
      lines.push(line);
      line = word;
    } else line = line ? `${line} ${word}` : word;
  }
  lines.push(line);
  return lines.map((l) => indent + style(l)).join('\n');
}

// The fix text is the same for every finding of a rule, so it's only printed the first time.
let fixesShown = new Set();

function printFinding(f, indent) {
  const body = indent + ' '.repeat(9);
  console.log(`${indent}${badge(f.severity)} ${c.dim(f.id)} ${c.bold(f.title)}`);
  console.log(wrap(f.message, body));
  if (!fixesShown.has(f.id)) console.log(wrap('Fix: ' + f.fix, body, c.dim));
  fixesShown.add(f.id);
}

export function printReport(result, { version }) {
  const { configs, counts, serverCount, score } = result;
  fixesShown = new Set();
  console.log();
  console.log(`${c.bold('safemcp')} ${c.dim('v' + version)} — MCP security scan`);
  console.log();

  if (!configs.length) {
    console.log('No MCP config files found. Use --file <path> to scan a specific config.');
    return;
  }

  for (const cfg of configs) {
    console.log(`${c.cyan('●')} ${c.bold(cfg.client)}  ${c.dim(tildify(cfg.file))}`);
    if (cfg.error) console.log(`    ${c.yellow(cfg.error)}`);
    for (const f of cfg.fileFindings) printFinding(f, '    ');
    if (!cfg.servers.length && !cfg.error && !cfg.fileFindings.length) {
      const clean = { settings: 'no risky agent settings', instructions: 'no hidden or suspicious instructions' }[cfg.kind];
      console.log(clean ? `    ${c.green('\u2713')} ${c.dim(clean)}` : c.dim('    no MCP servers configured'));
    }
    for (const s of cfg.servers) {
      let label = s.scope ? `${s.name} ${c.dim('(' + s.scope + ')')}` : s.name;
      if (s.live?.error) label += c.dim(`  live: ${s.live.error}`);
      else if (s.live) label += c.dim(`  ${s.live.tools} tool(s) inspected`);
      if (!s.findings.length) {
        console.log(`    ${c.green('✓')} ${label}`);
        continue;
      }
      console.log(`    ${c.red('✗')} ${label}`);
      for (const f of s.findings) printFinding(f, '        ');
    }
    console.log();
  }

  const scoreColor = score >= 80 ? c.green : score >= 50 ? c.yellow : c.red;
  const summary = Object.entries(counts)
    .filter(([, n]) => n)
    .map(([sev, n]) => SEV_STYLE[sev](`${n} ${sev}`))
    .join(', ');
  console.log(
    `${c.bold('Score:')} ${scoreColor(c.bold(score + '/100'))}  ` +
      c.dim(`${configs.length} config file(s), ${serverCount} server(s)`) +
      (summary ? `  ${summary}` : `  ${c.green('no issues found')}`),
  );
  console.log();
}
