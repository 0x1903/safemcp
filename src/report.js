import { tildify } from './discover.js';

const useColor = process.stdout.isTTY && !process.env.NO_COLOR;
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

function printFinding(f, indent) {
  console.log(`${indent}${badge(f.severity)} ${c.dim(f.id)} ${c.bold(f.title)}`);
  console.log(`${indent}${' '.repeat(9)}${f.message}`);
  console.log(`${indent}${' '.repeat(9)}${c.dim('Fix: ' + f.fix)}`);
}

export function printReport(result, { version }) {
  const { configs, counts, serverCount, score } = result;
  console.log();
  console.log(`${c.bold('mcpguard')} ${c.dim('v' + version)} — MCP security scan`);
  console.log();

  if (!configs.length) {
    console.log('No MCP config files found. Use --file <path> to scan a specific config.');
    return;
  }

  for (const cfg of configs) {
    console.log(`${c.cyan('●')} ${c.bold(cfg.client)}  ${c.dim(tildify(cfg.file))}`);
    if (cfg.error) console.log(`    ${c.yellow(cfg.error)}`);
    for (const f of cfg.fileFindings) printFinding(f, '    ');
    if (!cfg.servers.length && !cfg.error) console.log(c.dim('    no MCP servers configured'));
    for (const s of cfg.servers) {
      const label = s.scope ? `${s.name} ${c.dim('(' + s.scope + ')')}` : s.name;
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
