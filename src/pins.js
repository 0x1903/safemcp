import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';

// Fingerprints of every tool seen in previous --live scans, to detect "rug pulls":
// a server that was reviewed once and later silently changes what its tools tell the model.
const pinFile = () => path.join(process.env.SAFEMCP_HOME || path.join(os.homedir(), '.safemcp'), 'pins.json');

export function loadPins() {
  try {
    return JSON.parse(fs.readFileSync(pinFile(), 'utf8'));
  } catch {
    return {};
  }
}

export function savePins(pins) {
  const file = pinFile();
  fs.mkdirSync(path.dirname(file), { recursive: true, mode: 0o700 });
  fs.writeFileSync(file, JSON.stringify(pins, null, 2) + '\n', { mode: 0o600 });
}

const stable = (v) =>
  Array.isArray(v)
    ? v.map(stable)
    : v && typeof v === 'object'
      ? Object.fromEntries(Object.keys(v).sort().map((k) => [k, stable(v[k])]))
      : v;

export function toolHash(tool) {
  const { name, title, description, inputSchema } = tool;
  return crypto.createHash('sha256').update(JSON.stringify(stable({ name, title, description, inputSchema }))).digest('hex').slice(0, 16);
}

export const RUG_PULL = {
  id: 'TP007',
  severity: 'high',
  title: 'Rug pull: tool definition changed since last scan',
  fix: 'Review what changed before using this server again. If the change is expected, re-run with --live to accept it.',
};
export const NEW_TOOL = {
  id: 'TP008',
  severity: 'low',
  title: 'New tool appeared since last scan',
  fix: 'Review the new tool. Servers can add capabilities without you noticing.',
};

// Compares tools to their pins and updates pins in place. Returns findings.
export function diffPins(pins, key, tools) {
  const prev = pins[key]?.tools;
  const next = Object.fromEntries(tools.filter((t) => t?.name).map((t) => [t.name, toolHash(t)]));
  pins[key] = { tools: next, seen: new Date().toISOString() };
  if (!prev) return [];
  const findings = [];
  for (const [name, hash] of Object.entries(next)) {
    const rule = !(name in prev) ? NEW_TOOL : prev[name] !== hash ? RUG_PULL : null;
    if (!rule) continue;
    const message = rule === RUG_PULL ? `[${name}] description or schema changed` : `[${name}] was not there last time`;
    findings.push({ ...rule, message });
  }
  return findings;
}
