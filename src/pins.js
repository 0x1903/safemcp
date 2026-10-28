import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';

// Fingerprints of every tool seen in previous --live scans, to detect "rug pulls":
// a server that was reviewed once and later silently changes what its tools tell the model.
//
// pins.json: { "<file>#<scope>#<server>": { server, tools: {name: hash}, defs: {name: def}, pending?: {name: {hash, def}}, seen } }
// `tools`/`defs` are what you accepted. A change goes to `pending` and is reported on every scan
// until `safemcp accept` moves it over, so a warning you missed doesn't silently become the baseline.
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

const toolDef = ({ title, description, inputSchema }) => stable({ title, description, inputSchema });

export function toolHash(tool) {
  const { name, title, description, inputSchema } = tool;
  return crypto.createHash('sha256').update(JSON.stringify(stable({ name, title, description, inputSchema }))).digest('hex').slice(0, 16);
}

export const RUG_PULL = {
  id: 'TP007',
  severity: 'high',
  title: 'Rug pull: tool definition changed since you accepted it',
  fix: 'Review what changed before using this server again. If the change is expected, run `safemcp accept <server>`; until then this is reported on every --live scan.',
};
export const NEW_TOOL = {
  id: 'TP008',
  severity: 'low',
  title: 'New tool appeared since you accepted this server',
  fix: 'Review the new tool, then run `safemcp accept <server>`. Servers can add capabilities without you noticing.',
};

// Invisible and control characters are shown as escapes, so a diff can't hide what was added.
const INVISIBLE = /[\u0000-\u001f\u007f-\u009f\u00ad\u200b-\u200f\u202a-\u202e\u2060-\u2064\ufeff]|\udb40[\udc00-\udc7f]/g;
const show = (s, max = 160) => {
  const t = String(s ?? '').replace(INVISIBLE, (c) => `\\u{${c.codePointAt(0).toString(16)}}`);
  return JSON.stringify(t.length > max ? t.slice(0, max) + '\u2026' : t);
};

// Only the part that differs: common prefix and suffix are cut off.
export function textDiff(a = '', b = '') {
  let p = 0;
  while (p < a.length && p < b.length && a[p] === b[p]) p++;
  let s = 0;
  while (s < a.length - p && s < b.length - p && a[a.length - 1 - s] === b[b.length - 1 - s]) s++;
  const removed = a.slice(p, a.length - s);
  const added = b.slice(p, b.length - s);
  return [removed && `-${show(removed)}`, added && `+${show(added)}`].filter(Boolean).join(' ');
}

function schemaDiff(a = {}, b = {}) {
  const pa = a?.properties || {};
  const pb = b?.properties || {};
  const parts = [];
  for (const k of Object.keys(pb)) if (!(k in pa)) parts.push(`+${k}${pb[k]?.description ? ` ${show(pb[k].description, 100)}` : ''}`);
  for (const k of Object.keys(pa)) if (!(k in pb)) parts.push(`-${k}`);
  for (const k of Object.keys(pb)) {
    if (!(k in pa) || JSON.stringify(pa[k]) === JSON.stringify(pb[k])) continue;
    const d = pa[k]?.description !== pb[k]?.description ? textDiff(pa[k]?.description, pb[k]?.description) : '';
    parts.push(`~${k}${d ? ` ${d}` : ''}`);
  }
  if (parts.length) return `inputs ${parts.join(', ')}`;
  return JSON.stringify(a) === JSON.stringify(b) ? '' : 'input schema changed';
}

function describeChange(before, after) {
  if (!before) return 'description or schema changed (no copy of the old version: pins from safemcp < 0.5 only kept hashes)';
  const parts = [];
  if (before.title !== after.title) parts.push(`title ${show(before.title)} \u2192 ${show(after.title)}`);
  if (before.description !== after.description) parts.push(`description ${textDiff(before.description, after.description)}`);
  const schema = schemaDiff(before.inputSchema, after.inputSchema);
  if (schema) parts.push(schema);
  return parts.join('; ') || 'definition changed';
}

const serverOf = (key, entry) => entry.server || key.slice(key.lastIndexOf('#') + 1);

// Compares tools to what was accepted and records the scan in place. Returns findings.
// The first scan of a server is accepted as the baseline; later changes stay pending until accepted.
export function diffPins(pins, key, tools, server = key.slice(key.lastIndexOf('#') + 1)) {
  const current = Object.fromEntries(tools.filter((t) => t?.name).map((t) => [t.name, { hash: toolHash(t), def: toolDef(t) }]));
  const seen = new Date().toISOString();
  const entry = pins[key];
  if (!entry) {
    pins[key] = { server, tools: {}, defs: {}, seen };
    for (const [name, { hash, def }] of Object.entries(current)) {
      pins[key].tools[name] = hash;
      pins[key].defs[name] = def;
    }
    return [];
  }
  Object.assign(entry, { server, seen });
  entry.defs ||= {};
  entry.pending = {};
  const findings = [];
  for (const [name, { hash, def }] of Object.entries(current)) {
    if (entry.tools[name] === hash) {
      entry.defs[name] ||= def; // older pins kept only hashes
      continue;
    }
    entry.pending[name] = { hash, def };
    findings.push(
      name in entry.tools
        ? { ...RUG_PULL, message: `[${name}] ${describeChange(entry.defs[name], def)}` }
        : { ...NEW_TOOL, message: `[${name}] was not there when you accepted this server` },
    );
  }
  if (!Object.keys(entry.pending).length) delete entry.pending;
  return findings;
}

export const pendingPins = (pins) =>
  Object.entries(pins)
    .filter(([, e]) => e.pending)
    .map(([key, e]) => ({ key, server: serverOf(key, e), tools: Object.keys(e.pending) }));

// Moves pending changes into the accepted baseline. `servers` = names to accept, or null for all.
export function acceptPins(pins, servers = null) {
  const accepted = pendingPins(pins).filter((p) => !servers || servers.includes(p.server));
  for (const { key } of accepted) {
    const entry = pins[key];
    entry.defs ||= {};
    for (const [name, { hash, def }] of Object.entries(entry.pending)) {
      entry.tools[name] = hash;
      entry.defs[name] = def;
    }
    delete entry.pending;
  }
  return accepted;
}
