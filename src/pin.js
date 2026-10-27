// `safemcp pin`: rewrites unpinned MCP server packages (npx/uvx/pnpm dlx/pipx run) to the exact
// version that is current right now, so a later malicious release can't run on your machine.
import { execFile } from 'node:child_process';
import fs from 'node:fs';
import { packageSpec, isPinned } from './rules.js';

// "pkg", "pkg@latest", "@scope/pkg@next" → { name, tag }; ranges like "^1.2" can't be pinned safely.
export function splitNpm(spec) {
  const at = spec.lastIndexOf('@');
  if (at <= 0) return { name: spec, tag: 'latest' };
  const name = spec.slice(0, at);
  const rest = spec.slice(at + 1);
  return /^[a-z][\w.-]*$/i.test(rest) ? { name, tag: rest } : { name, range: rest };
}

// "pkg", "pkg[extra]", "pkg>=1" → { name, extras }; specifiers other than a bare name are left alone.
export function splitPypi(spec) {
  const m = /^([A-Za-z0-9][\w.-]*)(\[[^\]]*\])?$/.exec(spec);
  return m ? { name: m[1], extras: m[2] || '' } : { range: spec };
}

async function getJson(url) {
  const res = await fetch(url, { headers: { accept: 'application/json' }, signal: AbortSignal.timeout(15000) });
  if (res.status === 404) throw new Error('not found in registry');
  if (!res.ok) throw new Error(`registry HTTP ${res.status}`);
  return res.json();
}

function gitHead(url) {
  return new Promise((resolve, reject) => {
    execFile('git', ['ls-remote', url, 'HEAD'], { timeout: 20000 }, (err, stdout) => {
      const sha = stdout?.split(/\s/)[0];
      if (err || !/^[0-9a-f]{40}$/.test(sha || '')) reject(new Error('could not read the repository HEAD'));
      else resolve(sha);
    });
  });
}

// Default resolver: real registries. Tests inject their own.
export const registry = {
  async npm(name, tag) {
    const meta = await getJson(`https://registry.npmjs.org/${name.replace('/', '%2f')}`);
    const version = meta['dist-tags']?.[tag];
    if (!version) throw new Error(`no "${tag}" tag`);
    return version;
  },
  async pypi(name) {
    return (await getJson(`https://pypi.org/pypi/${encodeURIComponent(name)}/json`)).info.version;
  },
  git: gitHead,
};

async function pinnedSpec(eco, spec, resolver) {
  if (spec.startsWith('git+')) {
    const url = spec.slice(4).replace(/@[^/@]*$/, '');
    const sha = await resolver.git(url);
    return `git+${url}@${sha}`;
  }
  if (eco === 'npm') {
    const { name, tag, range } = splitNpm(spec);
    if (range) throw new Error(`version range "${range}" — pin it to an exact version yourself`);
    return `${name}@${await resolver.npm(name, tag)}`;
  }
  const { name, extras, range } = splitPypi(spec);
  if (range) throw new Error(`version specifier in "${range}" — pin it with == yourself`);
  return `${name}${extras}==${await resolver.pypi(name)}`;
}

// Returns [{ file, client, server, from, to?, error? }] for every unpinned package in the scanned configs.
export async function planPins(configs, resolver = registry) {
  const plan = [];
  for (const cfg of configs) {
    for (const s of cfg.servers) {
      const p = packageSpec(s.server || {});
      if (!p || !p.spec || isPinned(p)) continue;
      const item = { file: cfg.file, client: cfg.client, server: s.name, scope: s.scope, from: p.spec };
      try {
        item.to = await pinnedSpec(p.eco, p.spec, resolver);
      } catch (e) {
        item.error = e.message;
      }
      plan.push(item);
    }
  }
  return plan;
}

// Replaces the quoted package string in place, so comments and formatting survive. Writes a backup first.
export function applyPins(plan) {
  const byFile = new Map();
  for (const item of plan.filter((i) => i.to)) byFile.set(item.file, [...(byFile.get(item.file) || []), item]);
  const written = [];
  for (const [file, items] of byFile) {
    const original = fs.readFileSync(file, 'utf8');
    let text = original;
    for (const { from, to } of items) {
      for (const q of ['"', "'"]) {
        const quoted = q + from + q;
        if (text.includes(quoted)) text = text.split(quoted).join(q + to + q);
      }
    }
    if (text === original) continue;
    fs.writeFileSync(`${file}.safemcp-bak`, original, { mode: fs.statSync(file).mode });
    fs.writeFileSync(file, text);
    written.push(file);
  }
  return written;
}

// ---------------------------------------------------------------------------
// `safemcp pin --check`: for pinned packages, is there a newer release, and does it look risky?
// Uses registry metadata only — nothing is downloaded or run.

const LIFECYCLE = ['preinstall', 'install', 'postinstall'];
const DAY = 86400000;

export const CHANGE_SIGNALS = {
  installScript: { severity: 'high', title: 'adds an install script' },
  provenanceDropped: { severity: 'high', title: 'no longer published with provenance' },
  publisherChanged: { severity: 'medium', title: 'published by a different account' },
  fresh: { severity: 'medium', title: 'released less than 3 days ago' },
  sizeJump: { severity: 'medium', title: 'package size grew a lot' },
  newDeps: { severity: 'low', title: 'new dependencies' },
};
const signal = (key, detail) => ({ ...CHANGE_SIGNALS[key], key, detail });

export function npmChangeSignals(doc, from, to, now = Date.now()) {
  const a = doc.versions?.[from] || {};
  const b = doc.versions?.[to] || {};
  const out = [];
  const added = LIFECYCLE.filter((s) => b.scripts?.[s] && !a.scripts?.[s]);
  if (added.length) out.push(signal('installScript', added.map((s) => `${s}: ${String(b.scripts[s]).slice(0, 80)}`).join('; ')));
  if (a.dist?.attestations && !b.dist?.attestations) out.push(signal('provenanceDropped', `${from} had provenance, ${to} does not`));
  const who = (v) => v._npmUser?.name;
  // Moving to trusted publishing (e.g. "GitHub Actions" via OIDC) is an improvement, not a warning sign.
  if (who(a) && who(b) && who(a) !== who(b) && !b._npmUser?.trustedPublisher) out.push(signal('publisherChanged', `${who(a)} → ${who(b)}`));
  const age = now - (Date.parse(doc.time?.[to]) || 0);
  if (age < 3 * DAY) out.push(signal('fresh', `${Math.max(1, Math.round(age / 3600000))}h ago`));
  const [sa, sb] = [a.dist?.unpackedSize, b.dist?.unpackedSize];
  if (sa && sb && sb > sa * 3 && sb - sa > 500_000) out.push(signal('sizeJump', `${Math.round(sa / 1024)} KB → ${Math.round(sb / 1024)} KB`));
  const deps = Object.keys(b.dependencies || {}).filter((d) => !(d in (a.dependencies || {})));
  if (deps.length) out.push(signal('newDeps', deps.slice(0, 8).join(', ')));
  return out;
}

export function pypiChangeSignals(from, to, now = Date.now()) {
  const out = [];
  const age = now - (Date.parse(to.upload) || 0);
  if (age < 3 * DAY) out.push(signal('fresh', `${Math.max(1, Math.round(age / 3600000))}h ago`));
  const name = (r) => r.split(/[\s;<>=!~[(]/)[0].toLowerCase();
  const before = new Set((from.requires || []).map(name));
  const deps = (to.requires || []).map(name).filter((d) => d && !before.has(d));
  if (deps.length) out.push(signal('newDeps', deps.slice(0, 8).join(', ')));
  const [sa, sb] = [from.size, to.size];
  if (sa && sb && sb > sa * 3 && sb - sa > 500_000) out.push(signal('sizeJump', `${Math.round(sa / 1024)} KB → ${Math.round(sb / 1024)} KB`));
  return out;
}

async function pypiRelease(name, version) {
  const j = await getJson(`https://pypi.org/pypi/${encodeURIComponent(name)}/${encodeURIComponent(version)}/json`);
  return { requires: j.info.requires_dist || [], upload: j.urls?.[0]?.upload_time_iso_8601, size: Math.max(0, ...(j.urls || []).map((u) => u.size || 0)) };
}

export const checkRegistry = {
  npmDoc: (name) => getJson(`https://registry.npmjs.org/${name.replace('/', '%2f')}`),
  pypiLatest: registry.pypi,
  pypiRelease,
  git: gitHead,
};

// Returns [{ file, server, spec, current, latest?, signals, error? }] for every pinned package.
export async function checkPins(configs, reg = checkRegistry, now = Date.now()) {
  const results = [];
  for (const cfg of configs) {
    for (const s of cfg.servers) {
      const p = packageSpec(s.server || {});
      if (!p || !p.spec || !isPinned(p)) continue;
      const item = { file: cfg.file, client: cfg.client, server: s.name, scope: s.scope, spec: p.spec, signals: [] };
      try {
        if (p.spec.startsWith('git+')) {
          const [, url, sha] = /^git\+(.+)@([^@/]+)$/.exec(p.spec);
          item.current = sha.slice(0, 12);
          const head = await reg.git(url);
          if (!head.startsWith(sha)) item.latest = head.slice(0, 12);
        } else if (p.eco === 'npm') {
          const at = p.spec.lastIndexOf('@');
          const [name, current] = [p.spec.slice(0, at), p.spec.slice(at + 1)];
          const doc = await reg.npmDoc(name);
          const latest = doc['dist-tags']?.latest;
          item.current = current;
          // Only report releases newer than the pinned one (not e.g. a pin to a newer prerelease).
          const time = (v) => Date.parse(doc.time?.[v]) || 0;
          if (latest && latest !== current && time(latest) > time(current)) {
            item.latest = latest;
            item.released = doc.time?.[latest];
            item.signals = npmChangeSignals(doc, current, latest, now);
          }
        } else {
          const m = /^([A-Za-z0-9][\w.-]*)(?:\[[^\]]*\])?==(.+)$/.exec(p.spec);
          if (!m) throw new Error('unrecognised pin');
          const [, name, current] = m;
          item.current = current;
          const latest = await reg.pypiLatest(name);
          if (latest !== current) {
            const [from, to] = await Promise.all([reg.pypiRelease(name, current), reg.pypiRelease(name, latest)]);
            item.latest = latest;
            item.released = to.upload;
            item.signals = pypiChangeSignals(from, to, now);
          }
        }
      } catch (e) {
        item.error = e.message;
      }
      results.push(item);
    }
  }
  return results;
}
