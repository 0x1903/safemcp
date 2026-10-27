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
