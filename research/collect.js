#!/usr/bin/env node
// Research: inspect the tool definitions of public remote MCP servers in the official registry.
//
// Ethics: only servers that advertise a public Streamable HTTP endpoint and need no credentials;
// only `initialize` + `tools/list` are sent (never a tool call); requests identify themselves and
// are rate-limited. Raw data stays in research/data/ (gitignored); only aggregates get published.
//
//   node research/collect.js            # fetch registry + tools  → research/data/
//   node research/collect.js --resume   # reuse registry.json, skip endpoints already in results.jsonl
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { listTools } from '../src/live.js';

const here = path.dirname(fileURLToPath(import.meta.url));
const out = path.join(here, 'data');
fs.mkdirSync(out, { recursive: true });

const REGISTRY = 'https://registry.modelcontextprotocol.io/v0/servers';
const UA = 'safemcp-research/0.2 (+https://github.com/0x1903/safemcp)';
const CONCURRENCY = 64;
const PER_HOST = 2; // never more than this many requests in flight to one hostname
const TIMEOUT_MS = 10000;
// Some operators register thousands of generated endpoints on one host; sample them so a single
// operator can't dominate the statistics (and so we don't load their infrastructure).
const MAX_PER_HOST = 25;
const resume = process.argv.includes('--resume');

async function fetchRegistry() {
  const entries = [];
  let cursor;
  do {
    const url = `${REGISTRY}?limit=100${cursor ? `&cursor=${encodeURIComponent(cursor)}` : ''}`;
    const res = await fetch(url, { headers: { 'user-agent': UA } });
    if (!res.ok) throw new Error(`registry HTTP ${res.status}`);
    const page = await res.json();
    entries.push(...page.servers);
    cursor = page.metadata?.nextCursor;
    process.stderr.write(`\rregistry: ${entries.length} entries`);
  } while (cursor);
  process.stderr.write('\n');
  return entries;
}

function publicRemotes(entries) {
  const byUrl = new Map();
  for (const { server, _meta } of entries) {
    const meta = _meta?.['io.modelcontextprotocol.registry/official'] || {};
    if (meta.status !== 'active' || meta.isLatest === false) continue;
    for (const r of server.remotes || []) {
      if (r.type !== 'streamable-http' || !r.url || /[{}]/.test(r.url)) continue;
      if ((r.headers || []).some((h) => h.isRequired)) continue;
      if (!byUrl.has(r.url)) byUrl.set(r.url, { name: server.name, version: server.version, url: r.url });
    }
  }
  return [...byUrl.values()];
}

// Global concurrency limit plus a per-hostname limit, so shared hosts are not hammered.
async function runPolite(items, fn) {
  const queue = [...items];
  const active = new Map();
  let done = 0;
  const host = (u) => new URL(u).hostname;
  const take = () => {
    const i = queue.findIndex((it) => (active.get(host(it.url)) || 0) < PER_HOST);
    return i < 0 ? null : queue.splice(i, 1)[0];
  };
  await Promise.all(
    Array.from({ length: CONCURRENCY }, async () => {
      while (queue.length) {
        const item = take();
        if (!item) {
          await new Promise((r) => setTimeout(r, 200));
          continue;
        }
        const h = host(item.url);
        active.set(h, (active.get(h) || 0) + 1);
        try {
          await fn(item);
        } finally {
          active.set(h, active.get(h) - 1);
        }
        if (++done % 100 === 0) fs.writeFileSync(path.join(out, 'progress.txt'), `${done}/${items.length} ${new Date().toISOString()}\n`);
      }
    }),
  );
}

const registryFile = path.join(out, 'registry.json');
const entries = resume && fs.existsSync(registryFile) ? JSON.parse(fs.readFileSync(registryFile, 'utf8')) : await fetchRegistry();
if (!resume) fs.writeFileSync(registryFile, JSON.stringify(entries));
const remotes = publicRemotes(entries);
console.log(`${entries.length} registry entries → ${remotes.length} public streamable-http endpoints`);

// One JSON line per endpoint, appended as results arrive, so runs can be resumed.
const jsonl = path.join(out, 'results.jsonl');
const read = () => (fs.existsSync(jsonl) ? fs.readFileSync(jsonl, 'utf8').split('\n').filter(Boolean).map((l) => JSON.parse(l)) : []);
if (!resume) fs.rmSync(jsonl, { force: true });
const prior = read();
const seen = new Set(prior.map((r) => r.url));
const perHost = {};
for (const r of prior) perHost[new URL(r.url).hostname] = (perHost[new URL(r.url).hostname] || 0) + 1;
const todo = remotes.filter((r) => {
  if (seen.has(r.url)) return false;
  const h = new URL(r.url).hostname;
  if ((perHost[h] || 0) >= MAX_PER_HOST) return false;
  perHost[h] = (perHost[h] || 0) + 1;
  return true;
});
console.log(`to inspect: ${todo.length}`);

await runPolite(todo, async (r) => {
  const started = Date.now();
  let rec;
  try {
    const { serverInfo, tools } = await listTools({ url: r.url, headers: { 'user-agent': UA } }, { timeoutMs: TIMEOUT_MS });
    rec = { ...r, ok: true, serverInfo, tools, ms: Date.now() - started };
  } catch (e) {
    rec = { ...r, ok: false, error: e.message, ms: Date.now() - started };
  }
  fs.appendFileSync(jsonl, JSON.stringify(rec) + '\n');
});

const results = read();
fs.writeFileSync(path.join(out, 'results.json'), JSON.stringify(results));
const ok = results.filter((r) => r.ok);
console.log(`reachable without auth: ${ok.length}/${results.length}, tools collected: ${ok.reduce((n, r) => n + r.tools.length, 0)}`);
