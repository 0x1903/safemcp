#!/usr/bin/env node
// Research B: sample agent configs committed to public GitHub repos and scan them with safemcp.
//
// Ethics: public files only, fetched through the GitHub API with the user's gh login; secrets found
// are never tested or used; files stay in research/data/github/ (gitignored); only aggregates are
// published, never repo names.
//
//   node research/github-sample.js           # fetch sample → research/data/github/<n>/<original path>
import { execFileSync } from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const out = path.join(path.dirname(fileURLToPath(import.meta.url)), 'data', 'github');
const SAMPLE = [
  { q: 'filename:.mcp.json', n: 35 },
  { q: 'path:.cursor filename:mcp.json', n: 15 },
  { q: 'path:.claude filename:settings.json', n: 25 },
  { q: 'filename:AGENTS.md', n: 25 },
];

const gh = (args) => JSON.parse(execFileSync('gh', ['api', ...args], { encoding: 'utf8', maxBuffer: 64 << 20 }));
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

fs.rmSync(out, { recursive: true, force: true });
fs.mkdirSync(out, { recursive: true });
const index = [];
let n = 0;
for (const { q, n: want } of SAMPLE) {
  // One file per repo, so a single project can't dominate the sample.
  const res = gh(['-X', 'GET', 'search/code', '-f', `q=${q}`, '-f', 'per_page=100']);
  const seen = new Set();
  const items = res.items.filter((it) => !seen.has(it.repository.full_name) && seen.add(it.repository.full_name)).slice(0, want);
  for (const it of items) {
    const blob = gh([`repos/${it.repository.full_name}/git/blobs/${it.sha}`]);
    const file = path.join(out, String(++n), it.path);
    fs.mkdirSync(path.dirname(file), { recursive: true });
    fs.writeFileSync(file, Buffer.from(blob.content, 'base64'));
    index.push({ n, query: q, repo: it.repository.full_name, path: it.path });
  }
  console.log(`${q}: ${items.length} files (of ${res.total_count} matches)`);
  await sleep(7000); // code search allows ~10 requests/minute
}
fs.writeFileSync(path.join(out, '..', 'github-index.json'), JSON.stringify(index, null, 1));
console.log(`saved ${index.length} files`);
