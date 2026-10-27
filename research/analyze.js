#!/usr/bin/env node
// Aggregates research/data/results.json with safemcp's tool rules.
// Writes research/data/findings.md (every finding with context, for manual review — stays local)
// and prints the aggregate numbers that can go into a public report.
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { checkTools, toolStrings } from '../src/toolrules.js';

const data = path.join(path.dirname(fileURLToPath(import.meta.url)), 'data');
const all = JSON.parse(fs.readFileSync(path.join(data, 'results.json'), 'utf8'));
// Same sampling as collect.js: at most 25 endpoints per hostname, so bulk operators don't dominate.
const perHost = {};
const results = all.filter((r) => {
  const h = new URL(r.url).hostname;
  perHost[h] = (perHost[h] || 0) + 1;
  return perHost[h] <= 25;
});
console.log(`collected: ${all.length}, after per-host sampling: ${results.length}, hosts: ${Object.keys(perHost).length}`);
const ok = results.filter((r) => r.ok && Array.isArray(r.tools));
for (const r of ok) r.tools = r.tools.filter((t) => t && typeof t === 'object');

const byRule = {};
const serversByRule = {};
const review = [];
let tools = 0;
let chars = 0;

for (const r of ok) {
  tools += r.tools.length;
  for (const t of r.tools) chars += toolStrings(t).reduce((n, s) => n + s.text.length, 0);
  // Cross-server name matching is skipped here: across a whole registry common tool names collide.
  const findings = checkTools(r.name, r.tools, []);
  for (const f of findings) {
    byRule[f.id] = (byRule[f.id] || 0) + 1;
    (serversByRule[f.id] ||= new Set()).add(r.url);
  }
  if (findings.length) review.push({ r, findings });
}

const pct = (n, d) => `${((100 * n) / d).toFixed(1)}%`;
const flagged = (sev) => review.filter(({ findings }) => findings.some((f) => sev.includes(f.severity))).length;

console.log(`endpoints tried:          ${results.length}`);
console.log(`reachable without auth:   ${ok.length} (${pct(ok.length, results.length)}) on ${new Set(ok.map((r) => new URL(r.url).hostname)).size} hosts`);
console.log(`tools inspected:          ${tools} (avg ${(tools / ok.length).toFixed(1)}/server, ${(chars / 1e6).toFixed(2)}M chars of descriptions)`);
console.log(`servers with any finding: ${review.length} (${pct(review.length, ok.length)})`);
console.log(`  critical/high:          ${flagged(['critical', 'high'])} (${pct(flagged(['critical', 'high']), ok.length)})`);
console.log('by rule (findings / servers):');
for (const id of Object.keys(byRule).sort()) console.log(`  ${id}: ${byRule[id]} / ${serversByRule[id].size}`);

const tools0 = ok.filter((r) => r.tools.length === 0).length;
const big = ok.filter((r) => r.tools.length >= 50).length;
console.log(`servers exposing 0 tools: ${tools0}, ≥50 tools: ${big}`);

// Full context for manual verification — never published as-is.
const md = review
  .map(({ r, findings }) =>
    [
      `## ${r.name} — ${r.url}`,
      ...findings.map((f) => {
        const tool = r.tools.find((t) => f.message.startsWith(`[${t.name}]`));
        return `- **${f.id} ${f.severity}** ${f.message}\n\n  \`\`\`\n  ${(tool?.description || '').slice(0, 1200).replace(/\n/g, '\n  ')}\n  \`\`\``;
      }),
    ].join('\n\n'),
  )
  .join('\n\n');
fs.writeFileSync(path.join(data, 'findings.md'), md);
console.log(`\nreview file: research/data/findings.md (${review.length} servers)`);
