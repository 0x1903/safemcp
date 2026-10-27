// Prints unique findings per rule for manual review (local only): node research/review.js TP001 [limit]
import fs from 'node:fs';
import { checkTools } from '../src/toolrules.js';

const [id, limit = 60] = process.argv.slice(2);
const all = JSON.parse(fs.readFileSync(new URL('./data/results.json', import.meta.url), 'utf8'));
const perHost = {};
const ok = all.filter((r) => {
  const h = new URL(r.url).hostname;
  perHost[h] = (perHost[h] || 0) + 1;
  return perHost[h] <= 25 && r.ok && Array.isArray(r.tools);
});
const seen = new Set();
let n = 0;
for (const r of ok) {
  const tools = r.tools.filter((t) => t && typeof t === 'object');
  for (const f of checkTools(r.name, tools, [])) {
    if (f.id !== id) continue;
    const key = f.message.replace(/^\[[^\]]*\] /, '').slice(0, 90);
    if (seen.has(key)) continue;
    seen.add(key);
    if (n++ < Number(limit)) console.log(`- ${new URL(r.url).hostname} | ${f.message.slice(0, 200).replace(/\s+/g, ' ')}`);
  }
}
console.log(`(${seen.size} unique)`);
