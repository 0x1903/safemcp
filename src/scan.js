import fs from 'node:fs';
import path from 'node:path';
import { discover } from './discover.js';
import { checkServer, FILE_PERMS_RULE, SEVERITIES } from './rules.js';
import { checkTools } from './toolrules.js';
import { listTools } from './live.js';
import { loadPins, savePins, diffPins } from './pins.js';
import { checkAgentConfig, checkInstructionFile, instructionFiles, findInstructionFiles } from './agentrules.js';

const WEIGHTS = { critical: 25, high: 10, medium: 4, low: 1 };

function summarize(configs) {
  const all = configs.flatMap((c) => [...c.fileFindings, ...c.servers.flatMap((s) => s.findings)]);
  const counts = Object.fromEntries(SEVERITIES.map((sev) => [sev, all.filter((f) => f.severity === sev).length]));
  const penalty = all.reduce((sum, f) => sum + WEIGHTS[f.severity], 0);
  const serverCount = configs.reduce((n, c) => n + c.servers.length, 0);
  return { configs, counts, serverCount, score: Math.max(0, 100 - penalty) };
}

export function scan(opts = {}) {
  // --tools-file on its own analyzes just that file, without auto-discovering local configs
  const onlyToolsFiles = opts.toolsFiles?.length && !opts.files?.length && !opts.dirs?.length;
  const configs = (onlyToolsFiles ? [] : discover(opts)).map((cfg) => {
    const servers = cfg.servers.map((s) => ({ ...s, findings: checkServer(s.name, s.server) }));
    const fileFindings = [];
    const hasSecrets = servers.some((s) => s.findings.some((f) => f.id === 'MCP001' || f.id === 'MCP002'));
    if (hasSecrets && process.platform !== 'win32' && cfg.mode != null && cfg.mode & 0o044) {
      const { id, severity, title, fix } = FILE_PERMS_RULE;
      fileFindings.push({ id, severity, title, message: `Mode ${(cfg.mode & 0o777).toString(8)}`, fix });
    }
    fileFindings.push(...checkAgentConfig(cfg));
    const kind = cfg.client.startsWith('Claude Code settings') ? 'settings' : 'mcp';
    return { ...cfg, kind, servers, fileFindings };
  });
  // Agent instruction files: the project's (or --dir's) and the user's global ones; not with --file alone
  if (!onlyToolsFiles && !(opts.files?.length && !opts.dirs?.length)) {
    const files = opts.dirs?.length ? opts.dirs.flatMap((d) => findInstructionFiles(path.resolve(d))) : instructionFiles(opts.cwd);
    for (const file of files) {
      const fileFindings = checkInstructionFile(file);
      if (fileFindings) configs.push({ client: 'Agent instructions', kind: 'instructions', file, servers: [], fileFindings });
    }
  }
  for (const file of opts.toolsFiles || []) configs.push(toolsFileConfig(file));
  return summarize(configs);
}

// Offline analysis of a saved tools/list response ({ tools: [...] }, { result: { tools } } or a bare array).
function toolsFileConfig(file) {
  const cfg = { client: 'Tools file', file: path.resolve(file), servers: [], fileFindings: [] };
  try {
    const obj = JSON.parse(fs.readFileSync(file, 'utf8'));
    const tools = Array.isArray(obj) ? obj : obj.tools || obj.result?.tools || [];
    const name = path.basename(file, '.json');
    cfg.servers.push({ name, scope: null, server: {}, live: { tools: tools.length }, findings: checkTools(name, tools) });
  } catch (e) {
    cfg.error = `Could not read tools: ${e.message}`;
  }
  return cfg;
}

async function mapLimit(items, limit, fn) {
  const results = new Array(items.length);
  let next = 0;
  const workers = Array.from({ length: Math.min(limit, items.length) }, async () => {
    while (next < items.length) {
      const i = next++;
      results[i] = await fn(items[i]);
    }
  });
  await Promise.all(workers);
  return results;
}

// Connects to every configured server, lists its tools and checks them for poisoning and rug pulls.
export async function addLive(result, { timeoutMs = 20000, pin = true, onProgress } = {}) {
  const targets = result.configs.flatMap((cfg) =>
    cfg.servers.filter((s) => s.server && (s.server.command || s.server.url || s.server.serverUrl || s.server.httpUrl)).map((s) => ({ cfg, s })),
  );
  let done = 0;
  await mapLimit(targets, 4, async ({ s }) => {
    try {
      s.live = await listTools(s.server, { timeoutMs });
    } catch (e) {
      s.live = { error: e.message };
    }
    onProgress?.(++done, targets.length, s.name);
  });

  const allTools = targets.flatMap(({ s }) => (s.live.tools || []).map((t) => ({ server: s.name, name: t.name })));
  const pins = loadPins();
  for (const { cfg, s } of targets) {
    if (!s.live.tools) continue;
    s.findings.push(...checkTools(s.name, s.live.tools, allTools));
    s.findings.push(...diffPins(pins, `${cfg.file}#${s.scope || ''}#${s.name}`, s.live.tools));
    s.live = { tools: s.live.tools.length, serverInfo: s.live.serverInfo };
  }
  if (pin) savePins(pins);
  return summarize(result.configs);
}
