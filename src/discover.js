import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';

const home = os.homedir();

function userConfigDir() {
  if (process.platform === 'darwin') return path.join(home, 'Library', 'Application Support');
  if (process.platform === 'win32') return process.env.APPDATA || path.join(home, 'AppData', 'Roaming');
  return process.env.XDG_CONFIG_HOME || path.join(home, '.config');
}

// Known MCP config locations per client. Project-level files are resolved against cwd.
export function candidatePaths(cwd = process.cwd()) {
  const cfg = userConfigDir();
  return [
    { client: 'Claude Desktop', file: path.join(cfg, 'Claude', 'claude_desktop_config.json') },
    { client: 'Claude Code', file: path.join(home, '.claude.json') },
    { client: 'Claude Code (project)', file: path.join(cwd, '.mcp.json') },
    { client: 'Cursor', file: path.join(home, '.cursor', 'mcp.json') },
    { client: 'Cursor (project)', file: path.join(cwd, '.cursor', 'mcp.json') },
    { client: 'VS Code', file: path.join(cfg, 'Code', 'User', 'mcp.json') },
    { client: 'VS Code (project)', file: path.join(cwd, '.vscode', 'mcp.json') },
    { client: 'Windsurf', file: path.join(home, '.codeium', 'windsurf', 'mcp_config.json') },
  ];
}

// VS Code configs allow comments and trailing commas.
export function stripJsonc(text) {
  let out = '';
  let inStr = false;
  let i = 0;
  while (i < text.length) {
    const c = text[i];
    const n = text[i + 1];
    if (inStr) {
      out += c;
      if (c === '\\') {
        out += n ?? '';
        i += 2;
        continue;
      }
      if (c === '"') inStr = false;
      i++;
      continue;
    }
    if (c === '"') {
      inStr = true;
      out += c;
      i++;
      continue;
    }
    if (c === '/' && n === '/') {
      while (i < text.length && text[i] !== '\n') i++;
      continue;
    }
    if (c === '/' && n === '*') {
      i += 2;
      while (i < text.length && !(text[i] === '*' && text[i + 1] === '/')) i++;
      i += 2;
      continue;
    }
    out += c;
    i++;
  }
  return out.replace(/,(\s*[}\]])/g, '$1');
}

function serversIn(obj) {
  if (!obj || typeof obj !== 'object') return {};
  // plugin.json may point mcpServers at a separate file path instead of inlining them
  const servers = obj.mcpServers || obj.servers;
  return servers && typeof servers === 'object' && !Array.isArray(servers) ? servers : {};
}

const looksLikeServer = (v) =>
  v && typeof v === 'object' && !Array.isArray(v) && ['command', 'url', 'serverUrl', 'httpUrl'].some((k) => k in v);

const MCP_FILE_NAMES = new Set(['.mcp.json', 'mcp.json', 'mcp_config.json', 'claude_desktop_config.json', 'plugin.json']);
const SKIP_DIRS = new Set(['node_modules', '.git', 'dist', 'build', '.venv', 'venv', '__pycache__']);

// Recursively finds MCP config files under dir.
export function findMcpFiles(dir, maxDepth = 8) {
  const found = [];
  const walk = (d, depth) => {
    let entries;
    try {
      entries = fs.readdirSync(d, { withFileTypes: true });
    } catch {
      return;
    }
    for (const e of entries) {
      const p = path.join(d, e.name);
      if (e.isDirectory() && depth < maxDepth && !SKIP_DIRS.has(e.name)) walk(p, depth + 1);
      else if (e.isFile() && MCP_FILE_NAMES.has(e.name)) found.push(p);
    }
  };
  walk(dir, 0);
  return found.sort();
}

// "…/plugins/github/.mcp.json" → "github"; skips the .claude-plugin folder and hash-like dirs.
function pluginName(file) {
  const parts = path.dirname(file).split(path.sep).filter((s) => s !== '.claude-plugin' && !/^[0-9a-f]{8,}$/.test(s));
  return parts.at(-1);
}

function installedPluginFiles() {
  const roots = ['cache', 'synced'].map((d) => path.join(home, '.claude', 'plugins', d));
  return roots.flatMap((r) => findMcpFiles(r)).map((file) => ({ client: `Claude Code plugin: ${pluginName(file)}`, file }));
}

export function tildify(p) {
  return p.startsWith(home) ? '~' + p.slice(home.length) : p;
}

// Returns { client, file, mode, error?, servers: [{ name, scope, server }] }
export function loadConfig(client, file) {
  const result = { client, file, mode: null, servers: [] };
  let text;
  try {
    result.mode = fs.statSync(file).mode;
    text = fs.readFileSync(file, 'utf8');
  } catch {
    return null;
  }
  let obj;
  try {
    obj = JSON.parse(stripJsonc(text));
  } catch (e) {
    result.error = `Could not parse: ${e.message}`;
    return result;
  }
  let top = serversIn(obj);
  // Plugin .mcp.json files list servers at the top level, without an mcpServers wrapper
  if (!Object.keys(top).length && path.basename(file) === '.mcp.json') {
    top = Object.fromEntries(Object.entries(obj).filter(([, v]) => looksLikeServer(v)));
  }
  for (const [name, server] of Object.entries(top)) {
    result.servers.push({ name, scope: null, server });
  }
  // ~/.claude.json keeps per-project servers under projects[<path>].mcpServers
  if (obj.projects && typeof obj.projects === 'object') {
    for (const [proj, cfg] of Object.entries(obj.projects)) {
      for (const [name, server] of Object.entries(serversIn(cfg))) {
        result.servers.push({ name, scope: tildify(proj), server });
      }
    }
  }
  return result;
}

export function discover({ files, dirs, cwd } = {}) {
  let targets;
  if (files?.length || dirs?.length) {
    targets = [
      ...(files || []).map((f) => ({ client: 'Custom', file: path.resolve(f) })),
      ...(dirs || []).flatMap((d) =>
        findMcpFiles(path.resolve(d)).map((file) => ({ client: pluginName(file), file })),
      ),
    ];
  } else {
    targets = [...candidatePaths(cwd), ...installedPluginFiles()];
  }
  return (
    targets
      .map(({ client, file }) => loadConfig(client, file))
      .filter(Boolean)
      // plugin.json files without inline servers are just noise
      .filter((cfg) => cfg.servers.length || cfg.error || path.basename(cfg.file) !== 'plugin.json')
  );
}
