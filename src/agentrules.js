// Agent trust posture: settings that decide how much an AI agent may do without asking you,
// and instruction files (AGENTS.md, CLAUDE.md, .cursorrules…) that every session reads.
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { checkTools } from './toolrules.js';

const home = os.homedir();
const finding = (rule, message) => ({ id: rule.id, severity: rule.severity, title: rule.title, message, fix: rule.fix });
const list = (v) => (Array.isArray(v) ? v.filter((x) => typeof x === 'string') : []);

export const AGENT_RULES = {
  bypass: {
    id: 'AG001',
    severity: 'high',
    title: 'Agent starts with all permission prompts disabled',
    fix: 'Remove defaultMode "bypassPermissions" and use it only per session inside a container or VM.',
  },
  skipBypassPrompt: {
    id: 'AG002',
    severity: 'medium',
    title: 'Bypass-mode warning is switched off',
    fix: 'Remove skipDangerousModePermissionPrompt so entering bypass mode stays a conscious choice.',
  },
  allProjectServers: {
    id: 'AG003',
    severity: 'high',
    title: "Every project's .mcp.json servers are approved automatically",
    fix: 'Remove enableAllProjectMcpServers. Otherwise a cloned repository can start any MCP server it likes on your machine.',
  },
  allShell: {
    id: 'AG004',
    severity: 'high',
    title: 'Agent may run any shell command without asking',
    fix: 'Replace the blanket Bash allow rule with specific commands, e.g. "Bash(npm test)".',
  },
  wholeServer: {
    id: 'AG005',
    severity: 'medium',
    title: 'All tools of an MCP server are pre-approved',
    fix: 'Pre-approve individual read-only tools (mcp__server__tool) instead of the whole server.',
  },
  projectHooks: {
    id: 'AG006',
    severity: 'medium',
    title: 'Repository settings define hooks that run commands',
    fix: 'Review these hooks before trusting the folder: they run shell commands automatically for everyone who opens it.',
  },
  neverAsk: {
    id: 'AG007',
    severity: 'high',
    title: 'Codex never asks before acting',
    fix: 'Use approval_policy = "on-request" so risky actions need your approval.',
  },
  noSandbox: {
    id: 'AG008',
    severity: 'high',
    title: 'Codex sandbox is disabled',
    fix: 'Use sandbox_mode = "workspace-write" (or "read-only"); reserve danger-full-access for disposable VMs.',
  },
  hiddenText: {
    id: 'AG010',
    severity: 'critical',
    title: 'Hidden characters in an agent instruction file',
    fix: 'Instruction files are read by your agent in every session. Invisible text here is the "Rules File Backdoor" attack: inspect the file in a hex viewer and remove it.',
  },
  hiddenInstruction: {
    id: 'AG011',
    severity: 'high',
    title: 'Suspicious instruction in an agent instruction file',
    fix: 'Check who added this. Instructions that hide things from you, read secrets or send data elsewhere do not belong in AGENTS.md / rules files.',
  },
};

function claudeSettings(cfg, raw) {
  const R = AGENT_RULES;
  const out = [];
  const perms = raw.permissions && typeof raw.permissions === 'object' ? raw.permissions : {};
  if (perms.defaultMode === 'bypassPermissions') out.push(finding(R.bypass, 'permissions.defaultMode = "bypassPermissions"'));
  if (raw.skipDangerousModePermissionPrompt === true) out.push(finding(R.skipBypassPrompt, 'skipDangerousModePermissionPrompt = true'));
  if (raw.enableAllProjectMcpServers === true) out.push(finding(R.allProjectServers, 'enableAllProjectMcpServers = true'));
  out.push(...allowRules(list(perms.allow), 'permissions.allow'));
  if (cfg.client === 'Claude Code settings (project)' && raw.hooks && typeof raw.hooks === 'object') {
    const events = Object.keys(raw.hooks);
    if (events.length) out.push(finding(R.projectHooks, `hooks on ${events.join(', ')}`));
  }
  return out;
}

// Claude Code allow rules. Note: allow globs like "mcp__*" or "*" are ignored by Claude Code, so they are not flagged.
function allowRules(rules, where) {
  const out = [];
  if (rules.some((r) => r === 'Bash' || r === 'Bash(*)')) out.push(finding(AGENT_RULES.allShell, `${where} contains "${rules.find((r) => r === 'Bash' || r === 'Bash(*)')}"`));
  // "mcp__server" or "mcp__server__*"; the server segment must be literal for Claude Code to honor it
  const servers = rules.filter((r) => /^mcp__[^*_][^*]*?(__\*)?$/.test(r) && (r.split('__').length === 2 || r.endsWith('__*')));
  if (servers.length) out.push(finding(AGENT_RULES.wholeServer, `${where}: ${servers.slice(0, 5).join(', ')}${servers.length > 5 ? ', …' : ''}`));
  return out;
}

function codexConfig(raw) {
  const out = [];
  const scopes = [['', raw], ...Object.entries(raw.profiles && typeof raw.profiles === 'object' ? raw.profiles : {}).map(([n, p]) => [`profiles.${n}.`, p])];
  for (const [prefix, o] of scopes) {
    if (!o || typeof o !== 'object') continue;
    if (o.approval_policy === 'never') out.push(finding(AGENT_RULES.neverAsk, `${prefix}approval_policy = "never"`));
    if (o.sandbox_mode === 'danger-full-access') out.push(finding(AGENT_RULES.noSandbox, `${prefix}sandbox_mode = "danger-full-access"`));
  }
  // Never asking *and* no sandbox means any instruction the model follows runs with your full user rights.
  const top = out.filter((f) => !f.message.startsWith('profiles.'));
  if (top.length === 2) top.forEach((f) => (f.severity = 'critical'));
  return out;
}

// Per-project state Claude Code keeps in ~/.claude.json (allowedTools from "don't ask again").
function claudeJson(raw) {
  const out = [];
  for (const [proj, p] of Object.entries(raw.projects && typeof raw.projects === 'object' ? raw.projects : {})) {
    const rules = list(p?.allowedTools);
    const short = proj.startsWith(home) ? '~' + proj.slice(home.length) : proj;
    out.push(...allowRules(rules, `${short} allowedTools`));
  }
  return out;
}

export function checkAgentConfig(cfg) {
  const raw = cfg.raw;
  if (!raw || typeof raw !== 'object') return [];
  if (cfg.client.startsWith('Claude Code settings')) return claudeSettings(cfg, raw);
  if (cfg.client.startsWith('Codex')) return codexConfig(raw);
  if (cfg.client === 'Claude Code' && path.basename(cfg.file) === '.claude.json') return claudeJson(raw);
  return [];
}

// ---------------------------------------------------------------------------
// Agent instruction files

const INSTRUCTION_NAMES = new Set([
  'AGENTS.md',
  'CLAUDE.md',
  'CLAUDE.local.md',
  'GEMINI.md',
  '.cursorrules',
  '.windsurfrules',
  '.clinerules',
  'copilot-instructions.md',
]);
const isInstructionFile = (file) => {
  const base = path.basename(file);
  if (INSTRUCTION_NAMES.has(base)) return true;
  const dir = path.dirname(file).split(path.sep).slice(-2).join('/');
  return (/(^|\/)\.cursor\/rules$/.test(dir) && /\.mdc?$/.test(base)) || (/\.github\/instructions$/.test(dir) && base.endsWith('.instructions.md'));
};

export function instructionFiles(cwd = process.cwd()) {
  const fixed = [
    ...['AGENTS.md', 'CLAUDE.md', 'CLAUDE.local.md', 'GEMINI.md', '.cursorrules', '.windsurfrules', '.clinerules'].map((f) => path.join(cwd, f)),
    path.join(cwd, '.github', 'copilot-instructions.md'),
    path.join(home, '.claude', 'CLAUDE.md'),
    path.join(process.env.CODEX_HOME || path.join(home, '.codex'), 'AGENTS.md'),
    path.join(home, '.gemini', 'GEMINI.md'),
  ];
  const listDir = (d, test) => {
    try {
      return fs.readdirSync(d).filter(test).map((f) => path.join(d, f));
    } catch {
      return [];
    }
  };
  return [
    ...fixed,
    ...listDir(path.join(cwd, '.cursor', 'rules'), (f) => /\.mdc?$/.test(f)),
    ...listDir(path.join(cwd, '.github', 'instructions'), (f) => f.endsWith('.instructions.md')),
  ].filter((f) => {
    try {
      return fs.statSync(f).isFile();
    } catch {
      return false;
    }
  });
}

export function findInstructionFiles(dir, maxDepth = 8) {
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
      if (e.isDirectory() && depth < maxDepth && !['node_modules', '.git'].includes(e.name)) walk(p, depth + 1);
      else if (e.isFile() && isInstructionFile(p)) found.push(p);
    }
  };
  walk(dir, 0);
  return found.sort();
}

// Runs the tool-poisoning detectors over an instruction file, as if it were one long tool description.
export function checkInstructionFile(file) {
  let text;
  try {
    text = fs.readFileSync(file, 'utf8').slice(0, 1_000_000);
  } catch {
    return null;
  }
  const findings = checkTools('instructions', [{ name: path.basename(file), description: text }])
    // TP003 is skipped: setup docs legitimately say things like "copy .env.example to .env"
    .filter((f) => ['TP001', 'TP002', 'TP004', 'TP006'].includes(f.id))
    .map((f) => finding(f.id === 'TP002' ? AGENT_RULES.hiddenText : AGENT_RULES.hiddenInstruction, f.message.replace(/^\[[^\]]*\] /, '')));
  return findings;
}
