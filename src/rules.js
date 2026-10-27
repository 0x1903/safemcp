import os from 'node:os';
import path from 'node:path';

export const SEVERITIES = ['critical', 'high', 'medium', 'low'];

const SECRET_PATTERNS = [
  [/sk-ant-[A-Za-z0-9_-]{20,}/, 'Anthropic API key'],
  [/sk-(?:proj-)?[A-Za-z0-9_-]{20,}/, 'OpenAI API key'],
  [/gh[pousr]_[A-Za-z0-9]{30,}/, 'GitHub token'],
  [/github_pat_[A-Za-z0-9_]{40,}/, 'GitHub token'],
  [/glpat-[A-Za-z0-9_-]{20,}/, 'GitLab token'],
  [/xox[abprs]-[A-Za-z0-9-]{10,}/, 'Slack token'],
  [/AKIA[0-9A-Z]{16}/, 'AWS access key'],
  [/AIza[0-9A-Za-z_-]{35}/, 'Google API key'],
  [/npm_[A-Za-z0-9]{36}/, 'npm token'],
  [/(?:sk|rk)_live_[A-Za-z0-9]{20,}/, 'Stripe live key'],
  [/-----BEGIN [A-Z ]*PRIVATE KEY-----/, 'Private key'],
  [/:\/\/[^\s:@/]+:[^\s@/]+@/, 'Credentials in URL'],
];
const SECRET_NAME = /(api[_-]?key|token|secret|passw(?:or)?d|private[_-]?key|access[_-]?key|credential|auth)/i;
// Values that reference the environment instead of embedding a secret.
const ENV_REF = /^\$\{?[A-Za-z_][A-Za-z0-9_:]*\}?$|^\$\{(?:env|input):[^}]+\}$/;

export function mask(value) {
  const v = String(value);
  return `${v.slice(0, 4)}… (${v.length} chars)`;
}

function knownSecret(value) {
  const v = String(value);
  for (const [re, label] of SECRET_PATTERNS) {
    const m = v.match(re);
    if (m) return { label, match: m[0] };
  }
  return null;
}

const argsOf = (s) => (Array.isArray(s.args) ? s.args.map(String) : []);
const cmdOf = (s) => path.basename(String(s.command || '')).replace(/\.(cmd|exe)$/i, '');
const urlsOf = (s) => {
  const urls = [s.url, s.serverUrl, s.httpUrl].filter(Boolean).map(String);
  return urls.concat(argsOf(s).filter((a) => /^https?:\/\//i.test(a)));
};

// Resolves the package a runner (npx, uvx, ...) will download and execute.
export function packageSpec(server) {
  const cmd = cmdOf(server);
  let args = argsOf(server);
  let eco;
  if (['npx', 'bunx', 'pnpx'].includes(cmd)) eco = 'npm';
  else if (['pnpm', 'yarn'].includes(cmd) && args[0] === 'dlx') [eco, args] = ['npm', args.slice(1)];
  else if (cmd === 'uvx') eco = 'pypi';
  else if (cmd === 'pipx' && args[0] === 'run') [eco, args] = ['pypi', args.slice(1)];
  else return null;
  for (let i = 0; i < args.length; i++) {
    const a = args[i];
    if (['--package', '-p', '--from'].includes(a)) return { eco, spec: args[i + 1] ?? '' };
    const eq = a.match(/^--(?:package|from)=(.+)$/);
    if (eq) return { eco, spec: eq[1] };
    if (a.startsWith('-')) continue;
    return { eco, spec: a };
  }
  return null;
}

export function isPinned({ eco, spec }) {
  // git sources are only reproducible when pinned to a commit or version tag
  if (spec.startsWith('git+')) return /@(?:[0-9a-f]{7,40}|v?\d+\.\d+[^/]*)$/i.test(spec);
  if (eco === 'npm') {
    const at = spec.lastIndexOf('@');
    if (at <= 0) return false; // no version, or only the @scope prefix
    return /^\d+\.\d+\.\d+/.test(spec.slice(at + 1));
  }
  return /==\d/.test(spec) || /@\d/.test(spec);
}

function isLocalHost(url) {
  try {
    const h = new URL(url).hostname.replace(/^\[|\]$/g, '');
    return ['localhost', '127.0.0.1', '::1', '0.0.0.0'].includes(h) || h.endsWith('.localhost');
  } catch {
    return false;
  }
}

function isBroadPath(arg) {
  const home = os.homedir();
  const s = arg.replace(/[\\/]+$/, '') || '/';
  return (
    ['/', '~', '$HOME', '${HOME}', '%USERPROFILE%'].includes(s) ||
    s === home.replace(/[\\/]+$/, '') ||
    /^[A-Za-z]:$/.test(s)
  );
}

const SHELLS = ['bash', 'sh', 'zsh', 'fish', 'dash', 'powershell', 'pwsh', 'cmd'];
const EXEC_CAPABLE = /(shell|terminal|exec|command|desktop-commander|run-?code|code-?runner|ssh)/i;

export const RULES = [
  {
    id: 'MCP001',
    severity: 'critical',
    title: 'Secret passed as command-line argument',
    fix: 'Move the secret into "env" (referencing an environment variable). Arguments are visible to every process via `ps`.',
    check(s) {
      return argsOf(s)
        .map((a) => knownSecret(a))
        .filter(Boolean)
        .map((hit) => `${hit.label} in args: ${mask(hit.match)}`);
    },
  },
  {
    id: 'MCP002',
    severity: 'high',
    title: 'Hardcoded secret in config',
    fix: 'Reference an environment variable (e.g. "${GITHUB_TOKEN}") or a secret manager instead of pasting the value, then rotate the exposed key.',
    check(s) {
      const out = [];
      const scan = (where, obj) => {
        for (const [k, v] of Object.entries(obj || {})) {
          const val = String(v ?? '');
          if (!val || ENV_REF.test(val.trim())) continue;
          const hit = knownSecret(val);
          if (hit) {
            out.push(`${hit.label} in ${where}.${k}: ${mask(hit.match)}`);
            continue;
          }
          // "Bearer ${TOKEN}" is a reference, not a literal: judge only what's left after removing refs
          const literal = val
            .replace(/\$\{[^}]+\}|\$[A-Za-z_][A-Za-z0-9_]*/g, '')
            .replace(/^(Bearer|Basic|Token)\s+/i, '')
            .trim();
          if (SECRET_NAME.test(k) && literal.length >= 8 && !/\s/.test(literal))
            out.push(`${where}.${k} looks like a literal secret: ${mask(literal)}`);
        }
      };
      scan('env', s.env);
      scan('headers', s.headers);
      for (const u of urlsOf(s)) {
        const hit = knownSecret(u);
        if (hit) out.push(`${hit.label} in URL: ${mask(hit.match)}`);
      }
      return out;
    },
  },
  {
    id: 'MCP003',
    severity: 'medium',
    title: 'Unpinned package version',
    fix: 'Pin an exact version (e.g. "pkg@1.4.2" or "pkg==1.4.2"). Unpinned packages auto-update, so a compromised release runs on your machine on next launch.',
    check(s) {
      const p = packageSpec(s);
      if (!p || !p.spec || isPinned(p)) return [];
      if (p.spec.startsWith('git+')) return [`${p.spec} runs whatever is on the default branch (git)`];
      return [`${p.spec} runs whatever version is latest (${p.eco === 'npm' ? 'npm' : 'PyPI'})`];
    },
  },
  {
    id: 'MCP004',
    severity: 'high',
    title: 'Unencrypted remote connection',
    fix: 'Use https:// for any non-local MCP server. Over http:// tool calls, responses and tokens can be read or modified in transit.',
    check(s) {
      return urlsOf(s)
        .filter((u) => /^http:\/\//i.test(u) && !isLocalHost(u))
        .map((u) => `Plain HTTP to ${new URL(u).host}`);
    },
  },
  {
    id: 'MCP005',
    severity: 'high',
    title: 'Broad filesystem access',
    fix: 'Grant access only to the specific project folders the server needs, never "/" or your whole home directory (SSH keys, browser profiles, wallets live there).',
    check(s) {
      if (cmdOf(s) === 'docker') return [];
      return argsOf(s)
        .filter(isBroadPath)
        .map((a) => `Server is given access to "${a}"`);
    },
  },
  {
    id: 'MCP006',
    severity: 'critical',
    title: 'Remote script piped into a shell',
    fix: 'Never launch a server via `curl ... | sh`. Install a pinned, reviewed version instead.',
    check(s) {
      const line = [s.command, ...argsOf(s)].join(' ');
      return /(curl|wget|iwr|Invoke-WebRequest)[^|]*\|\s*(ba|z)?sh\b|\|\s*iex\b/i.test(line)
        ? ['Downloads and executes a remote script on every launch']
        : [];
    },
  },
  {
    id: 'MCP007',
    severity: 'medium',
    title: 'Launched through a shell',
    fix: 'Call the server binary directly instead of `sh -c "..."`. Shell wrappers hide what actually runs and make injection easier.',
    check(s) {
      const a = argsOf(s);
      return SHELLS.includes(cmdOf(s)) && a.some((x) => ['-c', '/c', '-Command', '-command'].includes(x))
        ? [`${cmdOf(s)} ${a.find((x) => x.startsWith('-') || x.startsWith('/'))} "${(a.at(-1) || '').slice(0, 60)}"`]
        : [];
    },
  },
  {
    id: 'MCP008',
    severity: 'medium',
    title: 'Server can execute arbitrary commands',
    fix: 'Command-execution servers turn any prompt injection into code execution. Enable them only when needed, and require confirmation for every call.',
    check(s, name) {
      const p = packageSpec(s);
      const hay = [name, p?.spec, cmdOf(s)].filter(Boolean).join(' ');
      return EXEC_CAPABLE.test(hay) ? [`"${name}" appears to provide shell/command execution`] : [];
    },
  },
  {
    id: 'MCP009',
    severity: 'high',
    title: 'Dangerous Docker options',
    fix: 'Drop --privileged/host networking and never mount the Docker socket or the host root into an MCP container.',
    check(s) {
      if (cmdOf(s) !== 'docker') return [];
      const a = argsOf(s);
      const line = a.join(' ');
      const out = [];
      if (a.includes('--privileged')) out.push('Runs a --privileged container');
      if (/--net(work)?[= ]host\b/.test(line)) out.push('Uses host networking');
      if (/docker\.sock/.test(line)) out.push('Mounts the Docker socket (full host control)');
      if (/(?:^|\s)(?:-v|--volume|--mount)[= ]\s*(?:type=bind,\s*)?(?:source=|src=)?(\/|~|\$HOME|\$\{HOME\})(?::|,|\s|$)/.test(line))
        out.push('Mounts the host root or home directory');
      return out;
    },
  },
  {
    id: 'MCP010',
    severity: 'high',
    title: 'Possible impersonation of an official package',
    fix: 'Official reference servers are published under the @modelcontextprotocol scope. Verify the publisher before running look-alike packages.',
    check(s) {
      const p = packageSpec(s);
      if (!p || p.eco !== 'npm') return [];
      const name = p.spec.replace(/@[^@/]*$/, '');
      return /model-?context-?protocol/i.test(name) && !name.startsWith('@modelcontextprotocol/')
        ? [`"${name}" mimics the official @modelcontextprotocol scope`]
        : [];
    },
  },
];

// File-level check, run once per config file after server rules.
export const FILE_PERMS_RULE = {
  id: 'MCP011',
  severity: 'medium',
  title: 'Config with secrets is readable by other users',
  fix: 'Restrict the file to your user: chmod 600 <file>',
};

export function checkServer(name, server) {
  if (!server || typeof server !== 'object') return [];
  const findings = [];
  for (const rule of RULES) {
    for (const message of rule.check(server, name)) {
      findings.push({ id: rule.id, severity: rule.severity, title: rule.title, message, fix: rule.fix });
    }
  }
  return findings;
}
