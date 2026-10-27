// Rules that inspect live tool definitions (description + input schema) for tool poisoning.

const OVERRIDE = [
  /ignore (?:all |any )?(?:previous|prior|above|earlier|other) (?:instructions|prompts|rules)/i,
  /(?:do not|don't|never) (?:tell|inform|mention|reveal|notify|show|alert)\b[^.]{0,30}\buser/i,
  /without (?:telling|informing|notifying|alerting|asking) (?:the )?user/i,
  /(?:the )?user (?:must|should|will) not (?:know|see|notice|be told)/i,
  /<\s*\/?\s*(?:important|system|instructions?|secret|hidden|admin)\s*>/i,
  /\b(?:this is|these are) (?:very )?(?:important|critical) (?:instructions|steps)\b/i,
  /\bbefore (?:using|calling|running) (?:this|any) tool,? (?:you )?(?:must|should|first)\b/i,
  /\b(?:otherwise|or else) the (?:tool|application|system) will (?:crash|fail|break)/i,
];

const SENSITIVE = [
  [/~?\/?\.ssh\b|\bid_(?:rsa|ed25519|ecdsa)\b/i, 'SSH keys'],
  [/\.aws\/credentials|\.config\/gcloud|\.azure\//i, 'cloud credentials'],
  [/(?:^|[\s/'"`])\.env\b|\.npmrc\b|\.netrc\b|\.git-credentials|\.pypirc\b/i, 'secret files'],
  [/mcp\.json|claude_desktop_config|\.cursor\/|\.claude\.json/i, 'MCP client configs'],
  [/\bseed phrase\b|\bmnemonic\b|wallet\.dat|\bprivate key\b|keystore/i, 'wallet keys'],
  [/\bkeychain\b|login data|cookies\.sqlite|\/etc\/(?:passwd|shadow)/i, 'system credential stores'],
];

const EXFIL = /\b(?:send|forward|post|upload|transmit|copy|bcc|cc|email|leak)\b[^.\n]{0,60}\b(?:to|at)\b[^.\n]{0,30}(?:https?:\/\/\S+|[\w.+-]+@[\w-]+\.[\w.]+|\+?\d[\d\s-]{7,})/i;
const SHADOW = /\b(?:when|whenever|before|after|if) (?:you )?(?:use|uses|using|call|calls|calling|invoke|invoking|run|running) (?:the |any )?[`'"]?([\w.-]+)[`'"]? tool\b/i;
const INVISIBLE = /[​-‏‪-‮⁠-⁤⁦-⁩﻿]|[\u{E0000}-\u{E007F}]/gu;
const BASE64_BLOB = /[A-Za-z0-9+/]{120,}={0,2}/;

// Every string a model sees for this tool, with where it came from.
export function toolStrings(tool) {
  const out = [];
  const add = (where, v) => typeof v === 'string' && v && out.push({ where, text: v });
  add('description', tool.description);
  add('title', tool.title);
  const walk = (node, at) => {
    if (!node || typeof node !== 'object') return;
    if (Array.isArray(node)) return node.forEach((n, i) => walk(n, `${at}[${i}]`));
    for (const [k, v] of Object.entries(node)) {
      const p = at ? `${at}.${k}` : k;
      if (typeof v === 'string' && ['description', 'title', 'default', 'examples', 'const'].includes(k)) add(`schema ${p}`, v);
      else if (k === 'enum' && Array.isArray(v)) v.forEach((e, i) => add(`schema ${p}[${i}]`, e));
      else walk(v, p);
    }
  };
  walk(tool.inputSchema, '');
  return out;
}

const excerpt = (text, index, len = 70) => {
  const start = Math.max(0, index - 10);
  const s = text.slice(start, start + len).replace(/\s+/g, ' ').trim();
  return `"${start > 0 ? '…' : ''}${s}${start + len < text.length ? '…' : ''}"`;
};

// Unicode tag characters (U+E0020–E007E) mirror ASCII and are a known way to smuggle invisible text.
export function decodeHidden(text) {
  return [...text]
    .map((ch) => {
      const cp = ch.codePointAt(0);
      return cp >= 0xe0020 && cp <= 0xe007e ? String.fromCharCode(cp - 0xe0000) : '';
    })
    .join('');
}

export const TOOL_RULES = [
  {
    id: 'TP001',
    severity: 'critical',
    title: 'Tool poisoning: hidden instructions to the model',
    fix: 'Remove this server. Tool descriptions are injected into the model prompt — instructions here can make your agent act against you.',
    check(tool) {
      for (const { where, text } of toolStrings(tool)) {
        for (const re of OVERRIDE) {
          const m = text.match(re);
          if (m) return [`${where}: ${excerpt(text, m.index)}`];
        }
      }
      return [];
    },
  },
  {
    id: 'TP002',
    severity: 'critical',
    title: 'Invisible characters in tool definition',
    fix: 'Legitimate tools have no reason to hide text from humans. Treat this server as malicious.',
    check(tool) {
      const out = [];
      for (const { where, text } of toolStrings(tool)) {
        const hits = text.match(INVISIBLE);
        if (!hits) continue;
        const hidden = decodeHidden(text).trim();
        out.push(
          hidden
            ? `${where} hides text: "${hidden.slice(0, 80)}${hidden.length > 80 ? '…' : ''}"`
            : `${where} contains ${hits.length} invisible character(s)`,
        );
      }
      return out;
    },
  },
  {
    id: 'TP003',
    severity: 'high',
    title: 'Tool description references sensitive files',
    fix: 'A tool that asks the model to read credentials is a classic exfiltration pattern. Verify why it needs them.',
    check(tool) {
      const text = toolStrings(tool).map((s) => s.text).join('\n') + '\n' + decodeHidden(tool.description || '');
      return SENSITIVE.filter(([re]) => re.test(text)).map(([re, label]) => {
        const m = text.match(re);
        return `Mentions ${label}: ${excerpt(text, m.index, 50)}`;
      });
    },
  },
  {
    id: 'TP004',
    severity: 'high',
    title: 'Tool description tries to send data elsewhere',
    fix: 'Descriptions should explain what a tool does, not tell the model where to send data.',
    check(tool) {
      for (const { where, text } of toolStrings(tool)) {
        const m = text.match(EXFIL);
        if (m) return [`${where}: ${excerpt(text, m.index)}`];
      }
      return [];
    },
  },
  {
    id: 'TP005',
    severity: 'high',
    title: 'Tool shadowing: description changes how another tool behaves',
    fix: 'A tool should never instruct the model about other tools. This lets one server hijack another (e.g. your email or payments server).',
    check(tool, ctx) {
      const out = [];
      const desc = tool.description || '';
      const m = desc.match(SHADOW);
      if (m && m[1] !== tool.name && !['this', 'that', 'any', 'a', 'the', 'your', 'my', 'our'].includes(m[1].toLowerCase())) out.push(`Gives instructions for "${m[1]}": ${excerpt(desc, m.index)}`);
      for (const other of ctx.otherTools) {
        if (other.server === ctx.server || other.name.length < 5 || !/[_-]/.test(other.name)) continue;
        if (new RegExp(`\\b${other.name.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}\\b`).test(desc))
          out.push(`Mentions "${other.name}" from server "${other.server}"`);
      }
      return out;
    },
  },
  {
    id: 'TP006',
    severity: 'medium',
    title: 'Encoded blob in tool description',
    fix: 'Long base64-like strings in descriptions can hide payloads from human review. Decode and inspect it.',
    check(tool) {
      for (const { where, text } of toolStrings(tool)) {
        const m = text.match(BASE64_BLOB);
        if (m) return [`${where}: ${m[0].length}-char encoded string`];
      }
      return [];
    },
  },
];

export function checkTools(serverName, tools, otherTools = []) {
  const findings = [];
  for (const tool of tools) {
    if (!tool || typeof tool !== 'object' || !tool.name) continue;
    const ctx = { server: serverName, otherTools };
    for (const rule of TOOL_RULES) {
      for (const message of rule.check(tool, ctx)) {
        findings.push({ id: rule.id, severity: rule.severity, title: rule.title, message: `[${tool.name}] ${message}`, fix: rule.fix });
      }
    }
  }
  return findings;
}
