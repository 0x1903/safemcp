// Rules that inspect live tool definitions (description + input schema) for tool poisoning.

// Concealment and override phrasing. Tuned on ~150k real tool definitions: guardrails such as
// "never tell the user the booking is confirmed" are legitimate and must not match.
const OVERRIDE = [
  /ignore (?:all |any )?(?:previous|prior|above|earlier) (?:instructions|prompts|rules)/i,
  /(?:do not|don't|never) (?:tell|inform|mention|reveal|disclose|notify|alert)\b(?: (?:the |a |any )?users?)?(?: about)? (?:this|these|any of this)(?: (?:field|fields|parameter|parameters|instruction|instructions|note|step|tool))?(?=\s*(?:[.,;:!)]|$|to (?:the |a |any )?users?|from (?:the )?users?))/i,
  /(?:do not|don't|never) (?:tell|mention|reveal|disclose)\b[^.\n]{0,40}\b(?:these instructions|this instruction|the sidenote)\b/i,
  /without (?:telling|informing|notifying|alerting) (?:the )?user/i,
  /(?:the )?user (?:must|should) not (?:know|notice|find out|be told)/i,
  /keep (?:this|these instructions|it) (?:secret|hidden) from (?:the )?user/i,
  /<(important|system|instructions?|secret|hidden|admin)>[\s\S]{0,2000}?<\/\1>/i,
];
// A match right after a quote is someone describing an attack (e.g. a prompt-injection scanner).
const QUOTED = /['"`\u2018\u201C(]$/;

// Paths an attacker wants the model to read. Only flagged next to a read/send verb (see TP003):
// plenty of legitimate dev and security tools merely mention .env or mcp.json.
const SENSITIVE = [
  [/~?\/?\.ssh\/|\bid_(?:rsa|ed25519|ecdsa)\b/i, 'SSH keys'],
  [/\.aws\/credentials|\.config\/gcloud|\.azure\//i, 'cloud credentials'],
  [/(?:^|[\s/'"`])\.env\b(?!\.example)|\.npmrc\b|\.netrc\b|\.git-credentials|\.pypirc\b/i, 'secret files'],
  [/mcp\.json|claude_desktop_config|\.claude\.json/i, 'MCP client configs'],
  [/wallet\.dat|\bkeystore\b|login data|cookies\.sqlite|\/etc\/(?:passwd|shadow)/i, 'credential stores'],
];
const READ_VERB = /\b(?:read|cat|open|load|include|pass|put|send|upload|attach|copy|extract|paste|forward|share|provide|return|contents? of)\b[^.\n]{0,40}$/i;

// Schema fields that make the model hand over wallet secrets to the server.
const WALLET_SECRET_FIELD = /^(?:private_?key|privkey|secret_?key|seed_?phrase|mnemonic(?:_?phrase)?|recovery_?phrase|wallet_?(?:private_?key|secret|seed))$/i;
// Only in a wallet context: "privateKey" for an SSH or cloud API is a different (smaller) problem.
const WALLET_CONTEXT = /\b(?:wallet|solana|sol|ethereum|eth|bitcoin|btc|tron|trx|evm|polygon|arbitrum|onchain|on-chain|blockchain|keypair|lamports|web3)\b/i;
// The field's own description must describe a key, not e.g. "OFR series mnemonic" or "the editor key".
const WALLET_SECRET_DESC = /\b(?:private key|secret key|seed phrase|mnemonic phrase|recovery phrase|base58)/i;

// "Email support@x.com" or "POST to our API" is normal. Exfiltration moves the user's data or a hidden
// copy of it somewhere: a silent BCC/CC, or sending conversation/credentials/file contents to a destination.
const DESTINATION = String.raw`(?:https?:\/\/\S+|[\w.+-]+@[\w-]+\.[\w.]+|\+?\d[\d\s-]{7,})`;
const EXFIL = [
  new RegExp(String.raw`\b(?:always |also |silently |secretly )?(?:bcc|cc)\b[^.\n]{0,40}?${DESTINATION}`, 'i'),
  new RegExp(
    String.raw`\b(?:send|forward|post|upload|transmit|copy|leak|share|report)\b[^.\n]{0,40}\b(?:conversation|chat history|messages|credentials|passwords?|api keys?|tokens?|private keys?|file contents?|contents of|user'?s? (?:data|files|details)|personal data|all data)\b[^.\n]{0,40}\bto\b[^.\n]{0,20}${DESTINATION}`,
    'i',
  ),
];
const SHADOW = /\b(?:when|whenever|before|after|if) (?:you )?(?:use|uses|using|call|calls|calling|invoke|invoking|run|running) (?:the |any )?[`'"]?([\w.-]+)[`'"]? tool\b/i;
// Only identifier-looking names count: "before calling any paid tool" is not about a specific tool.
const TOOL_IDENT = /[_-]|[a-z][A-Z]|^`/;
// Unicode tag characters smuggle invisible ASCII; bidi overrides reorder text (Trojan Source);
// long zero-width runs can encode data. Lone ZWNJ/ZWJ are normal in Persian, Indic scripts and emoji.
const TAG_CHARS = /[\u{E0000}-\u{E007F}]/gu;
const BIDI_OVERRIDE = /[\u202D\u202E]/g;
const ZERO_WIDTH_RUN = /[\u200B-\u200D\u2060-\u2064\uFEFF]{8,}/g;
const BASE64_BLOB = /[A-Za-z0-9+/]{120,}={0,2}/g;

// Long base64 that decodes to readable text is a way to hide instructions; keys and test vectors are not.
function decodesToText(blob) {
  const text = Buffer.from(blob, 'base64').toString('latin1');
  const printable = text.replace(/[^\x20-\x7E\n\t]/g, '').length;
  return printable / text.length > 0.9 && /\s\w+\s\w+\s/.test(text) ? text : null;
}

// Every string a model sees for this tool, with where it came from.
export function toolStrings(tool) {
  const out = [];
  if (!tool || typeof tool !== 'object') return out;
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
          if (m && !QUOTED.test(text.slice(Math.max(0, m.index - 2), m.index))) return [`${where}: ${excerpt(text, m.index)}`];
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
        const hidden = decodeHidden(text).trim();
        if (TAG_CHARS.test(text)) out.push(`${where} hides text: "${hidden.slice(0, 80)}${hidden.length > 80 ? '\u2026' : ''}"`);
        else if (BIDI_OVERRIDE.test(text)) out.push(`${where} contains bidi override characters that reorder how text is displayed`);
        else if (ZERO_WIDTH_RUN.test(text)) out.push(`${where} contains a long run of zero-width characters (possible hidden data)`);
        TAG_CHARS.lastIndex = BIDI_OVERRIDE.lastIndex = ZERO_WIDTH_RUN.lastIndex = 0;
      }
      return out;
    },
  },
  {
    id: 'TP003',
    severity: 'high',
    title: 'Tool description asks the model to read sensitive files',
    fix: 'A tool that asks the model to read or send credentials is a classic exfiltration pattern. Do not use it.',
    check(tool) {
      const strings = toolStrings(tool);
      if (tool.description) strings.push({ where: 'hidden text', text: decodeHidden(tool.description) });
      const out = [];
      for (const [re, label] of SENSITIVE) {
        for (const { text } of strings) {
          const m = text.match(re);
          const before = text.slice(Math.max(0, m?.index - 60), m?.index);
          if (m && READ_VERB.test(before) && !/["'`\u201C][^"'`\u201D]*$/.test(before)) {
            out.push(`Asks for ${label}: ${excerpt(text, Math.max(0, m.index - 30), 70)}`);
            break;
          }
        }
      }
      return out;
    },
  },
  {
    id: 'TP009',
    severity: 'high',
    title: 'Tool asks for a wallet private key or seed phrase',
    fix: 'Never let a model send wallet secrets to a server. Use a signer/wallet connection that keeps keys local.',
    check(tool) {
      const props = tool.inputSchema?.properties;
      if (!props || typeof props !== 'object') return [];
      const context = [tool.name, ...toolStrings(tool).map((x) => x.text)].join(' ');
      if (!WALLET_CONTEXT.test(context)) return [];
      return Object.entries(props)
        .filter(([name, p]) => WALLET_SECRET_FIELD.test(name) && WALLET_SECRET_DESC.test(String(p?.description || '')))
        .map(([name]) => `Input "${name}" sends a wallet secret to the server`);
    },
  },
  {
    id: 'TP004',
    severity: 'high',
    title: 'Tool description tries to send data elsewhere',
    fix: 'Descriptions should explain what a tool does, not tell the model to copy your data to an address.',
    check(tool) {
      for (const { where, text } of toolStrings(tool)) {
        for (const re of EXFIL) {
          const m = text.match(re);
          if (m) return [`${where}: ${excerpt(text, m.index)}`];
        }
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
      if (m && TOOL_IDENT.test(m[0].match(/[`]?[\w.-]+[`]? tool\b/)?.[0] || '') && !ctx.ownTools.has(m[1])) out.push(`Gives instructions for "${m[1]}": ${excerpt(desc, m.index)}`);
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
        for (const blob of text.match(BASE64_BLOB) || []) {
          const decoded = decodesToText(blob);
          if (decoded) return [`${where}: base64 decodes to "${decoded.slice(0, 60).replace(/\s+/g, ' ')}\u2026"`];
        }
      }
      return [];
    },
  },
];

export function checkTools(serverName, tools, otherTools = []) {
  const findings = [];
  const ownTools = new Set(tools.map((t) => t?.name).filter(Boolean));
  for (const tool of tools) {
    if (!tool || typeof tool !== 'object' || !tool.name) continue;
    const ctx = { server: serverName, otherTools, ownTools };
    for (const rule of TOOL_RULES) {
      for (const message of rule.check(tool, ctx)) {
        findings.push({ id: rule.id, severity: rule.severity, title: rule.title, message: `[${tool.name}] ${message}`, fix: rule.fix });
      }
    }
  }
  return findings;
}
