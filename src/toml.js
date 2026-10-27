// Minimal TOML reader for agent configs (e.g. ~/.codex/config.toml). Supports tables, dotted keys,
// strings (basic/literal, incl. multi-line), numbers, booleans, arrays and inline tables.
// Arrays of tables ([[x]]) are read as arrays. Dates are kept as strings. Not a validator.

export function parseToml(text) {
  const root = {};
  let table = root;
  let i = 0;

  const err = (msg) => {
    const line = text.slice(0, i).split('\n').length;
    throw new Error(`TOML line ${line}: ${msg}`);
  };
  const skipWs = () => {
    while (i < text.length && (text[i] === ' ' || text[i] === '\t')) i++;
  };
  const skipWsNlComments = () => {
    for (;;) {
      skipWs();
      if (text[i] === '#') while (i < text.length && text[i] !== '\n') i++;
      if (text[i] === '\n' || text[i] === '\r') i++;
      else break;
    }
  };

  const readKeyPart = () => {
    skipWs();
    if (text[i] === '"' || text[i] === "'") return readString();
    const m = /^[A-Za-z0-9_-]+/.exec(text.slice(i, i + 200));
    if (!m) err('expected key');
    i += m[0].length;
    return m[0];
  };
  const readKey = () => {
    const parts = [readKeyPart()];
    for (;;) {
      skipWs();
      if (text[i] !== '.') break;
      i++;
      parts.push(readKeyPart());
    }
    return parts;
  };

  function readString() {
    const q = text[i];
    const multi = text.startsWith(q.repeat(3), i);
    i += multi ? 3 : 1;
    if (multi && text[i] === '\n') i++;
    let out = '';
    for (;;) {
      if (i >= text.length) err('unterminated string');
      if (multi ? text.startsWith(q.repeat(3), i) : text[i] === q) {
        i += multi ? 3 : 1;
        return out;
      }
      const c = text[i];
      if (!multi && c === '\n') err('newline in string');
      if (q === '"' && c === '\\') {
        const n = text[i + 1];
        const map = { n: '\n', t: '\t', r: '\r', '"': '"', '\\': '\\', b: '\b', f: '\f' };
        if (n in map) {
          out += map[n];
          i += 2;
        } else if (n === 'u' || n === 'U') {
          const len = n === 'u' ? 4 : 8;
          out += String.fromCodePoint(parseInt(text.slice(i + 2, i + 2 + len), 16));
          i += 2 + len;
        } else if (multi && (n === '\n' || n === ' ' || n === '\r')) {
          i++;
          while (/[\s]/.test(text[i])) i++;
        } else err('bad escape');
        continue;
      }
      out += c;
      i++;
    }
  }

  function readValue() {
    skipWs();
    const c = text[i];
    if (c === '"' || c === "'") return readString();
    if (c === '[') {
      i++;
      const arr = [];
      for (;;) {
        skipWsNlComments();
        if (text[i] === ']') {
          i++;
          return arr;
        }
        arr.push(readValue());
        skipWsNlComments();
        if (text[i] === ',') i++;
        else if (text[i] !== ']') err('expected , or ]');
      }
    }
    if (c === '{') {
      i++;
      const obj = {};
      for (;;) {
        skipWs();
        if (text[i] === '}') {
          i++;
          return obj;
        }
        const key = readKey();
        skipWs();
        if (text[i] !== '=') err('expected =');
        i++;
        setPath(obj, key, readValue());
        skipWs();
        if (text[i] === ',') i++;
      }
    }
    const m = /^[^\s,\]}#]+/.exec(text.slice(i, i + 100));
    if (!m) err('expected value');
    i += m[0].length;
    const raw = m[0];
    if (raw === 'true') return true;
    if (raw === 'false') return false;
    const num = raw.replace(/_/g, '');
    if (/^[+-]?(\d+(\.\d+)?([eE][+-]?\d+)?|inf|nan)$/.test(num)) return Number(num.replace('inf', 'Infinity'));
    if (/^0x[0-9a-fA-F]+$/.test(num)) return parseInt(num, 16);
    return raw; // dates/times
  }

  function setPath(obj, keys, value) {
    let o = obj;
    for (const k of keys.slice(0, -1)) {
      if (o[k] == null) o[k] = {};
      o = o[k];
      if (typeof o !== 'object') err(`key ${k} is not a table`);
    }
    o[keys.at(-1)] = value;
  }

  while (i < text.length) {
    skipWsNlComments();
    if (i >= text.length) break;
    if (text[i] === '[') {
      const isArray = text[i + 1] === '[';
      i += isArray ? 2 : 1;
      const keys = readKey();
      skipWs();
      i += isArray ? 2 : 1;
      let o = root;
      for (const k of keys.slice(0, -1)) {
        if (o[k] == null) o[k] = {};
        o = Array.isArray(o[k]) ? o[k].at(-1) : o[k];
      }
      const last = keys.at(-1);
      if (isArray) {
        if (!Array.isArray(o[last])) o[last] = [];
        o[last].push({});
        table = o[last].at(-1);
      } else {
        if (o[last] == null) o[last] = {};
        table = o[last];
      }
      continue;
    }
    const key = readKey();
    skipWs();
    if (text[i] !== '=') err('expected =');
    i++;
    setPath(table, key, readValue());
    skipWs();
    if (text[i] === '#') while (i < text.length && text[i] !== '\n') i++;
  }
  return root;
}
