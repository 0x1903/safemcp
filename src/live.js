import { spawn } from 'node:child_process';

const PROTOCOL_VERSION = '2025-06-18';
const CLIENT_INFO = { name: 'safemcp', version: '0' };

// Clients expand ${VAR} in configs; do the same so servers start like they would there.
function expand(value) {
  return String(value).replace(/\$\{(?:env:)?([A-Za-z_][A-Za-z0-9_]*)\}/g, (_, k) => process.env[k] ?? '');
}
const expandAll = (obj) => Object.fromEntries(Object.entries(obj || {}).map(([k, v]) => [k, expand(v)]));

const initialize = (id) => ({
  jsonrpc: '2.0',
  id,
  method: 'initialize',
  params: { protocolVersion: PROTOCOL_VERSION, capabilities: {}, clientInfo: CLIENT_INFO },
});
const initialized = { jsonrpc: '2.0', method: 'notifications/initialized' };
const toolsList = (id, cursor) => ({ jsonrpc: '2.0', id, method: 'tools/list', params: cursor ? { cursor } : {} });

// Drives the initialize → tools/list handshake over any request/response transport.
async function handshake(request, notify) {
  const init = await request(initialize(1));
  if (init.error) throw new Error(`initialize failed: ${init.error.message}`);
  await notify(initialized);
  const tools = [];
  let cursor;
  for (let id = 2; id < 50; id++) {
    const res = await request(toolsList(id, cursor));
    if (res.error) throw new Error(`tools/list failed: ${res.error.message}`);
    tools.push(...(res.result?.tools || []));
    cursor = res.result?.nextCursor;
    if (!cursor) break;
  }
  return { serverInfo: init.result?.serverInfo, tools };
}

function withTimeout(promise, ms, onTimeout) {
  let timer;
  return Promise.race([
    promise,
    new Promise((_, reject) => {
      timer = setTimeout(() => {
        onTimeout?.();
        reject(new Error(`timed out after ${ms / 1000}s`));
      }, ms);
    }),
  ]).finally(() => clearTimeout(timer));
}

function listToolsStdio(server, timeoutMs) {
  const isWin = process.platform === 'win32';
  const command = expand(server.command);
  // npx etc. are .cmd shims on Windows and need cmd.exe, which re-splits arguments, so quote them there
  const useShell = isWin && !/\.exe$/i.test(command);
  const quote = (a) => (/[\s"&|<>^()]/.test(a) ? `"${a.replace(/"/g, '\\"')}"` : a);
  const args = (server.args || []).map(expand).map((a) => (useShell ? quote(a) : a));
  const child = spawn(useShell ? quote(command) : command, args, {
    env: { ...process.env, ...expandAll(server.env) },
    cwd: server.cwd,
    stdio: ['pipe', 'pipe', 'pipe'],
    shell: useShell,
    // elsewhere use a process group so the whole tree can be killed
    detached: !isWin,
  });
  const kill = () => {
    try {
      if (isWin) spawn('taskkill', ['/pid', String(child.pid), '/T', '/F'], { stdio: 'ignore' });
      else process.kill(-child.pid, 'SIGKILL');
    } catch {
      // already exited
    }
  };

  const pending = new Map();
  let buf = '';
  let stderr = '';
  let exitError = null;
  const failAll = (err) => {
    exitError = err;
    for (const { reject } of pending.values()) reject(err);
    pending.clear();
  };
  child.stdout.on('data', (chunk) => {
    buf += chunk;
    let nl;
    while ((nl = buf.indexOf('\n')) >= 0) {
      const line = buf.slice(0, nl).trim();
      buf = buf.slice(nl + 1);
      if (!line) continue;
      let msg;
      try {
        msg = JSON.parse(line);
      } catch {
        continue; // servers sometimes log to stdout
      }
      if (msg.id != null && pending.has(msg.id)) {
        pending.get(msg.id).resolve(msg);
        pending.delete(msg.id);
      }
    }
  });
  child.stderr.on('data', (chunk) => {
    stderr = (stderr + chunk).slice(-2000);
  });
  child.on('error', (e) => failAll(new Error(`could not start: ${e.message}`)));
  child.on('exit', (code) => {
    const tail = stderr.trim().split('\n').at(-1) || '';
    failAll(new Error(`server exited (code ${code})${tail ? ': ' + tail.slice(0, 160) : ''}`));
  });
  child.stdin.on('error', () => {});

  const write = (msg) => child.stdin.write(JSON.stringify(msg) + '\n');
  const request = (msg) =>
    new Promise((resolve, reject) => {
      if (exitError) return reject(exitError);
      pending.set(msg.id, { resolve, reject });
      write(msg);
    });
  const notify = async (msg) => write(msg);

  return withTimeout(handshake(request, notify), timeoutMs, kill).finally(kill);
}

// Reads a JSON-RPC response from either a JSON body or an SSE stream (Streamable HTTP transport).
async function readResponse(res, id) {
  const type = res.headers.get('content-type') || '';
  if (!type.includes('text/event-stream')) return res.json();
  const reader = res.body.getReader();
  const decoder = new TextDecoder();
  let buf = '';
  try {
    for (;;) {
      const { value, done } = await reader.read();
      if (done) break;
      buf += decoder.decode(value, { stream: true });
      let sep;
      while ((sep = buf.search(/\r?\n\r?\n/)) >= 0) {
        const event = buf.slice(0, sep);
        buf = buf.slice(sep).replace(/^\r?\n\r?\n/, '');
        const data = event
          .split(/\r?\n/)
          .filter((l) => l.startsWith('data:'))
          .map((l) => l.slice(5).trimStart())
          .join('\n');
        if (!data) continue;
        try {
          const msg = JSON.parse(data);
          if (msg.id === id) return msg;
        } catch {
          // ignore non-JSON events
        }
      }
    }
  } finally {
    reader.cancel().catch(() => {});
  }
  throw new Error('stream ended without a response');
}

function listToolsHttp(server, timeoutMs) {
  const url = expand(server.url || server.serverUrl || server.httpUrl);
  const headers = expandAll(server.headers);
  const controller = new AbortController();
  let sessionId;

  const post = async (msg) => {
    const res = await fetch(url, {
      method: 'POST',
      headers: {
        'content-type': 'application/json',
        accept: 'application/json, text/event-stream',
        'mcp-protocol-version': PROTOCOL_VERSION,
        ...(sessionId ? { 'mcp-session-id': sessionId } : {}),
        ...headers,
      },
      body: JSON.stringify(msg),
      signal: controller.signal,
    });
    if (res.status === 401 || res.status === 403) throw new Error('requires authentication (OAuth) — skipped');
    if (!res.ok && res.status !== 202) throw new Error(`HTTP ${res.status}`);
    sessionId = res.headers.get('mcp-session-id') || sessionId;
    return res;
  };
  const request = async (msg) => readResponse(await post(msg), msg.id);
  const notify = async (msg) => {
    const res = await post(msg);
    await res.body?.cancel();
  };

  return withTimeout(
    handshake(request, notify).catch((e) => {
      throw new Error(e.cause?.code === 'ENOTFOUND' ? `host not found: ${new URL(url).host}` : e.message);
    }),
    timeoutMs,
    () => controller.abort(),
  ).finally(() => controller.abort());
}

export async function listTools(server, { timeoutMs = 20000 } = {}) {
  if (server.command) return listToolsStdio(server, timeoutMs);
  if (server.url || server.serverUrl || server.httpUrl) {
    if (server.type === 'sse') throw new Error('legacy SSE transport is not supported yet — skipped');
    return listToolsHttp(server, timeoutMs);
  }
  throw new Error('no command or url to connect to');
}
