import { test } from 'node:test';
import assert from 'node:assert/strict';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { checkServer, isPinned, packageSpec, mask } from '../src/rules.js';
import { scan } from '../src/scan.js';
import { stripJsonc } from '../src/discover.js';

// Built at runtime so secret scanners don't flag this file.
const FAKE_GH = 'ghp' + '_' + 'A'.repeat(36);
const FAKE_OPENAI = 'sk' + '-proj-' + 'b'.repeat(40);

const ids = (server, name = 'test') => checkServer(name, server).map((f) => f.id);

test('MCP001: secret in args', () => {
  assert.ok(ids({ command: 'node', args: ['server.js', '--token', FAKE_GH] }).includes('MCP001'));
});

test('MCP002: hardcoded secret in env, but env references are fine', () => {
  assert.ok(ids({ command: 'node', env: { GITHUB_TOKEN: FAKE_GH } }).includes('MCP002'));
  assert.ok(ids({ command: 'node', env: { MY_API_KEY: 'plainliteralvalue123' } }).includes('MCP002'));
  assert.ok(ids({ url: 'https://x.dev/mcp', headers: { Authorization: 'Bearer ' + FAKE_OPENAI } }).includes('MCP002'));
  assert.ok(!ids({ command: 'node', env: { GITHUB_TOKEN: '${GITHUB_TOKEN}' } }).includes('MCP002'));
  assert.ok(!ids({ command: 'node', env: { API_KEY: '${env:API_KEY}' } }).includes('MCP002'));
  assert.ok(!ids({ command: 'node', env: { LOG_LEVEL: 'debug' } }).includes('MCP002'));
  assert.ok(!ids({ url: 'https://x.dev/mcp', headers: { Authorization: 'Bearer ${CONTEXT7_API_KEY}' } }).includes('MCP002'));
  assert.ok(ids({ url: 'https://x.dev/mcp', headers: { Authorization: 'Bearer abcdef123456789' } }).includes('MCP002'));
});

test('findings never contain the full secret', () => {
  const all = JSON.stringify(checkServer('x', { command: 'npx', args: ['-y', 'a', FAKE_GH], env: { T: FAKE_OPENAI } }));
  assert.ok(!all.includes(FAKE_GH));
  assert.ok(!all.includes(FAKE_OPENAI));
  assert.equal(mask('abcdefgh'), 'abcd… (8 chars)');
});

test('MCP003: package pinning', () => {
  assert.deepEqual(packageSpec({ command: 'npx', args: ['-y', '@scope/pkg@1.2.3'] }), { eco: 'npm', spec: '@scope/pkg@1.2.3' });
  assert.equal(isPinned({ eco: 'npm', spec: '@scope/pkg@1.2.3' }), true);
  assert.equal(isPinned({ eco: 'npm', spec: '@scope/pkg' }), false);
  assert.equal(isPinned({ eco: 'npm', spec: 'pkg@latest' }), false);
  assert.equal(isPinned({ eco: 'npm', spec: 'pkg@^1.0.0' }), false);
  assert.equal(isPinned({ eco: 'pypi', spec: 'mcp-server-git==0.6.2' }), true);
  assert.equal(isPinned({ eco: 'pypi', spec: 'mcp-server-git' }), false);
  assert.equal(isPinned({ eco: 'pypi', spec: 'git+https://github.com/o/r' }), false);
  assert.equal(isPinned({ eco: 'pypi', spec: 'git+https://github.com/o/r@3f2a9c1' }), true);
  assert.equal(isPinned({ eco: 'pypi', spec: 'git+https://github.com/o/r@v0.4.0' }), true);
  assert.ok(ids({ command: 'npx', args: ['-y', '@modelcontextprotocol/server-memory'] }).includes('MCP003'));
  assert.ok(ids({ command: 'uvx', args: ['mcp-server-fetch'] }).includes('MCP003'));
  assert.ok(ids({ command: 'pnpm', args: ['dlx', 'some-mcp'] }).includes('MCP003'));
  assert.ok(!ids({ command: 'npx', args: ['-y', 'some-mcp@0.3.1'] }).includes('MCP003'));
});

test('MCP004: plain http to remote hosts only', () => {
  assert.ok(ids({ url: 'http://mcp.example.com/sse' }).includes('MCP004'));
  assert.ok(ids({ command: 'npx', args: ['mcp-remote@0.1.0', 'http://evil.example/mcp'] }).includes('MCP004'));
  assert.ok(!ids({ url: 'http://localhost:3000/mcp' }).includes('MCP004'));
  assert.ok(!ids({ url: 'http://127.0.0.1:3000/mcp' }).includes('MCP004'));
  assert.ok(!ids({ url: 'http://192.168.0.222:8020/mcp' }).includes('MCP004'));
  assert.ok(!ids({ url: 'http://10.1.2.3/mcp' }).includes('MCP004'));
  assert.ok(!ids({ url: 'http://nas.local:8080/mcp' }).includes('MCP004'));
  assert.ok(ids({ url: 'http://172.32.0.1/mcp' }).includes('MCP004'));
  assert.ok(!ids({ url: 'https://mcp.example.com/mcp' }).includes('MCP004'));
});

test('MCP005: broad filesystem access', () => {
  const fs = (p) => ({ command: 'npx', args: ['-y', '@modelcontextprotocol/server-filesystem@1.0.0', p] });
  assert.ok(ids(fs('/')).includes('MCP005'));
  assert.ok(ids(fs(os.homedir())).includes('MCP005'));
  assert.ok(ids(fs(os.homedir() + '/')).includes('MCP005'));
  assert.ok(ids(fs('~')).includes('MCP005'));
  assert.ok(!ids(fs(path.join(os.homedir(), 'projects', 'app'))).includes('MCP005'));
});

test('MCP006/007: shells and piped scripts', () => {
  const piped = { command: 'bash', args: ['-c', 'curl -fsSL https://x.sh/install | sh'] };
  assert.ok(ids(piped).includes('MCP006'));
  assert.ok(ids(piped).includes('MCP007'));
  assert.ok(ids({ command: '/bin/zsh', args: ['-c', 'source .env && node s.js'] }).includes('MCP007'));
  assert.ok(!ids({ command: 'node', args: ['-c', 'x'] }).includes('MCP007'));
});

test('MCP008: exec-capable servers', () => {
  assert.ok(ids({ command: 'npx', args: ['@wonderwhy-er/desktop-commander@0.2.0'] }, 'dc').includes('MCP008'));
  assert.ok(ids({ command: 'node', args: ['x.js'] }, 'shell').includes('MCP008'));
  assert.ok(!ids({ command: 'node', args: ['x.js'] }, 'github').includes('MCP008'));
});

test('MCP009: docker options', () => {
  const d = (...a) => ({ command: 'docker', args: ['run', '-i', '--rm', ...a, 'img'] });
  assert.ok(ids(d('--privileged')).includes('MCP009'));
  assert.ok(ids(d('--network', 'host')).includes('MCP009'));
  assert.ok(ids(d('-v', '/var/run/docker.sock:/var/run/docker.sock')).includes('MCP009'));
  assert.ok(ids(d('-v', '/:/host')).includes('MCP009'));
  assert.ok(!ids(d('-v', '/Users/me/project:/work')).includes('MCP009'));
  assert.ok(!ids(d('-v', '/:/host')).includes('MCP005'));
});

test('MCP010: look-alike packages', () => {
  assert.ok(ids({ command: 'npx', args: ['modelcontextprotocol-server-github@1.0.0'] }).includes('MCP010'));
  assert.ok(!ids({ command: 'npx', args: ['@modelcontextprotocol/server-github@1.0.0'] }).includes('MCP010'));
});

test('stripJsonc handles comments, trailing commas and slashes inside strings', () => {
  const text = '{\n // c\n "servers": { "a": { "url": "https://x.dev//p", /* b */ }, },\n}';
  assert.deepEqual(JSON.parse(stripJsonc(text)), { servers: { a: { url: 'https://x.dev//p' } } });
});

test('scan() reads plugin-style .mcp.json with top-level servers', () => {
  const dir = path.dirname(fileURLToPath(import.meta.url));
  const r = scan({ dirs: [path.join(dir, 'fixtures', 'plugin')] });
  assert.deepEqual(r.configs[0].servers.map((s) => s.name), ['pw']);
});

test('scan() on fixture files', () => {
  const dir = path.dirname(fileURLToPath(import.meta.url));
  const r = scan({ files: [path.join(dir, 'fixtures', 'vscode.jsonc'), path.join(dir, 'fixtures', 'missing.json')] });
  assert.equal(r.configs.length, 1);
  assert.equal(r.serverCount, 2);
  assert.ok(r.counts.high >= 1);
  assert.ok(r.score < 100);
});
