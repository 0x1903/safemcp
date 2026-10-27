import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { planPins, applyPins, splitNpm, splitPypi, checkPins } from '../src/pin.js';
import { scan } from '../src/scan.js';

// Offline stand-in for npm, PyPI and git.
const fake = {
  npm: async (name, tag) => {
    if (name === 'missing-pkg') throw new Error('not found in registry');
    return tag === 'next' ? '3.0.0-beta.1' : '2.1.0';
  },
  pypi: async () => '0.9.4',
  git: async () => 'a'.repeat(40),
};

test('spec parsing', () => {
  assert.deepEqual(splitNpm('@scope/pkg'), { name: '@scope/pkg', tag: 'latest' });
  assert.deepEqual(splitNpm('@scope/pkg@next'), { name: '@scope/pkg', tag: 'next' });
  assert.deepEqual(splitNpm('pkg@^1.2.0'), { name: 'pkg', range: '^1.2.0' });
  assert.deepEqual(splitPypi('mcp-server-git[cli]'), { name: 'mcp-server-git', extras: '[cli]' });
  assert.deepEqual(splitPypi('pkg>=1.0'), { range: 'pkg>=1.0' });
});

test('pin: plan and apply across JSONC and TOML, keeping comments and formatting', async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'safemcp-pin-'));
  const jsonc = path.join(dir, 'mcp.json');
  fs.writeFileSync(
    jsonc,
    `{
  // my servers
  "servers": {
    "fs":   { "command": "npx", "args": ["-y", "@modelcontextprotocol/server-filesystem", "/tmp/x"] },
    "beta": { "command": "npx", "args": ["thing@next"] },
    "git":  { "command": "uvx", "args": ["mcp-server-git[cli]"] },
    "src":  { "command": "uvx", "args": ["--from", "git+https://github.com/o/r", "r"] },
    "ok":   { "command": "npx", "args": ["already@1.2.3"] },
    "rng":  { "command": "npx", "args": ["ranged@^1.0.0"] },
    "gone": { "command": "npx", "args": ["missing-pkg"] },
  },
}
`,
  );
  const toml = path.join(dir, '.codex', 'config.toml');
  fs.mkdirSync(path.dirname(toml));
  fs.writeFileSync(toml, `# codex\n[mcp_servers.fetch]\ncommand = 'uvx'\nargs = ['mcp-server-fetch']\n`);

  const { configs } = scan({ files: [jsonc, toml] });
  const plan = await planPins(configs, fake);
  assert.deepEqual(
    plan.map((p) => [p.server, p.to || `skip: ${p.error}`]),
    [
      ['fs', '@modelcontextprotocol/server-filesystem@2.1.0'],
      ['beta', 'thing@3.0.0-beta.1'],
      ['git', 'mcp-server-git[cli]==0.9.4'],
      ['src', `git+https://github.com/o/r@${'a'.repeat(40)}`],
      ['rng', 'skip: version range "^1.0.0" — pin it to an exact version yourself'],
      ['gone', 'skip: not found in registry'],
      ['fetch', 'mcp-server-fetch==0.9.4'],
    ],
  );

  const written = applyPins(plan);
  assert.deepEqual(written.sort(), [jsonc, toml].sort());
  const after = fs.readFileSync(jsonc, 'utf8');
  assert.match(after, /\/\/ my servers/);
  assert.match(after, /"ok":   \{ "command": "npx", "args": \["already@1\.2\.3"\] \}/);
  assert.match(after, /"ranged@\^1\.0\.0"/);
  assert.match(fs.readFileSync(toml, 'utf8'), /args = \['mcp-server-fetch==0\.9\.4'\]/);
  assert.ok(fs.existsSync(`${jsonc}.safemcp-bak`));

  // Re-scan: only the two packages we deliberately skipped are still unpinned.
  const unpinned = scan({ files: [jsonc, toml] }).configs.flatMap((c) => c.servers.filter((s) => s.findings.some((f) => f.id === 'MCP003')).map((s) => s.name));
  assert.deepEqual(unpinned.sort(), ['gone', 'rng']);
});

test('pin --check: supply-chain signals from registry metadata', async () => {
  const now = Date.parse('2026-10-27T12:00:00Z');
  const v = (o) => ({ dist: { unpackedSize: 50_000, attestations: { provenance: {} } }, _npmUser: { name: 'ci', trustedPublisher: { id: 'github' } }, ...o });
  const doc = {
    'dist-tags': { latest: '1.1.0' },
    time: { '1.0.0': '2026-09-01T00:00:00Z', '1.1.0': '2026-10-26T20:00:00Z' },
    versions: {
      '1.0.0': v({}),
      '1.1.0': v({
        scripts: { postinstall: 'node collect.js', test: 'x' },
        dist: { unpackedSize: 2_000_000 },
        _npmUser: { name: 'someone-new' },
        dependencies: { 'left-pad': '1' },
      }),
    },
  };
  const reg = { npmDoc: async () => doc, pypiLatest: async () => '0.2.0', pypiRelease: async (n, ver) => ({ requires: ver === '0.2.0' ? ['httpx>=1', 'mcp>=1'] : ['mcp>=1'], upload: '2026-01-01T00:00:00Z', size: 1000 }), git: async () => 'b'.repeat(40) };
  const configs = [
    {
      file: 'x.json',
      servers: [
        { name: 'evil', server: { command: 'npx', args: ['some-mcp@1.0.0'] } },
        { name: 'py', server: { command: 'uvx', args: ['mcp-thing==0.1.0'] } },
        { name: 'git', server: { command: 'uvx', args: ['--from', `git+https://github.com/o/r@${'a'.repeat(40)}`, 'r'] } },
        { name: 'unpinned', server: { command: 'npx', args: ['other-mcp'] } },
      ],
    },
  ];
  const results = await checkPins(configs, reg, now);
  assert.deepEqual(results.map((r) => [r.server, r.current, r.latest, r.signals.map((s) => s.key)]), [
    ['evil', '1.0.0', '1.1.0', ['installScript', 'provenanceDropped', 'publisherChanged', 'fresh', 'sizeJump', 'newDeps']],
    ['py', '0.1.0', '0.2.0', ['newDeps']],
    ['git', 'aaaaaaaaaaaa', 'bbbbbbbbbbbb', []],
  ]);
  assert.match(results[0].signals[0].detail, /postinstall: node collect\.js/);
  // switching *to* trusted publishing is not a warning
  const upgrade = { ...doc, versions: { '1.0.0': v({ _npmUser: { name: 'alice' }, dist: { unpackedSize: 50_000 } }), '1.1.0': v({}) }, time: { ...doc.time, '1.1.0': '2026-10-01T00:00:00Z' } };
  const [r] = await checkPins([{ file: 'x', servers: [configs[0].servers[0]] }], { ...reg, npmDoc: async () => upgrade }, now);
  assert.deepEqual(r.signals, []);
});
