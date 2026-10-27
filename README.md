# mcpguard

[![test](https://github.com/0x1903/mcpguard/actions/workflows/test.yml/badge.svg)](https://github.com/0x1903/mcpguard/actions/workflows/test.yml) [![npm](https://img.shields.io/npm/v/mcpguard)](https://www.npmjs.com/package/mcpguard) [![license](https://img.shields.io/badge/license-MIT-blue)](LICENSE)

**Is your AI agent setup safe?** One command scans every MCP server you've connected to Claude, Cursor, VS Code or Windsurf and tells you what could go wrong.

```bash
npx mcpguard
```

Runs locally, needs no account, sends nothing anywhere. Secrets are always masked in the output.

```
● Claude Desktop  ~/Library/Application Support/Claude/claude_desktop_config.json
    ✗ filesystem
        HIGH     MCP005 Broad filesystem access
                 Server is given access to "/Users/me"
                 Fix: Grant access only to the specific project folders the server needs…
    ✗ github
        HIGH     MCP002 Hardcoded secret in config
                 GitHub token in env.GITHUB_TOKEN: ghp_… (40 chars)
    ✓ memory

Score: 74/100  1 config file(s), 3 server(s)  2 high, 1 medium
```

## What it finds

| ID | Severity | Check |
|---|---|---|
| MCP001 | critical | Secret passed as a command-line argument (visible to every process) |
| MCP002 | high | Hardcoded API keys/tokens in `env`, `headers` or URLs |
| MCP003 | medium | Unpinned packages (`npx pkg`, `uvx pkg`, `@latest`, git branches) — a compromised release runs on next launch |
| MCP004 | high | Plain `http://` to a remote MCP server |
| MCP005 | high | Filesystem access to `/` or your entire home directory |
| MCP006 | critical | `curl … \| sh` style launchers |
| MCP007 | medium | Server launched through `sh -c` / `cmd /c` |
| MCP008 | medium | Servers that can execute arbitrary shell commands |
| MCP009 | high | Dangerous Docker options (`--privileged`, host network, docker.sock, host root mounts) |
| MCP010 | high | Packages impersonating the official `@modelcontextprotocol` scope |
| MCP011 | medium | Config files containing secrets that other users can read |

## Where it looks

- Claude Desktop, Claude Code (`~/.claude.json`, per-project servers, installed plugins, `.mcp.json`)
- Cursor (`~/.cursor/mcp.json`, `.cursor/mcp.json`)
- VS Code (user and `.vscode/mcp.json`, JSONC supported)
- Windsurf (`~/.codeium/windsurf/mcp_config.json`)

## Options

```bash
mcpguard --file path/to/config.json   # scan a specific file
mcpguard --dir ./some/repo            # find and scan every MCP config under a folder
mcpguard --json                       # machine-readable output
mcpguard --fail-on high               # exit 1 on high+ findings (for CI)
```

### CI

```yaml
- run: npx mcpguard --file .mcp.json --fail-on high
```

## Roadmap

- Live tool-description analysis (tool poisoning, hidden instructions, rug-pull detection between versions)
- Known-malicious package feed
- GitHub App with PR comments

## License

MIT
