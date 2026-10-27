# Security Policy

## Reporting a vulnerability in safemcp

Please **do not open a public issue**. Use GitHub's private reporting instead:
**[Report a vulnerability](https://github.com/0x1903/safemcp/security/advisories/new)**.

You'll get a response within 72 hours. Fixes are released through the normal signed (provenance) npm pipeline and credited in the advisory unless you prefer otherwise.

## Reporting a malicious MCP server

If you found an MCP server or package that is actively malicious, open a
[Malicious server report](https://github.com/0x1903/safemcp/issues/new?template=malicious-server.yml) so detection rules can cover it.
If the issue is an undisclosed vulnerability in someone else's server, report it to its maintainers first.

## What safemcp does on your machine

- **Default scan:** reads MCP config files locally. Nothing is sent anywhere; secrets are masked in all output, including `--json`.
- **`--live`:** starts each configured stdio server (exactly as your AI client would) and connects to remote servers. It only sends `initialize` and `tools/list` — it never calls a tool. Only use it on configs you'd run anyway.
- **Pins:** `--live` stores tool fingerprints (hashes, not contents) in `~/.safemcp/pins.json` with mode 600.
- **Zero dependencies:** the published package has no runtime dependencies, and every release is built and signed by GitHub Actions (npm provenance).
