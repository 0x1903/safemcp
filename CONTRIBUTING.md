# Contributing

Thanks for helping make AI agents safer! The most valuable contributions are **new detection rules** and **false-positive fixes**.

## Setup

```bash
git clone https://github.com/0x1903/safemcp && cd safemcp
npm test                                                # zero dependencies, nothing to install
node bin/safemcp.js --file examples/demo-config.json --live
```

## Adding a rule

| Rule type | File | Gets |
|---|---|---|
| Config rules (`MCPxxx`) | `src/rules.js` | one server entry from a config file |
| Tool rules (`TPxxx`) | `src/toolrules.js` | one tool definition from `tools/list` |

Each rule has an `id`, `severity`, `title`, `fix` and a `check()` that returns a list of messages. Then:

1. Add a test in `test/` with at least one positive **and one legitimate example that must not be flagged** — false positives are what make people uninstall scanners.
2. Add the rule to the table in `README.md`.
3. If it's a tool-poisoning pattern, consider adding it to `examples/poisoned-server.js`.

Never put real secrets or real attacker infrastructure in tests or examples; build fake tokens at runtime (see `test/rules.test.js`).

## Pull requests

- Keep the package dependency-free.
- `npm test` must pass on Node 18+ (CI runs Linux, macOS and Windows).
