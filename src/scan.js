import { discover } from './discover.js';
import { checkServer, FILE_PERMS_RULE, SEVERITIES } from './rules.js';

const WEIGHTS = { critical: 25, high: 10, medium: 4, low: 1 };

export function scan(opts = {}) {
  const configs = discover(opts).map((cfg) => {
    const servers = cfg.servers.map((s) => ({ ...s, findings: checkServer(s.name, s.server) }));
    const fileFindings = [];
    const hasSecrets = servers.some((s) => s.findings.some((f) => f.id === 'MCP001' || f.id === 'MCP002'));
    if (hasSecrets && process.platform !== 'win32' && cfg.mode != null && cfg.mode & 0o044) {
      const { id, severity, title, fix } = FILE_PERMS_RULE;
      fileFindings.push({ id, severity, title, message: `Mode ${(cfg.mode & 0o777).toString(8)}`, fix });
    }
    return { ...cfg, servers, fileFindings };
  });

  const all = configs.flatMap((c) => [...c.fileFindings, ...c.servers.flatMap((s) => s.findings)]);
  const counts = Object.fromEntries(SEVERITIES.map((sev) => [sev, all.filter((f) => f.severity === sev).length]));
  const penalty = all.reduce((sum, f) => sum + WEIGHTS[f.severity], 0);
  const serverCount = configs.reduce((n, c) => n + c.servers.length, 0);

  return { configs, counts, serverCount, score: Math.max(0, 100 - penalty) };
}
