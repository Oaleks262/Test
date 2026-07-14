const fetch = require('node-fetch');

const SUBDOMAINS = [
  { name: 'dev', risk: 'high' },
  { name: 'staging', risk: 'high' },
  { name: 'test', risk: 'high' },
  { name: 'api', risk: 'medium' },
  { name: 'admin', risk: 'high' },
  { name: 'backup', risk: 'high' },
  { name: 'old', risk: 'medium' },
  { name: 'beta', risk: 'medium' },
  { name: 'portal', risk: 'medium' },
  { name: 'vpn', risk: 'medium' },
  { name: 'mail', risk: 'low' },
  { name: 'ftp', risk: 'medium' },
];

async function probeSubdomains(url) {
  const hostname = new URL(url).hostname;

  // Skip IP addresses
  if (/^\d+\.\d+\.\d+\.\d+$/.test(hostname)) {
    return [{
      id: 'subdomain_probe', category: 'RECON', name: 'Subdomain Enumeration',
      status: 'info', detail: 'Subdomain сканування пропущено — ціль є IP адресою', recommendation: null,
    }];
  }

  // Get root domain
  const parts = hostname.split('.');
  const rootDomain = parts.length >= 2 ? parts.slice(-2).join('.') : hostname;

  const found = [];

  await Promise.allSettled(SUBDOMAINS.map(async ({ name, risk }) => {
    const sub = `${name}.${rootDomain}`;
    for (const proto of ['https', 'http']) {
      try {
        const ctrl = new AbortController();
        setTimeout(() => ctrl.abort(), 4000);
        const res = await fetch(`${proto}://${sub}`, {
          method: 'HEAD', redirect: 'manual', signal: ctrl.signal,
        });
        if (res.status < 500) {
          found.push({ sub, status: res.status, risk, proto });
          break;
        }
      } catch { /* continue */ }
    }
  }));

  if (found.length === 0) {
    return [{
      id: 'subdomain_probe', category: 'RECON', name: 'Subdomain Enumeration',
      status: 'pass',
      detail: `Перевірено ${SUBDOMAINS.length} субдоменів — жодного відкритого не знайдено`,
      recommendation: null,
    }];
  }

  const highRisk = found.filter(f => f.risk === 'high');
  return [{
    id: 'subdomain_probe', category: 'RECON', name: 'Subdomain Enumeration',
    status: highRisk.length > 0 ? 'warn' : 'info',
    detail: `Знайдено ${found.length} відкритих субдоменів: ${found.map(f => `${f.sub} (HTTP ${f.status})`).join(', ')}`,
    recommendation: highRisk.length > 0
      ? `Переконайтеся що тестові/dev субдомени захищені або відключені: ${highRisk.map(f => f.sub).join(', ')}`
      : null,
  }];
}

module.exports = probeSubdomains;
