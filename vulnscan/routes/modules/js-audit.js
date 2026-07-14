const fetch = require('node-fetch');

// Known vulnerable version ranges: [major, minor, patch] minimum safe version
const VULN_LIBS = [
  {
    name: 'jQuery',
    pattern: /jquery[.\-\/](\d+\.\d+\.\d+)/i,
    safe: [3, 7, 0],
    cve: 'CVE-2020-11022, CVE-2019-11358',
    desc: 'XSS через HTML manipulation',
  },
  {
    name: 'Bootstrap',
    pattern: /bootstrap[.\-\/](\d+\.\d+\.\d+)/i,
    safe: [4, 0, 0],
    cve: 'CVE-2018-14040',
    desc: 'XSS через data-attributes',
  },
  {
    name: 'AngularJS',
    pattern: /angular[.\-\/](1\.\d+\.\d+)/i,
    safe: null, // AngularJS (v1) is EOL entirely
    cve: 'EOL',
    desc: 'Підтримку припинено, більше не отримує патчів безпеки',
  },
  {
    name: 'moment.js',
    pattern: /moment[.\-\/](\d+\.\d+\.\d+)/i,
    safe: [2, 29, 2],
    cve: 'CVE-2022-24785',
    desc: 'ReDoS вразливість',
  },
];

function versionLessThan(ver, safe) {
  const [ma, mi, pa] = ver.split('.').map(Number);
  const [sma, smi, spa] = safe;
  if (ma !== sma) return ma < sma;
  if (mi !== smi) return mi < smi;
  return pa < spa;
}

async function auditJSLibraries(url) {
  const checks = [];

  try {
    const ctrl = new AbortController();
    setTimeout(() => ctrl.abort(), 8000);
    const res = await fetch(url, { method: 'GET', signal: ctrl.signal });
    const html = await res.text();

    const issues = [];
    const found = [];

    // Extract all script src attributes
    const srcMatches = [...html.matchAll(/<script[^>]+src=["']([^"']+)["'][^>]*>/gi)];

    for (const [, src] of srcMatches) {
      for (const lib of VULN_LIBS) {
        const m = src.match(lib.pattern);
        if (!m) continue;
        const version = m[1];
        found.push(`${lib.name} ${version}`);

        if (!lib.safe) {
          issues.push(`${lib.name} ${version} — EOL версія. ${lib.desc}`);
        } else if (versionLessThan(version, lib.safe)) {
          const safeStr = lib.safe.join('.');
          issues.push(`${lib.name} ${version} → вразлива (мін. безпечна: ${safeStr}). ${lib.cve}: ${lib.desc}`);
        }
      }
    }

    // Also check inline scripts for version declarations
    const inlineMatches = [...html.matchAll(/jquery[\s\S]{0,20}v?(\d+\.\d+\.\d+)/gi)];
    for (const [, v] of inlineMatches) {
      if (!found.some(f => f.includes(v))) {
        found.push(`jQuery (inline) ${v}`);
      }
    }

    // Check for inline event handlers (basic XSS surface check)
    const inlineEvents = (html.match(/\son\w+\s*=/gi) || []).length;
    const hasEval = /\beval\s*\(/.test(html);
    const hasDocWrite = /document\.write\s*\(/.test(html);

    if (issues.length > 0) {
      checks.push({
        id: 'js_library_audit', category: 'CLIENT', name: 'JavaScript Library Security',
        status: 'fail',
        detail: `Вразливі бібліотеки (${issues.length}): ${issues.join(' | ')}`,
        recommendation: 'Оновіть вразливі JavaScript бібліотеки до актуальних версій. Перевірте npm audit або snyk.io',
      });
    } else if (found.length > 0) {
      checks.push({
        id: 'js_library_audit', category: 'CLIENT', name: 'JavaScript Library Security',
        status: 'pass',
        detail: `Перевірено бібліотеки: ${found.join(', ')} — вразливих версій не виявлено`,
        recommendation: null,
      });
    } else {
      checks.push({
        id: 'js_library_audit', category: 'CLIENT', name: 'JavaScript Library Security',
        status: 'info',
        detail: `Перевірено ${srcMatches.length} скриптів — CDN-бібліотеки з версіями не виявлено`,
        recommendation: null,
      });
    }

    // Risky JS practices
    if (hasEval || hasDocWrite || inlineEvents > 10) {
      checks.push({
        id: 'js_practices', category: 'CLIENT', name: 'Risky JS Practices',
        status: 'warn',
        detail: [
          hasEval ? 'eval() виявлено' : null,
          hasDocWrite ? 'document.write() виявлено' : null,
          inlineEvents > 10 ? `${inlineEvents} inline event handlers (потенційний XSS вектор)` : null,
        ].filter(Boolean).join(', '),
        recommendation: 'Уникайте eval(), document.write() та надмірного використання inline event handlers',
      });
    }
  } catch {
    // Ignore
  }

  return checks;
}

module.exports = auditJSLibraries;
