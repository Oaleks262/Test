const express = require('express');
const router = express.Router();
const fetch = require('node-fetch');
const { v4: uuidv4 } = require('uuid');
const OpenAI = require('openai');

const { scanOps } = require('../lib/db');
const queue = require('../lib/queue');

const checkDNS = require('./modules/dns');
const checkTLS = require('./modules/tls-check');
const checkModernHeaders = require('./modules/modern-headers');
const checkCORS = require('./modules/cors-check');
const detectWAF = require('./modules/waf');
const auditJS = require('./modules/js-audit');
const probeSubdomains = require('./modules/subdomains');
const checkOpenRedirect = require('./modules/open-redirect');

const openai = new OpenAI({ apiKey: process.env.OPENAI_API_KEY });
const FETCH_TIMEOUT = 5000;

// ── Fetch з таймаутом ──
async function fetchWithTimeout(url, options = {}) {
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), FETCH_TIMEOUT);
  try {
    const res = await fetch(url, { ...options, signal: ctrl.signal });
    clearTimeout(timer); return res;
  } catch (err) { clearTimeout(timer); throw err; }
}

// ── SSL/HTTPS ──
async function checkSSL(url) {
  const isHttps = url.startsWith('https://');
  const result = {
    id: 'ssl', category: 'TRANSPORT', name: 'SSL/TLS Certificate',
    status: isHttps ? 'pass' : 'fail',
    detail: isHttps ? 'Сайт використовує HTTPS протокол' : 'Сайт не використовує HTTPS',
    recommendation: isHttps ? null : 'Налаштуйте SSL сертифікат та перейдіть на HTTPS',
  };
  if (isHttps) {
    try {
      await fetchWithTimeout(url, { method: 'HEAD' });
      result.detail = 'SSL сертифікат дійсний, з\'єднання захищене';
    } catch {
      result.status = 'fail';
      result.detail = 'SSL сертифікат недійсний або сайт недоступний';
      result.recommendation = 'Перевірте SSL сертифікат та його термін дії';
    }
  }
  return result;
}

// ── HTTP → HTTPS redirect ──
async function checkHttpRedirect(url) {
  const result = {
    id: 'http_redirect', category: 'TRANSPORT', name: 'HTTP→HTTPS Redirect',
    status: 'info', detail: '', recommendation: null,
  };
  const httpUrl = url.replace(/^https?:\/\//, 'http://');
  try {
    const res = await fetchWithTimeout(httpUrl, { method: 'HEAD', redirect: 'manual' });
    const loc = res.headers.get('location') || '';
    if (res.status >= 301 && res.status <= 308 && loc.startsWith('https://')) {
      result.status = 'pass'; result.detail = `HTTP автоматично перенаправляє на HTTPS (${res.status})`;
    } else if (res.status >= 301 && res.status <= 308) {
      result.status = 'warn'; result.detail = `Редірект на: ${loc || 'невідомо'} (не HTTPS)`;
      result.recommendation = 'Налаштуйте редірект з HTTP на HTTPS';
    } else {
      result.status = 'fail'; result.detail = `HTTP відповідає без редіректу (статус ${res.status})`;
      result.recommendation = 'Налаштуйте примусовий редірект HTTP → HTTPS';
    }
  } catch {
    result.status = 'info'; result.detail = 'HTTP версія недоступна або заблокована';
  }
  return result;
}

// ── Заголовки безпеки ──
async function checkHeaders(url) {
  const checks = [];
  let headers = null;
  let cookies = [];

  try {
    const res = await fetchWithTimeout(url, { method: 'GET' });
    headers = res.headers;
    cookies = res.headers.raw ? (res.headers.raw()['set-cookie'] || []) : [];
  } catch (err) {
    return ['Content-Security-Policy', 'X-Frame-Options', 'Strict-Transport-Security',
      'X-Content-Type-Options', 'X-XSS-Protection'].map(h => ({
      id: h.toLowerCase().replace(/-/g, '_'), category: 'HEADERS', name: h,
      status: 'fail', detail: `Не вдалося отримати заголовки: ${err.message}`,
      recommendation: `Налаштуйте заголовок ${h}`,
    }));
  }

  // CSP
  const csp = headers.get('content-security-policy');
  checks.push({
    id: 'csp', category: 'HEADERS', name: 'Content-Security-Policy',
    status: csp ? 'pass' : 'fail',
    detail: csp ? `CSP встановлено: ${csp.substring(0, 120)}${csp.length > 120 ? '...' : ''}` : 'Заголовок CSP відсутній',
    recommendation: csp ? null : 'Додайте Content-Security-Policy для захисту від XSS атак',
  });

  // X-Frame-Options
  const xfo = headers.get('x-frame-options');
  checks.push({
    id: 'x_frame_options', category: 'HEADERS', name: 'X-Frame-Options',
    status: xfo ? 'pass' : 'fail',
    detail: xfo ? `X-Frame-Options: ${xfo}` : 'Заголовок відсутній — вразливість до Clickjacking',
    recommendation: xfo ? null : 'Додайте X-Frame-Options: DENY або SAMEORIGIN',
  });

  // HSTS
  const hsts = headers.get('strict-transport-security');
  let hstsStatus = 'fail', hstsDetail = 'HSTS заголовок відсутній';
  if (hsts) {
    const s = parseInt((hsts.match(/max-age=(\d+)/) || [])[1] || 0);
    const days = Math.round(s / 86400);
    hstsStatus = s >= 15552000 ? 'pass' : 'warn';
    hstsDetail = s >= 15552000
      ? `HSTS активний: max-age=${s} (${days} днів)${hsts.includes('includeSubDomains') ? ', includeSubDomains' : ''}`
      : `HSTS встановлено, але max-age замалий: ${s}s (рекомендується ≥180 днів)`;
  }
  checks.push({
    id: 'hsts', category: 'HEADERS', name: 'Strict-Transport-Security (HSTS)',
    status: hstsStatus, detail: hstsDetail,
    recommendation: hstsStatus !== 'pass' ? 'Встановіть HSTS з max-age≥15552000 та includeSubDomains' : null,
  });

  // X-Content-Type-Options
  const xcto = headers.get('x-content-type-options');
  checks.push({
    id: 'x_content_type_options', category: 'HEADERS', name: 'X-Content-Type-Options',
    status: xcto === 'nosniff' ? 'pass' : 'fail',
    detail: xcto ? `X-Content-Type-Options: ${xcto}` : 'Заголовок відсутній — ризик MIME sniffing',
    recommendation: xcto === 'nosniff' ? null : 'Додайте X-Content-Type-Options: nosniff',
  });

  // X-XSS-Protection
  const xxss = headers.get('x-xss-protection');
  checks.push({
    id: 'x_xss_protection', category: 'HEADERS', name: 'X-XSS-Protection',
    status: xxss ? (xxss.includes('1') ? 'pass' : 'warn') : 'warn',
    detail: xxss ? `X-XSS-Protection: ${xxss}` : 'Заголовок відсутній (застарілий, але рекомендується)',
    recommendation: xxss ? null : 'Додайте X-XSS-Protection: 1; mode=block',
  });

  // X-Powered-By
  const xpb = headers.get('x-powered-by');
  checks.push({
    id: 'x_powered_by', category: 'RECON', name: 'X-Powered-By (витік технологій)',
    status: xpb ? 'fail' : 'pass',
    detail: xpb ? `Сервер розкриває технологію: ${xpb}` : 'Заголовок X-Powered-By прихований',
    recommendation: xpb ? 'Видаліть або приховайте заголовок X-Powered-By' : null,
  });

  // Server
  const srv = headers.get('server');
  const hasVer = srv ? /[\d.]+/.test(srv) : false;
  checks.push({
    id: 'server_header', category: 'RECON', name: 'Server Header (версія сервера)',
    status: srv ? (hasVer ? 'fail' : 'warn') : 'pass',
    detail: srv ? (hasVer ? `Сервер розкриває версію: ${srv}` : `Сервер частково ідентифікується: ${srv}`) : 'Заголовок Server прихований',
    recommendation: srv ? 'Приховайте або знеособте заголовок Server' : null,
  });

  // Cookie flags
  if (cookies.length > 0) {
    const noSecure = cookies.filter(c => !c.toLowerCase().includes('secure'));
    const noHttp = cookies.filter(c => !c.toLowerCase().includes('httponly'));
    const noSame = cookies.filter(c => !c.toLowerCase().includes('samesite'));
    const cookieStatus = noSecure.length === 0 && noHttp.length === 0 ? 'pass' : noSecure.length > 0 ? 'fail' : 'warn';
    checks.push({
      id: 'cookies', category: 'HEADERS', name: 'Cookie Security Flags',
      status: cookieStatus,
      detail: `Знайдено ${cookies.length} cookie. Без Secure: ${noSecure.length}, без HttpOnly: ${noHttp.length}, без SameSite: ${noSame.length}`,
      recommendation: cookieStatus !== 'pass' ? 'Встановіть прапори Secure, HttpOnly та SameSite для всіх cookie' : null,
    });
  }

  // Modern headers
  const modernChecks = await checkModernHeaders(headers);
  checks.push(...modernChecks);

  return checks;
}

// ── Sensitive paths ──
async function checkSensitivePaths(baseUrl) {
  const paths = [
    { path: '/.git/HEAD',  name: 'Git Repository (.git/HEAD)',       risk: 'critical' },
    { path: '/.env',       name: 'Environment File (.env)',          risk: 'critical' },
    { path: '/phpinfo.php',name: 'PHP Info (phpinfo.php)',            risk: 'high' },
    { path: '/info.php',   name: 'PHP Info (info.php)',               risk: 'high' },
    { path: '/backup.zip', name: 'Backup Archive (backup.zip)',       risk: 'high' },
    { path: '/wp-admin',   name: 'WordPress Admin (/wp-admin)',       risk: 'medium' },
    { path: '/administrator', name: 'Admin Panel (/administrator)',   risk: 'medium' },
    { path: '/admin',      name: 'Admin Panel (/admin)',              risk: 'medium' },
    { path: '/robots.txt', name: 'Robots.txt',                        risk: 'info' },
    { path: '/sitemap.xml',name: 'Sitemap',                           risk: 'info' },
  ];

  const origin = new URL(baseUrl).origin;
  const checks = [];

  await Promise.all(paths.map(async ({ path: p, name, risk }) => {
    let status = 'pass', detail = `Шлях ${p} недоступний`, recommendation = null;
    try {
      const res = await fetchWithTimeout(`${origin}${p}`, { method: 'HEAD', redirect: 'manual' });
      if (res.status === 200) {
        if (risk === 'critical') {
          status = 'fail'; detail = `КРИТИЧНО: ${p} публічно доступний! (HTTP ${res.status})`;
          recommendation = `Негайно заблокуйте доступ до ${p}`;
        } else if (risk === 'high') {
          status = 'fail'; detail = `${p} публічно доступний (HTTP ${res.status})`;
          recommendation = `Заблокуйте або видаліть ${p}`;
        } else if (risk === 'medium') {
          status = 'warn'; detail = `${p} доступний — переконайтеся що захищений автентифікацією`;
          recommendation = `Обмежте доступ до ${p}`;
        } else {
          status = 'info'; detail = `${p} публічно доступний (${res.status})`;
        }
      } else if (res.status === 403) {
        status = 'warn'; detail = `${p} заблокований (403) — файл може існувати`;
      } else {
        status = 'pass'; detail = `${p} недоступний (HTTP ${res.status})`;
      }
    } catch {
      status = 'pass'; detail = `${p} не відповідає або недоступний`;
    }
    checks.push({ id: `path_${p.replace(/[^a-z0-9]/gi, '_')}`, category: 'ACCESS', name, status, detail, recommendation });
  }));

  return checks;
}

// ── Deep PHP ──
async function checkPhpDeep(baseUrl) {
  const origin = new URL(baseUrl).origin;
  const checks = [];

  const phpInfoPaths = [
    { path: '/php.php', name: 'PHP Info (php.php)', risk: 'high' },
    { path: '/phptest.php', name: 'PHP Info (phptest.php)', risk: 'high' },
    { path: '/test.php', name: 'PHP Info (test.php)', risk: 'high' },
    { path: '/i.php', name: 'PHP Info (i.php)', risk: 'high' },
    { path: '/_info.php', name: 'PHP Info (_info.php)', risk: 'high' },
  ];
  const configPaths = [
    { path: '/composer.json', name: 'Composer Manifest', risk: 'critical' },
    { path: '/composer.lock', name: 'Composer Lock', risk: 'critical' },
    { path: '/wp-config.php', name: 'WordPress Config', risk: 'critical' },
    { path: '/wp-config.php.bak', name: 'WP Config Backup', risk: 'critical' },
    { path: '/config.php', name: 'Config File', risk: 'high' },
    { path: '/database.php', name: 'DB Config', risk: 'high' },
    { path: '/db.php', name: 'DB Config (db.php)', risk: 'high' },
    { path: '/configuration.php', name: 'Joomla Config', risk: 'critical' },
    { path: '/config/database.php', name: 'Laravel DB Config', risk: 'critical' },
    { path: '/.htaccess', name: 'Apache Config (.htaccess)', risk: 'high' },
  ];
  const cmsPaths = [
    { path: '/wp-login.php', name: 'WordPress Login', risk: 'medium' },
    { path: '/xmlrpc.php', name: 'WordPress XML-RPC', risk: 'medium' },
    { path: '/wp-json/wp/v2/users', name: 'WordPress REST Users API', risk: 'high' },
    { path: '/joomla.xml', name: 'Joomla Manifest', risk: 'medium' },
    { path: '/sites/default/settings.php', name: 'Drupal Config', risk: 'critical' },
    { path: '/artisan', name: 'Laravel Artisan', risk: 'info' },
    { path: '/index.php/admin', name: 'CodeIgniter Admin', risk: 'medium' },
  ];
  const backdoorPaths = [
    { path: '/shell.php', name: 'PHP Shell', risk: 'critical' },
    { path: '/c99.php', name: 'c99 Shell', risk: 'critical' },
    { path: '/r57.php', name: 'r57 Shell', risk: 'critical' },
    { path: '/cmd.php', name: 'CMD Shell', risk: 'critical' },
    { path: '/webshell.php', name: 'Webshell', risk: 'critical' },
    { path: '/b374k.php', name: 'b374k Shell', risk: 'critical' },
    { path: '/wso.php', name: 'WSO Shell', risk: 'critical' },
    { path: '/alfa.php', name: 'Alfa Shell', risk: 'critical' },
  ];
  const uploadPaths = [
    { path: '/uploads/', name: 'Upload Directory (/uploads/)', risk: 'medium' },
    { path: '/upload/', name: 'Upload Directory (/upload/)', risk: 'medium' },
    { path: '/files/', name: 'Files Directory (/files/)', risk: 'medium' },
    { path: '/tmp/', name: 'Temp Directory (/tmp/)', risk: 'high' },
    { path: '/temp/', name: 'Temp Directory (/temp/)', risk: 'high' },
  ];

  async function probePath(p, name, risk, gid) {
    let status = 'pass', detail = `${p} недоступний`, recommendation = null;
    try {
      const res = await fetchWithTimeout(`${origin}${p}`, { method: 'GET', redirect: 'manual' });
      if (res.status === 200) {
        const body = await res.text().catch(() => '');
        if (p.endsWith('/')) {
          const listing = /Index of\s+\//i.test(body) || /<title>Index of/i.test(body);
          if (listing) {
            status = risk === 'high' ? 'fail' : 'warn';
            detail = `Directory Listing увімкнено: ${p}`;
            recommendation = 'Вимкніть Directory Listing (Options -Indexes або nginx autoindex off)';
          } else { status = 'pass'; detail = `${p} доступний, Directory Listing вимкнено`; }
          return checks.push({ id: `php_${gid}_${p.replace(/[^a-z0-9]/gi,'_')}`, category: 'PHP', name, status, detail, recommendation });
        }
        if (p.includes('composer') && body.includes('"require"')) {
          status = 'fail'; detail = `КРИТИЧНО: ${p} розкриває залежності проекту`;
          recommendation = `Заблокуйте доступ до ${p}`;
        } else if (p.includes('wp-config') && (body.includes('DB_') || body.includes('table_prefix'))) {
          status = 'fail'; detail = `КРИТИЧНО: ${p} містить облікові дані БД!`;
          recommendation = `Негайно заблокуйте ${p} та перенесіть файл вище кореня сайту`;
        } else if (risk === 'critical') {
          status = 'fail'; detail = `КРИТИЧНО: ${p} публічно доступний`;
          recommendation = `Негайно заблокуйте доступ до ${p}`;
        } else if (risk === 'high') {
          status = 'fail'; detail = `${p} публічно доступний`;
          recommendation = `Заблокуйте або видаліть ${p}`;
        } else if (risk === 'medium') {
          status = 'warn'; detail = `${p} доступний — переконайтеся в захисті`;
          recommendation = `Обмежте доступ до ${p}`;
        } else { status = 'info'; detail = `${p} доступний`; }
      } else if (res.status === 403) {
        status = risk === 'critical' ? 'warn' : 'pass';
        detail = `${p} заблокований (403)${risk === 'critical' ? ' — файл існує але недоступний' : ''}`;
        if (risk === 'critical') recommendation = 'Переконайтеся що файл видалений, а не просто заблокований';
      } else { status = 'pass'; detail = `${p} недоступний (HTTP ${res.status})`; }
    } catch { status = 'pass'; detail = `${p} не відповідає`; }
    checks.push({ id: `php_${gid}_${p.replace(/[^a-z0-9]/gi,'_')}`, category: 'PHP', name, status, detail, recommendation });
  }

  const all = [
    ...phpInfoPaths.map(({ path: p, name, risk }) => probePath(p, name, risk, 'info')),
    ...configPaths.map(({ path: p, name, risk }) => probePath(p, name, risk, 'config')),
    ...cmsPaths.map(({ path: p, name, risk }) => probePath(p, name, risk, 'cms')),
    ...backdoorPaths.map(({ path: p, name, risk }) => probePath(p, name, risk, 'back')),
    ...uploadPaths.map(({ path: p, name, risk }) => probePath(p, name, risk, 'upload')),
  ];
  await Promise.all(all);

  // PHP error disclosure
  try {
    const res = await fetchWithTimeout(baseUrl, { method: 'GET' });
    const body = await res.text();
    const errorPat = [
      { re: /\bParse error\b/i, label: 'Parse error' },
      { re: /\bFatal error\b/i, label: 'Fatal error' },
      { re: /\bWarning:\s+\w+\(/i, label: 'PHP Warning' },
      { re: /\bNotice:\s+\w+/i, label: 'PHP Notice' },
      { re: /Stack trace:/i, label: 'Stack trace' },
      { re: /in \/[a-z0-9_\/]+\.php on/i, label: 'File path exposure' },
    ];
    const found = errorPat.filter(({ re }) => re.test(body)).map(({ label }) => label);
    checks.push({
      id: 'php_error_disclosure', category: 'PHP', name: 'PHP Error Disclosure',
      status: found.length > 0 ? 'fail' : 'pass',
      detail: found.length > 0 ? `PHP помилки у body: ${found.join(', ')}` : 'PHP помилки не виявлено у відповіді',
      recommendation: found.length > 0 ? 'Встановіть display_errors=Off та log_errors=On у php.ini' : null,
    });
    const xpb = res.headers.get('x-powered-by') || '';
    const phpVer = xpb.match(/PHP\/([\d.]+)/i);
    if (phpVer) {
      const ver = phpVer[1];
      const [maj, min] = ver.split('.').map(Number);
      const isEol = maj < 8 || (maj === 8 && min < 1);
      checks.push({
        id: 'php_version_leak', category: 'PHP', name: 'PHP Version Disclosure',
        status: isEol ? 'fail' : 'warn',
        detail: isEol ? `PHP ${ver} — EOL версія, не отримує патчів безпеки` : `PHP ${ver} — версія розкрита у заголовках`,
        recommendation: isEol ? 'Оновіть PHP до 8.2+ та встановіть expose_php=Off' : 'Встановіть expose_php=Off у php.ini',
      });
    }
  } catch { /* ignore */ }

  return checks;
}

// ── AI аналіз ──
async function analyzeWithAI(url, checks) {
  const failed = checks.filter(c => c.status === 'fail');
  const warned = checks.filter(c => c.status === 'warn');
  const passed = checks.filter(c => c.status === 'pass');

  const prompt = `Ти — експерт з веб-безпеки. Проаналізуй результати сканування сайту ${url}.

РЕЗУЛЬТАТИ: провалено ${failed.length}, попереджень ${warned.length}, пройдено ${passed.length}.

ПРОВАЛЕНІ: ${failed.map(c => `[${c.name}]: ${c.detail}`).join('\n')}
ПОПЕРЕДЖЕННЯ: ${warned.map(c => `[${c.name}]: ${c.detail}`).join('\n')}

Відповідай ТІЛЬКИ JSON (без markdown):
{"score":<0-100>,"grade":"<A|B|C|D|F>","summary":"<2-3 речення>","critical_issues":["..."],"recommendations":["...","...","..."]}
Шкала: A=90-100, B=75-89, C=60-74, D=40-59, F=0-39`;

  try {
    const r = await openai.chat.completions.create({
      model: 'gpt-4o-mini',
      messages: [{ role: 'user', content: prompt }],
      temperature: 0.3,
      max_tokens: 800,
    });
    const text = r.choices[0].message.content.trim();
    const json = text.match(/\{[\s\S]*\}/);
    if (!json) throw new Error('Некоректний формат відповіді AI');
    return JSON.parse(json[0]);
  } catch (err) {
    const failPenalty = failed.length * 10;
    const warnPenalty = warned.length * 3;
    const score = Math.max(0, 100 - failPenalty - warnPenalty);
    const grade = score >= 90 ? 'A' : score >= 75 ? 'B' : score >= 60 ? 'C' : score >= 40 ? 'D' : 'F';
    return {
      score, grade,
      summary: `Автоматична оцінка: ${failed.length} критичних проблем, ${warned.length} попереджень. AI недоступний: ${err.message}`,
      critical_issues: failed.slice(0, 5).map(c => c.detail),
      recommendations: failed.slice(0, 3).map(c => c.recommendation).filter(Boolean),
    };
  }
}

// ── POST /api/scan ──
router.post('/', async (req, res) => {
  const { url, deepPhp = false, scheduled = false } = req.body;

  if (!url || typeof url !== 'string') return res.status(400).json({ error: 'URL обовязковий' });

  let parsedUrl;
  try {
    parsedUrl = new URL(url.trim());
    if (!['http:', 'https:'].includes(parsedUrl.protocol)) throw new Error('Непідтримуваний протокол');
  } catch {
    return res.status(400).json({ error: 'Некоректний URL. Вкажіть повний URL з протоколом (https://example.com)' });
  }

  const targetUrl = parsedUrl.href;

  // Queue position header
  if (queue.size > 0) res.setHeader('X-Queue-Position', queue.size + 1);

  try {
    const scanResult = await queue.add(async () => {
      // Run all checks in parallel groups
      const [
        sslCheck,
        redirectCheck,
        sensitiveChecks,
        tlsChecks,
        dnsChecks,
        corsChecks,
        wafChecks,
        subdomainChecks,
        redirectChecks,
        jsChecks,
        phpChecks,
      ] = await Promise.all([
        checkSSL(targetUrl),
        checkHttpRedirect(targetUrl),
        checkSensitivePaths(targetUrl),
        checkTLS(targetUrl),
        checkDNS(targetUrl),
        checkCORS(targetUrl),
        detectWAF(targetUrl),
        probeSubdomains(targetUrl),
        checkOpenRedirect(targetUrl),
        auditJS(targetUrl),
        deepPhp ? checkPhpDeep(targetUrl) : Promise.resolve([]),
      ]);

      const headerChecks = await checkHeaders(targetUrl);

      const allChecks = [
        sslCheck,
        ...tlsChecks,
        redirectCheck,
        ...headerChecks,
        ...corsChecks,
        ...wafChecks,
        ...subdomainChecks,
        ...sensitiveChecks,
        ...redirectChecks,
        ...jsChecks,
        ...dnsChecks,
        ...(phpChecks || []),
      ];

      const aiResult = await analyzeWithAI(targetUrl, allChecks);

      return {
        id: uuidv4(),
        url: targetUrl,
        date: new Date().toISOString(),
        score: aiResult.score,
        grade: aiResult.grade,
        summary: aiResult.summary,
        critical_issues: aiResult.critical_issues || [],
        recommendations: aiResult.recommendations || [],
        checks: allChecks,
        deepPhp: Boolean(deepPhp),
      };
    });

    scanOps.insert(scanResult);
    res.json(scanResult);
  } catch (err) {
    console.error('Помилка сканування:', err);
    res.status(500).json({ error: `Помилка під час сканування: ${err.message}` });
  }
});

// ── GET /api/scan/trend?url=... ── (must be before /:id)
router.get('/trend', (req, res) => {
  const url = req.query.url;
  if (!url) return res.status(400).json({ error: 'URL обовязковий' });
  res.json(scanOps.findByUrl(url, 20));
});

// ── GET /api/scan/compare?a=id1&b=id2 ── (must be before /:id)
router.get('/compare', (req, res) => {
  const { a, b } = req.query;
  if (!a || !b) return res.status(400).json({ error: 'Потрібні параметри a та b' });
  const scanA = scanOps.findById(a);
  const scanB = scanOps.findById(b);
  if (!scanA || !scanB) return res.status(404).json({ error: 'Одне або обидва сканування не знайдено' });
  res.json({ a: scanA, b: scanB });
});

// ── GET /api/scan/:id ──
router.get('/:id', (req, res) => {
  const scan = scanOps.findById(req.params.id);
  if (!scan) return res.status(404).json({ error: 'Сканування не знайдено' });
  res.json(scan);
});

// ── DELETE /api/scan/:id ──
router.delete('/:id', (req, res) => {
  if (!scanOps.delete(req.params.id)) return res.status(404).json({ error: 'Сканування не знайдено' });
  res.json({ success: true });
});

module.exports = router;
