// Маршрути для сканування — основна логіка перевірок безпеки
const express = require('express');
const router = express.Router();
const fetch = require('node-fetch');
const { v4: uuidv4 } = require('uuid');
const OpenAI = require('openai');
const fs = require('fs');
const path = require('path');

const DATA_FILE = path.join(__dirname, '..', 'data', 'scans.json');
const FETCH_TIMEOUT = 5000;

const openai = new OpenAI({ apiKey: process.env.OPENAI_API_KEY });

// Зчитуємо або створюємо файл даних
function readData() {
  if (!fs.existsSync(DATA_FILE)) {
    fs.writeFileSync(DATA_FILE, JSON.stringify({ scans: [] }, null, 2));
  }
  try {
    return JSON.parse(fs.readFileSync(DATA_FILE, 'utf8'));
  } catch {
    return { scans: [] };
  }
}

// Зберігаємо дані у файл
function saveData(data) {
  fs.writeFileSync(DATA_FILE, JSON.stringify(data, null, 2));
}

// Fetch з таймаутом
async function fetchWithTimeout(url, options = {}) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), FETCH_TIMEOUT);
  try {
    const res = await fetch(url, { ...options, signal: controller.signal });
    clearTimeout(timer);
    return res;
  } catch (err) {
    clearTimeout(timer);
    throw err;
  }
}

// Перевірка SSL/HTTPS
async function checkSSL(url) {
  const isHttps = url.startsWith('https://');
  const result = {
    id: 'ssl',
    category: 'TRANSPORT',
    name: 'SSL/TLS Certificate',
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

// Перевірка HTTP → HTTPS редіректу
async function checkHttpRedirect(url) {
  const result = {
    id: 'http_redirect',
    category: 'TRANSPORT',
    name: 'HTTP→HTTPS Redirect',
    status: 'info',
    detail: '',
    recommendation: null,
  };
  const httpUrl = url.replace(/^https?:\/\//, 'http://');
  try {
    const res = await fetchWithTimeout(httpUrl, { method: 'HEAD', redirect: 'manual' });
    const location = res.headers.get('location') || '';
    if ((res.status >= 301 && res.status <= 308) && location.startsWith('https://')) {
      result.status = 'pass';
      result.detail = `HTTP автоматично перенаправляє на HTTPS (${res.status})`;
    } else if (res.status >= 301 && res.status <= 308) {
      result.status = 'warn';
      result.detail = `Редірект на: ${location || 'невідомо'} (не HTTPS)`;
      result.recommendation = 'Налаштуйте редірект з HTTP на HTTPS';
    } else {
      result.status = 'fail';
      result.detail = `HTTP відповідає без редіректу (статус ${res.status})`;
      result.recommendation = 'Налаштуйте примусовий редірект HTTP → HTTPS';
    }
  } catch {
    result.status = 'info';
    result.detail = 'HTTP версія недоступна або заблокована';
  }
  return result;
}

// Аналіз заголовків безпеки
async function checkHeaders(url) {
  const checks = [];
  let headers = null;
  let cookies = [];

  try {
    const res = await fetchWithTimeout(url, { method: 'GET' });
    headers = res.headers;

    // Збираємо всі Set-Cookie заголовки
    const rawCookies = res.headers.raw ? res.headers.raw()['set-cookie'] || [] : [];
    cookies = rawCookies;
  } catch (err) {
    // Якщо не вдалося отримати заголовки — повертаємо fail для всіх
    const headerChecks = [
      'Content-Security-Policy', 'X-Frame-Options', 'Strict-Transport-Security',
      'X-Content-Type-Options', 'X-XSS-Protection',
    ];
    return headerChecks.map(h => ({
      id: h.toLowerCase().replace(/-/g, '_'),
      category: 'HEADERS',
      name: h,
      status: 'fail',
      detail: `Не вдалося отримати заголовки: ${err.message}`,
      recommendation: `Налаштуйте заголовок ${h}`,
    }));
  }

  // Content-Security-Policy
  const csp = headers.get('content-security-policy');
  checks.push({
    id: 'csp',
    category: 'HEADERS',
    name: 'Content-Security-Policy',
    status: csp ? 'pass' : 'fail',
    detail: csp ? `CSP встановлено: ${csp.substring(0, 120)}${csp.length > 120 ? '...' : ''}` : 'Заголовок CSP відсутній',
    recommendation: csp ? null : 'Додайте Content-Security-Policy для захисту від XSS атак',
  });

  // X-Frame-Options
  const xfo = headers.get('x-frame-options');
  checks.push({
    id: 'x_frame_options',
    category: 'HEADERS',
    name: 'X-Frame-Options',
    status: xfo ? 'pass' : 'fail',
    detail: xfo ? `X-Frame-Options: ${xfo}` : 'Заголовок відсутній — вразливість до Clickjacking',
    recommendation: xfo ? null : 'Додайте X-Frame-Options: DENY або SAMEORIGIN',
  });

  // HSTS
  const hsts = headers.get('strict-transport-security');
  let hstsStatus = 'fail';
  let hstsDetail = 'HSTS заголовок відсутній';
  if (hsts) {
    const maxAge = hsts.match(/max-age=(\d+)/);
    const seconds = maxAge ? parseInt(maxAge[1]) : 0;
    const days = Math.round(seconds / 86400);
    if (seconds >= 15552000) {
      hstsStatus = 'pass';
      hstsDetail = `HSTS активний: max-age=${seconds} (${days} днів)${hsts.includes('includeSubDomains') ? ', includeSubDomains' : ''}`;
    } else {
      hstsStatus = 'warn';
      hstsDetail = `HSTS встановлено, але max-age замалий: ${seconds}s (рекомендується ≥180 днів)`;
    }
  }
  checks.push({
    id: 'hsts',
    category: 'HEADERS',
    name: 'Strict-Transport-Security (HSTS)',
    status: hstsStatus,
    detail: hstsDetail,
    recommendation: hstsStatus !== 'pass' ? 'Встановіть HSTS з max-age не менше 15552000 та includeSubDomains' : null,
  });

  // X-Content-Type-Options
  const xcto = headers.get('x-content-type-options');
  checks.push({
    id: 'x_content_type_options',
    category: 'HEADERS',
    name: 'X-Content-Type-Options',
    status: xcto === 'nosniff' ? 'pass' : 'fail',
    detail: xcto ? `X-Content-Type-Options: ${xcto}` : 'Заголовок відсутній — ризик MIME sniffing',
    recommendation: xcto === 'nosniff' ? null : 'Додайте X-Content-Type-Options: nosniff',
  });

  // X-XSS-Protection
  const xxss = headers.get('x-xss-protection');
  checks.push({
    id: 'x_xss_protection',
    category: 'HEADERS',
    name: 'X-XSS-Protection',
    status: xxss ? (xxss.includes('1') ? 'pass' : 'warn') : 'warn',
    detail: xxss ? `X-XSS-Protection: ${xxss}` : 'Заголовок відсутній (застарілий, але рекомендується)',
    recommendation: xxss ? null : 'Додайте X-XSS-Protection: 1; mode=block',
  });

  // X-Powered-By — витік технологій
  const xpb = headers.get('x-powered-by');
  checks.push({
    id: 'x_powered_by',
    category: 'RECON',
    name: 'X-Powered-By (витік технологій)',
    status: xpb ? 'fail' : 'pass',
    detail: xpb ? `Сервер розкриває технологію: ${xpb}` : 'Заголовок X-Powered-By прихований',
    recommendation: xpb ? 'Видаліть або приховайте заголовок X-Powered-By' : null,
  });

  // Server — витік версії сервера
  const server = headers.get('server');
  let serverStatus = 'pass';
  let serverDetail = 'Заголовок Server прихований';
  if (server) {
    const hasVersion = /[\d.]+/.test(server);
    serverStatus = hasVersion ? 'fail' : 'warn';
    serverDetail = hasVersion
      ? `Сервер розкриває версію: ${server}`
      : `Сервер частково ідентифікується: ${server}`;
  }
  checks.push({
    id: 'server_header',
    category: 'RECON',
    name: 'Server Header (версія сервера)',
    status: serverStatus,
    detail: serverDetail,
    recommendation: serverStatus !== 'pass' ? 'Приховайте або знеособте заголовок Server' : null,
  });

  // Cookie flags
  if (cookies.length > 0) {
    const insecure = cookies.filter(c => !c.toLowerCase().includes('secure'));
    const noHttpOnly = cookies.filter(c => !c.toLowerCase().includes('httponly'));
    const noSameSite = cookies.filter(c => !c.toLowerCase().includes('samesite'));
    const cookieStatus = (insecure.length === 0 && noHttpOnly.length === 0) ? 'pass' :
      (insecure.length > 0 ? 'fail' : 'warn');
    checks.push({
      id: 'cookies',
      category: 'HEADERS',
      name: 'Cookie Security Flags',
      status: cookieStatus,
      detail: `Знайдено ${cookies.length} cookie. Без Secure: ${insecure.length}, без HttpOnly: ${noHttpOnly.length}, без SameSite: ${noSameSite.length}`,
      recommendation: cookieStatus !== 'pass' ? 'Встановіть прапори Secure, HttpOnly та SameSite для всіх cookie' : null,
    });
  }

  return checks;
}

// Перевірка доступності чутливих шляхів
async function checkSensitivePaths(baseUrl) {
  const paths = [
    { path: '/.git/HEAD', name: 'Git Repository (.git/HEAD)', risk: 'critical' },
    { path: '/.env', name: 'Environment File (.env)', risk: 'critical' },
    { path: '/phpinfo.php', name: 'PHP Info (phpinfo.php)', risk: 'high' },
    { path: '/info.php', name: 'PHP Info (info.php)', risk: 'high' },
    { path: '/backup.zip', name: 'Backup Archive (backup.zip)', risk: 'high' },
    { path: '/wp-admin', name: 'WordPress Admin (/wp-admin)', risk: 'medium' },
    { path: '/administrator', name: 'Admin Panel (/administrator)', risk: 'medium' },
    { path: '/admin', name: 'Admin Panel (/admin)', risk: 'medium' },
    { path: '/robots.txt', name: 'Robots.txt (/robots.txt)', risk: 'info' },
    { path: '/sitemap.xml', name: 'Sitemap (/sitemap.xml)', risk: 'info' },
  ];

  const origin = new URL(baseUrl).origin;
  const checks = [];

  await Promise.all(paths.map(async ({ path: p, name, risk }) => {
    let status = 'pass';
    let detail = `Шлях ${p} недоступний`;
    let recommendation = null;

    try {
      const res = await fetchWithTimeout(`${origin}${p}`, { method: 'HEAD', redirect: 'manual' });
      if (res.status === 200) {
        if (risk === 'critical') {
          status = 'fail';
          detail = `КРИТИЧНО: ${p} публічно доступний! (HTTP ${res.status})`;
          recommendation = `Негайно заблокуйте доступ до ${p} через налаштування сервера`;
        } else if (risk === 'high') {
          status = 'fail';
          detail = `${p} публічно доступний (HTTP ${res.status})`;
          recommendation = `Заблокуйте або видаліть ${p}`;
        } else if (risk === 'medium') {
          status = 'warn';
          detail = `${p} доступний — переконайтеся що захищений автентифікацією`;
          recommendation = `Обмежте доступ до ${p} через IP або автентифікацію`;
        } else {
          status = 'info';
          detail = `${p} публічно доступний (${res.status})`;
        }
      } else if (res.status === 403) {
        status = 'warn';
        detail = `${p} заблокований (403 Forbidden) — файл може існувати`;
      } else {
        status = 'pass';
        detail = `${p} недоступний (HTTP ${res.status})`;
      }
    } catch {
      status = 'pass';
      detail = `${p} не відповідає або недоступний`;
    }

    checks.push({
      id: `path_${p.replace(/[^a-z0-9]/gi, '_')}`,
      category: 'ACCESS',
      name,
      status,
      detail,
      recommendation,
    });
  }));

  return checks;
}

// Deep PHP сканування — розширена перевірка PHP-специфічних вразливостей
async function checkPhpDeep(baseUrl) {
  const origin = new URL(baseUrl).origin;
  const checks = [];

  // ── 1. PHP Info файли ──
  const phpInfoPaths = [
    { path: '/php.php',      name: 'PHP Info (php.php)',      risk: 'high' },
    { path: '/phptest.php',  name: 'PHP Info (phptest.php)',  risk: 'high' },
    { path: '/test.php',     name: 'PHP Info (test.php)',     risk: 'high' },
    { path: '/i.php',        name: 'PHP Info (i.php)',        risk: 'high' },
    { path: '/_info.php',    name: 'PHP Info (_info.php)',    risk: 'high' },
  ];

  // ── 2. Витік конфігурацій та вихідного коду ──
  const configPaths = [
    { path: '/composer.json',       name: 'Composer Manifest (composer.json)',       risk: 'critical' },
    { path: '/composer.lock',       name: 'Composer Lock (composer.lock)',           risk: 'critical' },
    { path: '/wp-config.php',       name: 'WordPress Config (wp-config.php)',        risk: 'critical' },
    { path: '/wp-config.php.bak',   name: 'WP Config Backup (wp-config.php.bak)',   risk: 'critical' },
    { path: '/config.php',          name: 'Config File (config.php)',                risk: 'high'     },
    { path: '/database.php',        name: 'DB Config (database.php)',                risk: 'high'     },
    { path: '/db.php',              name: 'DB Config (db.php)',                      risk: 'high'     },
    { path: '/configuration.php',   name: 'Joomla Config (configuration.php)',       risk: 'critical' },
    { path: '/config/database.php', name: 'Laravel DB Config (config/database.php)', risk: 'critical' },
    { path: '/.htaccess',           name: 'Apache Config (.htaccess)',               risk: 'high'     },
  ];

  // ── 3. CMS та фреймворк детектування ──
  const cmsPaths = [
    { path: '/wp-login.php',              name: 'WordPress Login (/wp-login.php)',           risk: 'medium' },
    { path: '/xmlrpc.php',                name: 'WordPress XML-RPC (/xmlrpc.php)',            risk: 'medium' },
    { path: '/wp-json/wp/v2/users',       name: 'WordPress REST Users API',                  risk: 'high'   },
    { path: '/joomla.xml',                name: 'Joomla Manifest (joomla.xml)',               risk: 'medium' },
    { path: '/administrator/manifests/files/joomla.xml', name: 'Joomla Version (manifests)', risk: 'medium' },
    { path: '/sites/default/settings.php', name: 'Drupal Config (sites/default/settings.php)', risk: 'critical' },
    { path: '/artisan',                   name: 'Laravel Artisan (/artisan)',                 risk: 'info'   },
    { path: '/index.php/admin',           name: 'CodeIgniter Admin',                         risk: 'medium' },
  ];

  // ── 4. PHP бекдори / вебшели ──
  const backdoorPaths = [
    { path: '/shell.php',     name: 'PHP Shell (shell.php)',       risk: 'critical' },
    { path: '/c99.php',       name: 'c99 Shell (c99.php)',         risk: 'critical' },
    { path: '/r57.php',       name: 'r57 Shell (r57.php)',         risk: 'critical' },
    { path: '/cmd.php',       name: 'CMD Shell (cmd.php)',         risk: 'critical' },
    { path: '/webshell.php',  name: 'Webshell (webshell.php)',     risk: 'critical' },
    { path: '/b374k.php',     name: 'b374k Shell (b374k.php)',     risk: 'critical' },
    { path: '/wso.php',       name: 'WSO Shell (wso.php)',         risk: 'critical' },
    { path: '/alfa.php',      name: 'Alfa Shell (alfa.php)',       risk: 'critical' },
  ];

  // ── 5. Директорії завантажень (перевірка Directory Listing) ──
  const uploadPaths = [
    { path: '/uploads/',  name: 'Upload Directory (/uploads/)',  risk: 'medium' },
    { path: '/upload/',   name: 'Upload Directory (/upload/)',   risk: 'medium' },
    { path: '/files/',    name: 'Files Directory (/files/)',     risk: 'medium' },
    { path: '/tmp/',      name: 'Temp Directory (/tmp/)',        risk: 'high'   },
    { path: '/temp/',     name: 'Temp Directory (/temp/)',       risk: 'high'   },
  ];

  // Обробник перевірки одного шляху
  async function probePath(p, name, risk, groupId) {
    let status = 'pass';
    let detail = `${p} недоступний`;
    let recommendation = null;

    try {
      const res = await fetchWithTimeout(`${origin}${p}`, { method: 'GET', redirect: 'manual' });

      if (res.status === 200) {
        const body = await res.text().catch(() => '');

        // Для директорій — шукаємо ознаки directory listing
        if (p.endsWith('/')) {
          const hasListing = /Index of\s+\//i.test(body) || /<title>Index of/i.test(body);
          if (hasListing) {
            status = risk === 'high' ? 'fail' : 'warn';
            detail = `Directory Listing увімкнено: ${p} — файли видимі публічно`;
            recommendation = 'Вимкніть Directory Listing (Options -Indexes в .htaccess або nginx autoindex off)';
          } else {
            status = 'pass';
            detail = `${p} доступний, але Directory Listing вимкнено`;
          }
          return;
        }

        // Для composer.json — перевіряємо чи справжній JSON
        if (p.includes('composer') && body.includes('"require"')) {
          status = 'fail';
          detail = `КРИТИЧНО: ${p} розкриває залежності проекту та може містити чутливу інформацію`;
          recommendation = `Заблокуйте доступ до ${p} через веб-сервер`;
          return;
        }

        // Для wp-config — частковий body (не завантажуємо повністю)
        if (p.includes('wp-config') && (body.includes('DB_') || body.includes('table_prefix'))) {
          status = 'fail';
          detail = `КРИТИЧНО: ${p} містить облікові дані бази даних!`;
          recommendation = `Негайно заблокуйте ${p} та перенесіть файл вище кореня сайту`;
          return;
        }

        // Загальне правило по ризику
        if (risk === 'critical') {
          status = 'fail';
          detail = `КРИТИЧНО: ${p} публічно доступний (HTTP 200)`;
          recommendation = `Негайно заблокуйте доступ до ${p}`;
        } else if (risk === 'high') {
          status = 'fail';
          detail = `${p} публічно доступний (HTTP 200)`;
          recommendation = `Заблокуйте або видаліть ${p}`;
        } else if (risk === 'medium') {
          status = 'warn';
          detail = `${p} доступний — переконайтеся в захисті автентифікацією`;
          recommendation = `Обмежте доступ до ${p}`;
        } else {
          status = 'info';
          detail = `${p} доступний (HTTP 200)`;
        }

      } else if (res.status === 403) {
        status = risk === 'critical' ? 'warn' : 'pass';
        detail = `${p} заблокований (403 Forbidden)${risk === 'critical' ? ' — файл існує, але недоступний' : ''}`;
        if (risk === 'critical') recommendation = 'Переконайтеся що файл не просто захищений, а видалений або перенесений';
      } else {
        status = 'pass';
        detail = `${p} недоступний (HTTP ${res.status})`;
      }
    } catch {
      status = 'pass';
      detail = `${p} не відповідає або недоступний`;
    }

    checks.push({
      id: `php_${groupId}_${p.replace(/[^a-z0-9]/gi, '_')}`,
      category: 'PHP',
      name,
      status,
      detail,
      recommendation,
    });
  }

  // Запускаємо всі групи паралельно
  const allPathGroups = [
    ...phpInfoPaths.map(({ path: p, name, risk }) => probePath(p, name, risk, 'info')),
    ...configPaths.map(({ path: p, name, risk }) => probePath(p, name, risk, 'config')),
    ...cmsPaths.map(({ path: p, name, risk }) => probePath(p, name, risk, 'cms')),
    ...backdoorPaths.map(({ path: p, name, risk }) => probePath(p, name, risk, 'backdoor')),
    ...uploadPaths.map(({ path: p, name, risk }) => probePath(p, name, risk, 'upload')),
  ];

  await Promise.all(allPathGroups);

  // ── 6. Перевірка PHP error disclosure у body головної сторінки ──
  try {
    const res = await fetchWithTimeout(baseUrl, { method: 'GET' });
    const body = await res.text();

    // Патерни PHP помилок у відповіді
    const errorPatterns = [
      { re: /\bParse error\b/i,               label: 'Parse error' },
      { re: /\bFatal error\b/i,               label: 'Fatal error' },
      { re: /\bWarning:\s+\w+\(/i,            label: 'PHP Warning' },
      { re: /\bNotice:\s+\w+/i,               label: 'PHP Notice' },
      { re: /Stack trace:/i,                  label: 'Stack trace' },
      { re: /on line \d+/i,                   label: 'Error line reference' },
      { re: /in \/[a-z0-9_\/]+\.php on/i,    label: 'File path exposure' },
    ];

    const found = errorPatterns.filter(({ re }) => re.test(body)).map(({ label }) => label);

    if (found.length > 0) {
      checks.push({
        id: 'php_error_disclosure',
        category: 'PHP',
        name: 'PHP Error Disclosure',
        status: 'fail',
        detail: `Сторінка розкриває PHP помилки в body: ${found.join(', ')}`,
        recommendation: 'Встановіть display_errors=Off та log_errors=On у php.ini для production оточення',
      });
    } else {
      checks.push({
        id: 'php_error_disclosure',
        category: 'PHP',
        name: 'PHP Error Disclosure',
        status: 'pass',
        detail: 'PHP помилки не виявлено у відповіді сторінки',
        recommendation: null,
      });
    }

    // ── 7. PHP версія з заголовків (детальний аналіз) ──
    const xpb = res.headers.get('x-powered-by') || '';
    const phpVerMatch = xpb.match(/PHP\/([\d.]+)/i);
    if (phpVerMatch) {
      const ver = phpVerMatch[1];
      const major = parseInt(ver.split('.')[0]);
      const minor = parseInt(ver.split('.')[1] || '0');
      const isEol = major < 8 || (major === 8 && minor < 1);
      checks.push({
        id: 'php_version_leak',
        category: 'PHP',
        name: 'PHP Version Disclosure',
        status: isEol ? 'fail' : 'warn',
        detail: isEol
          ? `PHP ${ver} — версія з підтримкою EOL (End of Life)! Більше не отримує патчів безпеки`
          : `PHP ${ver} — версія розкрита у заголовках (рекомендується приховати)`,
        recommendation: isEol
          ? `Оновіть PHP до 8.2+ та приховайте версію через expose_php=Off у php.ini`
          : `Встановіть expose_php=Off у php.ini для приховання версії`,
      });
    } else if (xpb.toLowerCase().includes('php')) {
      checks.push({
        id: 'php_version_leak',
        category: 'PHP',
        name: 'PHP Version Disclosure',
        status: 'warn',
        detail: `PHP присутній у заголовках, але версія прихована: ${xpb}`,
        recommendation: 'Повністю приховайте заголовок X-Powered-By',
      });
    }

  } catch {
    // Ігноруємо помилку аналізу body
  }

  return checks;
}

// AI аналіз результатів через OpenAI
async function analyzeWithAI(url, checks) {
  const failed = checks.filter(c => c.status === 'fail');
  const warned = checks.filter(c => c.status === 'warn');
  const passed = checks.filter(c => c.status === 'pass');

  const prompt = `Ти — експерт з веб-безпеки. Проаналізуй результати сканування сайту ${url}.

РЕЗУЛЬТАТИ СКАНУВАННЯ:
- Провалено перевірок: ${failed.length}
- Попереджень: ${warned.length}
- Пройдено: ${passed.length}

ДЕТАЛІ ПРОВАЛЕНИХ ПЕРЕВІРОК:
${failed.map(c => `• [${c.name}]: ${c.detail}`).join('\n')}

ПОПЕРЕДЖЕННЯ:
${warned.map(c => `• [${c.name}]: ${c.detail}`).join('\n')}

ПРОЙДЕНІ ПЕРЕВІРКИ:
${passed.map(c => `• [${c.name}]`).join('\n')}

Дай відповідь у форматі JSON (тільки JSON, без markdown):
{
  "score": <число 0-100>,
  "grade": "<A|B|C|D|F>",
  "summary": "<2-3 речення загальної оцінки безпеки сайту>",
  "critical_issues": ["<критична проблема 1>", "<критична проблема 2>"],
  "recommendations": ["<рекомендація 1>", "<рекомендація 2>", "<рекомендація 3>"]
}

Шкала оцінок: A=90-100, B=75-89, C=60-74, D=40-59, F=0-39`;

  try {
    const completion = await openai.chat.completions.create({
      model: 'gpt-4o-mini',
      messages: [{ role: 'user', content: prompt }],
      temperature: 0.3,
      max_tokens: 800,
    });

    const content = completion.choices[0].message.content.trim();
    // Витягуємо JSON з відповіді
    const jsonMatch = content.match(/\{[\s\S]*\}/);
    if (!jsonMatch) throw new Error('AI повернув некоректний формат');
    return JSON.parse(jsonMatch[0]);
  } catch (err) {
    // Якщо AI недоступний — розраховуємо score локально
    const failPenalty = failed.length * 10;
    const warnPenalty = warned.length * 3;
    const score = Math.max(0, 100 - failPenalty - warnPenalty);
    const grade = score >= 90 ? 'A' : score >= 75 ? 'B' : score >= 60 ? 'C' : score >= 40 ? 'D' : 'F';
    return {
      score,
      grade,
      summary: `Автоматична оцінка: виявлено ${failed.length} критичних проблем та ${warned.length} попереджень. AI аналіз недоступний: ${err.message}`,
      critical_issues: failed.slice(0, 5).map(c => c.detail),
      recommendations: failed.slice(0, 3).map(c => c.recommendation).filter(Boolean),
    };
  }
}

// POST /api/scan — головний маршрут сканування
router.post('/', async (req, res) => {
  const { url, deepPhp = false } = req.body;

  // Валідація URL
  if (!url || typeof url !== 'string') {
    return res.status(400).json({ error: 'URL обов\'язковий' });
  }

  let parsedUrl;
  try {
    parsedUrl = new URL(url.trim());
    if (!['http:', 'https:'].includes(parsedUrl.protocol)) {
      throw new Error('Непідтримуваний протокол');
    }
  } catch {
    return res.status(400).json({ error: 'Некоректний URL. Вкажіть повний URL з протоколом (https://example.com)' });
  }

  const targetUrl = parsedUrl.href;

  try {
    // Базові перевірки — завжди паралельно
    const parallelTasks = [
      checkSSL(targetUrl),
      checkHttpRedirect(targetUrl),
      checkSensitivePaths(targetUrl),
    ];
    if (deepPhp) parallelTasks.push(checkPhpDeep(targetUrl));

    const [sslCheck, redirectCheck, sensitiveChecks, phpChecks] = await Promise.all(parallelTasks);

    const headerChecks = await checkHeaders(targetUrl);

    const allChecks = [
      sslCheck,
      redirectCheck,
      ...headerChecks,
      ...sensitiveChecks,
      ...(phpChecks || []),
    ];

    // AI аналіз
    const aiResult = await analyzeWithAI(targetUrl, allChecks);

    // Формуємо результат
    const scanResult = {
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

    // Зберігаємо у файл
    const data = readData();
    data.scans.unshift(scanResult);
    // Зберігаємо максимум 100 сканів
    if (data.scans.length > 100) data.scans = data.scans.slice(0, 100);
    saveData(data);

    res.json(scanResult);
  } catch (err) {
    console.error('Помилка сканування:', err);
    res.status(500).json({ error: `Помилка під час сканування: ${err.message}` });
  }
});

// GET /api/scan/:id — отримання конкретного сканування
router.get('/:id', async (req, res) => {
  const data = readData();
  const scan = data.scans.find(s => s.id === req.params.id);
  if (!scan) return res.status(404).json({ error: 'Сканування не знайдено' });
  res.json(scan);
});

// DELETE /api/scan/:id — видалення сканування
router.delete('/:id', async (req, res) => {
  const data = readData();
  const index = data.scans.findIndex(s => s.id === req.params.id);
  if (index === -1) return res.status(404).json({ error: 'Сканування не знайдено' });
  data.scans.splice(index, 1);
  saveData(data);
  res.json({ success: true, message: 'Сканування видалено' });
});

module.exports = router;
