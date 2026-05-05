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
  const { url } = req.body;

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
    // Запускаємо всі перевірки паралельно де можливо
    const [sslCheck, redirectCheck, sensitiveChecks] = await Promise.all([
      checkSSL(targetUrl),
      checkHttpRedirect(targetUrl),
      checkSensitivePaths(targetUrl),
    ]);

    const headerChecks = await checkHeaders(targetUrl);

    const allChecks = [sslCheck, redirectCheck, ...headerChecks, ...sensitiveChecks];

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
