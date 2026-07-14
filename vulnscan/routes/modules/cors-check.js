const fetch = require('node-fetch');

async function checkCORS(url) {
  const TIMEOUT = 5000;
  const checks = [];

  async function fetchWithTimeout(u, opts) {
    const ctrl = new AbortController();
    const timer = setTimeout(() => ctrl.abort(), TIMEOUT);
    try {
      const r = await fetch(u, { ...opts, signal: ctrl.signal });
      clearTimeout(timer); return r;
    } catch (e) { clearTimeout(timer); throw e; }
  }

  try {
    const res = await fetchWithTimeout(url, {
      method: 'GET',
      headers: { 'Origin': 'https://evil-attacker-test.com' },
    });

    const acao = res.headers.get('access-control-allow-origin') || '';
    const acac = res.headers.get('access-control-allow-credentials') || '';

    if (!acao) {
      checks.push({
        id: 'cors_policy', category: 'CORS', name: 'CORS Policy',
        status: 'pass', detail: 'CORS заголовки відсутні — cross-origin запити заблоковані', recommendation: null,
      });
      return checks;
    }

    // Reflected origin — критична вразливість
    if (acao === 'https://evil-attacker-test.com') {
      checks.push({
        id: 'cors_reflection', category: 'CORS', name: 'CORS Origin Reflection',
        status: 'fail',
        detail: 'КРИТИЧНО: Сервер відображає довільний Origin у відповіді — вразливість до CORS атак',
        recommendation: 'Використовуйте статичний whitelist дозволених доменів замість відображення Origin',
      });
    }

    // Wildcard + credentials
    if (acao === '*' && acac.toLowerCase() === 'true') {
      checks.push({
        id: 'cors_policy', category: 'CORS', name: 'CORS Policy',
        status: 'fail',
        detail: 'КРИТИЧНО: Access-Control-Allow-Origin: * разом з Allow-Credentials: true — браузери блокують, але конфігурація небезпечна',
        recommendation: 'Встановіть конкретний домен в Access-Control-Allow-Origin та не використовуйте Allow-Credentials: true з wildcard',
      });
    } else if (acao === '*') {
      checks.push({
        id: 'cors_policy', category: 'CORS', name: 'CORS Policy',
        status: 'warn',
        detail: 'Access-Control-Allow-Origin: * — будь-який домен може надсилати запити до API',
        recommendation: 'Обмежте CORS до конкретних дозволених доменів якщо API не публічний',
      });
    } else {
      checks.push({
        id: 'cors_policy', category: 'CORS', name: 'CORS Policy',
        status: 'pass',
        detail: `CORS обмежено до: ${acao}${acac ? ` (credentials: ${acac})` : ''}`,
        recommendation: null,
      });
    }
  } catch {
    // Ignore network errors for CORS check
  }

  if (checks.length === 0) {
    checks.push({
      id: 'cors_policy', category: 'CORS', name: 'CORS Policy',
      status: 'info', detail: 'Перевірку CORS не вдалося виконати', recommendation: null,
    });
  }

  return checks;
}

module.exports = checkCORS;
