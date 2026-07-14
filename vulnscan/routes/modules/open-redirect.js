const fetch = require('node-fetch');

const REDIRECT_PARAMS = ['redirect', 'url', 'next', 'return', 'goto', 'link', 'target', 'redir', 'redirect_uri', 'return_url', 'callback', 'continue'];
const ATTACK_DOMAIN = 'evil-redirect-vulnscan-test.com';
const ATTACK_URL = `https://${ATTACK_DOMAIN}`;

async function checkOpenRedirect(url) {
  const vulnerable = [];

  await Promise.allSettled(REDIRECT_PARAMS.map(async (param) => {
    try {
      const testUrl = `${url}${url.includes('?') ? '&' : '?'}${param}=${encodeURIComponent(ATTACK_URL)}`;
      const ctrl = new AbortController();
      setTimeout(() => ctrl.abort(), 4000);
      const res = await fetch(testUrl, { method: 'GET', redirect: 'manual', signal: ctrl.signal });

      if (res.status >= 301 && res.status <= 308) {
        const loc = res.headers.get('location') || '';
        if (loc.includes(ATTACK_DOMAIN)) {
          vulnerable.push(`?${param}=`);
        }
      }
    } catch { /* ignore */ }
  }));

  return [{
    id: 'open_redirect', category: 'ACCESS', name: 'Open Redirect',
    status: vulnerable.length > 0 ? 'fail' : 'pass',
    detail: vulnerable.length > 0
      ? `Вразливі параметри відкритого редіректу: ${vulnerable.join(', ')} — зловмисник може перенаправити користувача на фішинговий сайт`
      : `Перевірено ${REDIRECT_PARAMS.length} параметрів — відкриті редіректи не виявлено`,
    recommendation: vulnerable.length > 0
      ? 'Валідуйте URL при редіректах. Використовуйте whitelist дозволених доменів або відносні URL'
      : null,
  }];
}

module.exports = checkOpenRedirect;
