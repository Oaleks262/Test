const fetch = require('node-fetch');

async function detectWAF(url) {
  let wafName = null;
  let wafDetail = '';

  try {
    const ctrl = new AbortController();
    setTimeout(() => ctrl.abort(), 5000);
    const res = await fetch(url, { method: 'GET', signal: ctrl.signal });
    const h = res.headers;
    const server = (h.get('server') || '').toLowerCase();
    const via = (h.get('via') || '').toLowerCase();

    if (h.get('cf-ray') || h.get('cf-cache-status') || server.includes('cloudflare')) {
      wafName = 'Cloudflare'; wafDetail = `CF-Ray: ${h.get('cf-ray') || 'присутній'}`;
    } else if (h.get('x-amz-cf-id') || h.get('x-amz-cf-pop')) {
      wafName = 'AWS CloudFront'; wafDetail = `X-Amz-Cf-Id: ${h.get('x-amz-cf-id') || 'присутній'}`;
    } else if (h.get('x-amzn-requestid') || server.includes('awselb')) {
      wafName = 'AWS ALB/ELB'; wafDetail = 'AWS Load Balancer виявлено';
    } else if (h.get('x-akamai-transformed') || server.includes('akamaighost')) {
      wafName = 'Akamai'; wafDetail = 'Akamai CDN/WAF виявлено';
    } else if (h.get('x-iinfo') || (h.get('x-cdn') || '').toLowerCase().includes('incapsula')) {
      wafName = 'Imperva/Incapsula'; wafDetail = `X-IInfo: ${h.get('x-iinfo') || 'присутній'}`;
    } else if (h.get('x-sucuri-id') || h.get('x-sucuri-cache')) {
      wafName = 'Sucuri WAF'; wafDetail = `X-Sucuri-Id: ${h.get('x-sucuri-id') || 'присутній'}`;
    } else if (h.get('x-fastly-request-id') || via.includes('fastly')) {
      wafName = 'Fastly CDN'; wafDetail = 'Fastly CDN виявлено';
    } else if (via.includes('varnish') || h.get('x-varnish')) {
      wafName = 'Varnish Cache'; wafDetail = `X-Varnish: ${h.get('x-varnish') || 'присутній'}`;
    } else if (server.includes('ddos-guard')) {
      wafName = 'DDoS-Guard'; wafDetail = 'DDoS-Guard виявлено';
    }
  } catch {
    // ignore
  }

  return [{
    id: 'waf_detection', category: 'RECON', name: 'WAF/CDN Detection',
    status: wafName ? 'pass' : 'info',
    detail: wafName
      ? `Виявлено ${wafName} — додатковий рівень захисту присутній. ${wafDetail}`
      : 'WAF/CDN не виявлено — сервер напряму доступний з інтернету',
    recommendation: wafName ? null : 'Розгляньте підключення WAF (Cloudflare Free, AWS WAF) для захисту від DDoS та атак',
  }];
}

module.exports = detectWAF;
