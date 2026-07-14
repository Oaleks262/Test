async function checkModernHeaders(headers) {
  const checks = [];

  // Permissions-Policy
  const pp = headers.get('permissions-policy') || headers.get('feature-policy');
  checks.push({
    id: 'permissions_policy', category: 'HEADERS', name: 'Permissions-Policy',
    status: pp ? 'pass' : 'warn',
    detail: pp ? `Permissions-Policy: ${pp.substring(0, 150)}` : 'Заголовок Permissions-Policy відсутній',
    recommendation: pp ? null : 'Додайте Permissions-Policy для контролю доступу до камери, мікрофону, геолокації: camera=(), microphone=(), geolocation=()',
  });

  // Referrer-Policy
  const rp = (headers.get('referrer-policy') || '').toLowerCase();
  const strictPolicies = ['no-referrer', 'strict-origin', 'strict-origin-when-cross-origin', 'same-origin', 'no-referrer-when-downgrade'];
  const rpGood = strictPolicies.some(p => rp.includes(p));
  checks.push({
    id: 'referrer_policy', category: 'HEADERS', name: 'Referrer-Policy',
    status: rp ? (rpGood ? 'pass' : 'warn') : 'warn',
    detail: rp ? `Referrer-Policy: ${rp}` : 'Referrer-Policy відсутній — браузер надсилає повний URL як referrer',
    recommendation: (!rp || !rpGood)
      ? 'Встановіть Referrer-Policy: strict-origin-when-cross-origin'
      : null,
  });

  // Cross-Origin-Opener-Policy (COOP)
  const coop = headers.get('cross-origin-opener-policy');
  checks.push({
    id: 'coop', category: 'HEADERS', name: 'Cross-Origin-Opener-Policy (COOP)',
    status: coop ? 'pass' : 'warn',
    detail: coop ? `COOP: ${coop}` : 'COOP відсутній — вразливість до Spectre/XS-Leaks атак між вкладками',
    recommendation: coop ? null : 'Додайте Cross-Origin-Opener-Policy: same-origin',
  });

  // Cross-Origin-Resource-Policy (CORP)
  const corp = headers.get('cross-origin-resource-policy');
  checks.push({
    id: 'corp', category: 'HEADERS', name: 'Cross-Origin-Resource-Policy (CORP)',
    status: corp ? 'pass' : 'warn',
    detail: corp ? `CORP: ${corp}` : 'CORP відсутній — ресурси можуть завантажуватися зі сторонніх доменів',
    recommendation: corp ? null : 'Додайте Cross-Origin-Resource-Policy: same-site або same-origin',
  });

  // Cross-Origin-Embedder-Policy (COEP)
  const coep = headers.get('cross-origin-embedder-policy');
  checks.push({
    id: 'coep', category: 'HEADERS', name: 'Cross-Origin-Embedder-Policy (COEP)',
    status: coep ? 'pass' : 'warn',
    detail: coep ? `COEP: ${coep}` : 'COEP відсутній',
    recommendation: coep ? null : 'Додайте Cross-Origin-Embedder-Policy: require-corp для ізоляції між сайтами',
  });

  return checks;
}

module.exports = checkModernHeaders;
