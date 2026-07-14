const tls = require('tls');

async function checkTLS(targetUrl) {
  const parsed = new URL(targetUrl);
  if (parsed.protocol !== 'https:') {
    return [{
      id: 'tls_cert_expiry', category: 'TRANSPORT', name: 'SSL Certificate Expiry',
      status: 'fail', detail: 'Сайт не використовує HTTPS — TLS перевірка неможлива',
      recommendation: 'Налаштуйте HTTPS з актуальним TLS сертифікатом',
    }];
  }

  const hostname = parsed.hostname;
  const port = parseInt(parsed.port) || 443;
  const checks = [];

  return new Promise((resolve) => {
    let done = false;
    const finish = () => { if (!done) { done = true; resolve(checks); } };

    const socket = tls.connect(
      { host: hostname, port, servername: hostname, rejectUnauthorized: false },
      () => {
        try {
          const cert = socket.getPeerCertificate(true);
          const proto = socket.getProtocol();
          const cipher = socket.getCipher();

          // Expiry
          const expiry = cert.valid_to ? new Date(cert.valid_to) : null;
          const now = new Date();
          const daysLeft = expiry ? Math.floor((expiry - now) / 86400000) : null;

          if (expiry && daysLeft !== null) {
            let status = 'pass';
            let detail = `Сертифікат дійсний до ${expiry.toLocaleDateString('uk-UA')} (${daysLeft} днів залишилось)`;
            let recommendation = null;
            if (daysLeft < 0) {
              status = 'fail'; detail = `КРИТИЧНО: SSL сертифікат прострочений ${Math.abs(daysLeft)} днів тому!`;
              recommendation = 'Негайно оновіть SSL сертифікат';
            } else if (daysLeft < 14) {
              status = 'fail'; detail = `Сертифікат закінчується через ${daysLeft} днів! (${expiry.toLocaleDateString('uk-UA')})`;
              recommendation = 'Терміново оновіть SSL сертифікат';
            } else if (daysLeft < 30) {
              status = 'warn'; detail = `Сертифікат закінчується через ${daysLeft} днів (${expiry.toLocaleDateString('uk-UA')})`;
              recommendation = 'Оновіть SSL сертифікат найближчим часом';
            }
            checks.push({ id: 'tls_cert_expiry', category: 'TRANSPORT', name: 'SSL Certificate Expiry', status, detail, recommendation });
          }

          // Issuer
          if (cert.issuer) {
            const issuerStr = cert.issuer.O || cert.issuer.CN || 'Невідомо';
            checks.push({
              id: 'tls_cert_issuer', category: 'TRANSPORT', name: 'SSL Certificate Issuer',
              status: 'info', detail: `Видавець: ${issuerStr}${cert.subject?.CN ? ` | CN: ${cert.subject.CN}` : ''}`,
              recommendation: null,
            });
          }

          // Protocol version
          const weakProtos = ['TLSv1', 'TLSv1.1', 'SSLv2', 'SSLv3'];
          const isWeakProto = weakProtos.includes(proto);
          checks.push({
            id: 'tls_protocol', category: 'TRANSPORT', name: 'TLS Protocol Version',
            status: isWeakProto ? 'fail' : 'pass',
            detail: `Протокол: ${proto || 'невідомо'}`,
            recommendation: isWeakProto ? 'Вимкніть TLS 1.0/1.1 та SSLv2/3, використовуйте TLS 1.2 або TLS 1.3' : null,
          });

          // Cipher
          if (cipher) {
            const weakCiphers = ['RC4', 'DES', '3DES', 'NULL', 'EXPORT', 'anon', 'MD5'];
            const isWeak = weakCiphers.some(w => (cipher.name || '').toUpperCase().includes(w));
            checks.push({
              id: 'tls_cipher', category: 'TRANSPORT', name: 'TLS Cipher Suite',
              status: isWeak ? 'fail' : 'pass',
              detail: `Cipher: ${cipher.name || 'невідомо'} (${cipher.version || ''})`,
              recommendation: isWeak ? 'Вимкніть слабкі cipher suites (RC4, DES, 3DES, EXPORT, NULL)' : null,
            });
          }
        } catch (e) {
          checks.push({
            id: 'tls_cert_expiry', category: 'TRANSPORT', name: 'SSL Certificate Expiry',
            status: 'warn', detail: `Не вдалося розібрати сертифікат: ${e.message}`, recommendation: null,
          });
        }
        socket.destroy();
        finish();
      }
    );

    socket.on('error', (err) => {
      checks.push({
        id: 'tls_cert_expiry', category: 'TRANSPORT', name: 'TLS Configuration',
        status: 'warn', detail: `Помилка TLS підключення: ${err.message}`, recommendation: null,
      });
      finish();
    });

    socket.setTimeout(6000, () => { socket.destroy(); finish(); });
  });
}

module.exports = checkTLS;
