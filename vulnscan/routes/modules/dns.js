const dns = require('dns').promises;

async function checkDNS(url) {
  const hostname = new URL(url).hostname;
  const checks = [];

  // SPF
  try {
    const records = await dns.resolveTxt(hostname);
    const spf = records.flat().find(r => r.startsWith('v=spf1'));
    checks.push({
      id: 'dns_spf', category: 'DNS', name: 'SPF Record',
      status: spf ? 'pass' : 'fail',
      detail: spf ? `SPF знайдено: ${spf.substring(0, 120)}` : 'SPF запис відсутній — домен вразливий до email спуфінгу',
      recommendation: spf ? null : 'Додайте TXT запис: v=spf1 include:_spf.yourprovider.com ~all',
    });
  } catch {
    checks.push({
      id: 'dns_spf', category: 'DNS', name: 'SPF Record',
      status: 'warn', detail: 'Не вдалося перевірити SPF (DNS недоступний або немає TXT записів)', recommendation: null,
    });
  }

  // DMARC
  try {
    const records = await dns.resolveTxt(`_dmarc.${hostname}`);
    const dmarc = records.flat().find(r => r.startsWith('v=DMARC1'));
    const policy = dmarc?.match(/p=(none|quarantine|reject)/i)?.[1] || 'none';
    const policyStatus = policy === 'reject' ? 'pass' : policy === 'quarantine' ? 'warn' : 'fail';
    checks.push({
      id: 'dns_dmarc', category: 'DNS', name: 'DMARC Record',
      status: dmarc ? policyStatus : 'fail',
      detail: dmarc
        ? `DMARC знайдено (p=${policy}): ${dmarc.substring(0, 120)}`
        : 'DMARC запис відсутній — домен не захищений від email спуфінгу',
      recommendation: !dmarc
        ? 'Додайте TXT запис для _dmarc.domain: v=DMARC1; p=quarantine; rua=mailto:dmarc@yourdomain.com'
        : policy === 'none' ? 'Змініть DMARC policy з none на quarantine або reject для реального захисту' : null,
    });
  } catch (err) {
    const notFound = ['ENOTFOUND', 'ENODATA', 'ENOENT'].includes(err.code);
    checks.push({
      id: 'dns_dmarc', category: 'DNS', name: 'DMARC Record',
      status: notFound ? 'fail' : 'warn',
      detail: notFound ? 'DMARC запис відсутній — домен не захищений від email спуфінгу' : `Помилка перевірки DMARC: ${err.message}`,
      recommendation: notFound ? 'Додайте DMARC запис для _dmarc.yourdomain.com' : null,
    });
  }

  // CAA
  try {
    const caa = dns.resolveCaa ? await dns.resolveCaa(hostname) : null;
    if (caa && caa.length > 0) {
      checks.push({
        id: 'dns_caa', category: 'DNS', name: 'CAA Record',
        status: 'pass',
        detail: `CAA записи знайдено — дозволені CA: ${caa.map(r => r.value).join(', ')}`,
        recommendation: null,
      });
    } else {
      checks.push({
        id: 'dns_caa', category: 'DNS', name: 'CAA Record',
        status: 'warn',
        detail: 'CAA записи відсутні — будь-який CA може видати SSL сертифікат для домену',
        recommendation: 'Додайте CAA записи: 0 issue "letsencrypt.org" або відповідний CA',
      });
    }
  } catch {
    checks.push({
      id: 'dns_caa', category: 'DNS', name: 'CAA Record',
      status: 'warn',
      detail: 'CAA записи відсутні або недоступні для перевірки',
      recommendation: 'Додайте CAA записи для обмеження видачі SSL сертифікатів',
    });
  }

  return checks;
}

module.exports = checkDNS;
