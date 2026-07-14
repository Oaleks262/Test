const express = require('express');
const router = express.Router();
const { scanOps } = require('../lib/db');

const STATUS_ICON = { pass: '✓', fail: '✗', warn: '!', info: 'i' };
const STATUS_COLOR = { pass: '#00cc33', fail: '#ff3333', warn: '#ffcc00', info: '#00cccc' };
const GRADE_COLOR = { A: '#00ff41', B: '#88ff00', C: '#ffcc00', D: '#ff8800', F: '#ff3333' };

router.get('/:id', (req, res) => {
  const scan = scanOps.findById(req.params.id);
  if (!scan) return res.status(404).send('<h1>Сканування не знайдено</h1>');

  const byCategory = {};
  for (const c of scan.checks) {
    (byCategory[c.category] = byCategory[c.category] || []).push(c);
  }

  const catLabels = {
    TRANSPORT: 'Transport Security', HEADERS: 'HTTP Security Headers',
    RECON: 'Reconnaissance', ACCESS: 'Access Control',
    DNS: 'DNS Security', CORS: 'CORS Policy', CLIENT: 'Client-Side Security', PHP: 'Deep PHP Scan',
  };

  const checksHtml = Object.entries(byCategory).map(([cat, checks]) => `
    <div class="category">
      <h3>${catLabels[cat] || cat}</h3>
      ${checks.map(c => `
        <div class="check">
          <span class="badge" style="color:${STATUS_COLOR[c.status] || '#888'}">[${(STATUS_ICON[c.status] || '?')}]</span>
          <strong>${esc(c.name)}</strong>
          <div class="detail">${esc(c.detail || '')}</div>
          ${c.recommendation ? `<div class="rec">→ ${esc(c.recommendation)}</div>` : ''}
        </div>
      `).join('')}
    </div>
  `).join('');

  const gradeColor = GRADE_COLOR[scan.grade] || '#888';
  const passed = scan.checks.filter(c => c.status === 'pass').length;
  const failed = scan.checks.filter(c => c.status === 'fail').length;
  const warned = scan.checks.filter(c => c.status === 'warn').length;

  const html = `<!DOCTYPE html>
<html lang="uk">
<head>
  <meta charset="UTF-8">
  <title>VULNSCAN Report — ${esc(scan.url)}</title>
  <style>
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body { font-family: 'Segoe UI', Arial, sans-serif; font-size: 13px; color: #222; background: #fff; padding: 32px; }
    h1 { font-size: 22px; color: #1a1a2e; margin-bottom: 4px; }
    .subtitle { color: #666; font-size: 12px; margin-bottom: 24px; }
    .score-row { display: flex; align-items: center; gap: 24px; margin-bottom: 24px; padding: 16px; background: #f5f5f5; border-left: 4px solid ${gradeColor}; }
    .score-circle { width: 80px; height: 80px; border-radius: 50%; border: 3px solid ${gradeColor}; display: flex; flex-direction: column; align-items: center; justify-content: center; flex-shrink: 0; }
    .score-num { font-size: 28px; font-weight: bold; color: ${gradeColor}; }
    .score-grade { font-size: 13px; color: ${gradeColor}; }
    .score-meta h2 { font-size: 15px; word-break: break-all; margin-bottom: 4px; }
    .score-meta .date { color: #888; font-size: 11px; margin-bottom: 8px; }
    .score-meta .summary { color: #444; line-height: 1.6; }
    .stats { display: flex; gap: 12px; margin-bottom: 20px; }
    .stat { padding: 8px 16px; border-radius: 4px; font-weight: bold; font-size: 13px; }
    .stat-pass { background: #e6ffe6; color: #006600; }
    .stat-fail { background: #ffe6e6; color: #cc0000; }
    .stat-warn { background: #fffde6; color: #886600; }
    .section { margin-bottom: 20px; }
    .section h2 { font-size: 14px; font-weight: bold; margin-bottom: 8px; padding-bottom: 4px; border-bottom: 1px solid #ddd; color: #333; }
    .issue-item { padding: 6px 10px; margin-bottom: 4px; background: #fff5f5; border-left: 3px solid #ff3333; color: #cc0000; font-size: 12px; }
    .rec-item { padding: 6px 10px; margin-bottom: 4px; background: #f0fff4; border-left: 3px solid #00cc33; color: #006622; font-size: 12px; }
    .category { margin-bottom: 16px; }
    .category h3 { font-size: 12px; text-transform: uppercase; letter-spacing: 1px; color: #555; margin-bottom: 6px; padding: 4px 0; border-bottom: 1px solid #eee; }
    .check { display: flex; flex-wrap: wrap; gap: 6px; align-items: baseline; padding: 5px 0; border-bottom: 1px dotted #f0f0f0; }
    .badge { font-family: monospace; font-weight: bold; font-size: 14px; min-width: 24px; }
    .check strong { font-size: 12px; }
    .detail { flex: 1 1 100%; font-size: 11px; color: #555; margin-left: 30px; }
    .rec { flex: 1 1 100%; font-size: 11px; color: #006622; margin-left: 30px; }
    .footer { margin-top: 32px; padding-top: 12px; border-top: 1px solid #ddd; color: #aaa; font-size: 11px; }
    @media print {
      body { padding: 16px; font-size: 11px; }
      .no-print { display: none !important; }
      .check { page-break-inside: avoid; }
      .category { page-break-inside: avoid; }
    }
  </style>
</head>
<body>
  <div class="no-print" style="background:#1a1a2e;color:#00ff41;padding:10px 16px;margin:-32px -32px 24px;font-family:monospace;font-size:12px;display:flex;justify-content:space-between;align-items:center;">
    <span>VULNSCAN Security Report — натисніть Ctrl+P для збереження у PDF</span>
    <button onclick="window.print()" style="background:#00ff41;color:#000;border:none;padding:6px 14px;cursor:pointer;font-family:monospace;font-weight:bold;">[ PRINT / SAVE PDF ]</button>
  </div>

  <h1>VULNSCAN Security Audit Report</h1>
  <div class="subtitle">Згенеровано: ${new Date().toLocaleString('uk-UA')} | ID: ${scan.id}</div>

  <div class="score-row">
    <div class="score-circle">
      <div class="score-num">${scan.score}</div>
      <div class="score-grade">GRADE ${scan.grade}</div>
    </div>
    <div class="score-meta">
      <h2>${esc(scan.url)}</h2>
      <div class="date">Дата сканування: ${new Date(scan.date).toLocaleString('uk-UA')}</div>
      <div class="summary">${esc(scan.summary || '')}</div>
    </div>
  </div>

  <div class="stats">
    <div class="stat stat-pass">✓ Passed: ${passed}</div>
    <div class="stat stat-fail">✗ Failed: ${failed}</div>
    <div class="stat stat-warn">! Warnings: ${warned}</div>
  </div>

  ${scan.critical_issues?.length ? `
  <div class="section">
    <h2>⚠ Critical Issues (${scan.critical_issues.length})</h2>
    ${scan.critical_issues.map(i => `<div class="issue-item">${esc(i)}</div>`).join('')}
  </div>` : ''}

  ${scan.recommendations?.length ? `
  <div class="section">
    <h2>→ Recommendations (${scan.recommendations.length})</h2>
    ${scan.recommendations.map(r => `<div class="rec-item">${esc(r)}</div>`).join('')}
  </div>` : ''}

  <div class="section">
    <h2>Detailed Check Results</h2>
    ${checksHtml}
  </div>

  <div class="footer">
    VULNSCAN Security Audit Tool | ${new Date().getFullYear()}
  </div>
</body>
</html>`;

  res.setHeader('Content-Type', 'text/html; charset=utf-8');
  res.send(html);
});

function esc(s) {
  return String(s || '')
    .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

module.exports = router;
