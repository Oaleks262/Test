require('dotenv').config();
const express = require('express');
const cors = require('cors');
const path = require('path');
const rateLimit = require('express-rate-limit');
const cron = require('node-cron');
const fetch = require('node-fetch');

const app = express();
const PORT = process.env.PORT || 3001;

// Middleware
app.use(cors({ origin: '*', methods: ['GET', 'POST', 'DELETE', 'PATCH'], allowedHeaders: ['Content-Type'] }));
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// Rate limiting — 10 сканувань за 5 хвилин з одного IP
const scanLimiter = rateLimit({
  windowMs: 5 * 60 * 1000,
  max: 10,
  message: { error: 'Забагато запитів. Зачекайте 5 хвилин перед наступним скануванням.' },
  standardHeaders: true,
  legacyHeaders: false,
});

// Маршрути
const scanRouter = require('./routes/scan');
const historyRouter = require('./routes/history');
const scheduledRouter = require('./routes/scheduled');
const reportRouter = require('./routes/report');

app.use('/api/scan', scanLimiter, scanRouter);
app.use('/api/history', historyRouter);
app.use('/api/scheduled', scheduledRouter);
app.use('/api/report', reportRouter);

// SPA fallback
app.get('*', (req, res) => res.sendFile(path.join(__dirname, 'public', 'index.html')));

// Global error handler
app.use((err, req, res, next) => {
  console.error('Server error:', err.stack);
  res.status(500).json({ error: 'Внутрішня помилка сервера' });
});

// ── Scheduled scans cron ──
function startScheduledScans() {
  const { scheduleOps } = require('./lib/db');

  // Перевіряємо кожні 15 хвилин чи є розклади для виконання
  cron.schedule('*/15 * * * *', async () => {
    try {
      const schedules = scheduleOps.findAll().filter(s => s.enabled);
      const now = new Date();

      for (const s of schedules) {
        if (!s.next_scan || new Date(s.next_scan) > now) continue;

        console.log(`[CRON] Running scheduled scan: ${s.url}`);
        try {
          await fetch(`http://localhost:${PORT}/api/scan`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ url: s.url, deepPhp: s.deepPhp, scheduled: true }),
          });

          // Розраховуємо наступний запуск
          const next = new Date();
          if (s.schedule === 'daily') next.setDate(next.getDate() + 1);
          else if (s.schedule === 'weekly') next.setDate(next.getDate() + 7);
          else if (s.schedule === 'monthly') next.setMonth(next.getMonth() + 1);
          next.setHours(9, 0, 0, 0);

          scheduleOps.update(s.id, {
            last_scan: now.toISOString(),
            next_scan: next.toISOString(),
          });
          console.log(`[CRON] Done: ${s.url}, next: ${next.toISOString()}`);
        } catch (err) {
          console.error(`[CRON] Failed for ${s.url}:`, err.message);
        }
      }
    } catch (err) {
      console.error('[CRON] Error:', err.message);
    }
  });
}

app.listen(PORT, () => {
  startScheduledScans();
  console.log(`
╔══════════════════════════════════════════╗
║         VULNSCAN SERVER v2.0             ║
║   Security Audit Tool — Enhanced         ║
╠══════════════════════════════════════════╣
║  Порт:    ${PORT}                           ║
║  URL:     http://localhost:${PORT}          ║
║  SQLite:  data/vulnscan.db               ║
║  Queue:   3 concurrent scans             ║
║  Cron:    scheduled scans active         ║
║  Дата:    ${new Date().toLocaleString('uk-UA')}      ║
╚══════════════════════════════════════════╝
  `);
});
