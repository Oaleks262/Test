const express = require('express');
const router = express.Router();
const { v4: uuidv4 } = require('uuid');
const { scheduleOps } = require('../lib/db');

const VALID_SCHEDULES = { daily: '0 9 * * *', weekly: '0 9 * * 1', monthly: '0 9 1 * *' };

function nextRun(schedule) {
  const now = new Date();
  if (schedule === 'daily') now.setDate(now.getDate() + 1);
  else if (schedule === 'weekly') now.setDate(now.getDate() + 7);
  else if (schedule === 'monthly') now.setMonth(now.getMonth() + 1);
  now.setHours(9, 0, 0, 0);
  return now.toISOString();
}

// GET /api/scheduled
router.get('/', (req, res) => {
  try {
    res.json(scheduleOps.findAll());
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// POST /api/scheduled
router.post('/', (req, res) => {
  const { url, schedule, deepPhp = false } = req.body;
  if (!url || !schedule) return res.status(400).json({ error: 'URL та розклад обовязкові' });
  if (!VALID_SCHEDULES[schedule]) return res.status(400).json({ error: 'Розклад: daily, weekly, monthly' });

  let parsedUrl;
  try { parsedUrl = new URL(url.trim()).href; }
  catch { return res.status(400).json({ error: 'Некоректний URL' }); }

  const entry = {
    id: uuidv4(),
    url: parsedUrl,
    schedule,
    deepPhp: Boolean(deepPhp),
    enabled: true,
    last_scan: null,
    next_scan: nextRun(schedule),
    created_at: new Date().toISOString(),
  };

  scheduleOps.insert(entry);
  res.status(201).json(entry);
});

// PATCH /api/scheduled/:id/toggle
router.patch('/:id/toggle', (req, res) => {
  const s = scheduleOps.findById(req.params.id);
  if (!s) return res.status(404).json({ error: 'Не знайдено' });
  scheduleOps.update(req.params.id, { enabled: s.enabled ? 0 : 1 });
  res.json({ success: true, enabled: !s.enabled });
});

// DELETE /api/scheduled/:id
router.delete('/:id', (req, res) => {
  if (!scheduleOps.delete(req.params.id)) return res.status(404).json({ error: 'Не знайдено' });
  res.json({ success: true });
});

module.exports = router;
