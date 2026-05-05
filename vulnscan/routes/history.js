// Маршрути для перегляду історії сканувань
const express = require('express');
const router = express.Router();
const fs = require('fs');
const path = require('path');

const DATA_FILE = path.join(__dirname, '..', 'data', 'scans.json');

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

// GET /api/history — повертає останні 20 сканувань
router.get('/', (req, res) => {
  const data = readData();
  // Сортуємо за датою — найновіші першими
  const sorted = [...data.scans].sort((a, b) => new Date(b.date) - new Date(a.date));
  res.json(sorted.slice(0, 20));
});

module.exports = router;
