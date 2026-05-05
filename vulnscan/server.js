// VULNSCAN — Security Audit Tool
// Головний серверний файл
require('dotenv').config();
const express = require('express');
const cors = require('cors');
const path = require('path');
const fs = require('fs');

const app = express();
const PORT = process.env.PORT || 3001;

// Переконуємося що директорія data існує
const dataDir = path.join(__dirname, 'data');
if (!fs.existsSync(dataDir)) fs.mkdirSync(dataDir, { recursive: true });

// Ініціалізуємо файл сканувань якщо не існує
const dataFile = path.join(dataDir, 'scans.json');
if (!fs.existsSync(dataFile)) {
  fs.writeFileSync(dataFile, JSON.stringify({ scans: [] }, null, 2));
}

// Middleware
app.use(cors({
  origin: '*',
  methods: ['GET', 'POST', 'DELETE'],
  allowedHeaders: ['Content-Type'],
}));
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// Маршрути API
const scanRouter = require('./routes/scan');
const historyRouter = require('./routes/history');

app.use('/api/scan', scanRouter);
app.use('/api/history', historyRouter);

// Fallback — повертаємо index.html для всіх інших GET запитів (SPA)
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// Глобальна обробка помилок
app.use((err, req, res, next) => {
  console.error('Серверна помилка:', err.stack);
  res.status(500).json({ error: 'Внутрішня помилка сервера' });
});

app.listen(PORT, () => {
  console.log(`
╔══════════════════════════════════════╗
║         VULNSCAN SERVER              ║
║   Security Audit Tool v1.0           ║
╠══════════════════════════════════════╣
║  Порт:    ${PORT}                       ║
║  URL:     http://localhost:${PORT}      ║
║  Дата:    ${new Date().toLocaleString('uk-UA')}   ║
╚══════════════════════════════════════╝
  `);
});
