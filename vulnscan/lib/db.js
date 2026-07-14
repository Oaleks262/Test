const Database = require('better-sqlite3');
const path = require('path');
const fs = require('fs');

const dataDir = path.join(__dirname, '..', 'data');
if (!fs.existsSync(dataDir)) fs.mkdirSync(dataDir, { recursive: true });

const db = new Database(path.join(dataDir, 'vulnscan.db'));
db.pragma('journal_mode = WAL');

db.exec(`
  CREATE TABLE IF NOT EXISTS scans (
    id TEXT PRIMARY KEY,
    url TEXT NOT NULL,
    date TEXT NOT NULL,
    score INTEGER NOT NULL,
    grade TEXT NOT NULL,
    summary TEXT,
    critical_issues TEXT DEFAULT '[]',
    recommendations TEXT DEFAULT '[]',
    checks TEXT DEFAULT '[]',
    deep_php INTEGER DEFAULT 0
  );

  CREATE TABLE IF NOT EXISTS scheduled_scans (
    id TEXT PRIMARY KEY,
    url TEXT NOT NULL,
    schedule TEXT NOT NULL,
    deep_php INTEGER DEFAULT 0,
    enabled INTEGER DEFAULT 1,
    last_scan TEXT,
    next_scan TEXT,
    created_at TEXT NOT NULL
  );

  CREATE INDEX IF NOT EXISTS idx_scans_date ON scans(date);
  CREATE INDEX IF NOT EXISTS idx_scans_url ON scans(url);
`);

function parseScan(row) {
  if (!row) return null;
  const { deep_php, critical_issues, recommendations, checks, ...rest } = row;
  return {
    ...rest,
    deepPhp: Boolean(deep_php),
    critical_issues: JSON.parse(critical_issues || '[]'),
    recommendations: JSON.parse(recommendations || '[]'),
    checks: JSON.parse(checks || '[]'),
  };
}

function parseSchedule(row) {
  if (!row) return null;
  return { ...row, deepPhp: Boolean(row.deep_php), enabled: Boolean(row.enabled) };
}

const scanOps = {
  insert(scan) {
    db.prepare(`
      INSERT OR REPLACE INTO scans
        (id, url, date, score, grade, summary, critical_issues, recommendations, checks, deep_php)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).run(
      scan.id, scan.url, scan.date, scan.score, scan.grade, scan.summary,
      JSON.stringify(scan.critical_issues || []),
      JSON.stringify(scan.recommendations || []),
      JSON.stringify(scan.checks || []),
      scan.deepPhp ? 1 : 0
    );
    db.prepare(`
      DELETE FROM scans WHERE id NOT IN (SELECT id FROM scans ORDER BY date DESC LIMIT 500)
    `).run();
  },

  findById(id) {
    return parseScan(db.prepare('SELECT * FROM scans WHERE id = ?').get(id));
  },

  findRecent(limit = 20) {
    return db.prepare('SELECT * FROM scans ORDER BY date DESC LIMIT ?').all(limit).map(parseScan);
  },

  findByUrl(url, limit = 20) {
    return db.prepare('SELECT id, url, date, score, grade FROM scans WHERE url = ? ORDER BY date DESC LIMIT ?')
      .all(url, limit);
  },

  delete(id) {
    return db.prepare('DELETE FROM scans WHERE id = ?').run(id).changes > 0;
  },
};

const scheduleOps = {
  insert(s) {
    db.prepare(`
      INSERT OR REPLACE INTO scheduled_scans
        (id, url, schedule, deep_php, enabled, last_scan, next_scan, created_at)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    `).run(s.id, s.url, s.schedule, s.deepPhp ? 1 : 0, 1,
      s.last_scan || null, s.next_scan || null, s.created_at || new Date().toISOString());
  },

  findAll() {
    return db.prepare('SELECT * FROM scheduled_scans ORDER BY created_at DESC').all().map(parseSchedule);
  },

  findById(id) {
    return parseSchedule(db.prepare('SELECT * FROM scheduled_scans WHERE id = ?').get(id));
  },

  update(id, cols) {
    const sets = Object.keys(cols).map(k => `${k} = ?`).join(', ');
    db.prepare(`UPDATE scheduled_scans SET ${sets} WHERE id = ?`).run(...Object.values(cols), id);
  },

  delete(id) {
    return db.prepare('DELETE FROM scheduled_scans WHERE id = ?').run(id).changes > 0;
  },
};

module.exports = { db, scanOps, scheduleOps };
