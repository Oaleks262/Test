const express = require('express');
const router = express.Router();
const { scanOps } = require('../lib/db');

router.get('/', (req, res) => {
  try {
    res.json(scanOps.findRecent(20));
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

module.exports = router;
