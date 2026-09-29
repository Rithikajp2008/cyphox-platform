const express = require('express');
const router = express.Router();
const os = require('os');

// GET /api/health
router.get('/health', (req, res) => {
  res.json({
    status: 'OK',
    message: 'Cyphox Backend Recovery Engine is fully operational.',
    version: '1.0.0',
    platform: os.platform(),
    arch: os.arch(),
    uptime: process.uptime(),
    timestamp: new Date().toISOString()
  });
});

module.exports = router;
