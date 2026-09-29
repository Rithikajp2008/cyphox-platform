const express = require('express');
const router = express.Router();
const db = require('../db/database');
const { optionalAuth } = require('../middleware/auth');

// GET /api/dashboard/stats
router.get('/stats', optionalAuth, (req, res) => {
  const stats = db.getStats(req.user ? req.user.id : null);
  const recentOps = db.getOperations(req.user ? req.user.id : null).slice(0, 5);

  res.json({
    status: 'SUCCESS',
    stats: {
      devices: stats.devices,
      completedOps: stats.completedOps,
      pending: stats.pending,
      verified: stats.verified,
      totalCertificates: stats.totalCertificates
    },
    recentActivities: recentOps
  });
});

module.exports = router;
