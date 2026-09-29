const express = require('express');
const router = express.Router();
const db = require('../db/database');
const { optionalAuth } = require('../middleware/auth');

// GET /api/history
router.get('/history', optionalAuth, (req, res) => {
  const operations = db.getOperations(req.user ? req.user.id : null);
  res.json({
    status: 'SUCCESS',
    count: operations.length,
    operations
  });
});

// DELETE /api/history/:id
router.delete('/history/:id', optionalAuth, (req, res) => {
  const deleted = db.deleteOperation(req.params.id);
  if (!deleted) {
    return res.status(404).json({
      status: 'ERROR',
      message: 'History item not found.'
    });
  }

  res.json({
    status: 'SUCCESS',
    message: 'History item removed.'
  });
});

module.exports = router;
