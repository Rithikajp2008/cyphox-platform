const express = require('express');
const router = express.Router();
const erasureEngine = require('../engine/erasureEngine');

// GET /api/sanitization/methods
router.get('/methods', (req, res) => {
  const methods = erasureEngine.getMethods();
  res.json({
    status: 'SUCCESS',
    count: methods.length,
    methods
  });
});

module.exports = router;
