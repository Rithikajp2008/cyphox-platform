const express = require('express');
const router = express.Router();
const forensicsEngine = require('../engine/forensicsEngine');
const db = require('../db/database');
const { optionalAuth } = require('../middleware/auth');

// POST /api/forensics/analyze
router.post('/analyze', optionalAuth, (req, res) => {
  try {
    const { targetPath, targetName } = req.body;
    const analysis = forensicsEngine.analyzeArtifact(targetPath, { name: targetName });

    db.addOperation({
      type: 'FORENSIC_ANALYSIS',
      target: targetName || targetPath || 'Evidence Target',
      status: 'COMPLETED',
      userId: req.user ? req.user.id : 'guest',
      details: `Forensic analysis complete. SHA256: ${analysis.hashes.sha256.substring(0, 16)}...`,
      sha256: analysis.hashes.sha256
    });

    res.json({
      status: 'SUCCESS',
      analysis
    });
  } catch (err) {
    res.status(500).json({
      status: 'ERROR',
      message: 'Forensic analysis failed.',
      error: err.message
    });
  }
});

// POST /api/forensics/hex-view
router.post('/hex-view', optionalAuth, (req, res) => {
  try {
    const { offset = 0, length = 256, targetPath } = req.body;
    let buffer;

    if (targetPath && require('fs').existsSync(targetPath)) {
      const fd = require('fs').openSync(targetPath, 'r');
      buffer = Buffer.alloc(length);
      require('fs').readSync(fd, buffer, 0, length, parseInt(offset, 10) || 0);
      require('fs').closeSync(fd);
    } else {
      buffer = Buffer.from('435950484F585F464F52454E5349435F45564944454E43455F534543544F5200FFD8FFE000104A46494600010101006000600000FFDB004300080606070605080707070909080A0C140D0C0B0B0C1912130F141D1A1F1E1D1A1C1C20242E2720222C231C1C2837292C30313434341F27393D38323C2E333432', 'hex');
    }

    const hexDump = forensicsEngine.getHexDump(buffer, parseInt(offset, 10) || 0, length);

    res.json({
      status: 'SUCCESS',
      hexDump
    });
  } catch (err) {
    res.status(500).json({
      status: 'ERROR',
      message: 'Failed to generate hex dump.',
      error: err.message
    });
  }
});

// GET /api/forensics/timeline
router.get('/timeline', optionalAuth, (req, res) => {
  const operations = db.getOperations(req.user ? req.user.id : null);
  const timeline = forensicsEngine.getTimeline(operations);

  res.json({
    status: 'SUCCESS',
    count: timeline.length,
    timeline
  });
});

module.exports = router;
