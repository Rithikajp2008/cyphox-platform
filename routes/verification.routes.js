const express = require('express');
const router = express.Router();
const verificationEngine = require('../engine/verificationEngine');
const db = require('../db/database');
const { optionalAuth } = require('../middleware/auth');

const activeVerifications = {};

// POST /api/verification/start
router.post('/start', optionalAuth, async (req, res) => {
  try {
    const { targetId, targetName, samplingRate = 25 } = req.body;
    const jobId = `ver_job_${Date.now()}_${Math.random().toString(36).substr(2, 6)}`;

    const job = {
      id: jobId,
      userId: req.user ? req.user.id : 'guest',
      targetName: targetName || targetId || 'Sanitized Storage Target',
      samplingRate: `${samplingRate}%`,
      status: 'RUNNING',
      percentage: 0,
      currentEntropy: 0.0000,
      startedAt: new Date().toISOString()
    };

    activeVerifications[jobId] = job;
    db.setJob(jobId, job);

    (async () => {
      try {
        const result = await verificationEngine.verifyTarget(
          { id: targetId, name: job.targetName, sectors: 2048000 },
          samplingRate,
          (progress) => {
            activeVerifications[jobId] = { ...activeVerifications[jobId], ...progress };
            db.setJob(jobId, activeVerifications[jobId]);
          }
        );

        activeVerifications[jobId].status = result.status;
        activeVerifications[jobId].percentage = 100;
        activeVerifications[jobId].result = result;
        activeVerifications[jobId].completedAt = new Date().toISOString();
        db.setJob(jobId, activeVerifications[jobId]);

        // Add to history log
        db.addOperation({
          type: 'INDEPENDENT_VERIFICATION',
          target: job.targetName,
          status: result.status,
          userId: job.userId,
          details: `Verification completed (${result.status}): Entropy ${result.entropy}, Sampling Rate ${result.samplingRate}`,
          verified: result.status === 'VERIFIED'
        });
      } catch (err) {
        console.error('Verification error:', err);
        if (activeVerifications[jobId]) {
          activeVerifications[jobId].status = 'FAILED';
          activeVerifications[jobId].error = err.message;
          db.setJob(jobId, activeVerifications[jobId]);
        }
      }
    })();

    res.status(202).json({
      status: 'SUCCESS',
      message: 'Independent verification process initialized.',
      jobId,
      job
    });
  } catch (err) {
    res.status(500).json({
      status: 'ERROR',
      message: 'Failed to start verification.',
      error: err.message
    });
  }
});

// GET /api/verification/status/:jobId
router.get('/status/:jobId', optionalAuth, (req, res) => {
  const job = activeVerifications[req.params.jobId] || db.getJob(req.params.jobId);
  if (!job) {
    return res.status(404).json({ status: 'ERROR', message: 'Verification job not found.' });
  }

  res.json({
    status: 'SUCCESS',
    job
  });
});

module.exports = router;
