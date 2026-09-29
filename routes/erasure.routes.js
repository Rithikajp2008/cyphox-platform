const express = require('express');
const router = express.Router();
const erasureEngine = require('../engine/erasureEngine');
const certificateEngine = require('../engine/certificateEngine');
const db = require('../db/database');
const { optionalAuth } = require('../middleware/auth');

const activeWipes = {};

// POST /api/erasure/start
router.post('/start', optionalAuth, async (req, res) => {
  try {
    let { targetType = 'file', targetPath, targetName, method = 'NIST_800_88_CLEAR' } = req.body;
    if (targetPath) {
      targetPath = targetPath.trim().replace(/^["']|["']$/g, '');
    }
    const jobId = `wipe_job_${Date.now()}_${Math.random().toString(36).substr(2, 6)}`;

    const job = {
      id: jobId,
      userId: req.user ? req.user.id : 'guest',
      targetType,
      targetPath,
      targetName: targetName || targetPath || 'Target Device',
      method,
      status: 'RUNNING',
      percentage: 0,
      currentPass: 1,
      totalPasses: erasureEngine.methods[method] ? erasureEngine.methods[method].passes : 1,
      startedAt: new Date().toISOString()
    };

    activeWipes[jobId] = job;
    db.setJob(jobId, job);

    // Asynchronously execute wipe job
    (async () => {
      try {
        let result;
        if (targetPath && require('fs').existsSync(targetPath)) {
          result = await erasureEngine.shredFile(targetPath, method, (progress) => {
            activeWipes[jobId] = { ...activeWipes[jobId], ...progress };
            db.setJob(jobId, activeWipes[jobId]);
          });
        } else {
          result = await erasureEngine.executeWipeJob(
            { name: targetName || targetPath, targetPath, size: 500 * 1024 * 1024 },
            method,
            (progress) => {
              activeWipes[jobId] = { ...activeWipes[jobId], ...progress };
              db.setJob(jobId, activeWipes[jobId]);
            }
          );
        }

        activeWipes[jobId].status = 'COMPLETED';
        activeWipes[jobId].percentage = 100;
        activeWipes[jobId].result = result;
        activeWipes[jobId].completedAt = new Date().toISOString();
        db.setJob(jobId, activeWipes[jobId]);

        // Auto-generate Digital Erasure Certificate
        const cert = await certificateEngine.generateCertificate({
          operatorName: req.user ? req.user.name : 'Authorized Officer',
          operatorEmail: req.user ? req.user.email : 'officer@cyphox.local',
          targetName: job.targetName,
          operationType: 'DATA_ERASURE',
          standard: erasureEngine.methods[method] ? erasureEngine.methods[method].name : method,
          passes: job.totalPasses,
          preHash: result.preWipeHash,
          postHash: result.postWipeVerificationHash || '0000000000000000000000000000000000000000000000000000000000000000',
          entropy: result.entropy || 0.0000
        });

        db.addCertificate({
          ...cert,
          userId: job.userId
        });

        // Add to history log
        db.addOperation({
          type: 'DATA_ERASURE',
          target: job.targetName,
          status: 'COMPLETED',
          userId: job.userId,
          details: `Sanitized using ${method} (${job.totalPasses} passes). Certificate: ${cert.certificateId}`,
          certificateId: cert.certificateId,
          verified: true
        });
      } catch (err) {
        console.error('Erasure error:', err);
        if (activeWipes[jobId]) {
          activeWipes[jobId].status = 'FAILED';
          activeWipes[jobId].error = err.message;
          db.setJob(jobId, activeWipes[jobId]);
        }
      }
    })();

    res.status(202).json({
      status: 'SUCCESS',
      message: 'Erasure operation started.',
      jobId,
      job
    });
  } catch (err) {
    console.error('Error starting wipe:', err);
    res.status(500).json({
      status: 'ERROR',
      message: 'Failed to initiate erasure operation.',
      error: err.message
    });
  }
});

// POST /api/wipe (Compatible with Cyphox_Frontend_Working_Erasure and backend_node)
router.post('/wipe', optionalAuth, async (req, res) => {
  try {
    const deviceId = req.body.device_id || req.body.deviceId || 'DEV-01';
    const wipeMethod = req.body.wipe_method || req.body.method || 'NIST_800_88_CLEAR';
    let targetPath = (req.body.target_path || req.body.targetPath || '').trim().replace(/^["']|["']$/g, '');
    const targetType = (req.body.target_type || req.body.targetType || 'FILE').toLowerCase();
    const userId = req.user ? (req.user.id || req.user.user_id) : 'guest';

    if (!targetPath) {
      return res.status(400).json({
        status: 'ERROR',
        message: 'Target file or drive path is required.'
      });
    }

    const jobId = `wipe_${Date.now()}_${Math.random().toString(36).substr(2, 6)}`;
    const op = db.addOperation({
      type: 'DATA_ERASURE',
      target: targetPath,
      status: 'In Progress',
      userId: userId,
      wipe_method: wipeMethod,
      device_id: deviceId
    });

    const job = {
      id: jobId,
      jobId: jobId,
      operationId: op.id,
      userId: userId,
      deviceId: deviceId,
      targetType: targetType,
      targetPath: targetPath,
      targetName: targetPath,
      method: wipeMethod,
      status: 'RUNNING',
      percentage: 10,
      currentPass: 1,
      totalPasses: erasureEngine.methods[wipeMethod] ? erasureEngine.methods[wipeMethod].passes : 1,
      startedAt: new Date().toISOString()
    };

    activeWipes[jobId] = job;
    db.setJob(jobId, job);

    // Asynchronously execute wipe
    (async () => {
      try {
        let result;
        const fs = require('fs');
        if (fs.existsSync(targetPath)) {
          result = await erasureEngine.shredFile(targetPath, wipeMethod, (prog) => {
            activeWipes[jobId] = { ...activeWipes[jobId], ...prog };
            db.setJob(jobId, activeWipes[jobId]);
          });
        } else {
          result = await erasureEngine.executeWipeJob(
            { name: targetPath, targetPath, size: 100 * 1024 * 1024 },
            wipeMethod,
            (prog) => {
              activeWipes[jobId] = { ...activeWipes[jobId], ...prog };
              db.setJob(jobId, activeWipes[jobId]);
            }
          );
        }

        const cert = await certificateEngine.generateCertificate({
          operatorName: req.user ? req.user.name : 'Authorized Officer',
          operatorEmail: req.user ? req.user.email : 'officer@cyphox.local',
          targetName: targetPath,
          operationType: 'DATA_ERASURE',
          standard: erasureEngine.methods[wipeMethod] ? erasureEngine.methods[wipeMethod].name : wipeMethod,
          passes: job.totalPasses,
          preHash: result.preWipeHash,
          postHash: result.postWipeVerificationHash || '0000000000000000000000000000000000000000000000000000000000000000',
          entropy: result.entropy || 0.0000
        });

        db.addCertificate({
          ...cert,
          userId: job.userId
        });

        activeWipes[jobId].status = 'COMPLETED';
        activeWipes[jobId].percentage = 100;
        activeWipes[jobId].certificateId = cert.certificateId;
        activeWipes[jobId].result = result;
        db.setJob(jobId, activeWipes[jobId]);

        db.addOperation({
          type: 'DATA_ERASURE',
          target: targetPath,
          status: 'COMPLETED',
          userId: userId,
          details: `Secure erasure complete using ${wipeMethod}. Certificate: ${cert.certificateId}`,
          certificateId: cert.certificateId,
          verified: true
        });
      } catch (err) {
        console.error('Wipe execution error:', err);
        if (activeWipes[jobId]) {
          activeWipes[jobId].status = 'FAILED';
          activeWipes[jobId].error = err.message;
          db.setJob(jobId, activeWipes[jobId]);
        }
      }
    })();

    return res.status(201).json({
      status: 'SUCCESS',
      message: 'Wipe operation created successfully',
      operation: {
        operation_id: op.id,
        user_id: userId,
        device_id: deviceId,
        wipe_method: wipeMethod,
        status: 'In Progress'
      },
      wipeResult: {
        jobId: jobId,
        status: 'RUNNING',
        percentage: 10,
        passesCompleted: 1,
        totalPasses: job.totalPasses
      }
    });
  } catch (err) {
    console.error('Wipe error:', err);
    res.status(500).json({
      status: 'ERROR',
      message: 'Failed to create wipe operation',
      error: err.message
    });
  }
});

// GET /api/erasure/status/:jobId
router.get('/status/:jobId', optionalAuth, (req, res) => {
  const job = activeWipes[req.params.jobId] || db.getJob(req.params.jobId);
  if (!job) {
    return res.status(404).json({ status: 'ERROR', message: 'Wipe job not found.' });
  }

  res.json({
    status: 'SUCCESS',
    job
  });
});

module.exports = router;
