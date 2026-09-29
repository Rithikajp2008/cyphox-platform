const express = require('express');
const router = express.Router();
const backupEngine = require('../engine/backupEngine');
const db = require('../db/database');
const { optionalAuth } = require('../middleware/auth');

// POST /api/backup/create
router.post('/create', optionalAuth, async (req, res) => {
  try {
    const { targetName, targetPath, type = 'FULL_IMAGE_SNAPSHOT', encrypt = false } = req.body;

    const backupRecord = await backupEngine.createBackup(
      { name: targetName, path: targetPath },
      { type, encrypt }
    );

    // Save to operations
    db.addOperation({
      type: 'BACKUP_CREATION',
      target: targetName || targetPath || 'System Storage',
      status: 'COMPLETED',
      userId: req.user ? req.user.id : 'guest',
      details: `Created ${type} backup (${backupRecord.sizeFormatted})`,
      backupId: backupRecord.id
    });

    res.status(201).json({
      status: 'SUCCESS',
      message: 'Backup created successfully.',
      backup: backupRecord
    });
  } catch (err) {
    console.error('Backup creation error:', err);
    res.status(500).json({
      status: 'ERROR',
      message: 'Failed to create backup.',
      error: err.message
    });
  }
});

// GET /api/backup/list
router.get('/list', optionalAuth, (req, res) => {
  try {
    const backups = backupEngine.listBackups();
    res.json({
      status: 'SUCCESS',
      count: backups.length,
      backups
    });
  } catch (err) {
    res.status(500).json({
      status: 'ERROR',
      message: 'Failed to list backups.'
    });
  }
});

// POST /api/backup/restore
router.post('/restore', optionalAuth, (req, res) => {
  try {
    const { backupId, targetDir } = req.body;
    if (!backupId) {
      return res.status(400).json({ status: 'ERROR', message: 'backupId is required.' });
    }

    const result = backupEngine.restoreBackup(backupId, targetDir);

    db.addOperation({
      type: 'BACKUP_RESTORE',
      target: targetDir || 'Default Location',
      status: 'COMPLETED',
      userId: req.user ? req.user.id : 'guest',
      details: `Restored backup ${backupId}`,
      backupId
    });

    res.json({
      status: 'SUCCESS',
      message: 'Backup restored successfully.',
      result
    });
  } catch (err) {
    res.status(500).json({
      status: 'ERROR',
      message: err.message || 'Failed to restore backup.'
    });
  }
});

module.exports = router;
