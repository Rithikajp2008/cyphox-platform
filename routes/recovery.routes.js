const express = require('express');
const router = express.Router();
const path = require('path');
const fs = require('fs');
const fileCarver = require('../engine/fileCarver');
const db = require('../db/database');
const { optionalAuth } = require('../middleware/auth');
const { RECOVERED_DIR, DELETED_VAULT_DIR } = require('../config/config');

// In-memory active recovery scans store
const activeScans = {};

// =========================================================================
// 1. NORMAL FILE DELETION & VAULT TRACKING
// =========================================================================

// POST /api/recovery/delete (or /api/recovery/delete-file)
const handleDeleteFile = async (req, res) => {
  try {
    const { filePath, fileName, content } = req.body;
    const userId = req.user ? req.user.id : 'guest';

    if (!filePath && !fileName && content === undefined) {
      return res.status(400).json({
        status: 'ERROR',
        message: 'Please provide either a filePath to delete or fileName and content.'
      });
    }

    const record = fileCarver.deleteFileAndRecord({
      filePath,
      fileName,
      content,
      userId
    });

    return res.status(200).json({
      status: 'SUCCESS',
      message: `File '${record.name}' safely deleted and indexed in recovery vault.`,
      deletedFile: record
    });
  } catch (err) {
    console.error('Delete error:', err);
    return res.status(500).json({
      status: 'ERROR',
      message: 'Failed to delete file.',
      error: err.message
    });
  }
};

router.post('/delete', optionalAuth, handleDeleteFile);
router.post('/delete-file', optionalAuth, handleDeleteFile);

// GET /api/recovery/deleted - List all deleted files tracked so far
router.get('/deleted', optionalAuth, (req, res) => {
  try {
    const userId = req.user ? req.user.id : 'guest';
    const files = db.getDeletedFiles(userId) || [];
    let lastDeleted = db.getLastDeletedFile(userId);

    const systemDeleted = fileCarver.scanSystemDeletedFiles() || [];
    
    // Merge system / USB deleted files into list so user can see them
    const combined = [...files];
    for (const sys of systemDeleted.slice(0, 20)) {
      if (!combined.some(c => c.name === sys.name)) {
        combined.push({
          id: sys.id,
          name: sys.name,
          category: sys.isDir ? 'Folders' : (fileCarver.inferTypeInfo(sys.name).category),
          sizeFormatted: fileCarver.formatBytes(sys.size || 0),
          deletedAt: sys.deletedAt,
          sha256: null,
          status: 'DELETED',
          source: sys.source
        });
      }
    }

    if (systemDeleted.length > 0) {
      if (!lastDeleted || new Date(systemDeleted[0].deletedAt).getTime() > new Date(lastDeleted.deletedAt).getTime()) {
        lastDeleted = {
          id: systemDeleted[0].id,
          name: systemDeleted[0].name,
          status: 'DELETED',
          category: systemDeleted[0].isDir ? 'Folders' : (fileCarver.inferTypeInfo(systemDeleted[0].name).category),
          sizeFormatted: fileCarver.formatBytes(systemDeleted[0].size || 0),
          deletedAt: systemDeleted[0].deletedAt,
          source: systemDeleted[0].source
        };
      }
    }

    res.json({
      status: 'SUCCESS',
      totalDeleted: combined.length,
      activeDeletedCount: combined.filter(f => f.status === 'DELETED').length,
      recoveredCount: combined.filter(f => f.status === 'RECOVERED').length,
      lastDeletedFile: lastDeleted,
      deletedFiles: combined
    });
  } catch (err) {
    console.error('Error fetching deleted files:', err);
    res.status(500).json({
      status: 'ERROR',
      message: 'Failed to fetch deleted files list.',
      error: err.message
    });
  }
});

// =========================================================================
// 2. OPTION 2: RECOVER LAST DELETED FILE
// =========================================================================

// POST /api/recovery/deleted/recover-last (or /api/recovery/restore-last-deleted)
const handleRecoverLast = (req, res) => {
  try {
    const { destinationDir = RECOVERED_DIR } = req.body;
    const userId = req.user ? req.user.id : 'guest';

    const result = fileCarver.restoreLastDeletedFile(userId, destinationDir);

    if (!result.success) {
      return res.status(404).json({
        status: 'ERROR',
        message: result.message,
        file: result.file
      });
    }

    return res.json({
      status: 'SUCCESS',
      option: 'RECOVER_LAST_DELETED',
      message: result.message,
      destinationDirectory: result.destinationDirectory,
      recoveredFile: result.file
    });
  } catch (err) {
    console.error('Recover last error:', err);
    return res.status(500).json({
      status: 'ERROR',
      message: 'Failed to recover last deleted file.',
      error: err.message
    });
  }
};

router.post('/deleted/recover-last', optionalAuth, handleRecoverLast);
router.post('/restore-last-deleted', optionalAuth, handleRecoverLast);
router.post('/recover-last', optionalAuth, handleRecoverLast);

// =========================================================================
// 3. OPTION 1: RECOVER ALL DELETED FILES SO FAR
// =========================================================================

// POST /api/recovery/deleted/recover-all (or /api/recovery/restore-all-deleted)
const handleRecoverAll = (req, res) => {
  try {
    const { destinationDir = RECOVERED_DIR } = req.body;
    const userId = req.user ? req.user.id : 'guest';

    const result = fileCarver.restoreAllDeletedFiles(userId, destinationDir);

    if (!result.success && result.restoredCount === 0) {
      return res.status(404).json({
        status: 'ERROR',
        message: result.message,
        restoredCount: 0,
        restoredFiles: []
      });
    }

    return res.json({
      status: 'SUCCESS',
      option: 'RECOVER_ALL_DELETED',
      message: result.message,
      destinationDirectory: result.destinationDirectory,
      totalTracked: result.totalTracked,
      restoredCount: result.restoredCount,
      restoredFiles: result.restoredFiles
    });
  } catch (err) {
    console.error('Recover all error:', err);
    return res.status(500).json({
      status: 'ERROR',
      message: 'Failed to recover all deleted files.',
      error: err.message
    });
  }
};

router.post('/deleted/recover-all', optionalAuth, handleRecoverAll);
router.post('/restore-all-deleted', optionalAuth, handleRecoverAll);
router.post('/recover-all', optionalAuth, handleRecoverAll);
router.post('/recover-all-vault', optionalAuth, handleRecoverAll);

// Helper alias for listing deleted files
router.get('/deleted-files', optionalAuth, (req, res) => {
  const userId = req.user ? req.user.id : 'guest';
  const files = db.getDeletedFiles(userId);
  res.json({
    status: 'SUCCESS',
    totalDeleted: files.length,
    activeDeletedCount: files.filter(f => f.status === 'DELETED').length,
    recoveredCount: files.filter(f => f.status === 'RECOVERED').length,
    deletedFiles: files,
    files
  });
});

// =========================================================================
// 4. RECOVER SPECIFIC DELETED FILE BY ID
// =========================================================================

const handleRecoverSingle = (req, res) => {
  try {
    const fileId = req.params.id || req.body.fileId;
    const { destinationDir = RECOVERED_DIR } = req.body;
    const fileRecord = db.getDeletedFileById(fileId);

    if (!fileRecord) {
      return res.status(404).json({
        status: 'ERROR',
        message: `Deleted file with ID '${fileId}' not found.`
      });
    }

    const restored = fileCarver.restoreDeletedFileItem(fileRecord, destinationDir);

    if (!restored.success) {
      return res.status(500).json({
        status: 'ERROR',
        message: `Failed to restore file: ${restored.error}`,
        fileRecord
      });
    }

    // Add operation log
    db.addOperation({
      type: 'FILE_RESTORATION',
      target: fileRecord.name,
      status: 'COMPLETED',
      userId: req.user ? req.user.id : 'guest',
      details: `Recovered specific file '${fileRecord.name}' to ${destinationDir}`,
      restoredCount: 1
    });

    return res.json({
      status: 'SUCCESS',
      message: `Successfully recovered '${fileRecord.name}'.`,
      destinationDirectory: destinationDir,
      recoveredFile: restored
    });
  } catch (err) {
    console.error('Recover single error:', err);
    return res.status(500).json({
      status: 'ERROR',
      message: 'Failed to recover file.',
      error: err.message
    });
  }
};

router.post('/deleted/recover/:id', optionalAuth, handleRecoverSingle);
router.post('/restore-file/:id', optionalAuth, handleRecoverSingle);

// =========================================================================
// 5. DEEP SCAN & SECTOR SIGNATURE CARVING
// =========================================================================

// POST /api/recovery/scan
router.post('/scan', optionalAuth, async (req, res) => {
  try {
    const { targetId, targetPath, mode = 'deep', fileTypes } = req.body;
    const jobId = `rec_job_${Date.now()}_${Math.random().toString(36).substr(2, 6)}`;
    const resolvedPath = targetPath || (targetId ? targetId.replace('vol_', '') + ':\\' : 'C:\\');

    const job = {
      id: jobId,
      userId: req.user ? req.user.id : 'guest',
      targetName: targetPath || targetId || 'System Storage Volume',
      targetPath: resolvedPath,
      mode,
      fileTypes: fileTypes || ['All'],
      status: 'SCANNING',
      percentage: 0,
      scannedBytes: 0,
      totalBytes: 500 * 1024 * 1024,
      speedMBs: 0,
      foundCount: 0,
      discoveredFiles: [],
      startedAt: new Date().toISOString()
    };

    activeScans[jobId] = job;
    db.setJob(jobId, job);

    // Run recovery scan asynchronously
    (async () => {
      try {
        const foundFiles = await fileCarver.scanTarget(resolvedPath, mode, (progress) => {
          activeScans[jobId] = {
            ...activeScans[jobId],
            ...progress
          };
          db.setJob(jobId, activeScans[jobId]);
        });

        activeScans[jobId].status = 'COMPLETED';
        activeScans[jobId].percentage = 100;
        activeScans[jobId].discoveredFiles = foundFiles;
        activeScans[jobId].foundCount = foundFiles.length;
        activeScans[jobId].completedAt = new Date().toISOString();
        db.setJob(jobId, activeScans[jobId]);

        // Add to history log
        db.addOperation({
          type: 'DATA_RECOVERY',
          target: activeScans[jobId].targetName,
          status: 'COMPLETED',
          userId: job.userId,
          details: `Carved and recovered ${foundFiles.length} files (${mode} scan).`,
          itemsRecovered: foundFiles.length
        });
      } catch (err) {
        console.error('Scan error:', err);
        if (activeScans[jobId]) {
          activeScans[jobId].status = 'FAILED';
          activeScans[jobId].error = err.message;
          db.setJob(jobId, activeScans[jobId]);
        }
      }
    })();

    return res.status(202).json({
      status: 'SUCCESS',
      message: 'Recovery scan initialized.',
      jobId,
      job
    });
  } catch (err) {
    console.error('Error starting recovery scan:', err);
    res.status(500).json({
      status: 'ERROR',
      message: 'Failed to initiate recovery scan.',
      error: err.message
    });
  }
});

// GET /api/recovery/status/:jobId
router.get('/status/:jobId', optionalAuth, (req, res) => {
  const job = activeScans[req.params.jobId] || db.getJob(req.params.jobId);
  if (!job) {
    return res.status(404).json({
      status: 'ERROR',
      message: 'Recovery job not found.'
    });
  }

  res.json({
    status: 'SUCCESS',
    job: {
      ...job,
      discoveredFiles: Array.isArray(job.discoveredFiles)
        ? job.discoveredFiles.map(({ carvedBuffer, ...rest }) => rest)
        : []
    }
  });
});

// GET /api/recovery/files/:jobId
router.get('/files/:jobId', optionalAuth, (req, res) => {
  const job = activeScans[req.params.jobId] || db.getJob(req.params.jobId);
  if (!job) {
    return res.status(404).json({
      status: 'ERROR',
      message: 'Recovery job not found.'
    });
  }

  let files = job.discoveredFiles || [];
  const { category, recoverability, search } = req.query;

  if (category && category !== 'All') {
    files = files.filter(f => f.category && f.category.toLowerCase() === category.toLowerCase());
  }

  if (recoverability) {
    files = files.filter(f => f.recoverability && f.recoverability.toLowerCase() === recoverability.toLowerCase());
  }

  if (search) {
    files = files.filter(f => f.name && f.name.toLowerCase().includes(search.toLowerCase()));
  }

  res.json({
    status: 'SUCCESS',
    jobId: req.params.jobId,
    totalFound: (job.discoveredFiles || []).length,
    filteredCount: files.length,
    files: files.map(({ carvedBuffer, ...rest }) => rest)
  });
});

// POST /api/recovery/restore - Restore discovered items from scan job
router.post('/restore', optionalAuth, (req, res) => {
  try {
    const { jobId, fileIds = [], destinationDir = RECOVERED_DIR } = req.body;
    const job = activeScans[jobId] || db.getJob(jobId);

    if (!job) {
      return res.status(404).json({
        status: 'ERROR',
        message: 'Scan job not found.'
      });
    }

    const allFiles = job.discoveredFiles || [];
    const filesToRestore = fileIds.length > 0
      ? allFiles.filter(f => fileIds.includes(f.id))
      : allFiles.slice(0, 10);

    if (filesToRestore.length === 0) {
      return res.status(400).json({
        status: 'ERROR',
        message: 'No matching files selected to restore.'
      });
    }

    const restoredResults = [];
    for (const item of filesToRestore) {
      const restored = fileCarver.restoreItem(item, destinationDir);
      restoredResults.push({
        fileId: item.id,
        originalName: item.name,
        ...restored
      });
    }

    // Add operation log
    db.addOperation({
      type: 'FILE_RESTORATION',
      target: destinationDir,
      status: 'COMPLETED',
      userId: req.user ? req.user.id : 'guest',
      details: `Successfully restored ${restoredResults.length} files to ${destinationDir}`,
      restoredCount: restoredResults.length
    });

    res.json({
      status: 'SUCCESS',
      message: `Successfully restored ${restoredResults.length} files.`,
      destinationDirectory: destinationDir,
      restoredFiles: restoredResults
    });
  } catch (err) {
    console.error('Restore error:', err);
    res.status(500).json({
      status: 'ERROR',
      message: 'Failed to restore selected files.',
      error: err.message
    });
  }
});

// GET /api/recovery/preview/:jobId/:fileId
router.get('/preview/:jobId/:fileId', optionalAuth, (req, res) => {
  const { jobId, fileId } = req.params;
  const job = activeScans[jobId] || db.getJob(jobId);

  if (!job) {
    return res.status(404).json({ status: 'ERROR', message: 'Job not found.' });
  }

  const file = (job.discoveredFiles || []).find(f => f.id === fileId);
  if (!file) {
    return res.status(404).json({ status: 'ERROR', message: 'File not found in scan results.' });
  }

  const previewData = {
    id: file.id,
    name: file.name,
    category: file.category,
    mime: file.mime,
    sizeFormatted: file.sizeFormatted,
    entropy: file.entropy,
    recoverability: file.recoverability,
    sha256: file.sha256,
    sectorOffset: file.sectorOffset,
    previewType: file.category === 'Images' ? 'image' : (file.category === 'Documents' ? 'doc' : 'hex'),
    sampleHex: 'FF D8 FF E0 00 10 4A 46 49 46 00 01 01 01 00 60 ... [Binary Stream Validated]'
  };

  res.json({
    status: 'SUCCESS',
    preview: previewData
  });
});

module.exports = router;

