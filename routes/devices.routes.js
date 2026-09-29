const express = require('express');
const router = express.Router();
const driveManager = require('../engine/driveManager');
const db = require('../db/database');
const { optionalAuth } = require('../middleware/auth');

// GET /api/devices
router.get('/devices', optionalAuth, async (req, res) => {
  try {
    const devices = await driveManager.getSystemDevices();
    db.data.devices = devices;
    db.save();

    res.json({
      status: 'SUCCESS',
      count: devices.length,
      devices
    });
  } catch (err) {
    console.error('Error fetching devices:', err);
    res.status(500).json({
      status: 'ERROR',
      message: 'Failed to enumerate connected storage devices.',
      error: err.message
    });
  }
});

// GET /api/devices/:id
router.get('/devices/:id', optionalAuth, async (req, res) => {
  try {
    const devices = await driveManager.getSystemDevices();
    const device = devices.find(d => d.id === req.params.id || d.deviceId === req.params.id);

    if (!device) {
      return res.status(404).json({
        status: 'ERROR',
        message: 'Device not found.'
      });
    }

    res.json({
      status: 'SUCCESS',
      device
    });
  } catch (err) {
    res.status(500).json({
      status: 'ERROR',
      message: 'Failed to get device details.'
    });
  }
});

module.exports = router;
