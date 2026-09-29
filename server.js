const express = require('express');
const cors = require('cors');
const path = require('path');
const { PORT } = require('./config/config');

// Initialize database
require('./db/database');

const app = express();

// Middleware
app.use(cors({
  origin: '*',
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization']
}));
app.use(express.json({ limit: '50mb' }));
app.use(express.urlencoded({ extended: true, limit: '50mb' }));

// Serve static frontend files from 'public' directory
app.use(express.static(path.join(__dirname, 'public')));

// Register API Routes & Full Compatibility Aliases
app.use('/api', require('./routes/health.routes'));
app.use('/api/auth', require('./routes/auth.routes'));
app.use('/api', require('./routes/auth.routes')); // Allow /api/login and /api/register
app.use('/api', require('./routes/devices.routes'));
app.use('/api/devices', require('./routes/devices.routes'));
app.use('/api/recovery', require('./routes/recovery.routes'));
app.use('/api/backup', require('./routes/backup.routes'));
app.use('/api/erasure', require('./routes/erasure.routes'));
app.use('/api', require('./routes/erasure.routes')); // Allow /api/wipe directly
app.use('/api/sanitization', require('./routes/sanitization.routes'));
app.use('/api/verification', require('./routes/verification.routes'));
app.use('/api/forensics', require('./routes/forensics.routes'));
app.use('/api/certificates', require('./routes/certificates.routes'));
app.use('/api', require('./routes/certificates.routes'));
app.use('/api/history', require('./routes/history.routes'));
app.use('/api/operations', require('./routes/history.routes')); // backend_node compatibility
app.use('/api', require('./routes/history.routes'));
app.use('/api/dashboard', require('./routes/dashboard.routes'));

// Microservice / Contract Aliases (Forensic & Tamper modules)
app.use('/api/v1/forensics', require('./routes/forensics.routes'));
app.use('/api/v1/tamper', require('./routes/verification.routes'));
app.use('/api/v1', require('./routes/certificates.routes'));

// Catch-all route to serve the Cyphox Web App
app.get('*', (req, res) => {
  if (req.path.startsWith('/api')) {
    return res.status(404).json({
      status: 'ERROR',
      message: `API endpoint '${req.method} ${req.originalUrl}' not found.`
    });
  }
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// Error handling middleware
app.use((err, req, res, next) => {
  console.error('Unhandled server error:', err);
  res.status(500).json({
    status: 'ERROR',
    message: 'An unexpected internal server error occurred.',
    error: process.env.NODE_ENV === 'development' ? err.message : undefined
  });
});

app.listen(PORT, () => {
  console.log('===========================================================');
  console.log('  🛡️  CYPHOX RECOVERY & SANITIZATION ENGINE ACTIVE 🛡️ ');
  console.log('===========================================================');
  console.log(`⚡ Backend API Server running at: http://localhost:${PORT}/api`);
  console.log(`⚡ Web Application ready at:      http://localhost:${PORT}`);
  console.log(`⚡ Health Check Endpoint:         http://localhost:${PORT}/api/health`);
  console.log('===========================================================');
});
