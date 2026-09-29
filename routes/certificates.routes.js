const express = require('express');
const router = express.Router();
const certificateEngine = require('../engine/certificateEngine');
const db = require('../db/database');
const { optionalAuth } = require('../middleware/auth');

// GET /api/certificates
router.get('/certificates', optionalAuth, (req, res) => {
  const certs = db.getCertificates(req.user ? req.user.id : null);
  res.json({
    status: 'SUCCESS',
    count: certs.length,
    certificates: certs
  });
});

// GET /api/certificates/:id
router.get('/certificates/:id', optionalAuth, (req, res) => {
  const cert = db.getCertificateById(req.params.id);
  if (!cert) {
    return res.status(404).json({
      status: 'ERROR',
      message: 'Certificate not found.'
    });
  }

  res.json({
    status: 'SUCCESS',
    certificate: cert
  });
});

// GET /api/certificates/:id/verify (Public QR validation endpoint)
router.get('/certificates/:id/verify', (req, res) => {
  const cert = db.getCertificateById(req.params.id);
  if (!cert) {
    return res.status(404).json({
      status: 'ERROR',
      verified: false,
      message: 'Certificate not found or has been revoked.'
    });
  }

  const verification = certificateEngine.verifyCertificateSignature(cert);

  res.json({
    status: 'SUCCESS',
    verified: verification.isValid,
    certificateId: cert.certificateId,
    issuedAt: cert.issuedAt,
    target: cert.target,
    operation: cert.operation,
    operator: cert.operator,
    integrityCheck: verification.status
  });
});

// POST /api/certificates/generate
router.post('/certificates/generate', optionalAuth, async (req, res) => {
  try {
    const certData = await certificateEngine.generateCertificate({
      operatorName: req.user ? req.user.name : (req.body.operatorName || 'Forensic Officer'),
      operatorEmail: req.user ? req.user.email : 'admin@cyphox.local',
      targetName: req.body.targetName || 'Storage Device',
      operationType: req.body.operationType || 'DATA_ERASURE',
      standard: req.body.standard || 'NIST SP 800-88 Rev 1',
      passes: req.body.passes || 3,
      entropy: req.body.entropy || 0.0000
    });

    db.addCertificate({
      ...certData,
      userId: req.user ? req.user.id : 'guest'
    });

    res.status(201).json({
      status: 'SUCCESS',
      message: 'Certificate issued successfully.',
      certificate: certData
    });
  } catch (err) {
    res.status(500).json({
      status: 'ERROR',
      message: 'Failed to generate certificate.'
    });
  }
});

module.exports = router;
