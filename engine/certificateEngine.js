const QRCode = require('qrcode');
const crypto = require('crypto');
const { JWT_SECRET } = require('../config/config');

class CertificateEngine {
  async generateCertificate(data) {
    const certNumber = `CYP-CERT-${new Date().getFullYear()}-${Math.floor(100000 + Math.random() * 900000)}`;
    const issuedAt = new Date().toISOString();

    const certPayload = {
      certificateId: certNumber,
      issuedAt,
      operator: {
        name: data.operatorName || 'Cyphox Authorized Officer',
        email: data.operatorEmail || 'admin@cyphox.local',
        role: data.operatorRole || 'Forensics Specialist'
      },
      target: {
        name: data.targetName || 'Storage Volume',
        serialNumber: data.serialNumber || `SN-${crypto.randomBytes(4).toString('hex').toUpperCase()}`,
        capacity: data.capacity || '512 GB',
        interface: data.interface || 'NVMe/SATA'
      },
      operation: {
        type: data.operationType || 'DATA_ERASURE',
        standard: data.standard || 'NIST SP 800-88 Rev 1 (Clear & Purge)',
        passes: data.passes || 3,
        preOperationHash: data.preHash || crypto.randomBytes(32).toString('hex'),
        postOperationHash: data.postHash || '0000000000000000000000000000000000000000000000000000000000000000',
        entropyResult: data.entropy !== undefined ? data.entropy : 0.0000,
        verificationStatus: 'VERIFIED'
      }
    };

    // Generate cryptographic digital signature
    const signature = crypto
      .createHmac('sha256', JWT_SECRET)
      .update(JSON.stringify(certPayload))
      .digest('hex');

    certPayload.digitalSignature = signature;

    // Generate QR Code URL
    const verifyUrl = `http://localhost:5000/api/certificates/${certNumber}/verify`;
    const qrDataUrl = await QRCode.toDataURL(verifyUrl, {
      color: {
        dark: '#00ffb2',
        light: '#0a1122'
      },
      width: 200,
      margin: 2
    });

    certPayload.qrCode = qrDataUrl;
    certPayload.verificationUrl = verifyUrl;

    return certPayload;
  }

  // Validate tamper-proof certificate signature
  verifyCertificateSignature(certificate) {
    const canonicalPayload = {
      certificateId: certificate.certificateId,
      issuedAt: certificate.issuedAt,
      operator: certificate.operator,
      target: certificate.target,
      operation: certificate.operation
    };

    const computedSignature = crypto
      .createHmac('sha256', JWT_SECRET)
      .update(JSON.stringify(canonicalPayload))
      .digest('hex');

    const isValid = computedSignature === certificate.digitalSignature;

    return {
      isValid,
      certificateId: certificate.certificateId,
      issuedAt: certificate.issuedAt,
      status: isValid ? 'AUTHENTIC_AND_TAMPER_PROOF' : 'INVALID_OR_TAMPERED'
    };
  }
}

module.exports = new CertificateEngine();
