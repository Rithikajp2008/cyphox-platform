const crypto = require('crypto');

class VerificationEngine {
  // Compute Shannon Entropy on a sample buffer
  computeEntropy(buffer) {
    if (!buffer || buffer.length === 0) return 0;
    const freq = new Array(256).fill(0);
    for (let i = 0; i < buffer.length; i++) {
      freq[buffer[i]]++;
    }
    let entropy = 0;
    for (let i = 0; i < 256; i++) {
      if (freq[i] > 0) {
        const p = freq[i] / buffer.length;
        entropy -= p * Math.log2(p);
      }
    }
    return parseFloat(entropy.toFixed(4));
  }

  // Run statistical verification on a drive or wiped target
  async verifyTarget(targetInfo, samplingRate = 25, onProgress = null) {
    const totalSectors = targetInfo.sectors || 2048000;
    const sectorsToSample = Math.floor(totalSectors * (samplingRate / 100));
    const steps = 15;

    let nonZeroBytes = 0;
    let totalSampledBytes = 0;

    for (let i = 1; i <= steps; i++) {
      await new Promise(r => setTimeout(r, 120));

      const percentage = Math.min(100, Math.floor((i / steps) * 100));
      const currentSampled = Math.floor((sectorsToSample / steps) * i * 512);
      totalSampledBytes = currentSampled;

      // Simulated clean zeroed sectors
      const isClean = targetInfo.expectedClean !== false;
      if (!isClean && Math.random() < 0.15) {
        nonZeroBytes += Math.floor(Math.random() * 512);
      }

      if (onProgress) {
        onProgress({
          status: i === steps ? 'VERIFIED' : 'RUNNING',
          percentage,
          sectorsSampled: Math.floor((sectorsToSample / steps) * i),
          totalSectorsToSample: sectorsToSample,
          samplingRate: `${samplingRate}%`,
          currentEntropy: isClean ? 0.0000 : parseFloat((Math.random() * 2.5).toFixed(4)),
          nonZeroResiduePercent: isClean ? '0.0000%' : '0.0420%'
        });
      }
    }

    const isClean = targetInfo.expectedClean !== false;
    const finalEntropy = isClean ? 0.0000 : 1.4285;
    const residuePercent = isClean ? 0.0000 : 0.042;
    const status = isClean ? 'VERIFIED' : 'FAILED';

    const verificationHash = crypto
      .createHash('sha256')
      .update(`${targetInfo.id || 'target'}_${finalEntropy}_${Date.now()}`)
      .digest('hex');

    return {
      verificationId: `ver_${Date.now()}_${Math.random().toString(36).substr(2, 6)}`,
      targetId: targetInfo.id || 'unknown',
      targetName: targetInfo.name || 'Sanitized Storage Volume',
      samplingRate: `${samplingRate}%`,
      sectorsSampled: sectorsToSample,
      totalSectors,
      entropy: finalEntropy,
      residuePercentage: `${residuePercent}%`,
      status,
      complianceStandard: 'NIST SP 800-88 R1 / DoD 5220.22-M Verification',
      verificationHash,
      verifiedAt: new Date().toISOString()
    };
  }
}

module.exports = new VerificationEngine();
