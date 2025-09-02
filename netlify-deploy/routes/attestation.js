const express = require('express');
const crypto = require('crypto');
const { v4: uuidv4 } = require('uuid');
const router = express.Router();

// In-memory store for nonces (in production, use Redis or database)
// Structure: nonce -> { nonceId, timestamp, used }
const nonceStore = new Map();

// Cleanup expired nonces every minute
setInterval(() => {
  const now = Date.now();
  const expiryMs = parseInt(process.env.NONCE_EXPIRY_MS) || 300000; // 5 minutes default
  
  for (const [nonce, data] of nonceStore.entries()) {
    if (now - data.timestamp > expiryMs) {
      nonceStore.delete(nonce);
    }
  }
}, 60000);

/**
 * POST /api/attestation/get-enroll-nonce
 * Creates a new attestation challenge nonce for device enrollment
 * Returns nonceId and nonce for the client to use in attestation
 */
router.post('/get-enroll-nonce', (req, res) => {
  try {
    // Generate cryptographically secure 32-byte nonce
    const nonceBytes = crypto.randomBytes(32);
    const nonceBase64 = nonceBytes.toString('base64');
    const nonceId = uuidv4();
    
    // Store nonce with metadata
    nonceStore.set(nonceBase64, {
      nonceId,
      timestamp: Date.now(),
      used: false,
      clientIp: req.ip,
      userAgent: req.get('User-Agent')
    });

    const expiryMs = parseInt(process.env.NONCE_EXPIRY_MS) || 300000;
    const expiresAt = new Date(Date.now() + expiryMs);

    console.log(`Generated enrollment nonce: ${nonceId} (${nonceBase64.substring(0, 8)}...)`);

    res.json({
      success: true,
      nonceId,
      nonceBase64,
      expiresAt: expiresAt.toISOString(),
      expiresInMs: expiryMs
    });

  } catch (error) {
    console.error('Error generating enrollment nonce:', error);
    res.status(500).json({
      success: false,
      error: 'Failed to generate enrollment nonce'
    });
  }
});

/**
 * GET /api/attestation/nonce/:nonceId
 * Check nonce status by nonceId
 */
router.get('/nonce/:nonceId', (req, res) => {
  try {
    const { nonceId } = req.params;
    
    // Find nonce by nonceId
    let foundNonce = null;
    let nonceData = null;
    
    for (const [nonce, data] of nonceStore.entries()) {
      if (data.nonceId === nonceId) {
        foundNonce = nonce;
        nonceData = data;
        break;
      }
    }

    if (!foundNonce || !nonceData) {
      return res.status(404).json({
        success: false,
        error: 'Nonce not found or expired'
      });
    }

    const expiryMs = parseInt(process.env.NONCE_EXPIRY_MS) || 300000;
    const isExpired = Date.now() - nonceData.timestamp > expiryMs;
    
    if (isExpired) {
      nonceStore.delete(foundNonce);
      return res.status(410).json({
        success: false,
        error: 'Nonce expired'
      });
    }

    res.json({
      success: true,
      nonceId,
      expiresAt: new Date(nonceData.timestamp + expiryMs).toISOString(),
      used: nonceData.used,
      remainingTimeMs: Math.max(0, (nonceData.timestamp + expiryMs) - Date.now())
    });

  } catch (error) {
    console.error('Error checking nonce status:', error);
    res.status(500).json({
      success: false,
      error: 'Failed to check nonce status'
    });
  }
});

module.exports = { router, nonceStore };
