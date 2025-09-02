const crypto = require('crypto');
const { v4: uuidv4 } = require('uuid');

// Simple in-memory store for nonces (in production, use external KV store like Redis/FaunaDB)
// For Netlify, consider using Netlify Blobs or external database
const nonceStore = new Map();

// Cleanup function (called on each request)
function cleanupExpiredNonces() {
  const now = Date.now();
  const expiryMs = parseInt(process.env.NONCE_EXPIRY_MS) || 300000; // 5 minutes
  
  for (const [nonce, data] of nonceStore.entries()) {
    if (now - data.timestamp > expiryMs) {
      nonceStore.delete(nonce);
    }
  }
}

/**
 * Netlify Function: GET /api/get-enroll-nonce
 * Generate attestation challenge nonce for device enrollment
 */
exports.handler = async (event, context) => {
  // Only allow POST requests
  if (event.httpMethod !== 'POST') {
    return {
      statusCode: 405,
      headers: {
        'Content-Type': 'application/json',
        'Access-Control-Allow-Origin': '*',
        'Access-Control-Allow-Methods': 'POST, OPTIONS',
        'Access-Control-Allow-Headers': 'Content-Type'
      },
      body: JSON.stringify({ error: 'Method not allowed' })
    };
  }

  // Handle CORS preflight
  if (event.httpMethod === 'OPTIONS') {
    return {
      statusCode: 200,
      headers: {
        'Access-Control-Allow-Origin': '*',
        'Access-Control-Allow-Methods': 'POST, OPTIONS',
        'Access-Control-Allow-Headers': 'Content-Type'
      },
      body: ''
    };
  }

  try {
    // Cleanup expired nonces
    cleanupExpiredNonces();

    // Generate cryptographically secure 32-byte nonce
    const nonceBytes = crypto.randomBytes(32);
    const nonceBase64 = nonceBytes.toString('base64');
    const nonceId = uuidv4();
    
    // Store nonce with metadata
    nonceStore.set(nonceBase64, {
      nonceId,
      timestamp: Date.now(),
      used: false,
      clientIp: event.headers['x-forwarded-for'] || event.headers['client-ip'],
      userAgent: event.headers['user-agent']
    });

    const expiryMs = parseInt(process.env.NONCE_EXPIRY_MS) || 300000;
    const expiresAt = new Date(Date.now() + expiryMs);

    console.log(`Generated enrollment nonce: ${nonceId} (${nonceBase64.substring(0, 8)}...)`);

    return {
      statusCode: 200,
      headers: {
        'Content-Type': 'application/json',
        'Access-Control-Allow-Origin': '*'
      },
      body: JSON.stringify({
        success: true,
        nonceId,
        nonceBase64,
        expiresAt: expiresAt.toISOString(),
        expiresInMs: expiryMs
      })
    };

  } catch (error) {
    console.error('Error generating enrollment nonce:', error);
    
    return {
      statusCode: 500,
      headers: {
        'Content-Type': 'application/json',
        'Access-Control-Allow-Origin': '*'
      },
      body: JSON.stringify({
        success: false,
        error: 'Failed to generate enrollment nonce'
      })
    };
  }
};

// Export nonceStore for use by other functions
global.nonceStore = nonceStore;
