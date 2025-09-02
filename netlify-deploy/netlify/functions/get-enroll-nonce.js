const crypto = require('crypto');
const { v4: uuidv4 } = require('uuid');

/**
 * Netlify Function: Generate enrollment nonce
 * POST /.netlify/functions/get-enroll-nonce
 */
exports.handler = async (event, context) => {
  // Set CORS headers
  const headers = {
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Headers': 'Content-Type',
    'Access-Control-Allow-Methods': 'POST, OPTIONS',
    'Content-Type': 'application/json'
  };

  // Handle preflight requests
  if (event.httpMethod === 'OPTIONS') {
    return {
      statusCode: 200,
      headers,
      body: ''
    };
  }

  // Only allow POST requests
  if (event.httpMethod !== 'POST') {
    return {
      statusCode: 405,
      headers,
      body: JSON.stringify({
        success: false,
        error: 'Method not allowed'
      })
    };
  }

  try {
    // Generate cryptographically secure 32-byte nonce
    const nonce = crypto.randomBytes(32);
    const nonceBase64 = nonce.toString('base64');
    const nonceId = uuidv4();
    
    const expiryMs = parseInt(process.env.NONCE_EXPIRY_MS) || 300000; // 5 minutes
    const expiresAt = new Date(Date.now() + expiryMs);

    console.log(`Generated nonce ID: ${nonceId}`);

    // In serverless environment, return both nonce and nonceId
    // The enrollment function will validate the nonce directly
    return {
      statusCode: 200,
      headers,
      body: JSON.stringify({
        success: true,
        nonceId,
        nonce: nonceBase64, // The actual nonce for Android attestation
        expiresAt: expiresAt.toISOString(),
        expiresInMs: expiryMs,
        usage: "Use 'nonce' as Android attestation challenge, include both 'nonceId' and 'nonce' in enrollment request"
      })
    };

  } catch (error) {
    console.error('Nonce generation error:', error);
    
    return {
      statusCode: 500,
      headers,
      body: JSON.stringify({
        success: false,
        error: 'Failed to generate nonce'
      })
    };
  }
};
