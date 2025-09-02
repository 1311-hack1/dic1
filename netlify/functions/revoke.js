const { v4: uuidv4 } = require('uuid');

// Simple revocation store (in production, use proper database)
const revokedDevices = new Map();

/**
 * Netlify Function: POST /api/revoke
 * Revoke a device certificate
 */
exports.handler = async (event, context) => {
  // Only allow POST requests
  if (event.httpMethod !== 'POST') {
    return {
      statusCode: 405,
      headers: {
        'Content-Type': 'application/json',
        'Access-Control-Allow-Origin': '*'
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
        'Access-Control-Allow-Headers': 'Content-Type, Authorization'
      },
      body: ''
    };
  }

  try {
    const body = JSON.parse(event.body);
    const { deviceId, certificateSerialNumber, reason, authToken } = body;
    
    if (!deviceId && !certificateSerialNumber) {
      return {
        statusCode: 400,
        headers: { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*' },
        body: JSON.stringify({ 
          error: 'Either deviceId or certificateSerialNumber required' 
        })
      };
    }

    // Basic auth check (in production, implement proper authentication)
    if (process.env.REVOCATION_AUTH_TOKEN && authToken !== process.env.REVOCATION_AUTH_TOKEN) {
      return {
        statusCode: 401,
        headers: { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*' },
        body: JSON.stringify({ error: 'Unauthorized' })
      };
    }

    const revocationId = uuidv4();
    const revocationRecord = {
      revocationId,
      deviceId,
      certificateSerialNumber,
      reason: reason || 'Device compromised',
      revokedAt: new Date().toISOString(),
      revokedBy: event.headers['x-forwarded-for'] || 'unknown'
    };

    // Store revocation record
    const key = deviceId || certificateSerialNumber;
    revokedDevices.set(key, revocationRecord);

    console.log(`Device revoked: ${key}, reason: ${revocationRecord.reason}`);

    return {
      statusCode: 200,
      headers: {
        'Content-Type': 'application/json',
        'Access-Control-Allow-Origin': '*'
      },
      body: JSON.stringify({
        success: true,
        revocationId,
        message: 'Device certificate revoked successfully',
        revokedAt: revocationRecord.revokedAt
      })
    };

  } catch (error) {
    console.error('Revocation error:', error);
    return {
      statusCode: 500,
      headers: {
        'Content-Type': 'application/json',
        'Access-Control-Allow-Origin': '*'
      },
      body: JSON.stringify({ 
        error: 'Server error during revocation: ' + (error.message || error) 
      })
    };
  }
};

// Export revoked devices for checking in other functions
global.revokedDevices = revokedDevices;
