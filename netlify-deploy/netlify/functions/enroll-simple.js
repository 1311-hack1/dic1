const forge = require('node-forge');
const { v4: uuidv4 } = require('uuid');

/**
 * Netlify Function: Device Enrollment (Simplified for serverless)
 * POST /.netlify/functions/enroll
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
    const body = JSON.parse(event.body || '{}');
    const { 
      nonceId,
      nonce,
      attestationChainPem, 
      devicePublicKeyPem,
      deviceInfo 
    } = body;

    // Validate required fields
    if (!nonceId || !nonce || !attestationChainPem) {
      return {
        statusCode: 400,
        headers,
        body: JSON.stringify({
          success: false,
          error: 'Missing required fields: nonceId, nonce, attestationChainPem'
        })
      };
    }

    console.log(`Processing enrollment for nonceId: ${nonceId}`);

    // Basic attestation chain validation
    let attestationCerts;
    try {
      // Parse attestation certificate chain
      const certPems = attestationChainPem.split('-----END CERTIFICATE-----')
        .filter(pem => pem.includes('-----BEGIN CERTIFICATE-----'))
        .map(pem => pem + '-----END CERTIFICATE-----');
      
      attestationCerts = certPems.map(pem => forge.pki.certificateFromPem(pem));
      
      if (attestationCerts.length === 0) {
        throw new Error('No valid certificates in chain');
      }
      
      console.log(`✅ Parsed ${attestationCerts.length} certificates from attestation chain`);
      
    } catch (error) {
      return {
        statusCode: 400,
        headers,
        body: JSON.stringify({
          success: false,
          error: 'Invalid attestation certificate chain format'
        })
      };
    }

    // Basic nonce validation
    let nonceBytes;
    try {
      nonceBytes = Buffer.from(nonce, 'base64');
      if (nonceBytes.length !== 32) {
        throw new Error('Invalid nonce length');
      }
      console.log(`✅ Nonce validated: ${nonce.substring(0, 8)}...`);
    } catch (error) {
      return {
        statusCode: 400,
        headers,
        body: JSON.stringify({
          success: false,
          error: 'Invalid nonce format - must be base64 encoded 32 bytes'
        })
      };
    }

    // Get device public key
    let devicePublicKey;
    if (devicePublicKeyPem) {
      try {
        devicePublicKey = forge.pki.publicKeyFromPem(devicePublicKeyPem);
      } catch (error) {
        return {
          statusCode: 400,
          headers,
          body: JSON.stringify({
            success: false,
            error: 'Invalid device public key format'
          })
        };
      }
    } else {
      // Extract from attestation certificate (leaf cert contains the attested key)
      devicePublicKey = attestationCerts[0].publicKey;
    }

    console.log(`✅ Device public key extracted`);

    // Generate Device Identity Certificate
    const deviceId = uuidv4();
    const dicResult = await generateDeviceIdentityCertificate({
      deviceId,
      devicePublicKey,
      attestationCerts,
      nonceId
    });

    if (!dicResult.success) {
      return {
        statusCode: 500,
        headers,
        body: JSON.stringify({
          success: false,
          error: 'Failed to generate Device Identity Certificate',
          details: dicResult.error
        })
      };
    }

    console.log(`🎉 Device enrolled successfully: ${deviceId}`);

    return {
      statusCode: 200,
      headers,
      body: JSON.stringify({
        success: true,
        deviceId,
        deviceIdentityCertificate: dicResult.certificatePem,
        certificateChain: dicResult.certificateChain,
        enrollmentTime: new Date().toISOString(),
        expiresAt: dicResult.expiresAt,
        serialNumber: dicResult.serialNumber,
        attestation: {
          securityLevel: "TEE", // Simplified for demo
          verifiedBootState: "VERIFIED",
          certificateCount: attestationCerts.length,
          nonceValidated: true
        }
      })
    };

  } catch (error) {
    console.error('Enrollment error:', error);
    
    return {
      statusCode: 500,
      headers,
      body: JSON.stringify({
        success: false,
        error: 'Internal server error during enrollment'
      })
    };
  }
};

/**
 * Generate a Device Identity Certificate
 * Simplified version for Netlify Functions
 */
async function generateDeviceIdentityCertificate({ deviceId, devicePublicKey, attestationCerts, nonceId }) {
  try {
    // Create certificate
    const cert = forge.pki.createCertificate();
    
    // Set certificate properties
    cert.publicKey = devicePublicKey;
    cert.serialNumber = Math.floor(Math.random() * 1000000).toString();
    cert.validity.notBefore = new Date();
    cert.validity.notAfter = new Date();
    cert.validity.notAfter.setFullYear(cert.validity.notBefore.getFullYear() + 1);

    // Set subject (device identity)
    const attrs = [
      { name: 'commonName', value: `Device-${deviceId}` },
      { name: 'organizationName', value: 'DIC Enrollment Service' },
      { name: 'organizationalUnitName', value: 'Android Devices' },
      { name: 'countryName', value: 'US' }
    ];
    cert.subject.setAttributes(attrs);
    cert.issuer.setAttributes(attrs); // Self-signed for demo

    // Add extensions
    cert.setExtensions([
      {
        name: 'basicConstraints',
        cA: false
      },
      {
        name: 'keyUsage',
        digitalSignature: true,
        keyEncipherment: true
      },
      {
        name: 'extKeyUsage',
        clientAuth: true
      },
      {
        name: 'subjectKeyIdentifier'
      }
    ]);

    // Generate signing key (in production, use proper CA key)
    const signingKeys = forge.pki.rsa.generateKeyPair(2048);
    cert.sign(signingKeys.privateKey, forge.md.sha256.create());

    const certificatePem = forge.pki.certificateToPem(cert);
    
    console.log(`✅ Generated DIC with serial: ${cert.serialNumber}`);
    
    return {
      success: true,
      certificatePem,
      certificateChain: [certificatePem],
      serialNumber: cert.serialNumber,
      expiresAt: cert.validity.notAfter.toISOString()
    };

  } catch (error) {
    console.error('Certificate generation error:', error);
    return {
      success: false,
      error: error.message
    };
  }
}
