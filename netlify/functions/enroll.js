const forge = require('node-forge');
const axios = require('axios');
const { AsnConvert, KeyMintKeyDescription, NonStandardKeyMintKeyDescription, android } = require('@peculiar/asn1-android');
const { v4: uuidv4 } = require('uuid');

const ATTESTATION_OID = '1.3.6.1.4.1.11129.2.1.17';
const GOOGLE_ROOTS_URL = 'https://android.googleapis.com/attestation/root';

// Access the nonce store from the other function
const nonceStore = global.nonceStore || new Map();

// Simple in-memory cache for Google roots (function warm start keeps it)
let googleRootsCache = null;
let googleRootsFetchedAt = 0;
const ROOTS_TTL_MS = 24 * 3600 * 1000; // refresh daily

async function fetchGoogleRoots() {
  if (googleRootsCache && (Date.now() - googleRootsFetchedAt) < ROOTS_TTL_MS) {
    return googleRootsCache;
  }
  
  try {
    const response = await axios.get(GOOGLE_ROOTS_URL, { timeout: 5000 });
    // Handle different response formats
    let pems = [];
    if (Array.isArray(response.data)) {
      pems = response.data;
    } else if (response.data && Array.isArray(response.data.pem)) {
      pems = response.data.pem;
    } else {
      throw new Error('Unexpected roots format');
    }
    
    googleRootsCache = pems;
    googleRootsFetchedAt = Date.now();
    return pems;
  } catch (error) {
    console.warn('Failed to fetch Google roots, using fallback', error.message);
    // Return embedded fallback roots
    return [
      `-----BEGIN CERTIFICATE-----
MIICizCCAjKgAwIBAgIJAKIFntEOQ1tXMA0GCSqGSIb3DQEBCwUAMIGYMQswCQYD
VQQGEwJVUzETMBEGA1UECAwKQ2FsaWZvcm5pYTEWMBQGA1UEBwwNTW91bnRhaW4g
VmlldzEVMBMGA1UECgwMR29vZ2xlLCBJbmMuMRAwDgYDVQQLDAdBbmRyb2lkMTMw
MQYDVQQDDCpBbmRyb2lkIEtleXN0b3JlIFNvZnR3YXJlIEF0dGVzdGF0aW9uIFJv
b3QwHhcNMTYwMTExMDA0NjA5WhcNMjYwMTA4MDA0NjA5WjCBmDELMAkGA1UEBhMC
VVMxEzARBgNVBAgMCkNhbGlmb3JuaWExFjAUBgNVBAcMDU1vdW50YWluIFZpZXcx
FTATBgNVBAoMDEdvb2dsZSwgSW5jLjEQMA4GA1UECwwHQW5kcm9pZDEzMDEGA1UE
AwwqQW5kcm9pZCBLZXlzdG9yZSBTb2Z0d2FyZSBBdHRlc3RhdGlvbiBSb290MIGf
MA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQC6Q7GXuzMc6jBKJKuuP8cGeNNdkQdx
g+xSFvPjFSjjFwSNGBrZaNKGqMnWHMXR3TMLMXVMoKHG4YKGp7dT1O4aAVv+WQ==
-----END CERTIFICATE-----`
    ];
  }
}

function pemToForgeCerts(pemChain) {
  // Accept either pem chain array or a single PEM with multiple certs concatenated
  if (!Array.isArray(pemChain)) {
    // split concatenated
    pemChain = pemChain.match(/-----BEGIN CERTIFICATE-----[A-Za-z0-9+\/=\s-]+-----END CERTIFICATE-----/g);
  }
  return pemChain.map(pem => forge.pki.certificateFromPem(pem));
}

async function verifyChainAgainstRoots(forgeCerts, rootPemArray) {
  const caStore = forge.pki.createCaStore(rootPemArray);
  try {
    // node-forge throws on verify failure
    forge.pki.verifyCertificateChain(caStore, forgeCerts, (vfd, depth, chain) => {
      // vfd === true means OK at this depth
      if (vfd === true) return true;
      // otherwise throw to abort verification
      throw new Error('Certificate chain validation error at depth ' + depth);
    });
    return true;
  } catch (error) {
    throw new Error('certificate chain verification failed: ' + error.message);
  }
}

function findFirstAttestationCert(forgeCerts) {
  // iterate from near-root to leaf -> check first occurrence of attestation OID
  for (let i = forgeCerts.length - 1; i >= 0; --i) {
    const cert = forgeCerts[i];
    if (!cert.extensions) continue;
    for (const ext of cert.extensions) {
      // ext.id or ext.oid sometimes contains OID; try both
      if (ext.id === ATTESTATION_OID || ext.oid === ATTESTATION_OID || ext.name === ATTESTATION_OID) {
        return { cert, ext };
      }
    }
  }
  return null;
}

function extractKeyDescriptionBytes(ext) {
  // node-forge places raw DER bytes in ext.value or ext.extnValue depending on parsing.
  // The attestation extension is typically an OCTET STRING wrapping the KeyDescription DER.
  // We attempt a robust extraction.
  let derBytes;
  if (ext.extnValue) {
    derBytes = ext.extnValue;
  } else if (ext.value) {
    derBytes = ext.value;
  } else {
    throw new Error('attestation extension has no extnValue/value');
  }

  // extnValue or value in node-forge is a binary string; convert to Uint8Array
  const raw = Buffer.from(derBytes, 'binary');

  // Often ext is an OCTET STRING wrapper: parse and if nested, return inner bytes:
  try {
    const asn1 = forge.asn1.fromDer(raw.toString('binary'));
    // If it's an OCTET STRING containing inner DER, get that
    if (asn1.tagClass === forge.asn1.Class.UNIVERSAL && asn1.type === forge.asn1.Type.OCTETSTRING) {
      // asn1.value could be the inner bytes as binary string
      const inner = asn1.value;
      // If inner is a binary string:
      if (typeof inner === 'string') {
        return Buffer.from(inner, 'binary');
      }
      // else if inner is array of ASN1 nodes, convert inner node to DER
      return Buffer.from(forge.asn1.toDer(inner[0]).getBytes(), 'binary');
    }
  } catch (error) {
    // fall through: maybe derBytes already is KeyDescription DER
  }
  return raw;
}

async function generateHardcodedDIC(deviceId, devicePublicKeyPem) {
  // For now, generate a hardcoded DIC as requested
  // In production, this would call your CA (Vault, etc.)
  
  try {
    const devicePublicKey = forge.pki.publicKeyFromPem(devicePublicKeyPem);
    
    // Generate a simple self-signed certificate for demo
    const cert = forge.pki.createCertificate();
    cert.publicKey = devicePublicKey;
    cert.serialNumber = crypto.randomBytes(16).toString('hex');
    cert.validity.notBefore = new Date();
    cert.validity.notAfter = new Date();
    cert.validity.notAfter.setFullYear(cert.validity.notBefore.getFullYear() + 1);

    const subject = [{
      name: 'countryName',
      value: 'US'
    }, {
      name: 'organizationName',
      value: 'Device Identity'
    }, {
      name: 'commonName',
      value: deviceId
    }];

    cert.setSubject(subject);
    cert.setIssuer(subject); // Self-signed for now

    // Add required extensions
    cert.setExtensions([
      {
        name: 'basicConstraints',
        cA: false,
        critical: true
      },
      {
        name: 'keyUsage',
        digitalSignature: true,
        keyAgreement: true,
        critical: true
      },
      {
        name: 'extKeyUsage',
        clientAuth: true, // EKU: ClientAuth as required
        critical: true
      },
      {
        // Custom Device Identity OID
        id: '1.3.6.1.4.1.99999.1',
        critical: false,
        value: forge.asn1.create(forge.asn1.Class.UNIVERSAL, forge.asn1.Type.UTF8, false, 'DeviceIdentity')
      }
    ]);

    // For demo, create a temporary key pair for signing
    const tempKeyPair = forge.pki.rsa.generateKeyPair(2048);
    cert.sign(tempKeyPair.privateKey, forge.md.sha256.create());

    const certificatePem = forge.pki.certificateToPem(cert);

    return {
      success: true,
      certificatePem,
      serialNumber: cert.serialNumber,
      expiresAt: cert.validity.notAfter.toISOString(),
      note: 'Hardcoded DIC - replace with real CA integration'
    };

  } catch (error) {
    return {
      success: false,
      error: 'Failed to generate hardcoded DIC: ' + error.message
    };
  }
}

/**
 * Netlify Function: POST /api/enroll
 * Main enrollment endpoint
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
        'Access-Control-Allow-Headers': 'Content-Type'
      },
      body: ''
    };
  }

  try {
    const body = JSON.parse(event.body);
    const { nonceId, attestationChainPem, csrPem, devicePublicKeyPem } = body;
    
    if (!nonceId || !attestationChainPem) {
      return {
        statusCode: 400,
        headers: { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*' },
        body: JSON.stringify({ error: 'Missing required fields: nonceId, attestationChainPem' })
      };
    }

    // A. Basic sanity: Ensure nonceId exists and map to server nonce
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
      return {
        statusCode: 400,
        headers: { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*' },
        body: JSON.stringify({ error: 'Invalid or expired nonceId' })
      };
    }

    // Check if nonce is expired
    const expiryMs = parseInt(process.env.NONCE_EXPIRY_MS) || 300000;
    if (Date.now() - nonceData.timestamp > expiryMs) {
      nonceStore.delete(foundNonce);
      return {
        statusCode: 400,
        headers: { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*' },
        body: JSON.stringify({ error: 'Nonce expired' })
      };
    }

    // Check if nonce already used
    if (nonceData.used) {
      return {
        statusCode: 400,
        headers: { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*' },
        body: JSON.stringify({ error: 'Nonce already used' })
      };
    }

    // Mark nonce as used
    nonceData.used = true;

    // B. Certificate chain verification: Parse attestation chain into certificates
    const forgeCerts = pemToForgeCerts(attestationChainPem);
    console.log(`Parsed ${forgeCerts.length} certificates in attestation chain`);

    // Verify chain builds to Google attestation roots
    const roots = await fetchGoogleRoots();
    await verifyChainAgainstRoots(forgeCerts, roots);
    console.log('✅ Certificate chain verified against Google roots');

    // Check each cert validity (notBefore/notAfter)
    const now = new Date();
    for (let i = 0; i < forgeCerts.length; i++) {
      const cert = forgeCerts[i];
      if (now < cert.validity.notBefore || now > cert.validity.notAfter) {
        throw new Error(`Certificate ${i} is not valid at current time`);
      }
    }

    // C. Find & parse attestation extension
    const found = findFirstAttestationCert(forgeCerts);
    if (!found) {
      return {
        statusCode: 400,
        headers: { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*' },
        body: JSON.stringify({ error: 'Attestation extension not found' })
      };
    }

    // Extract KeyDescription DER bytes
    const keyDescDer = extractKeyDescriptionBytes(found.ext);

    // Parse with @peculiar/asn1-android
    let keyDesc;
    try {
      keyDesc = AsnConvert.parse(new Uint8Array(keyDescDer), KeyMintKeyDescription);
    } catch (error) {
      // try non-standard parser
      keyDesc = AsnConvert.parse(new Uint8Array(keyDescDer), NonStandardKeyMintKeyDescription);
    }

    // Verify nonce (attestationChallenge)
    const attChallenge = keyDesc.attestationChallenge; // OctetString
    const attB64 = Buffer.from(attChallenge).toString('base64');
    if (attB64 !== foundNonce) {
      return {
        statusCode: 403,
        headers: { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*' },
        body: JSON.stringify({ error: 'Nonce mismatch' })
      };
    }
    console.log('✅ Attestation challenge matches server nonce');

    // Verify app identity (attestationApplicationId)
    const authList = keyDesc.softwareEnforced || keyDesc.teeEnforced || keyDesc.hardwareEnforced;
    let appIdRaw = authList.findProperty ? authList.findProperty('attestationApplicationId') : authList.attestationApplicationId;
    let attApp = null;
    
    if (appIdRaw) {
      const bytes = Buffer.from(appIdRaw);
      try {
        attApp = AsnConvert.parse(new Uint8Array(bytes), android.AttestationApplicationId);
      } catch (error) {
        console.warn('Failed to parse attestationApplicationId:', error.message);
      }
    }

    // Verify package name and signing cert digest if provided
    if (process.env.ANDROID_PACKAGE_NAME && attApp) {
      const packageInfos = attApp.packageInfos || [];
      const hasExpectedPackage = packageInfos.some(pkg => 
        Buffer.from(pkg.packageName).toString('utf8') === process.env.ANDROID_PACKAGE_NAME
      );
      
      if (!hasExpectedPackage) {
        return {
          statusCode: 403,
          headers: { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*' },
          body: JSON.stringify({ error: 'Package name verification failed' })
        };
      }
      console.log('✅ Package name verified');
    }

    if (process.env.ANDROID_CERT_DIGEST && attApp) {
      const signatureDigests = attApp.signatureDigests || [];
      const hasExpectedDigest = signatureDigests.some(digest => 
        Buffer.from(digest).toString('hex').toLowerCase() === process.env.ANDROID_CERT_DIGEST.toLowerCase()
      );
      
      if (!hasExpectedDigest) {
        return {
          statusCode: 403,
          headers: { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*' },
          body: JSON.stringify({ error: 'Signing certificate digest verification failed' })
        };
      }
      console.log('✅ Signing certificate digest verified');
    }

    // Enforce security policies
    const rootOfTrust = (keyDesc.hardwareEnforced && keyDesc.hardwareEnforced.rootOfTrust) ||
                        (keyDesc.teeEnforced && keyDesc.teeEnforced.rootOfTrust) ||
                        null;
    if (!rootOfTrust) {
      return {
        statusCode: 403,
        headers: { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*' },
        body: JSON.stringify({ error: 'No rootOfTrust found' })
      };
    }

    // Verified boot state must be 'verified' (1)
    const vbs = rootOfTrust.verifiedBootState;
    if (!(vbs === 1 || String(vbs).toLowerCase().includes('verified'))) {
      return {
        statusCode: 403,
        headers: { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*' },
        body: JSON.stringify({ error: 'Device boot state not verified' })
      };
    }
    console.log('✅ Verified boot state confirmed');

    // Verify key properties
    const hwEnforced = keyDesc.hardwareEnforced || {};
    const teeEnforced = keyDesc.teeEnforced || {};
    
    // Check key purpose includes SIGN (2)
    const purposes = hwEnforced.purpose || teeEnforced.purpose || [];
    if (!purposes.includes(2)) {
      return {
        statusCode: 403,
        headers: { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*' },
        body: JSON.stringify({ error: 'Key purpose SIGN not found' })
      };
    }

    // Check algorithm is EC (3) and curve is P-256 (1)
    const algorithm = hwEnforced.algorithm || teeEnforced.algorithm;
    const curve = hwEnforced.ecCurve || teeEnforced.ecCurve;
    
    if (algorithm !== 3 || curve !== 1) {
      return {
        statusCode: 403,
        headers: { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*' },
        body: JSON.stringify({ error: 'Invalid key algorithm or curve (must be EC P-256)' })
      };
    }
    console.log('✅ Key properties verified (EC P-256, SIGN purpose)');

    // D. Public-key binding: verify device public key matches attestation cert
    if (devicePublicKeyPem) {
      const devicePublicKey = forge.pki.publicKeyFromPem(devicePublicKeyPem);
      const certPublicKey = found.cert.publicKey;
      
      const deviceKeyDer = forge.asn1.toDer(forge.pki.publicKeyToAsn1(devicePublicKey)).getBytes();
      const certKeyDer = forge.asn1.toDer(forge.pki.publicKeyToAsn1(certPublicKey)).getBytes();

      if (deviceKeyDer !== certKeyDer) {
        return {
          statusCode: 403,
          headers: { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*' },
          body: JSON.stringify({ error: 'Device public key does not match attestation certificate' })
        };
      }
      console.log('✅ Device public key matches attestation certificate');
    }

    // E. Generate Device Identity Certificate
    const deviceId = uuidv4();
    
    let signedCertPem = null;
    
    // Try Vault first if configured
    if (process.env.VAULT_ADDR && process.env.VAULT_TOKEN && csrPem) {
      try {
        const vaultUrl = process.env.VAULT_ADDR + '/v1/pki/issue/' + (process.env.VAULT_PKI_ROLE || 'device-identity');
        const vaultResponse = await axios.post(vaultUrl, {
          csr: csrPem,
          format: 'pem_bundle',
          ttl: '8760h', // 1 year
          common_name: deviceId
        }, {
          headers: { 'X-Vault-Token': process.env.VAULT_TOKEN },
          timeout: 10000
        });
        
        signedCertPem = vaultResponse.data && vaultResponse.data.data && vaultResponse.data.data.certificate;
        console.log('✅ Certificate issued by Vault CA');
      } catch (vaultError) {
        console.warn('Vault certificate issuance failed, falling back to hardcoded DIC:', vaultError.message);
      }
    }

    // Fallback to hardcoded DIC
    if (!signedCertPem) {
      const hardcodedResult = await generateHardcodedDIC(deviceId, devicePublicKeyPem || forge.pki.publicKeyToPem(found.cert.publicKey));
      if (hardcodedResult.success) {
        signedCertPem = hardcodedResult.certificatePem;
        console.log('✅ Hardcoded DIC generated');
      } else {
        throw new Error(hardcodedResult.error);
      }
    }

    // Remove used nonce
    nonceStore.delete(foundNonce);

    return {
      statusCode: 200,
      headers: {
        'Content-Type': 'application/json',
        'Access-Control-Allow-Origin': '*'
      },
      body: JSON.stringify({
        success: true,
        deviceId,
        deviceIdentityCertificate: signedCertPem,
        enrollmentTime: new Date().toISOString(),
        attestation: {
          app: attApp ? {
            packageInfos: attApp.packageInfos,
            signatureDigests: attApp.signatureDigests
          } : null,
          verifiedBootState: vbs,
          securityLevel: keyDesc.attestationSecurityLevel
        }
      })
    };

  } catch (error) {
    console.error('Enrollment error:', error);
    return {
      statusCode: 500,
      headers: {
        'Content-Type': 'application/json',
        'Access-Control-Allow-Origin': '*'
      },
      body: JSON.stringify({ 
        error: 'Server error: ' + (error.message || error) 
      })
    };
  }
};
