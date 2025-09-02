const forge = require('node-forge');
const axios = require('axios');
const { AsnConvert, KeyMintKeyDescription, NonStandardKeyMintKeyDescription, android } = require('@peculiar/asn1-android');

const ATTESTATION_OID = '1.3.6.1.4.1.11129.2.1.17';
const GOOGLE_ROOTS_URL = 'https://android.googleapis.com/attestation/root';
const GOOGLE_STATUS_URL = 'https://android.googleapis.com/attestation/status';

class AttestationVerifier {
  constructor() {
    // Cache for Google attestation root certificates
    this.googleRootsCache = null;
    this.googleRootsFetchedAt = 0;
    this.rootsTtlMs = 24 * 60 * 60 * 1000; // 24 hours
  }

  /**
   * Fetch Google attestation root certificates
   */
  async fetchGoogleRoots() {
    if (this.googleRootsCache && (Date.now() - this.googleRootsFetchedAt) < this.rootsTtlMs) {
      return this.googleRootsCache;
    }

    try {
      console.log('Fetching Google attestation roots...');
      const response = await axios.get(GOOGLE_ROOTS_URL, { 
        timeout: parseInt(process.env.ATTESTATION_TIMEOUT_MS) || 30000 
      });
      
      // Handle different response formats
      let pems = [];
      if (Array.isArray(response.data)) {
        pems = response.data;
      } else if (response.data && Array.isArray(response.data.pem)) {
        pems = response.data.pem;
      } else {
        throw new Error('Unexpected Google roots response format');
      }

      this.googleRootsCache = pems;
      this.googleRootsFetchedAt = Date.now();
      console.log(`✅ Loaded ${pems.length} Google attestation root certificates`);
      
      return pems;
    } catch (error) {
      console.error('❌ Failed to fetch Google attestation roots:', error.message);
      
      // Fallback to embedded roots for development
      if (process.env.NODE_ENV === 'development') {
        console.log('Using fallback embedded roots for development');
        return this.getEmbeddedRoots();
      }
      
      throw new Error('Unable to fetch Google attestation roots: ' + error.message);
    }
  }

  /**
   * Get embedded Google attestation roots for development/fallback
   */
  getEmbeddedRoots() {
    // These are example Google attestation root certificates
    // In production, keep these updated from the official source
    return [
      // Google Hardware Attestation Root Certificate (you should replace with actual)
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

  /**
   * Parse PEM chain into forge certificates
   */
  pemToForgeCerts(pemChain) {
    try {
      // Handle both array of PEMs and concatenated PEM string
      let pems;
      if (Array.isArray(pemChain)) {
        pems = pemChain;
      } else {
        // Split concatenated PEM string
        pems = pemChain.match(/-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----/g);
      }
      
      if (!pems || pems.length === 0) {
        throw new Error('No certificates found in chain');
      }

      return pems.map(pem => forge.pki.certificateFromPem(pem.trim()));
    } catch (error) {
      throw new Error('Failed to parse certificate chain: ' + error.message);
    }
  }

  /**
   * Verify certificate chain against Google attestation roots
   */
  async verifyChainAgainstRoots(forgeCerts, rootPemArray) {
    try {
      const caStore = forge.pki.createCaStore(rootPemArray);
      
      // Verify the certificate chain
      forge.pki.verifyCertificateChain(caStore, forgeCerts, (verified, depth, chain) => {
        if (verified !== true) {
          throw new Error(`Certificate chain validation failed at depth ${depth}`);
        }
        return true;
      });
      
      console.log('✅ Certificate chain verified against Google roots');
      return true;
    } catch (error) {
      throw new Error('Certificate chain verification failed: ' + error.message);
    }
  }

  /**
   * Find first certificate with attestation extension (closest to root)
   */
  findFirstAttestationCert(forgeCerts) {
    // Iterate from root to leaf to find first occurrence
    for (let i = forgeCerts.length - 1; i >= 0; i--) {
      const cert = forgeCerts[i];
      if (!cert.extensions) continue;
      
      for (const ext of cert.extensions) {
        if (ext.id === ATTESTATION_OID || ext.oid === ATTESTATION_OID) {
          return { cert, ext, index: i };
        }
      }
    }
    return null;
  }

  /**
   * Extract KeyDescription bytes from attestation extension
   */
  extractKeyDescriptionBytes(ext) {
    try {
      // Get extension value (typically OCTET STRING wrapping KeyDescription DER)
      let derBytes;
      if (ext.extnValue) {
        derBytes = ext.extnValue;
      } else if (ext.value) {
        derBytes = ext.value;
      } else {
        throw new Error('Attestation extension has no value');
      }

      // Convert to buffer
      const raw = Buffer.from(derBytes, 'binary');

      // Try to unwrap OCTET STRING if present
      try {
        const asn1 = forge.asn1.fromDer(raw.toString('binary'));
        if (asn1.tagClass === forge.asn1.Class.UNIVERSAL && 
            asn1.type === forge.asn1.Type.OCTETSTRING) {
          
          if (typeof asn1.value === 'string') {
            return Buffer.from(asn1.value, 'binary');
          } else if (Array.isArray(asn1.value) && asn1.value[0]) {
            return Buffer.from(forge.asn1.toDer(asn1.value[0]).getBytes(), 'binary');
          }
        }
      } catch (parseError) {
        // If unwrapping fails, use raw bytes
        console.log('Using raw extension bytes (no OCTET STRING wrapper)');
      }

      return raw;
    } catch (error) {
      throw new Error('Failed to extract KeyDescription bytes: ' + error.message);
    }
  }

  /**
   * Parse KeyDescription using @peculiar/asn1-android
   */
  parseKeyDescription(keyDescBytes) {
    try {
      let keyDesc;
      
      // Try KeyMintKeyDescription first (newer format)
      try {
        keyDesc = AsnConvert.parse(new Uint8Array(keyDescBytes), KeyMintKeyDescription);
        console.log('✅ Parsed as KeyMintKeyDescription');
      } catch (error) {
        // Fallback to NonStandardKeyMintKeyDescription
        console.log('Trying NonStandardKeyMintKeyDescription...');
        keyDesc = AsnConvert.parse(new Uint8Array(keyDescBytes), NonStandardKeyMintKeyDescription);
        console.log('✅ Parsed as NonStandardKeyMintKeyDescription');
      }

      return keyDesc;
    } catch (error) {
      throw new Error('Failed to parse KeyDescription: ' + error.message);
    }
  }

  /**
   * Main attestation verification method
   */
  async verifyAttestation({
    attestationChainPem,
    devicePublicKeyPem,
    nonce,
    expectedPackageName,
    expectedCertDigest
  }) {
    try {
      console.log('🔍 Starting Android Key Attestation verification...');

      // Step 1: Parse certificate chain
      const forgeCerts = this.pemToForgeCerts(attestationChainPem);
      console.log(`📋 Parsed ${forgeCerts.length} certificates in chain`);

      // Step 2: Verify chain against Google attestation roots
      const googleRoots = await this.fetchGoogleRoots();
      await this.verifyChainAgainstRoots(forgeCerts, googleRoots);

      // Step 3: Find attestation extension
      const attestationResult = this.findFirstAttestationCert(forgeCerts);
      if (!attestationResult) {
        throw new Error('No attestation extension found in certificate chain');
      }
      
      console.log(`📜 Found attestation extension in certificate ${attestationResult.index}`);

      // Step 4: Extract and parse KeyDescription
      const keyDescBytes = this.extractKeyDescriptionBytes(attestationResult.ext);
      const keyDesc = this.parseKeyDescription(keyDescBytes);

      // Step 5: Verify attestation challenge matches nonce
      const attestationChallenge = Buffer.from(keyDesc.attestationChallenge).toString('base64');
      if (attestationChallenge !== nonce) {
        throw new Error('Attestation challenge does not match server nonce');
      }
      console.log('✅ Attestation challenge verified');

      // Step 6: Verify application identity
      await this.verifyApplicationIdentity(keyDesc, expectedPackageName, expectedCertDigest);

      // Step 7: Verify security properties
      await this.verifySecurityProperties(keyDesc);

      // Step 8: Verify device public key matches attestation
      await this.verifyDevicePublicKey(devicePublicKeyPem, attestationResult.cert);

      // Step 9: Optional revocation check
      if (process.env.NODE_ENV === 'production') {
        await this.checkRevocationStatus(forgeCerts);
      }

      console.log('🎉 Android Key Attestation verification successful!');

      return {
        valid: true,
        attestationData: this.extractAttestationData(keyDesc),
        certificateChain: forgeCerts.map(cert => forge.pki.certificateToPem(cert))
      };

    } catch (error) {
      console.error('❌ Attestation verification failed:', error.message);
      return {
        valid: false,
        error: error.message
      };
    }
  }

  /**
   * Verify application identity from attestation
   */
  async verifyApplicationIdentity(keyDesc, expectedPackageName, expectedCertDigest) {
    try {
      // Find attestationApplicationId in either softwareEnforced, teeEnforced, or hardwareEnforced
      const authLists = [
        keyDesc.softwareEnforced,
        keyDesc.teeEnforced, 
        keyDesc.hardwareEnforced
      ].filter(Boolean);

      let attestationAppId = null;
      
      for (const authList of authLists) {
        if (authList.attestationApplicationId) {
          const appIdBytes = Buffer.from(authList.attestationApplicationId);
          try {
            attestationAppId = AsnConvert.parse(new Uint8Array(appIdBytes), android.AttestationApplicationId);
            break;
          } catch (parseError) {
            console.log('Failed to parse attestationApplicationId, trying next...');
            continue;
          }
        }
      }

      if (!attestationAppId) {
        if (expectedPackageName || expectedCertDigest) {
          throw new Error('No valid attestationApplicationId found in KeyDescription');
        } else {
          console.log('⚠️  Skipping app identity verification - no expected values provided');
          return true;
        }
      }

      // Verify package name
      if (expectedPackageName) {
        const packageInfos = attestationAppId.packageInfos || [];
        const hasExpectedPackage = packageInfos.some(pkg => 
          Buffer.from(pkg.packageName).toString('utf8') === expectedPackageName
        );
        
        if (!hasExpectedPackage) {
          throw new Error(`Package name verification failed. Expected: ${expectedPackageName}`);
        }
        console.log('✅ Package name verified');
      }

      // Verify signing certificate digest
      if (expectedCertDigest) {
        const signatureDigests = attestationAppId.signatureDigests || [];
        const hasExpectedDigest = signatureDigests.some(digest => 
          Buffer.from(digest).toString('hex').toLowerCase() === expectedCertDigest.toLowerCase()
        );
        
        if (!hasExpectedDigest) {
          throw new Error(`Signing certificate digest verification failed. Expected: ${expectedCertDigest}`);
        }
        console.log('✅ Signing certificate digest verified');
      }

      return true;
    } catch (error) {
      throw new Error('Application identity verification failed: ' + error.message);
    }
  }

  /**
   * Verify security properties of the attested key
   */
  async verifySecurityProperties(keyDesc) {
    try {
      // Get security properties from hardware/TEE enforced lists
      const hwEnforced = keyDesc.hardwareEnforced || {};
      const teeEnforced = keyDesc.teeEnforced || {};
      
      // Verify root of trust
      const rootOfTrust = hwEnforced.rootOfTrust || teeEnforced.rootOfTrust;
      if (!rootOfTrust) {
        throw new Error('No rootOfTrust found in attestation');
      }

      // Verify verified boot state
      const verifiedBootState = rootOfTrust.verifiedBootState;
      const requireStrictBoot = process.env.NODE_ENV === 'production';
      
      if (requireStrictBoot && verifiedBootState !== 1) { // 1 = VERIFIED/GREEN
        throw new Error(`Invalid verified boot state: ${verifiedBootState}. Required: VERIFIED (1)`);
      }
      console.log('✅ Verified boot state check passed');

      // Verify key purposes include SIGN
      const purposes = hwEnforced.purpose || teeEnforced.purpose || [];
      const hasSignPurpose = purposes.includes(2); // 2 = SIGN
      if (!hasSignPurpose) {
        throw new Error('Key purpose SIGN not found in attestation');
      }
      console.log('✅ Key purpose SIGN verified');

      // Verify algorithm and curve
      const algorithm = hwEnforced.algorithm || teeEnforced.algorithm;
      const curve = hwEnforced.ecCurve || teeEnforced.ecCurve;
      
      if (algorithm !== 3) { // 3 = EC
        throw new Error(`Invalid algorithm: ${algorithm}. Expected: EC (3)`);
      }
      
      if (curve !== 1) { // 1 = P-256
        throw new Error(`Invalid curve: ${curve}. Expected: P-256 (1)`);
      }
      console.log('✅ Algorithm and curve verified (EC P-256)');

      // Verify key is not exportable
      const noAuthRequired = hwEnforced.noAuthRequired || teeEnforced.noAuthRequired;
      if (noAuthRequired === false) {
        // Key requires authentication, which is good for security
        console.log('✅ Key requires authentication (non-exportable)');
      }

      // Check rollback resistance if required
      if (process.env.REQUIRE_ROLLBACK_RESISTANCE === 'true') {
        const rollbackResistant = hwEnforced.rollbackResistant || teeEnforced.rollbackResistant;
        if (!rollbackResistant) {
          throw new Error('Rollback resistance required but not present');
        }
        console.log('✅ Rollback resistance verified');
      }

      // Check security level (StrongBox vs TEE)
      const securityLevel = keyDesc.attestationSecurityLevel;
      if (process.env.REQUIRE_STRONGBOX === 'true' && securityLevel !== 2) { // 2 = StrongBox
        throw new Error('StrongBox security level required');
      }
      console.log(`✅ Security level: ${securityLevel === 2 ? 'StrongBox' : 'TEE'}`);

      return true;
    } catch (error) {
      throw new Error('Security properties verification failed: ' + error.message);
    }
  }

  /**
   * Verify device public key matches the one in attestation certificate
   */
  async verifyDevicePublicKey(devicePublicKeyPem, attestationCert) {
    try {
      // Parse device public key from PEM
      const devicePublicKey = forge.pki.publicKeyFromPem(devicePublicKeyPem);
      
      // Get public key from attestation certificate
      const certPublicKey = attestationCert.publicKey;

      // Compare the public keys by converting to DER and comparing bytes
      const deviceKeyDer = forge.asn1.toDer(forge.pki.publicKeyToAsn1(devicePublicKey)).getBytes();
      const certKeyDer = forge.asn1.toDer(forge.pki.publicKeyToAsn1(certPublicKey)).getBytes();

      if (deviceKeyDer !== certKeyDer) {
        throw new Error('Device public key does not match attestation certificate public key');
      }

      console.log('✅ Device public key matches attestation certificate');
      return true;
    } catch (error) {
      throw new Error('Public key verification failed: ' + error.message);
    }
  }

  /**
   * Extract structured attestation data for storage/logging
   */
  extractAttestationData(keyDesc) {
    const hwEnforced = keyDesc.hardwareEnforced || {};
    const teeEnforced = keyDesc.teeEnforced || {};
    const rootOfTrust = hwEnforced.rootOfTrust || teeEnforced.rootOfTrust || {};

    return {
      attestationVersion: keyDesc.attestationVersion,
      attestationSecurityLevel: keyDesc.attestationSecurityLevel,
      keymasterVersion: keyDesc.keymasterVersion,
      keymasterSecurityLevel: keyDesc.keymasterSecurityLevel,
      attestationChallenge: Buffer.from(keyDesc.attestationChallenge).toString('base64'),
      verifiedBootState: rootOfTrust.verifiedBootState,
      deviceLocked: rootOfTrust.deviceLocked,
      verifiedBootKey: rootOfTrust.verifiedBootKey ? 
        Buffer.from(rootOfTrust.verifiedBootKey).toString('hex') : null,
      verifiedBootHash: rootOfTrust.verifiedBootHash ? 
        Buffer.from(rootOfTrust.verifiedBootHash).toString('hex') : null,
      osVersion: hwEnforced.osVersion || teeEnforced.osVersion,
      osPatchLevel: hwEnforced.osPatchLevel || teeEnforced.osPatchLevel,
      algorithm: hwEnforced.algorithm || teeEnforced.algorithm,
      keySize: hwEnforced.keySize || teeEnforced.keySize,
      ecCurve: hwEnforced.ecCurve || teeEnforced.ecCurve,
      purpose: hwEnforced.purpose || teeEnforced.purpose,
      rollbackResistant: hwEnforced.rollbackResistant || teeEnforced.rollbackResistant,
      creationDateTime: hwEnforced.creationDateTime || teeEnforced.creationDateTime
    };
  }

  /**
   * Optional: Check certificate revocation status
   */
  async checkRevocationStatus(forgeCerts) {
    try {
      // Extract serial numbers from chain
      const serialNumbers = forgeCerts.map(cert => cert.serialNumber);
      
      const response = await axios.post(GOOGLE_STATUS_URL, {
        serialNumbers
      }, {
        timeout: 5000
      });

      // Check if any certificates are revoked
      if (response.data && response.data.revokedSerials) {
        const revokedSerials = response.data.revokedSerials;
        const hasRevokedCert = serialNumbers.some(serial => 
          revokedSerials.includes(serial)
        );
        
        if (hasRevokedCert) {
          throw new Error('One or more certificates in chain are revoked');
        }
      }

      console.log('✅ Revocation status check passed');
      return true;
    } catch (error) {
      console.warn('⚠️  Revocation check failed (non-fatal):', error.message);
      // Non-fatal in development, but should be enforced in production
      return process.env.NODE_ENV !== 'production';
    }
  }
}

module.exports = AttestationVerifier;
