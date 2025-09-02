const express = require('express');
const crypto = require('crypto');
const forge = require('node-forge');
const { v4: uuidv4 } = require('uuid');
const { nonceStore } = require('./attestation');
const AttestationVerifier = require('../utils/attestationVerifier');
const CertificateGenerator = require('../utils/certificateGenerator');

const router = express.Router();

/**
 * POST /api/enrollment/enroll
 * Main enrollment endpoint that verifies attestation and issues DIC
 */
router.post('/enroll', async (req, res) => {
  try {
    const { 
      nonceId,
      attestationChainPem, 
      csrPem,
      devicePublicKeyPem,
      deviceInfo 
    } = req.body;

    // Validate required fields
    if (!nonceId || !attestationChainPem) {
      return res.status(400).json({
        success: false,
        error: 'Missing required fields: nonceId, attestationChainPem'
      });
    }

    console.log(`Processing enrollment request with nonceId: ${nonceId}`);

    // Step 1: Find and validate nonce by nonceId
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
      return res.status(400).json({
        success: false,
        error: 'Invalid or expired nonceId'
      });
    }

    // Check if nonce is expired
    const expiryMs = parseInt(process.env.NONCE_EXPIRY_MS) || 300000;
    if (Date.now() - nonceData.timestamp > expiryMs) {
      nonceStore.delete(foundNonce);
      return res.status(400).json({
        success: false,
        error: 'Nonce expired'
      });
    }

    // Check if nonce already used
    if (nonceData.used) {
      return res.status(400).json({
        success: false,
        error: 'Nonce already used'
      });
    }

    // Mark nonce as used
    nonceData.used = true;

    // Step 2: Verify attestation chain and extract attestation
    const verifier = new AttestationVerifier();
    const verificationResult = await verifier.verifyAttestation({
      attestationChainPem,
      devicePublicKeyPem,
      nonce: foundNonce, // Use the actual nonce, not nonceId
      expectedPackageName: process.env.ANDROID_PACKAGE_NAME,
      expectedCertDigest: process.env.ANDROID_CERT_DIGEST
    });

    if (!verificationResult.valid) {
      console.error('Attestation verification failed:', verificationResult.error);
      return res.status(400).json({
        success: false,
        error: 'Attestation verification failed',
        details: process.env.NODE_ENV === 'development' ? verificationResult.error : undefined
      });
    }

    console.log('✅ Attestation verification successful');

    // Step 3: Generate Device Identity Certificate (DIC)
    const deviceId = uuidv4();
    const certGenerator = new CertificateGenerator();
    
    const dicResult = await certGenerator.generateDeviceIdentityCertificate({
      deviceId,
      devicePublicKeyPem: devicePublicKeyPem || forge.pki.publicKeyToPem(verificationResult.devicePublicKey),
      attestationData: verificationResult.attestationData,
      csrPem
    });

    if (!dicResult.success) {
      console.error('DIC generation failed:', dicResult.error);
      return res.status(500).json({
        success: false,
        error: 'Failed to generate Device Identity Certificate'
      });
    }

    // Step 4: Store enrollment record (in production, use database)
    const enrollmentRecord = {
      deviceId,
      enrollmentTime: new Date().toISOString(),
      devicePublicKeyPem: devicePublicKeyPem || forge.pki.publicKeyToPem(verificationResult.devicePublicKey),
      attestationData: verificationResult.attestationData,
      certificateSerialNumber: dicResult.serialNumber,
      deviceInfo: deviceInfo || null,
      ipAddress: req.ip,
      userAgent: req.get('User-Agent')
    };

    // In production, save to database
    console.log(`📝 Enrollment record created:`, {
      deviceId,
      serialNumber: dicResult.serialNumber,
      enrollmentTime: enrollmentRecord.enrollmentTime
    });

    console.log(`🎉 Device enrolled successfully: ${deviceId}`);

    // Remove used nonce
    nonceStore.delete(foundNonce);

    res.json({
      success: true,
      deviceId,
      deviceIdentityCertificate: dicResult.certificatePem,
      certificateChain: dicResult.certificateChain,
      enrollmentTime: enrollmentRecord.enrollmentTime,
      expiresAt: dicResult.expiresAt,
      serialNumber: dicResult.serialNumber,
      attestation: {
        securityLevel: verificationResult.attestationData.attestationSecurityLevel,
        verifiedBootState: verificationResult.attestationData.verifiedBootState,
        osVersion: verificationResult.attestationData.osVersion,
        patchLevel: verificationResult.attestationData.osPatchLevel
      }
    });

  } catch (error) {
    console.error('Enrollment error:', error);
    res.status(500).json({
      success: false,
      error: 'Internal server error during enrollment'
    });
  }
});

/**
 * GET /api/enrollment/status/:deviceId
 * Check enrollment status of a device
 */
router.get('/status/:deviceId', (req, res) => {
  try {
    const { deviceId } = req.params;
    
    // In production, query from database
    // For now, return basic status
    res.json({
      success: true,
      deviceId,
      status: 'enrolled', // would be 'not_enrolled', 'pending', 'revoked', etc.
      enrollmentTime: new Date().toISOString(), // placeholder
      message: 'Device status check - implement database lookup in production'
    });

  } catch (error) {
    console.error('Status check error:', error);
    res.status(500).json({
      success: false,
      error: 'Failed to check enrollment status'
    });
  }
});

/**
 * POST /api/enrollment/verify-certificate
 * Verify a Device Identity Certificate
 */
router.post('/verify-certificate', async (req, res) => {
  try {
    const { certificatePem } = req.body;

    if (!certificatePem) {
      return res.status(400).json({
        success: false,
        error: 'Certificate PEM required'
      });
    }

    // Parse and verify certificate
    const cert = forge.pki.certificateFromPem(certificatePem);
    const now = new Date();
    
    // Check validity period
    const isValid = now >= cert.validity.notBefore && now <= cert.validity.notAfter;
    
    // Extract device ID from subject CN
    const subject = cert.subject;
    const cnAttr = subject.getField('CN');
    const deviceId = cnAttr ? cnAttr.value : null;

    res.json({
      success: true,
      verification: {
        valid: isValid,
        deviceId,
        subject: forge.pki.certificateToAsn1(cert).value[0].value[5],
        serialNumber: cert.serialNumber,
        notBefore: cert.validity.notBefore.toISOString(),
        notAfter: cert.validity.notAfter.toISOString(),
        expired: now > cert.validity.notAfter,
        notYetValid: now < cert.validity.notBefore
      }
    });

  } catch (error) {
    console.error('Certificate verification error:', error);
    res.status(400).json({
      success: false,
      error: 'Invalid certificate format'
    });
  }
});

module.exports = router;
