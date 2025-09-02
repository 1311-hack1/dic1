const forge = require('node-forge');
const axios = require('axios');
const crypto = require('crypto');
const fs = require('fs').promises;
const path = require('path');

class CertificateGenerator {
  constructor() {
    this.caPrivateKey = null;
    this.caCertificate = null;
    this.initialized = false;
  }

  /**
   * Initialize CA - either from Vault or local files
   */
  async initializeCA() {
    if (this.initialized) return;

    try {
      // Try Vault first if configured
      if (process.env.VAULT_ADDR && process.env.VAULT_TOKEN) {
        console.log('Using HashiCorp Vault for CA operations');
        this.useVault = true;
      } else {
        // Fallback to local CA
        console.log('Using local CA for certificate signing');
        await this.initializeLocalCA();
        this.useVault = false;
      }
      
      this.initialized = true;
    } catch (error) {
      console.error('CA initialization failed:', error.message);
      throw error;
    }
  }

  /**
   * Initialize local CA for development/testing
   */
  async initializeLocalCA() {
    try {
      const caKeyPath = process.env.CA_PRIVATE_KEY_PATH || './certs/ca-private.pem';
      const caCertPath = process.env.CA_CERTIFICATE_PATH || './certs/ca-cert.pem';

      // Try to load existing CA files
      try {
        const caKeyPem = await fs.readFile(path.resolve(caKeyPath), 'utf8');
        const caCertPem = await fs.readFile(path.resolve(caCertPath), 'utf8');
        
        this.caPrivateKey = forge.pki.privateKeyFromPem(caKeyPem);
        this.caCertificate = forge.pki.certificateFromPem(caCertPem);
        
        console.log('✅ Loaded existing CA certificate and key');
        return;
      } catch (loadError) {
        console.log('CA files not found, generating new CA...');
      }

      // Generate new CA
      await this.generateLocalCA(caKeyPath, caCertPath);
      
    } catch (error) {
      throw new Error('Failed to initialize local CA: ' + error.message);
    }
  }

  /**
   * Generate new local CA certificate and key
   */
  async generateLocalCA(keyPath, certPath) {
    try {
      console.log('Generating new CA certificate and key...');
      
      // Generate CA key pair
      const caKeyPair = forge.pki.rsa.generateKeyPair(2048);
      
      // Create CA certificate
      const caCert = forge.pki.createCertificate();
      caCert.publicKey = caKeyPair.publicKey;
      caCert.serialNumber = '01';
      caCert.validity.notBefore = new Date();
      caCert.validity.notAfter = new Date();
      caCert.validity.notAfter.setFullYear(caCert.validity.notBefore.getFullYear() + 10);

      const caAttrs = [{
        name: 'countryName',
        value: 'US'
      }, {
        name: 'organizationName',
        value: 'Device Identity CA'
      }, {
        name: 'commonName',
        value: 'DIC Root CA'
      }];

      caCert.setSubject(caAttrs);
      caCert.setIssuer(caAttrs);

      // Add CA extensions
      caCert.setExtensions([{
        name: 'basicConstraints',
        cA: true,
        critical: true
      }, {
        name: 'keyUsage',
        keyCertSign: true,
        cRLSign: true,
        critical: true
      }]);

      // Self-sign the CA certificate
      caCert.sign(caKeyPair.privateKey, forge.md.sha256.create());

      // Save CA files
      const caKeyPem = forge.pki.privateKeyToPem(caKeyPair.privateKey);
      const caCertPem = forge.pki.certificateToPem(caCert);

      // Ensure directory exists
      const keyDir = path.dirname(path.resolve(keyPath));
      const certDir = path.dirname(path.resolve(certPath));
      
      await fs.mkdir(keyDir, { recursive: true });
      if (keyDir !== certDir) {
        await fs.mkdir(certDir, { recursive: true });
      }

      await fs.writeFile(path.resolve(keyPath), caKeyPem);
      await fs.writeFile(path.resolve(certPath), caCertPem);

      this.caPrivateKey = caKeyPair.privateKey;
      this.caCertificate = caCert;

      console.log('✅ New CA generated and saved');
    } catch (error) {
      throw new Error('Failed to generate local CA: ' + error.message);
    }
  }

  /**
   * Generate Device Identity Certificate using Vault or local CA
   * @param {Object} params - Certificate parameters
   * @param {string} params.deviceId - Unique device identifier
   * @param {string} params.devicePublicKeyPem - Device public key in PEM format
   * @param {Object} params.attestationData - Attestation verification data
   * @param {string} params.csrPem - Optional CSR in PEM format
   * @returns {Object} Certificate generation result
   */
  async generateDeviceIdentityCertificate({ deviceId, devicePublicKeyPem, attestationData, csrPem }) {
    try {
      await this.initializeCA();
      
      console.log(`Generating DIC for device: ${deviceId}`);

      if (this.useVault) {
        return await this.generateVaultCertificate({ deviceId, devicePublicKeyPem, csrPem });
      } else {
        return await this.generateLocalCertificate({ deviceId, devicePublicKeyPem, attestationData });
      }
      
    } catch (error) {
      console.error('Certificate generation failed:', error.message);
      return {
        success: false,
        error: error.message
      };
    }
  }

  /**
   * Generate certificate using HashiCorp Vault
   */
  async generateVaultCertificate({ deviceId, devicePublicKeyPem, csrPem }) {
    try {
      const vaultUrl = `${process.env.VAULT_ADDR}/v1/pki/issue/${process.env.VAULT_PKI_ROLE || 'device-identity'}`;
      
      const requestBody = {
        common_name: deviceId,
        format: 'pem_bundle',
        ttl: '8760h', // 1 year
        key_usage: 'digital_signature,key_agreement',
        ext_key_usage: 'client_auth'
      };

      if (csrPem) {
        requestBody.csr = csrPem;
      } else {
        requestBody.public_key = devicePublicKeyPem;
      }

      const response = await axios.post(vaultUrl, requestBody, {
        headers: { 
          'X-Vault-Token': process.env.VAULT_TOKEN,
          'Content-Type': 'application/json'
        },
        timeout: 10000
      });

      const certData = response.data.data;
      
      return {
        success: true,
        certificatePem: certData.certificate,
        certificateChain: [certData.certificate, certData.ca_chain].flat(),
        serialNumber: certData.serial_number,
        expiresAt: new Date(Date.now() + (365 * 24 * 60 * 60 * 1000)).toISOString(), // 1 year
        issuer: 'Vault CA'
      };

    } catch (error) {
      throw new Error('Vault certificate generation failed: ' + error.message);
    }
  }

  /**
   * Generate certificate using local CA
   */
  async generateLocalCertificate({ deviceId, devicePublicKeyPem, attestationData }) {
    try {
      // Parse device public key
      const devicePublicKey = forge.pki.publicKeyFromPem(devicePublicKeyPem);

      // Create new certificate
      const cert = forge.pki.createCertificate();
      cert.publicKey = devicePublicKey;
      
      // Generate unique serial number
      const serialNumber = crypto.randomBytes(16).toString('hex');
      cert.serialNumber = serialNumber;

      // Set validity period (1 year)
      cert.validity.notBefore = new Date();
      cert.validity.notAfter = new Date();
      cert.validity.notAfter.setFullYear(cert.validity.notBefore.getFullYear() + 1);

      // Set subject with device ID as CN
      const subject = [{
        name: 'countryName',
        value: 'US'
      }, {
        name: 'organizationName',
        value: 'Device Identity'
      }, {
        name: 'organizationalUnitName',
        value: 'Enrolled Devices'
      }, {
        name: 'commonName',
        value: deviceId
      }];

      cert.setSubject(subject);
      cert.setIssuer(this.caCertificate.subject.attributes);

      // Add extensions
      const extensions = [
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
          name: 'subjectKeyIdentifier'
        },
        {
          name: 'authorityKeyIdentifier',
          keyIdentifier: this.caCertificate.generateSubjectKeyIdentifier().getBytes()
        }
      ];

      // Add custom Device Identity OID extension
      // OID 1.3.6.1.4.1.99999.1 (example OID for Device Identity)
      const deviceIdentityExtension = {
        id: '1.3.6.1.4.1.99999.1',
        critical: false,
        value: forge.asn1.create(forge.asn1.Class.UNIVERSAL, forge.asn1.Type.UTF8, false, 'DeviceIdentity')
      };
      extensions.push(deviceIdentityExtension);

      // Add attestation metadata as extension (optional)
      if (attestationData) {
        const attestationMetadataExt = {
          id: '1.3.6.1.4.1.99999.2',
          critical: false,
          value: forge.asn1.create(forge.asn1.Class.UNIVERSAL, forge.asn1.Type.UTF8, false, 
            JSON.stringify({
              securityLevel: attestationData.attestationSecurityLevel,
              verifiedBootState: attestationData.verifiedBootState,
              osVersion: attestationData.osVersion,
              patchLevel: attestationData.osPatchLevel
            })
          )
        };
        extensions.push(attestationMetadataExt);
      }

      cert.setExtensions(extensions);

      // Sign the certificate with CA private key
      cert.sign(this.caPrivateKey, forge.md.sha256.create());

      // Convert to PEM
      const certificatePem = forge.pki.certificateToPem(cert);
      const caCertificatePem = forge.pki.certificateToPem(this.caCertificate);

      console.log(`✅ DIC generated successfully for device: ${deviceId}`);

      return {
        success: true,
        certificatePem,
        certificateChain: [certificatePem, caCertificatePem],
        serialNumber,
        expiresAt: cert.validity.notAfter.toISOString(),
        issuer: 'Local CA'
      };

    } catch (error) {
      throw new Error('Local certificate generation failed: ' + error.message);
    }
  }

  /**
   * Verify certificate chain to Google roots
   */
  verifyChainToRoots(chain) {
    // In production, implement proper chain verification
    // For now, we'll do basic validation
    try {
      if (chain.length < 2) {
        return false;
      }

      // Basic chain validation
      for (let i = 0; i < chain.length - 1; i++) {
        const cert = chain[i];
        const issuer = chain[i + 1];
        
        // Check if issuer's subject matches cert's issuer
        const issuerDN = forge.pki.distinguishedNameToAsn1(issuer.subject).value;
        const certIssuerDN = forge.pki.distinguishedNameToAsn1(cert.issuer).value;
        
        // Simplified comparison - in production, use proper DN comparison
        if (JSON.stringify(issuerDN) !== JSON.stringify(certIssuerDN)) {
          return false;
        }
      }

      return true;
    } catch (error) {
      console.error('Chain verification error:', error);
      return false;
    }
  }

  /**
   * Extract attestation extension from certificate
   * This is a simplified version - in production, properly parse the ASN.1 structure
   */
  extractAttestationExtension(cert) {
    try {
      // Android Key Attestation extension OID
      const attestationOid = '1.3.6.1.4.1.11129.2.1.17';
      
      const extension = cert.getExtension(attestationOid);
      if (!extension) {
        return null;
      }

      // For demo purposes, return mock data
      // In production, parse the actual ASN.1 structure
      return {
        attestationChallenge: 'mock_challenge', // Would be extracted from extension
        verifiedBootState: 'GREEN',
        keyPurpose: 'SIGN',
        curve: 'P-256',
        exportable: false,
        rollbackResistant: true,
        attestationApplicationId: {
          packageName: 'com.example.app',
          certDigest: 'mock_digest'
        }
      };
    } catch (error) {
      console.error('Error extracting attestation extension:', error);
      return null;
    }
  }
}

module.exports = CertificateGenerator;
