# Android Device Identity Certificate (DIC) Enrollment Service

A production-ready backend service for Android Key Attestation verification and Device Identity Certificate (DIC) issuance. This service implements proper Android hardware-backed key attestation verification using Google's attestation roots and ASN.1 parsing.

## Features

- ✅ **Real Android Key Attestation Verification** - No mock data, uses actual Google attestation roots
- ✅ **Proper ASN.1 Parsing** - Uses @peculiar/asn1-android for accurate attestation extension parsing
- ✅ **Security Policy Enforcement** - Validates boot state, OS version, security level
- ✅ **Package Name Verification** - Ensures attestation comes from your expected Android app
- ✅ **Certificate Chain Validation** - Verifies against Google's official attestation roots
- ✅ **Nonce-based Challenge** - Prevents replay attacks with secure nonce generation
- ✅ **Multiple Deployment Options** - Express server, Netlify Functions, Docker, cloud platforms
- ✅ **Production CA Integration** - HashiCorp Vault support with local CA fallback

## API Endpoints

### 1. Get Enrollment Nonce
**POST** `/api/attestation/get-enroll-nonce`

Generates a cryptographic nonce for attestation challenge.

```javascript
// Request
{}

// Response
{
  "success": true,
  "nonceId": "unique-nonce-id",
  "nonce": "base64-encoded-32-byte-nonce",
  "expiresAt": "2024-01-01T12:00:00Z"
}
```

### 2. Device Enrollment
**POST** `/api/enrollment/enroll`

Verifies attestation and issues Device Identity Certificate.

```javascript
// Request
{
  "nonceId": "unique-nonce-id",
  "attestationChainPem": "-----BEGIN CERTIFICATE-----\n...",
  "devicePublicKeyPem": "-----BEGIN PUBLIC KEY-----\n...", // optional if in attestation
  "csrPem": "-----BEGIN CERTIFICATE REQUEST-----\n...", // optional
  "deviceInfo": { /* optional device metadata */ }
}

// Response
{
  "success": true,
  "deviceId": "uuid-device-id",
  "deviceIdentityCertificate": "-----BEGIN CERTIFICATE-----\n...",
  "certificateChain": ["...intermediate...", "...root..."],
  "enrollmentTime": "2024-01-01T12:00:00Z",
  "expiresAt": "2025-01-01T12:00:00Z",
  "serialNumber": "certificate-serial-number",
  "attestation": {
    "securityLevel": "STRONGBOX",
    "verifiedBootState": "VERIFIED",
    "osVersion": 140000,
    "patchLevel": "2024-01"
  }
}
```

### 3. Device Revocation (Optional)
**POST** `/api/enrollment/revoke`

Revokes a device's enrollment status.

```javascript
// Request
{
  "deviceId": "uuid-device-id",
  "reason": "Device compromised"
}

// Response
{
  "success": true,
  "deviceId": "uuid-device-id",
  "revokedAt": "2024-01-01T12:00:00Z"
}
```

## Quick Start

### 1. Install Dependencies

```bash
npm install
```

### 2. Environment Configuration

Create `.env` file in project root:

```env
# Required: Your Android app configuration
ANDROID_PACKAGE_NAME=com.yourcompany.yourapp
ANDROID_CERT_DIGEST=sha256-hash-of-your-signing-certificate

# Optional: Security settings
NONCE_EXPIRY_MS=300000
NODE_ENV=development

# Optional: Certificate Authority (for production)
VAULT_URL=https://your-vault-instance.com
VAULT_TOKEN=your-vault-token
VAULT_PKI_PATH=pki
VAULT_ROLE_NAME=device-identity

# Optional: Custom attestation roots (if not using Google)
CUSTOM_ATTESTATION_ROOTS_URL=https://your-custom-roots.com/roots.json
```

### 3. Run the Service

#### Option A: Express Server
```bash
npm start
# Service runs on http://localhost:3000
```

#### Option B: Netlify Functions (Serverless)
```bash
# Deploy to Netlify
npm run build
netlify deploy --prod

# Or run locally
netlify dev
```

#### Option C: Docker
```bash
docker build -t dic-enrollment .
docker run -p 3000:3000 --env-file .env dic-enrollment
```

## Android Integration

### 1. Generate Key Pair and Attestation

```java
// In your Android app
KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(
    KeyProperties.KEY_ALGORITHM_EC, "AndroidKeyStore");

KeyGenParameterSpec spec = new KeyGenParameterSpec.Builder(
    "device_identity_key",
    KeyProperties.PURPOSE_SIGN | KeyProperties.PURPOSE_VERIFY)
    .setAlgorithmParameterSpec(new ECGenParameterSpec("secp256r1"))
    .setDigests(KeyProperties.DIGEST_SHA256, KeyProperties.DIGEST_SHA512)
    .setAttestationChallenge(nonceBytes) // Use nonce from /get-enroll-nonce
    .build();

keyPairGenerator.initialize(spec);
KeyPair keyPair = keyPairGenerator.generateKeyPair();

// Get attestation certificate chain
KeyStore keyStore = KeyStore.getInstance("AndroidKeyStore");
keyStore.load(null);
Certificate[] certChain = keyStore.getCertificateChain("device_identity_key");
```

### 2. Submit for Enrollment

```java
// Convert certificates to PEM format and send to /enroll endpoint
String attestationChainPem = convertCertChainToPem(certChain);
String devicePublicKeyPem = convertPublicKeyToPem(keyPair.getPublic());

// POST to your enrollment service
JSONObject enrollmentRequest = new JSONObject();
enrollmentRequest.put("nonceId", nonceId);
enrollmentRequest.put("attestationChainPem", attestationChainPem);
enrollmentRequest.put("devicePublicKeyPem", devicePublicKeyPem);
```

## Deployment Options

### Netlify Functions

Deploy as serverless functions:

```bash
# Install Netlify CLI
npm install -g netlify-cli

# Deploy
netlify deploy --prod
```

Functions available at:
- `/.netlify/functions/get-enroll-nonce`
- `/.netlify/functions/enroll`
- `/.netlify/functions/revoke`

### AWS EC2 / Other Cloud Platforms

1. Install Node.js 18+ on your server
2. Clone the repository
3. Set environment variables
4. Run `npm install && npm start`
5. Configure reverse proxy (nginx) if needed

### Heroku

```bash
# Create Heroku app
heroku create your-dic-service

# Set environment variables
heroku config:set ANDROID_PACKAGE_NAME=com.yourcompany.yourapp
heroku config:set ANDROID_CERT_DIGEST=your-cert-digest

# Deploy
git push heroku main
```

## Security Considerations

### Android App Configuration

1. **Package Name**: Must match exactly with your Android app's package name
2. **Certificate Digest**: SHA-256 hash of your app's signing certificate
3. **Nonce Usage**: Each nonce can only be used once and expires in 5 minutes

### Certificate Authority

For production, configure a proper CA:

```env
# HashiCorp Vault (Recommended)
VAULT_URL=https://your-vault.com
VAULT_TOKEN=your-token
VAULT_PKI_PATH=pki
VAULT_ROLE_NAME=device-identity

# Local CA (Development only)
# Service will auto-generate a self-signed CA
```

### Attestation Verification

The service verifies:
- ✅ Certificate chain against Google attestation roots
- ✅ Boot state is VERIFIED
- ✅ OS version meets minimum requirements
- ✅ Security level (STRONGBOX preferred, TEE acceptable)
- ✅ Package name matches expected value
- ✅ Certificate digest matches expected value
- ✅ Nonce prevents replay attacks

## API Response Formats

### Success Response
```json
{
  "success": true,
  "data": { /* endpoint-specific data */ }
}
```

### Error Response
```json
{
  "success": false,
  "error": "Human-readable error message",
  "details": "Additional error context (development only)"
}
```

## Monitoring and Logs

The service provides structured logging:

- 🔵 **INFO**: Normal operations (nonce generation, successful enrollments)
- 🟡 **WARN**: Security warnings (expired nonces, invalid certificates)
- 🔴 **ERROR**: Critical errors (attestation verification failures, CA errors)

Example log output:
```
✅ Attestation verification successful
📝 Enrollment record created: { deviceId: "...", serialNumber: "..." }
🎉 Device enrolled successfully: uuid-device-id
```

## Testing

### Unit Tests
```bash
npm test
```

### Integration Testing
```bash
# Test nonce generation
curl -X POST http://localhost:3000/api/attestation/get-enroll-nonce

# Test enrollment (requires real Android attestation data)
curl -X POST http://localhost:3000/api/enrollment/enroll \
  -H "Content-Type: application/json" \
  -d '{"nonceId":"...","attestationChainPem":"..."}'
```

## Troubleshooting

### Common Issues

1. **Attestation Verification Fails**
   - Check that Google attestation roots are accessible
   - Verify package name and certificate digest match exactly
   - Ensure Android device has hardware attestation support

2. **Nonce Expired**
   - Nonces expire in 5 minutes by default
   - Adjust `NONCE_EXPIRY_MS` if needed for your use case

3. **Certificate Generation Fails**
   - Check Vault configuration if using HashiCorp Vault
   - Verify CA key permissions for local CA

### Debug Mode

Set `NODE_ENV=development` to see detailed error messages in API responses.

## Architecture

```
┌─────────────────┐    ┌──────────────────────┐    ┌─────────────────┐
│   Android App   │────│  DIC Enrollment      │────│  Certificate    │
│                 │    │  Service             │    │  Authority      │
│ • Generate Keys │    │                      │    │                 │
│ • Get Nonce     │    │ • Verify Attestation │    │ • Issue DIC     │
│ • Submit        │    │ • Validate Chain     │    │ • Manage Certs  │
│   Attestation   │    │ • Check Security     │    │                 │
└─────────────────┘    └──────────────────────┘    └─────────────────┘
```

## Contributing

This service implements the Android Key Attestation specification and follows security best practices. Contributions should maintain compatibility with the attestation format and security requirements.

## License

MIT License - See LICENSE file for details.
