# Glitch Deployment

## Deploy to Glitch (Instant & Free)

### Method 1: Import from GitHub
1. **Go to**: https://glitch.com
2. **Sign up** with GitHub
3. **Create New Project** → "Import from GitHub"
4. **Enter repository URL**: Your GitHub repo URL
5. **Add Environment Variables**: Click "Settings" → "Environment Variables"
   ```
   ANDROID_PACKAGE_NAME=com.yourcompany.yourapp
   ANDROID_CERT_DIGEST=your-sha256-cert-digest
   NODE_ENV=production
   ```

### Method 2: Manual Upload
1. **Create New Project** → "hello-express"
2. **Upload your files** by dragging them into the file explorer
3. **Edit package.json** and other files directly in browser
4. **Auto-deploys** on every change

Your API will be available at: `https://your-project-name.glitch.me/api/attestation/get-enroll-nonce`

## Features:
- ✅ Instant deployment
- ✅ Online code editor
- ✅ Free HTTPS
- ✅ Always-on (no sleeping)
- ✅ Great for prototyping
