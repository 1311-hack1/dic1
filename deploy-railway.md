# Railway Deployment

## Quick Deploy to Railway

1. **Sign up**: Go to https://railway.app and sign up with GitHub
2. **Create Project**: Click "New Project" → "Deploy from GitHub repo"
3. **Connect Repository**: Select your DIC enrollment repository
4. **Environment Variables**: Add in Railway dashboard:
   ```
   ANDROID_PACKAGE_NAME=com.yourcompany.yourapp
   ANDROID_CERT_DIGEST=your-sha256-cert-digest
   NODE_ENV=production
   PORT=3000
   ```
5. **Deploy**: Railway automatically builds and deploys

## Alternative: Deploy without GitHub

```bash
# Install Railway CLI
npm install -g @railway/cli

# Login and deploy
railway login
cd c:\Users\sagar\Downloads\DIC_enroll
railway deploy
```

Your API will be available at: `https://your-app-name.up.railway.app/api/attestation/get-enroll-nonce`
