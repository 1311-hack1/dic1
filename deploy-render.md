# Render Deployment

## Deploy to Render (Free)

1. **Sign up**: Go to https://render.com and sign up with GitHub
2. **Create Web Service**: 
   - Click "New" → "Web Service"
   - Connect your GitHub repository
   - Choose "Node" environment
3. **Configure**:
   - **Build Command**: `npm install`
   - **Start Command**: `npm start`
   - **Port**: Service runs on PORT environment variable (automatic)
4. **Environment Variables**:
   ```
   ANDROID_PACKAGE_NAME=com.yourcompany.yourapp
   ANDROID_CERT_DIGEST=your-sha256-cert-digest
   NODE_ENV=production
   ```
5. **Deploy**: Render automatically builds and deploys

Your API will be available at: `https://your-service-name.onrender.com/api/attestation/get-enroll-nonce`

## Features:
- ✅ Free HTTPS
- ✅ Automatic deployments from GitHub
- ✅ Custom domains on free tier
- ⚠️ Sleeps after 15 minutes of inactivity (wakes up on first request)
