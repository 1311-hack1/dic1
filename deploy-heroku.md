# Heroku Deployment

## Deploy to Heroku (Free)

### Method 1: Heroku CLI
```bash
# Install Heroku CLI from https://devcenter.heroku.com/articles/heroku-cli

# Login and create app
heroku login
cd c:\Users\sagar\Downloads\DIC_enroll
heroku create your-dic-service

# Set environment variables
heroku config:set ANDROID_PACKAGE_NAME=com.yourcompany.yourapp
heroku config:set ANDROID_CERT_DIGEST=your-sha256-cert-digest
heroku config:set NODE_ENV=production

# Deploy
git init
git add .
git commit -m "Initial commit"
git push heroku main
```

### Method 2: GitHub Integration
1. **Push to GitHub** (if not already done)
2. **Heroku Dashboard**: https://dashboard.heroku.com
3. **Create New App** → Connect to GitHub repository
4. **Enable Automatic Deploys** from main branch
5. **Add Environment Variables** in Settings tab

Your API will be available at: `https://your-dic-service.herokuapp.com/api/attestation/get-enroll-nonce`

## Features:
- ✅ Free HTTPS
- ✅ Easy database add-ons (PostgreSQL, Redis)
- ✅ Automatic deployments from GitHub
- ⚠️ Sleeps after 30 minutes of inactivity
