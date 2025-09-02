# Deploy to Netlify - Step by Step Guide

## Method 1: Drag & Drop (Easiest)

### Step 1: Prepare Your Files
1. Create a ZIP file of your project folder
2. Make sure these files are included:
   - `netlify.toml` ✅
   - `netlify/functions/` folder ✅
   - `package.json` ✅
   - `utils/` folder ✅
   - `routes/` folder ✅

### Step 2: Deploy via Netlify Website
1. Go to **https://app.netlify.com**
2. Sign up/login with GitHub, GitLab, or email
3. Click **"Add new site"** → **"Deploy manually"**
4. Drag & drop your project folder or ZIP file
5. Netlify will automatically detect the `netlify.toml` config

### Step 3: Configure Environment Variables
In Netlify dashboard:
1. Go to **Site settings** → **Environment variables**
2. Add these required variables:
   ```
   ANDROID_PACKAGE_NAME = com.yourcompany.yourapp
   ANDROID_CERT_DIGEST = your-sha256-cert-digest
   NODE_ENV = production
   ```

### Step 4: Your Functions Will Be Available At:
- `https://your-site.netlify.app/.netlify/functions/get-enroll-nonce`
- `https://your-site.netlify.app/.netlify/functions/enroll`
- `https://your-site.netlify.app/.netlify/functions/revoke`

## Method 2: GitHub Integration (Recommended)

### Step 1: Push to GitHub
1. Create a new repository on GitHub
2. Push your code:
   ```bash
   git init
   git add .
   git commit -m "Initial DIC enrollment service"
   git branch -M main
   git remote add origin https://github.com/yourusername/dic-enrollment.git
   git push -u origin main
   ```

### Step 2: Connect to Netlify
1. Go to **https://app.netlify.com**
2. Click **"Add new site"** → **"Import an existing project"**
3. Choose **GitHub** and authorize
4. Select your repository
5. Netlify auto-detects `netlify.toml` configuration
6. Click **"Deploy site"**

### Step 3: Configure Environment Variables
Same as Method 1 - add your Android app config in Site settings.

## Method 3: Netlify CLI (Advanced)

### Step 1: Install Netlify CLI
```bash
npm install -g netlify-cli
```

### Step 2: Login and Deploy
```bash
# Login to Netlify
netlify login

# Deploy from your project folder
cd c:\Users\sagar\Downloads\DIC_enroll
netlify deploy --prod
```

## 🔧 Environment Variables You Need

In Netlify dashboard → Site settings → Environment variables:

```
ANDROID_PACKAGE_NAME = com.yourcompany.yourapp
ANDROID_CERT_DIGEST = A1B2C3D4E5F6... (your app's SHA-256 cert hash)
NODE_ENV = production
NONCE_EXPIRY_MS = 300000
```

## 🌐 Testing Your Deployed Service

Once deployed, test with:
```bash
# Replace YOUR-SITE-NAME with your actual Netlify site name
curl -X POST https://YOUR-SITE-NAME.netlify.app/.netlify/functions/get-enroll-nonce

# Should return:
# {"success":true,"nonceId":"...","nonceBase64":"...","expiresAt":"..."}
```

## 📱 Update Your Android App

In your Android app, change the base URL to your Netlify site:
```java
String baseUrl = "https://YOUR-SITE-NAME.netlify.app/.netlify/functions/";
String nonceUrl = baseUrl + "get-enroll-nonce";
String enrollUrl = baseUrl + "enroll";
```

That's it! Your Android DIC enrollment service will be live on Netlify with auto-scaling and global CDN.
