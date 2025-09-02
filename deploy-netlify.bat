@echo off
echo ==========================================
echo   DIC Enrollment Service - Netlify Deploy
echo ==========================================
echo.

echo Creating deployment package...

REM Create a clean directory for deployment
if exist "deploy-package" rmdir /s /q deploy-package
mkdir deploy-package

REM Copy essential files for Netlify deployment
xcopy netlify deploy-package\netlify\ /E /I /Q
copy netlify.toml deploy-package\
copy package.json deploy-package\
xcopy utils deploy-package\utils\ /E /I /Q
xcopy routes deploy-package\routes\ /E /I /Q
copy .env.example deploy-package\

echo.
echo ✅ Deployment package created in 'deploy-package' folder
echo.
echo Next steps:
echo 1. Go to https://app.netlify.com
echo 2. Click "Add new site" → "Deploy manually" 
echo 3. Drag the 'deploy-package' folder to Netlify
echo 4. Configure environment variables in Site settings:
echo    - ANDROID_PACKAGE_NAME = com.yourcompany.yourapp
echo    - ANDROID_CERT_DIGEST = your-sha256-cert-digest
echo    - NODE_ENV = production
echo.
echo 🚀 Your functions will be available at:
echo    https://your-site.netlify.app/.netlify/functions/get-enroll-nonce
echo    https://your-site.netlify.app/.netlify/functions/enroll
echo    https://your-site.netlify.app/.netlify/functions/revoke
echo.
pause
