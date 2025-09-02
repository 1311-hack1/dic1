@echo off
echo ==========================================
echo   Deploy DIC Service to Railway
echo ==========================================
echo.

echo Installing Railway CLI...
npm install -g @railway/cli

echo.
echo Please follow these steps:
echo.
echo 1. Go to https://railway.app and sign up with GitHub
echo 2. Run these commands:
echo.
echo    railway login
echo    railway deploy
echo.
echo 3. Add environment variables in Railway dashboard:
echo    - ANDROID_PACKAGE_NAME = com.yourcompany.yourapp
echo    - ANDROID_CERT_DIGEST = your-sha256-cert-digest
echo    - NODE_ENV = production
echo.
echo 4. Your API will be available at:
echo    https://your-app.up.railway.app/api/attestation/get-enroll-nonce
echo.
echo ==========================================
echo   Alternative: Manual Upload
echo ==========================================
echo.
echo 1. Go to railway.app → New Project → Empty Project
echo 2. Add Service → Upload files
echo 3. Drag this entire folder to Railway
echo 4. Add environment variables as above
echo.
pause
