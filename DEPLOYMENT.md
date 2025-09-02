# Deployment Configurations

## Netlify Deployment

### Option 1: Netlify Functions (Recommended)

Create `netlify/functions/` directory and convert routes to serverless functions:

```javascript
// netlify/functions/attestation-challenge.js
exports.handler = async (event, context) => {
  // Handle challenge generation
};

// netlify/functions/enrollment.js
exports.handler = async (event, context) => {
  // Handle enrollment
};
```

### Option 2: Netlify Build

```toml
# netlify.toml
[build]
  command = "npm run build"
  publish = "dist"

[functions]
  directory = "netlify/functions"

[[redirects]]
  from = "/api/*"
  to = "/.netlify/functions/:splat"
  status = 200
```

## AWS EC2 Deployment

### 1. Launch EC2 Instance
```bash
# Amazon Linux 2
sudo yum update -y
curl -o- https://raw.githubusercontent.com/nvm-sh/nvm/v0.38.0/install.sh | bash
source ~/.bashrc
nvm install node
npm install -g pm2
```

### 2. Deploy Application
```bash
# Clone repository
git clone <your-repo-url>
cd dic-enrollment-service

# Install dependencies
npm ci --only=production

# Configure environment
cp .env.example .env
nano .env

# Start with PM2
pm2 start server.js --name "dic-enrollment"
pm2 startup
pm2 save
```

### 3. Configure Security Group
- Inbound: HTTP (80), HTTPS (443), SSH (22)
- Outbound: All traffic

### 4. SSL/TLS Setup
```bash
# Install Certbot
sudo yum install -y certbot python3-certbot-nginx

# Get certificate
sudo certbot --nginx -d yourdomain.com

# Auto-renewal
echo "0 12 * * * /usr/bin/certbot renew --quiet" | sudo crontab -
```

## Docker Deployment

### Dockerfile
```dockerfile
FROM node:18-alpine

WORKDIR /app

# Copy package files
COPY package*.json ./

# Install dependencies
RUN npm ci --only=production && npm cache clean --force

# Copy application code
COPY . .

# Create non-root user
RUN addgroup -g 1001 -S nodejs
RUN adduser -S nodejs -u 1001

# Change ownership
RUN chown -R nodejs:nodejs /app
USER nodejs

EXPOSE 3000

HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
  CMD node healthcheck.js

CMD ["npm", "start"]
```

### Docker Compose
```yaml
version: '3.8'
services:
  dic-enrollment:
    build: .
    ports:
      - "3000:3000"
    environment:
      - NODE_ENV=production
      - PORT=3000
    env_file:
      - .env
    restart: unless-stopped
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:3000/health"]
      interval: 30s
      timeout: 10s
      retries: 3
```

## Heroku Deployment

### 1. Prepare for Heroku
```json
// Add to package.json
{
  "engines": {
    "node": "18.x"
  }
}
```

### 2. Deploy
```bash
# Install Heroku CLI
heroku create your-app-name
heroku config:set NODE_ENV=production
heroku config:set ANDROID_PACKAGE_NAME=com.yourapp
heroku config:set ANDROID_CERT_DIGEST=your_digest

git add .
git commit -m "Initial deployment"
git push heroku main
```

## Google Cloud Run

### 1. Build and Deploy
```bash
# Build container
gcloud builds submit --tag gcr.io/PROJECT_ID/dic-enrollment

# Deploy to Cloud Run
gcloud run deploy dic-enrollment \
  --image gcr.io/PROJECT_ID/dic-enrollment \
  --platform managed \
  --region us-central1 \
  --allow-unauthenticated
```

## Environment Variables by Platform

### Netlify
Set in Netlify dashboard under Site settings > Environment variables

### AWS EC2
Set in `/home/ec2-user/dic-enrollment-service/.env`

### Docker
Set in `docker-compose.yml` or pass via `-e` flags

### Heroku
```bash
heroku config:set VAR_NAME=value
```

### Google Cloud Run
```bash
gcloud run services update dic-enrollment \
  --set-env-vars NODE_ENV=production,PORT=8080
```

## Production Checklist

### Security
- [ ] Enable HTTPS
- [ ] Configure CORS properly
- [ ] Add rate limiting
- [ ] Implement authentication
- [ ] Use real Google attestation roots
- [ ] Secure CA private keys

### Monitoring
- [ ] Add logging (Winston, Bunyan)
- [ ] Set up error tracking (Sentry)
- [ ] Configure health checks
- [ ] Add metrics collection

### Database
- [ ] Set up PostgreSQL/MongoDB
- [ ] Implement enrollment record storage
- [ ] Add certificate revocation list
- [ ] Set up backups

### Performance
- [ ] Add Redis for nonce storage
- [ ] Implement connection pooling
- [ ] Set up load balancing
- [ ] Configure caching
