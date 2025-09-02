# Fly.io Deployment

## Deploy to Fly.io (Free Docker Hosting)

### Prerequisites
```bash
# Install Fly CLI
# Windows: Download from https://fly.io/docs/hands-on/install-flyctl/
# Or use: iwr https://fly.io/install.ps1 -useb | iex
```

### Deploy Steps
```bash
# Login to Fly.io
flyctl auth login

# Initialize your app
cd c:\Users\sagar\Downloads\DIC_enroll
flyctl launch

# This creates fly.toml config file
# Follow prompts to:
# - Choose app name
# - Select region (nearest to your users)
# - Don't setup PostgreSQL for now
# - Don't deploy immediately

# Set environment variables
flyctl secrets set ANDROID_PACKAGE_NAME=com.yourcompany.yourapp
flyctl secrets set ANDROID_CERT_DIGEST=your-sha256-cert-digest
flyctl secrets set NODE_ENV=production

# Deploy
flyctl deploy
```

### Free Tier Limits
- **Resources**: 256MB RAM, 1GB disk
- **Runtime**: 160 hours/month (enough for testing)
- **Benefits**: True Docker deployment, excellent performance

Your API will be available at: `https://your-app-name.fly.dev/api/attestation/get-enroll-nonce`

## Custom fly.toml Configuration
```toml
app = "your-dic-service"
primary_region = "iad"

[build]

[http_service]
  internal_port = 3000
  force_https = true
  auto_stop_machines = "stop"
  auto_start_machines = true
  min_machines_running = 0

[[vm]]
  cpu_kind = "shared"
  cpus = 1
  memory_mb = 256
```
