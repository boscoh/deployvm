# SSL and SSL Lockdown Documentation

This document covers deployvm's SSL certificate management and the enhanced SSL lockdown security feature.

## Table of Contents
- [Basic SSL Setup](#basic-ssl-setup)
- [SSL Lockdown Mode](#ssl-lockdown-mode)
- [Implementation Details](#implementation-details)
- [Known Issues and Limitations](#known-issues-and-limitations)
- [Troubleshooting](#troubleshooting)

## Basic SSL Setup

### Standard SSL Deployment

```bash
# Deploy with SSL certificate
deployvm uv deploy myapp "." "uv run app:app --port 8000" \
    --domain example.com \
    --email admin@example.com

# Add SSL to existing deployment
deployvm ssl myapp example.com admin@example.com
```

### Multi-App SSL Configuration

Each app needs its own domain and unique ports:

```bash
# First app
deployvm uv deploy myserver /api "uv run api:app --port 8000" \
    --app-name api --port 8000 \
    --domain api.example.com --email admin@example.com

# Second app  
deployvm uv deploy myserver /frontend "uv run frontend:app --port 8001" \
    --app-name frontend --port 8001 \
    --domain app.example.com --email admin@example.com
```

## SSL Lockdown Mode

### ⚠️ CRITICAL: Certificate Provisioning Limitation

**SSL lockdown currently has a critical limitation with new certificate issuance:**

- SSL lockdown blocks port 80 immediately during deployment
- Let's Encrypt ACME validation requires port 80 access
- **New domains will fail SSL certificate provisioning**

**REQUIRED WORKAROUND for new domains:**
```bash
# Step 1: Deploy without SSL lockdown to get certificate
deployvm uv deploy myapp "." "uv run app:app --port 8000" \
    --domain example.com --email admin@example.com

# Step 2: Re-deploy with SSL lockdown enabled  
deployvm uv deploy myapp "." "uv run app:app --port 8000" \
    --domain example.com --email admin@example.com \
    --ssl-only
```

**Existing domains with valid certificates can use `--ssl-only` directly.**

### Overview

SSL Lockdown mode provides enhanced security by completely blocking HTTP traffic at multiple levels:

- **Firewall Level**: Port 80 blocked at UFW and cloud provider (AWS/Vultr) level
- **Nginx Level**: HTTP requests return connection drop (444 status)
- **No Redirects**: HTTP traffic is eliminated entirely, not redirected

### Security Benefits

✅ **Complete HTTP Elimination**: No unencrypted traffic possible  
✅ **Attack Surface Reduction**: Port 80 unavailable to attackers  
✅ **Defense in Depth**: Multi-layer blocking (OS + cloud + application)  
✅ **Multi-App Compatible**: Works with multiple domains per instance  

### Usage

```bash
# Deploy with SSL lockdown
deployvm uv deploy myapp "." "uv run app:app --port 8000" \
    --domain example.com --email admin@example.com \
    --ssl-only

# Enable on existing SSL deployment  
deployvm uv deploy myapp "." "uv run app:app --port 8000" \
    --domain example.com --email admin@example.com \
    --ssl-only
```

### Requirements

- Valid domain name (`--domain` required)
- Email address for Let's Encrypt (`--email` required)
- **Existing SSL certificate** (see [Known Issues](#known-issues-and-limitations))

### Testing SSL Lockdown

```bash
# These should fail (connection refused/timeout)
curl http://example.com
curl http://your-instance-ip

# This should work
curl https://example.com
```

## Implementation Details

### Architecture

SSL Lockdown uses a dual-layer security approach:

#### Layer 1: Firewall Blocking
```bash
# UFW (server-level)
sudo ufw deny 80/tcp
sudo ufw allow 443/tcp

# Cloud providers
# AWS: Removes port 80 from security groups
# Vultr: Deletes port 80 firewall rules  
# DigitalOcean: UFW only (no cloud firewall)
```

#### Layer 2: Nginx Configuration  
```nginx
# HTTP blocking server
server {
    listen 80;
    server_name example.com www.example.com;
    return 444;  # Drop connection without response
}

# HTTPS server (normal configuration)
server {
    listen 443 ssl;
    server_name example.com www.example.com;
    # ... SSL certificates and proxy configuration
}
```

### Multi-Provider Support

| Provider | UFW Blocking | Cloud Firewall | Status |
|----------|-------------|----------------|---------|
| **AWS** | ✅ | ✅ Security Groups | Complete |
| **DigitalOcean** | ✅ | N/A (no cloud firewall) | Complete |
| **Vultr** | ✅ | ✅ Firewall Groups | Complete |

## Known Issues and Limitations

### ⚠️ Critical: Certificate Provisioning

**Issue**: SSL lockdown blocks port 80 before certificate issuance, breaking ACME HTTP-01 validation.

**Impact**: New domains requiring SSL certificates will fail during deployment.

**Current Workaround**: 
1. Deploy without `--ssl-only` first
2. Let SSL certificate be issued normally
3. Re-deploy with `--ssl-only` to enable lockdown

**Example**:
```bash
# Step 1: Initial deployment (gets certificate)
deployvm uv deploy myapp "." "uv run app:app --port 8000" \
    --domain example.com --email admin@example.com

# Step 2: Enable SSL lockdown
deployvm uv deploy myapp "." "uv run app:app --port 8000" \
    --domain example.com --email admin@example.com \
    --ssl-only
```

### ⚠️ Nginx Server Conflicts

Multiple server blocks listening on port 80 can cause conflicts:

```nginx
# Domain-specific block
server {
    listen 80;
    server_name example.com;
    return 444;
}

# Catch-all block (can override domain-specific)
server {
    listen 80;
    server_name _;
    return 444;
}
```

**Impact**: Catch-all server block may intercept requests intended for domain-specific blocks.

### ⚠️ Certbot Integration

Certbot's `--redirect` flag creates HTTP→HTTPS redirects that conflict with SSL-only blocking:

```nginx
# Certbot creates this (conflicts with SSL-only)
server {
    listen 80;
    server_name example.com;
    return 301 https://example.com$request_uri;
}
```

SSL-only mode regenerates the configuration to use `return 444;` instead.

## Troubleshooting

### SSL Lockdown Not Working

**Check firewall status:**
```bash
ssh user@your-server 'sudo ufw status'
# Should show: 80/tcp DENY and 443/tcp ALLOW
```

**Check nginx configuration:**
```bash
ssh user@your-server 'sudo nginx -T | grep -A 5 "listen 80"'
# Should show: return 444; for SSL-only blocks
```

**Check cloud provider firewall:**
```bash
# AWS
aws ec2 describe-security-groups --filters Name=group-name,Values=deploy-vm-web

# Vultr  
vultr-cli firewall group list
```

### Certificate Issues

**Renew certificate manually:**
```bash
ssh user@your-server 'sudo certbot renew --dry-run'
```

**Re-run SSL setup:**
```bash
deployvm ssl myapp example.com admin@example.com
```

### Deployment Failures

**If deployment fails with HTTP verification errors:**
1. Check if SSL-only mode is blocking certificate validation
2. Use the two-step deployment process (certificate first, then SSL-only)

**If port conflicts occur:**
```bash
# Check which processes are using ports
ssh user@your-server 'sudo netstat -tlnp | grep :80'
ssh user@your-server 'sudo netstat -tlnp | grep :443'
```

### Disable SSL Lockdown

**Temporary disable for troubleshooting:**
```bash
deployvm uv deploy myapp "." "uv run app:app --port 8000" \
    --domain example.com --email admin@example.com
# (omit --ssl-only flag)
```

**Emergency access via IP:**
```bash
# If domain access fails, try direct IP
curl http://your-instance-ip:custom-port
# (if using custom outgoing port)
```

## Best Practices

### When to Use SSL Lockdown

**Recommended for:**
- Production environments with sensitive data
- Compliance requirements (PCI DSS, HIPAA, SOX)
- High-security applications
- Public-facing services requiring encryption
- APIs handling authentication/authorization

**Consider normal mode for:**
- Development environments  
- Testing/staging with mixed HTTP/HTTPS tooling
- Legacy client compatibility requirements
- Troubleshooting connectivity issues

### Deployment Strategy

**For new domains:**
```bash
# Phase 1: Get SSL certificate
deployvm uv deploy myapp "." "uv run app:app --port 8000" \
    --domain example.com --email admin@example.com

# Phase 2: Enable lockdown  
deployvm uv deploy myapp "." "uv run app:app --port 8000" \
    --domain example.com --email admin@example.com \
    --ssl-only
```

**For existing domains with certificates:**
```bash
# Can enable SSL lockdown immediately
deployvm uv deploy myapp "." "uv run app:app --port 8000" \
    --domain example.com --email admin@example.com \
    --ssl-only
```

### Monitoring

**Regular checks:**
```bash
# Verify SSL certificate validity
curl -I https://example.com

# Confirm HTTP blocking
timeout 5 curl http://example.com || echo "HTTP correctly blocked"

# Check certificate expiry
ssh user@server 'sudo certbot certificates'
```

## Security Considerations

### Threat Model

SSL Lockdown protects against:
- **Man-in-the-middle attacks** via HTTP interception
- **Protocol downgrade attacks** forcing HTTP usage
- **Accidental HTTP exposure** of sensitive data
- **Mixed content vulnerabilities** in applications

### Limitations

SSL Lockdown does **not** protect against:
- **Application-layer vulnerabilities** (XSS, CSRF, etc.)
- **TLS/SSL protocol vulnerabilities** (outdated ciphers, etc.)
- **Certificate authority compromise** 
- **Server-side attacks** bypassing network layers

### Compliance

SSL Lockdown helps meet requirements for:
- **PCI DSS**: Requirement 4 (encrypt cardholder data transmission)
- **HIPAA**: Technical safeguards for PHI transmission
- **SOX**: Controls over financial data transmission
- **GDPR**: Technical measures for personal data protection

Always consult with security professionals for complete compliance validation.