# deploy-vm

Python CLI for deploying web applications to cloud providers (DigitalOcean and AWS).

**Important**: DigitalOcean and AWS use different parameter formats. See [PROVIDER_COMPARISON.md](PROVIDER_COMPARISON.md) for detailed differences in regions, VM sizes, and OS images.

## Installation

```bash
uv tool install deploy-vm
```

See [Requirements](#requirements) for prerequisites.

## Configuration

### Environment Variables (.env)

Create a `.env` file in your project root to set default configuration:

```bash
# Cloud Provider (optional)
DEPLOY_VM_PROVIDER=aws              # or "digitalocean" (default)

# AWS Configuration (optional)
AWS_PROFILE=your-profile            # AWS CLI profile name
AWS_REGION=ap-southeast-2           # Default AWS region
```

**Benefits:**
- Set provider once, no need for `--provider aws` on every command
- Use AWS CLI profiles for multiple accounts
- Override defaults with command-line flags when needed

**Note:** The `.env` file is loaded automatically. Command-line arguments always take precedence over environment variables.

## Quick Start

This guide walks you through three main tasks: creating a cloud instance, deploying a FastAPI application, and deploying a Nuxt application.

### Task 1: Create a Cloud Instance

Create a new cloud instance on DigitalOcean or AWS:

```bash
# DigitalOcean (default)
uv run deploy-vm instance create my-server

# AWS
uv run deploy-vm instance create my-server --provider aws
```

Instance details saved to `my-server.instance.json`. You can now SSH to the instance with passwordless SSH:

```bash
ssh root@<ip>
ssh deploy@<ip>
```

### Task 2: Deploy a FastAPI Application

Deploy a FastAPI application with nginx as a reverse proxy in front of it:

```bash
# DigitalOcean - IP-only access (no SSL)
uv run deploy-vm fastapi deploy my-server /path/to/app --no-ssl

# DigitalOcean - With SSL certificate
uv run deploy-vm fastapi deploy my-server /path/to/app \
    --domain example.com --email you@example.com

# AWS - With SSL certificate
uv run deploy-vm fastapi deploy my-server /path/to/app \
    --provider aws --vm-size t3.small \
    --domain example.com --email you@example.com
```

Configures nginx as reverse proxy to FastAPI (port 8000), managed by supervisord. SSL uses certbot (requires Route53 for AWS or DigitalOcean DNS).

### Task 3: Deploy a Nuxt Application

Deploy a Nuxt application with SSL:

```bash
# DigitalOcean
uv run deploy-vm nuxt deploy my-server example.com /path/to/nuxt you@example.com

# AWS
uv run deploy-vm nuxt deploy my-server /path/to/nuxt \
    --provider aws --region us-west-2 --vm-size t3.medium \
    --domain example.com --email you@example.com
```

Builds Nuxt app and configures nginx with SSL. Managed by PM2. Nginx serves static files from `.output/public/` and proxies API requests. SSL uses certbot (requires Route53 for AWS or DigitalOcean DNS).

## Commands

```
deploy-vm --help
```

- `deploy-vm instance`
  - `create` - Create a new cloud instance
    - `--provider digitalocean` (default)
      - `--region`: syd1 (default), sgp1, nyc1, sfo3, lon1, fra1
      - `--vm-size`: s-1vcpu-1gb (default), s-1vcpu-512mb* (nyc1, fra1, sfo3, sgp1, ams3 only), s-1vcpu-2gb, s-2vcpu-2gb, s-4vcpu-8gb
      - `--os-image`: ubuntu-24-04-x64 (default), ubuntu-22-04-x64
    - `--provider aws`
      - `--region`: ap-southeast-2 (default), us-east-1, us-west-2, eu-west-1, ap-southeast-1
      - `--vm-size`: t3.micro (default), t3.small, t3.medium, t3.large, t3.xlarge, t4g.micro, t4g.small
      - `--os-image`: Latest Ubuntu 22.04 LTS AMI (auto-selected)
  - `delete` - Delete an instance (use `--force` to skip confirmation)
  - `list` - List all instances
  - `apps` - List all apps deployed on an instance
  - `verify` - Verify server health (SSH, firewall, nginx, DNS)
    - Use `--domain` to check DNS and HTTPS
- `deploy-vm nginx`
  - `ip` - Setup nginx for IP-only access
  - `ssl` - Setup nginx with SSL certificate
    - Configures DigitalOcean DNS (A records for @ and www), verifies DNS propagation (retries up to 5 minutes), issues Let's Encrypt certificate
    - Use `--skip-dns` if managing DNS elsewhere
    - For Nuxt, nginx serves static files from `.output/public/` by default (use `--nuxt-static-dir` to customize)
- `deploy-vm nuxt`
  - `deploy` - Full deploy: create instance, setup, deploy, nginx
    - Options: `--port` (default: 3000), `--local-build` (default: true), `--node-version` (default: 20)
    - App name defaults to instance name
  - `sync` - Sync Nuxt app to existing server
    - Smart rebuild detection: computes source checksum and skips rebuild if unchanged
    - Use `--local-build=false` to build on server
  - `restart` - Restart Nuxt app via PM2 (use `--app-name` if multiple apps exist)
  - `status` - Check PM2 process status
  - `logs` - View PM2 logs (use `--app-name` if multiple apps exist)
- `deploy-vm fastapi`
  - `deploy` - Full deploy: create instance, setup, deploy, nginx
    - Options: `--app-module` (default: app:app), `--app-name` (default: fastapi), `--port` (default: 8000), `--workers` (default: 2)
    - App name defaults to instance name
  - `sync` - Sync FastAPI app to existing server
    - Smart rebuild detection: computes source checksum and skips rebuild if unchanged
  - `restart` - Restart FastAPI app via supervisor (use `--app-name` if multiple apps exist)
  - `status` - Check supervisor process status
  - `logs` - View supervisor logs (use `--app-name` if multiple apps exist)

## Requirements

### Local Tools

| Tool  | Purpose                        | Install                                             |
|-------|--------------------------------|-----------------------------------------------------|
| uv    | Python package manager         | `curl -LsSf https://astral.sh/uv/install.sh \| sh`  |
| doctl | DigitalOcean CLI (optional)    | `brew install doctl`                                |
| aws   | AWS CLI (optional)             | `brew install awscli`                               |
| rsync | File sync to server            | `brew install rsync`                                |
| tar   | Archive creation (fallback)    | Pre-installed on macOS/Linux                        |
| scp   | Secure file copy (fallback)    | Pre-installed on macOS/Linux (part of OpenSSH)      |
| ssh   | Remote command execution       | Pre-installed on macOS/Linux (required for rsync/scp) |
| npm   | Nuxt local builds              | `brew install node`                                 |

Note: While Fabric (Python library) uses Paramiko for SSH connections, `rsync` and `scp` commands require the SSH client binary to be installed.

### Setup

#### DigitalOcean

1. Authenticate doctl: `doctl auth init`
2. SSH key in `~/.ssh/` (id_ed25519, id_rsa, or id_ecdsa)
3. SSH key uploaded to DigitalOcean (auto-uploaded on first deploy)

#### AWS

1. **Configure AWS credentials** (choose one method):

   **Option A: AWS CLI**
   ```bash
   aws configure
   # Prompts for: Access Key ID, Secret Access Key, Region, Output format
   ```

   **Option B: Environment variables**
   ```bash
   # For temporary use (session only)
   export AWS_PROFILE=your-profile
   export AWS_REGION=ap-southeast-2

   # For persistent use, add to .env file:
   echo "AWS_PROFILE=your-profile" >> .env
   echo "AWS_REGION=ap-southeast-2" >> .env
   ```

   **Option C: Multiple profiles**
   ```bash
   # Edit ~/.aws/credentials
   [default]
   aws_access_key_id = YOUR_KEY
   aws_secret_access_key = YOUR_SECRET

   [work]
   aws_access_key_id = WORK_KEY
   aws_secret_access_key = WORK_SECRET

   # Use in .env
   echo "AWS_PROFILE=work" >> .env
   ```

2. **Set default provider** (optional but recommended):
   ```bash
   # Add to .env file in project root
   echo "DEPLOY_VM_PROVIDER=aws" >> .env
   ```
   This allows you to omit `--provider aws` from all commands.

3. **SSH key setup**:
   - SSH key in `~/.ssh/` (id_ed25519, id_rsa, or id_ecdsa)
   - Automatically uploaded to AWS on first deploy

4. **Credentials file**: `~/.aws/credentials` stores your access keys

### Domain Setup

#### DigitalOcean

Configure your domain registrar to use DigitalOcean's nameservers:

```
ns1.digitalocean.com
ns2.digitalocean.com
ns3.digitalocean.com
```

Nameserver changes can take up to 48 hours to propagate.

#### AWS

Configure Route53 hosted zone for your domain:

1. Create a hosted zone in Route53 for your domain
2. Update your domain registrar to use AWS Route53 nameservers
3. The tool will automatically update A records in the hosted zone

## Instance State

Instance details are stored in `<name>.instance.json`:

```json
{
  "id": 543540359,
  "ip": "170.64.235.136",
  "provider": "digitalocean",
  "region": "syd1",
  "os_image": "ubuntu-24-04-x64",
  "vm_size": "s-1vcpu-1gb",
  "user": "deploy",
  "apps": [
    {"name": "myapp", "type": "nuxt", "port": 3000},
    {"name": "api", "type": "fastapi", "port": 8000}
  ]
}
```

The `apps` array tracks all apps deployed on the instance. Each app entry includes:
- `name`: App name (PM2 process name or supervisor program name)
- `type`: App type (`nuxt` or `fastapi`)
- `port`: Port number (optional, saved during deployment)

**Multiple Apps Support**: You can deploy multiple apps to the same instance. Management commands (restart, logs) will:
- Automatically use the app if only one exists
- Require `--app-name` if multiple apps exist
- Use `deploy-vm instance apps <name>` to list all apps on an instance

## Environment Variables Reference

Deploy-vm reads configuration from a `.env` file in your project root (if it exists):

| Variable | Description | Example | Default |
|----------|-------------|---------|---------|
| `DEPLOY_VM_PROVIDER` | Default cloud provider | `aws` or `digitalocean` | `digitalocean` |
| `AWS_PROFILE` | AWS CLI profile name | `default`, `production`, `staging` | None |
| `AWS_REGION` | Default AWS region | `ap-southeast-2`, `us-east-1` | `ap-southeast-2` |

**Example `.env` file:**
```bash
# Use AWS by default
DEPLOY_VM_PROVIDER=aws

# Use specific AWS profile
AWS_PROFILE=production

# Default to Sydney region
AWS_REGION=ap-southeast-2
```

**Priority order** (highest to lowest):
1. Command-line flags (e.g., `--provider aws`)
2. Environment variables in `.env` file
3. Built-in defaults

**Note:** The `.env` file is gitignored by default to prevent accidentally committing credentials.

