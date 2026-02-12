# deploy-vm

Python CLI for deploying web applications to cloud providers (DigitalOcean and AWS).

## Installation

```bash
uv tool install deploy-vm
```

## Quick Start

### 1. Configure Provider

Create `.env` in your **project root** (optional - defaults to DigitalOcean):

```bash
# AWS (recommended for production)
DEPLOY_VM_PROVIDER=aws
AWS_PROFILE=default
AWS_REGION=ap-southeast-2

# Or use DigitalOcean (default)
DEPLOY_VM_PROVIDER=digitalocean
```

> **Note**: This configures `deploy-vm` itself. Your **application credentials** go in a separate `.env` inside your app directory (see [Application Credentials](#application-credentials-env)).

**Setup requirements:**
- **AWS**: Run `aws configure` ([setup guide](https://docs.aws.amazon.com/cli/latest/userguide/cli-configure-quickstart.html))
- **DigitalOcean**: Run `doctl auth init`

### 2. Deploy Your App

**Simple deployment (no SSL):**
```bash
uv run deploy-vm fastapi deploy my-server /path/to/app --no-ssl
```

**With domain + SSL:**
```bash
# 1. Get nameservers first (see Domain Setup section for details)
uv run deploy-vm dns nameservers example.com --provider aws

# 2. Configure at registrar, wait 24-48h for propagation

# 3. Deploy with SSL
uv run deploy-vm fastapi deploy my-server /path/to/app \
    --domain example.com --email you@example.com
```

**Supported app types:**
- `fastapi deploy` - FastAPI apps with uvicorn + supervisord
- `nuxt deploy` - Nuxt apps with PM2

### 3. Manage Your Deployment

```bash
# Check status
uv run deploy-vm instance verify my-server --domain example.com

# View logs
uv run deploy-vm fastapi logs my-server

# Restart app
uv run deploy-vm fastapi restart my-server

# Redeploy code
uv run deploy-vm fastapi sync my-server /path/to/app
```

## Common Workflows

### Add SSL After Deployment

Deploy first, add SSL when domain is ready:

```bash
# 1. Deploy without SSL
uv run deploy-vm fastapi deploy my-server /path/to/app --no-ssl

# 2. Configure domain (see Domain Setup section)
uv run deploy-vm dns nameservers example.com --provider aws

# 3. Update nameservers at registrar, wait 24-48h

# 4. Add SSL
uv run deploy-vm nginx ssl my-server example.com you@example.com --port 8000
```

### Multiple Apps on One Instance

```bash
# Deploy first app
uv run deploy-vm fastapi deploy my-server /path/to/api \
    --app-name api --port 8000 --domain api.example.com --email you@example.com

# Deploy second app
uv run deploy-vm nuxt deploy my-server /path/to/frontend \
    --app-name frontend --port 3000 --domain example.com --email you@example.com

# List all apps
uv run deploy-vm instance apps my-server

# Manage specific app
uv run deploy-vm fastapi restart my-server --app-name api
```

## Configuration Reference

### Environment Variables

**Deploy-VM Configuration** (`.env` in project root):

| Variable               | Description                              | Default          |
|------------------------|------------------------------------------|------------------|
| `DEPLOY_VM_PROVIDER`   | Cloud provider (`aws` or `digitalocean`) | `digitalocean`   |
| `AWS_PROFILE`          | AWS CLI profile name                     | None             |
| `AWS_REGION`           | Default AWS region                       | `ap-southeast-2` |

**Priority:** Command-line flags > `.env` file > Built-in defaults

### Application Credentials (.env)

> **Important**: This is a **different `.env` file** than the deploy-vm configuration above.

Your deployed apps use a `.env` file **inside the app directory** for credentials:

- **Location**: `.env` in your app's root (e.g., `/path/to/app/.env`)
- **Purpose**: API keys, database URLs, secrets your app needs to run
- **Deployment**: Automatically uploaded during `deploy` or `sync`

**AWS credential filtering:**

When deploying to AWS EC2, credentials are automatically filtered:
- ❌ **Removed**: `AWS_PROFILE`, `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY` (EC2 uses IAM roles)
- ✅ **Preserved/Added**: `AWS_REGION` (required for Bedrock and other services)

**Example app `.env`:**
```bash
# API credentials
ANTHROPIC_API_KEY=sk-ant-...
OPENAI_API_KEY=sk-proj-...

# AWS region (auto-added if missing when deploying to AWS)
AWS_REGION=ap-southeast-2

# Other config
DATABASE_URL=postgresql://...
SECRET_KEY=your-secret-key
```

### Provider-Specific Settings

| Setting      | AWS                                          | DigitalOcean                                    |
|--------------|----------------------------------------------|-------------------------------------------------|
| **Regions**  | `us-east-1`, `us-west-2`, `ap-southeast-2`  | `syd1`, `sgp1`, `nyc1`, `sfo3`, `lon1`         |
| **VM Sizes** | `t3.micro`, `t3.small`, `t3.medium`         | `s-1vcpu-1gb`, `s-2vcpu-2gb`, `s-4vcpu-8gb`   |
| **DNS**      | Route53 hosted zone (auto-created)          | DigitalOcean nameservers required              |
| **Auth**     | `aws configure`                             | `doctl auth init`                              |

See [PROVIDER_COMPARISON.md](PROVIDER_COMPARISON.md) for complete details.

## AWS-Specific Features

### Bedrock Access

AWS EC2 instances automatically get **full Bedrock access** via IAM roles:

**Default behavior:**
```bash
# Bedrock access included automatically
uv run deploy-vm fastapi deploy my-server /path/to/app --no-ssl
```

**Custom IAM role:**
```bash
# Use custom role name
uv run deploy-vm fastapi deploy my-server /path/to/app \
    --iam-role custom-role-name --no-ssl
```

**What's included:**
- IAM role with EC2 trust policy
- `AmazonBedrockFullAccess` managed policy attached
- Instance profile created and attached
- Access to all Bedrock foundation models and runtime APIs

**Configuration:**
- Default role name: `deploy-vm-bedrock`
- Customize with `--iam-role <name>` flag
- Your app must include `AWS_REGION` in `.env` (auto-added if missing)

### IAM Role Details

The IAM setup enables your application to call Bedrock APIs without hardcoded credentials:

```python
# Your app code (no credentials needed)
import boto3

bedrock = boto3.client('bedrock-runtime', region_name=os.getenv('AWS_REGION'))
response = bedrock.invoke_model(...)
```

## Commands Reference

```bash
deploy-vm --help  # See all commands

# Core commands
deploy-vm instance create|delete|list|verify|apps
deploy-vm dns nameservers
deploy-vm nginx ip|ssl
deploy-vm fastapi deploy|sync|restart|status|logs
deploy-vm nuxt deploy|sync|restart|status|logs
```

**Common options:**
- `--provider aws|digitalocean` - Cloud provider
- `--region <region>` - Provider region
- `--vm-size <size>` - Instance size
- `--domain <domain>` - Domain for SSL
- `--no-ssl` - Skip SSL configuration
- `--app-name <name>` - App identifier (for multiple apps)
- `--iam-role <name>` - AWS only: Custom IAM role name

See full documentation: `deploy-vm <command> --help`

## Domain & SSL Setup

### Prerequisites

**AWS Route53:**
```bash
# Creates hosted zone automatically
uv run deploy-vm dns nameservers example.com --provider aws
```

**DigitalOcean:**
- Configure `ns1.digitalocean.com`, `ns2.digitalocean.com`, `ns3.digitalocean.com` at your registrar

### Deployment Paths

**Path A - SSL from start:**
1. Get nameservers: `uv run deploy-vm dns nameservers example.com --provider aws`
2. Configure at registrar, wait 24-48h
3. Deploy with `--domain example.com --email you@example.com`

**Path B - Add SSL later:**
1. Deploy with `--no-ssl`
2. Get nameservers (creates hosted zone automatically)
3. Configure at registrar, wait 24-48h
4. Add SSL: `uv run deploy-vm nginx ssl my-server example.com you@example.com --port 8000`

### Troubleshooting

See [DOMAIN_SETUP.md](DOMAIN_SETUP.md) for:
- Detailed setup instructions
- DNS propagation checking
- Common issues and solutions
- Technical reference

## Requirements

### Local Tools

| Tool                           | Purpose                    | Required | Install                     |
|--------------------------------|----------------------------|----------|-----------------------------|
| `uv`                           | Python package manager     | ✅ Yes   | `curl -LsSf https://astral.sh/uv/install.sh \| sh` |
| `ssh`, `rsync`, `tar`, `scp`   | File transfer & remote ops | ✅ Yes   | Pre-installed (macOS/Linux) |
| `doctl`                        | DigitalOcean CLI           | Optional | `brew install doctl`        |
| `aws`                          | AWS CLI                    | Optional | `brew install awscli`       |
| `npm`                          | Nuxt local builds          | Optional | `brew install node`         |

**Install uv:**
```bash
curl -LsSf https://astral.sh/uv/install.sh | sh
```

**Install provider CLIs:**
```bash
# AWS
brew install awscli
aws configure

# DigitalOcean
brew install doctl
doctl auth init
```

### FastAPI Deployment Requirements

- Uses `uv` for Python package management
- Expects `pyproject.toml` with project dependencies
- Runs via `uvicorn` with supervisord for process management
- App source must be a valid Python package

### SSH Key

Tool automatically uploads your SSH key (`~/.ssh/id_ed25519.pub`, `id_rsa.pub`, or `id_ecdsa.pub`) to the provider on first use.

### Server User Management

All server operations use the `deploy` user:

1. **Initial creation**: Connects as cloud default (`root` for DigitalOcean, `ubuntu` for AWS)
2. **Setup**: Creates `deploy` user with passwordless sudo
3. **All operations**: Use `deploy` user with `sudo` for privileged commands

Override with `--ssh-user` flag if needed.

## Advanced Topics

### Instance State

Instance metadata stored in `<name>.instance.json`:

```json
{
  "id": "i-0abc123",
  "ip": "54.123.45.67",
  "provider": "aws",
  "region": "ap-southeast-2",
  "os_image": "ubuntu/images/hvm-ssd-gp3/ubuntu-noble-24.04-amd64-server-*",
  "vm_size": "t3.small",
  "user": "deploy",
  "iam_role": "deploy-vm-bedrock",
  "apps": [
    {"name": "api", "type": "fastapi", "port": 8000},
    {"name": "frontend", "type": "nuxt", "port": 3000}
  ]
}
```

DNS nameservers cached in `<domain>.nameservers.json` (auto-generated).

### Additional Resources

- **Domain & SSL**: [DOMAIN_SETUP.md](DOMAIN_SETUP.md) - Complete guide with troubleshooting
- **Provider comparison**: [PROVIDER_COMPARISON.md](PROVIDER_COMPARISON.md) - Detailed feature matrix
- **Multiple environments**: Use different `.env` files or AWS profiles
- **CI/CD integration**: Use `--force` flags to skip confirmations

## Support

- **Issues**: [GitHub Issues](https://github.com/boscoh/deploy-vm/issues)
- **Documentation**: `deploy-vm --help` or `deploy-vm <command> --help`
