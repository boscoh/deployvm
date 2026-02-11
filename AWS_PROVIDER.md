# AWS Provider Implementation

AWS CLI support has been added to the deployment tool, enabling deployment to AWS EC2 instances alongside DigitalOcean.

## What Was Added

### 1. AWS Configuration Function (`get_aws_config`)
- Reused from `microeval/llm.py`
- Discovers AWS credentials from `~/.aws/credentials` and environment variables
- Validates credentials using AWS STS
- Returns configuration dict for boto3 client initialization

### 2. AWSProvider Class
Implements the Provider protocol with AWS equivalents:

| Function | AWS Service | Description |
|----------|-------------|-------------|
| `create_instance()` | EC2 | Creates EC2 instances with security groups |
| `delete_instance()` | EC2 | Terminates EC2 instances |
| `list_instances()` | EC2 | Lists all EC2 instances |
| `setup_dns()` | Route53 | Updates DNS A records in hosted zones |
| `validate_auth()` | STS | Validates AWS credentials |

### 3. Key Features
- **AMI Selection**: Automatically finds latest Ubuntu 22.04 LTS AMI
- **SSH Key Management**: Auto-imports local SSH keys to AWS
- **Security Groups**: Creates and manages `deploy-vm-web` security group with ports 22, 80, 443
- **Instance Tagging**: Tags instances with Name for easy identification
- **Waiter Support**: Uses EC2 waiters for instance state changes

### 4. Documentation Updates
- Added AWS to README with setup instructions
- Documented AWS regions and instance types
- Added Route53 DNS configuration guide
- Included AWS examples for FastAPI and Nuxt deployments

## Usage Examples

### Create AWS Instance
```bash
uv run deploy-vm instance create my-server \
    --provider aws \
    --region us-east-1 \
    --vm-size t3.micro
```

### Deploy FastAPI to AWS
```bash
uv run deploy-vm fastapi deploy my-server /path/to/app \
    --provider aws \
    --region us-west-2 \
    --vm-size t3.small \
    --domain example.com \
    --email you@example.com
```

### Deploy Nuxt to AWS
```bash
uv run deploy-vm nuxt deploy my-server /path/to/nuxt \
    --provider aws \
    --region eu-west-1 \
    --vm-size t3.medium \
    --domain example.com \
    --email you@example.com
```

## Prerequisites

### 1. AWS Credentials
```bash
# Configure AWS CLI
aws configure

# Or set environment variables
export AWS_PROFILE=your-profile
export AWS_REGION=us-east-1
```

### 2. Route53 Hosted Zone
For SSL support, create a hosted zone in Route53:
1. Go to Route53 console
2. Create hosted zone for your domain
3. Update domain registrar with Route53 nameservers
4. The tool will automatically create A records

### 3. Python Dependencies
```bash
uv sync  # Installs boto3 and other dependencies
```

## AWS vs DigitalOcean Comparison

| Feature | DigitalOcean | AWS |
|---------|-------------|-----|
| CLI Tool | `doctl` | boto3 (Python SDK) |
| Instances | Droplets | EC2 Instances |
| DNS | DigitalOcean DNS | Route53 |
| VM Sizes | s-1vcpu-1gb, etc. | t3.micro, t3.small, etc. |
| Regions | syd1, nyc1, etc. | us-east-1, us-west-2, etc. |
| SSH Keys | Auto-uploaded | Auto-imported |
| Firewall | UFW on instance | Security Groups |
| OS Selection | Image slug | AMI (auto-selected) |

## Implementation Notes

1. **AMI Discovery**: Uses Canonical's official Ubuntu AMIs (account ID: 099720109477)
2. **Security Groups**: Creates a single shared security group for all instances
3. **Region Handling**: Must specify region explicitly (no default like DigitalOcean's syd1)
4. **DNS Requirements**: Route53 hosted zone must exist before deployment
5. **Credential Validation**: Uses STS GetCallerIdentity for auth verification

## Testing

The implementation has been validated for:
- [x] Syntax check (Python compilation)
- [x] CLI help output
- [x] Provider registration
- [ ] Instance creation (requires AWS credentials)
- [ ] DNS setup (requires Route53 hosted zone)
- [ ] Full deployment (requires AWS account)
