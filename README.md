# VM Deployment Tool

Python CLI for deploying web applications to cloud providers (currently DigitalOcean).

## Installation

```bash
uv sync
```

## Quick Start

```bash
# Create a cloud instance
uv run deploy-vm instance create my-server

# Deploy FastAPI app (IP-only)
uv run deploy-vm fastapi deploy my-server /path/to/app --no-ssl

# Deploy Nuxt app with SSL
uv run deploy-vm nuxt deploy my-server example.com /path/to/nuxt you@example.com
```

## Commands

```
uv run deploy-vm --help
```

| Group      | Command   | Description                                        |
|------------|-----------|----------------------------------------------------| 
| `instance` | `create`  | Create a new cloud instance                        |
| `instance` | `delete`  | Delete an instance                                 |
| `instance` | `list`    | List all instances                                 |
| `instance` | `verify`  | Verify server health (SSH, firewall, nginx, DNS)   |
| `nginx`    | `ip`      | Setup nginx for IP-only access                     |
| `nginx`    | `ssl`     | Setup nginx with SSL certificate                   |
| `nuxt`     | `deploy`  | Full deploy: create instance, setup, deploy, nginx |
| `nuxt`     | `sync`    | Sync Nuxt app to existing server                   |
| `nuxt`     | `restart` | Restart Nuxt app via PM2                           |
| `nuxt`     | `status`  | Check PM2 process status                           |
| `nuxt`     | `logs`    | View PM2 logs                                      |
| `fastapi`  | `deploy`  | Full deploy: create instance, setup, deploy, nginx |
| `fastapi`  | `sync`    | Sync FastAPI app to existing server                |
| `fastapi`  | `restart` | Restart FastAPI app via supervisor                 |
| `fastapi`  | `status`  | Check supervisor process status                    |
| `fastapi`  | `logs`    | View supervisor logs                               |

## Instance Management

### Create Instance

```bash
uv run deploy-vm instance create my-server --region syd1 --vm-size s-1vcpu-1gb
```

Creates `my-server.instance.json` with instance details.

**Regions:** `syd1`, `sgp1`, `nyc1`, `sfo3`, `lon1`, `fra1`
**VM Sizes:** `s-1vcpu-512mb`*, `s-1vcpu-1gb`, `s-1vcpu-2gb`, `s-2vcpu-2gb`, `s-4vcpu-8gb`
**OS Images:** `ubuntu-24-04-x64`, `ubuntu-22-04-x64`

*512mb only available in: nyc1, fra1, sfo3, sgp1, ams3

### Delete Instance

```bash
uv run deploy-vm instance delete my-server
uv run deploy-vm instance delete my-server --force  # skip confirmation
```

### List Instances

```bash
uv run deploy-vm instance list
```

### Verify Instance

Check server health (SSH, firewall, nginx, DNS, HTTP/HTTPS):

```bash
uv run deploy-vm instance verify my-server
uv run deploy-vm instance verify my-server --domain example.com
```

## FastAPI Deployment

### Full Deploy

Creates instance, sets up server, deploys app, configures nginx:

```bash
# With SSL
uv run deploy-vm fastapi deploy my-server /path/to/app \
    --domain example.com --email you@example.com

# IP-only (no SSL)
uv run deploy-vm fastapi deploy my-server /path/to/app --no-ssl
```

Options:
- `--app-module` - Uvicorn module (default: `app:app`)
- `--app-name` - Supervisor process name (default: `fastapi`)
- `--port` - Backend port (default: 8000)
- `--workers` - Uvicorn workers (default: 2)

### Sync Only

Sync code to existing server without recreating instance:

```bash
uv run deploy-vm fastapi sync my-server /path/to/app
```

Smart rebuild detection: computes source checksum and skips rebuild if unchanged.

### Management

```bash
uv run deploy-vm fastapi status my-server
uv run deploy-vm fastapi logs my-server --lines 100
uv run deploy-vm fastapi restart my-server
```

The `--app-name` parameter defaults to the instance name (e.g., `my-server` uses app name `my-server`).

## Nuxt Deployment

### Full Deploy

Creates instance, sets up server, deploys app, configures SSL:

```bash
uv run deploy-vm nuxt deploy my-server example.com /path/to/nuxt you@example.com
```

Options:
- `--port` - Backend port (default: 3000)
- `--local-build` - Build locally, upload .output (default: true)
- `--node-version` - Node.js version (default: 20)

### Sync Only

```bash
# Build locally (recommended for low-memory servers)
uv run deploy-vm nuxt sync my-server /path/to/nuxt

# Build on server
uv run deploy-vm nuxt sync my-server /path/to/nuxt --local-build=false
```

### Management

```bash
uv run deploy-vm nuxt status my-server
uv run deploy-vm nuxt logs my-server --lines 100
uv run deploy-vm nuxt restart my-server
```

The `--app-name` parameter defaults to the instance name (e.g., `my-server` uses PM2 app name `my-server`).

## Nginx Configuration

### IP-Only Access

```bash
uv run deploy-vm nginx ip my-server --port 8000
```

### SSL Certificate

```bash
uv run deploy-vm nginx ssl my-server example.com you@example.com --port 8000
```

- Configures DigitalOcean DNS (A records for @ and www)
- Installs nginx reverse proxy
- Verifies DNS propagation (retries up to 5 minutes)
- Issues Let's Encrypt SSL certificate

Use `--skip-dns` if managing DNS elsewhere.

### Static Files

For Nuxt deployments, nginx serves static files directly from `.output/public/` for better performance. Use `--nuxt-static-dir` to specify a custom static directory:

```bash
uv run deploy-vm nginx ssl my-server example.com you@example.com \
    --nuxt-static-dir /home/deploy/nuxt/.output/public
```

## Requirements

### Local Tools

| Tool   | Purpose                  | Install                                             |
|--------|--------------------------|-----------------------------------------------------|
| Python | Runtime (3.11+)          | `brew install python`                               |
| uv     | Python package manager   | `curl -LsSf https://astral.sh/uv/install.sh \| sh`  |
| doctl  | DigitalOcean CLI         | `brew install doctl`                                |
| rsync  | File sync to server      | `brew install rsync`                                |
| ssh    | Remote command execution | Pre-installed on macOS/Linux                        |
| dig    | DNS verification         | Pre-installed (or `brew install bind`)              |
| npm    | Nuxt local builds        | `brew install node`                                 |

### Setup

1. Authenticate doctl: `doctl auth init`
2. SSH key in `~/.ssh/` (id_ed25519, id_rsa, or id_ecdsa)
3. SSH key uploaded to DigitalOcean (auto-uploaded on first deploy)

### Domain Setup

Configure your domain registrar to use DigitalOcean's nameservers:

```
ns1.digitalocean.com
ns2.digitalocean.com
ns3.digitalocean.com
```

Nameserver changes can take up to 48 hours to propagate.

## Instance State

Instance details are stored in `<name>.instance.json`:

```json
{
  "id": 543540359,
  "ip": "170.64.235.136",
  "provider": "digitalocean",
  "region": "syd1",
  "vm_size": "s-1vcpu-1gb",
  "user": "deploy"
}
```

