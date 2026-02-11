#!/bin/bash

# Nginx + SSL Setup Script
# Configures nginx as reverse proxy with Let's Encrypt SSL

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

log_info() { echo -e "${GREEN}[INFO]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }

usage() {
    echo "Usage: $0 [options]"
    echo ""
    echo "Options:"
    echo "  --ip IP               Server IP address (required)"
    echo "  --domain DOMAIN       Domain name (required)"
    echo "  --port PORT           Backend port to proxy to (default: 3000)"
    echo "  --email EMAIL         Email for Let's Encrypt (required for SSL)"
    echo "  --user USER           SSH user (default: root)"
    echo "  --skip-dns            Skip DigitalOcean DNS setup"
    echo "  -h, --help            Show this help message"
    exit 0
}

parse_args() {
while [[ $# -gt 0 ]]; do
    case $1 in
        --ip)
                [[ -z "$2" || "$2" == --* ]] && { log_error "--ip requires a value"; exit 1; }
            SERVER_IP="$2"
            shift 2
            ;;
        --domain)
                [[ -z "$2" || "$2" == --* ]] && { log_error "--domain requires a value"; exit 1; }
            DOMAIN_NAME="$2"
            shift 2
            ;;
        --port)
                [[ -z "$2" || "$2" == --* ]] && { log_error "--port requires a value"; exit 1; }
            BACKEND_PORT="$2"
            shift 2
            ;;
        --email)
                [[ -z "$2" || "$2" == --* ]] && { log_error "--email requires a value"; exit 1; }
            EMAIL_ADDRESS="$2"
            shift 2
            ;;
        --user)
                [[ -z "$2" || "$2" == --* ]] && { log_error "--user requires a value"; exit 1; }
            SSH_USER="$2"
            shift 2
            ;;
        --skip-dns)
            SKIP_DNS=1
            shift
            ;;
        -h|--help)
            usage
            ;;
        *)
                log_error "Unknown option: $1"
            usage
            ;;
    esac
done

SSH_USER="${SSH_USER:-root}"
BACKEND_PORT="${BACKEND_PORT:-3000}"
SSH_OPTS="-o StrictHostKeyChecking=no -o BatchMode=no"

if [ -z "$SERVER_IP" ]; then
    log_error "Server IP is required. Use --ip"
    exit 1
fi
if [ -z "$DOMAIN_NAME" ]; then
    log_error "Domain name is required. Use --domain"
    exit 1
fi
if [ -z "$EMAIL_ADDRESS" ]; then
    log_error "Email is required for SSL. Use --email"
    exit 1
fi
}

setup_dns() {
    if [ -n "$SKIP_DNS" ]; then
        log_info "Skipping DNS setup"
        return
    fi

    if ! command -v doctl &> /dev/null; then
        log_warn "doctl not installed, skipping DNS setup"
        return
    fi

    if ! doctl account get &> /dev/null; then
        log_warn "doctl not authenticated, skipping DNS setup"
        return
    fi

    log_info "Setting up DNS for $DOMAIN_NAME..."

    if doctl compute domain get "$DOMAIN_NAME" &> /dev/null; then
        log_info "Domain $DOMAIN_NAME already exists, updating records..."
    else
        log_info "Creating domain: $DOMAIN_NAME"
        doctl compute domain create "$DOMAIN_NAME" --ip-address "$SERVER_IP"
    fi

    update_dns_record "@"
    update_dns_record "www"

    log_info "DNS configured"
}

update_dns_record() {
    local name="$1"

    if doctl compute domain records list "$DOMAIN_NAME" --format "Type,Name" --no-header | grep -q "^A[[:space:]]*${name}$"; then
        log_info "Updating $name A record..."
        RECORD_ID=$(doctl compute domain records list "$DOMAIN_NAME" --format "ID,Type,Name" --no-header | grep "^[0-9]*[[:space:]]*A[[:space:]]*${name}$" | awk '{print $1}')
        doctl compute domain records update "$DOMAIN_NAME" --record-id "$RECORD_ID" --record-data "$SERVER_IP"
    else
        log_info "Creating $name A record..."
        doctl compute domain records create "$DOMAIN_NAME" --record-type A --record-name "$name" --record-data "$SERVER_IP"
    fi
}

verify_dns() {
    log_info "Verifying DNS propagation..."

    local max_attempts=30
    local attempt=1

    while [ $attempt -le $max_attempts ]; do
        RESOLVED_IP=$(dig +short "$DOMAIN_NAME" @8.8.8.8 | head -1)

        if [ "$RESOLVED_IP" = "$SERVER_IP" ]; then
            log_info "DNS verified: $DOMAIN_NAME -> $SERVER_IP"
            return 0
        fi

        log_warn "Attempt $attempt/$max_attempts: DNS resolves to '$RESOLVED_IP', expected '$SERVER_IP'"
        log_info "Waiting 10 seconds for DNS propagation..."
        sleep 10
        attempt=$((attempt + 1))
    done

    log_error "DNS verification failed after $max_attempts attempts"
    log_error "Domain $DOMAIN_NAME does not resolve to $SERVER_IP"
    log_error "Please check your DNS settings and try again"
    exit 1
}

verify_http() {
    log_info "Verifying HTTP connectivity on port 80..."

    local max_attempts=6
    local attempt=1

    while [ $attempt -le $max_attempts ]; do
        if curl -s --connect-timeout 5 -o /dev/null -w "%{http_code}" "http://$SERVER_IP/" | grep -qE "^[2345]"; then
            log_info "HTTP connectivity verified on port 80"
            return 0
        fi

        log_warn "Attempt $attempt/$max_attempts: Cannot connect to http://$SERVER_IP/"
        log_info "Waiting 5 seconds..."
        sleep 5
        attempt=$((attempt + 1))
    done

    log_error "Cannot connect to server on port 80"
    log_error "Check that UFW allows port 80: ssh $SSH_USER@$SERVER_IP 'sudo ufw status'"
    exit 1
}

setup_nginx() {
    log_info "Setting up nginx..."

    ssh $SSH_OPTS "$SSH_USER@$SERVER_IP" bash -s "$DOMAIN_NAME" "$BACKEND_PORT" << 'ENDSSH'
DOMAIN_NAME="$1"
BACKEND_PORT="$2"
set -e

echo "Installing nginx..."
sudo apt-get update
sudo apt-get install -y nginx

echo "Configuring nginx for $DOMAIN_NAME -> localhost:$BACKEND_PORT..."

sudo tee /etc/nginx/sites-available/$DOMAIN_NAME > /dev/null <<NGINX
server {
    listen 80;
    server_name $DOMAIN_NAME www.$DOMAIN_NAME;

    location / {
        proxy_pass http://127.0.0.1:$BACKEND_PORT;
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection 'upgrade';
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
        proxy_cache_bypass \$http_upgrade;
    }
}
NGINX

sudo ln -sf /etc/nginx/sites-available/$DOMAIN_NAME /etc/nginx/sites-enabled/
sudo rm -f /etc/nginx/sites-enabled/default

sudo nginx -t
sudo systemctl reload nginx

echo "Opening firewall for HTTP/HTTPS..."
sudo ufw allow 80/tcp
sudo ufw allow 443/tcp
sudo ufw reload

echo "Nginx configured!"
ENDSSH

    log_info "Nginx setup completed"
}

setup_ssl() {
    log_info "Setting up SSL..."

    ssh $SSH_OPTS "$SSH_USER@$SERVER_IP" bash -s "$DOMAIN_NAME" "$EMAIL_ADDRESS" << 'ENDSSH'
DOMAIN_NAME="$1"
EMAIL_ADDRESS="$2"
set -e

echo "Installing certbot..."
sudo apt-get install -y certbot python3-certbot-nginx

if [ -d "/etc/letsencrypt/live/$DOMAIN_NAME" ]; then
    echo "Certificate already exists for $DOMAIN_NAME"
    sudo certbot certificates -d $DOMAIN_NAME
    sudo certbot --nginx -d $DOMAIN_NAME -d www.$DOMAIN_NAME \
        --non-interactive --agree-tos --email $EMAIL_ADDRESS \
        --redirect --keep-until-expiring
else
    echo "Issuing new SSL certificate..."
    sudo certbot --nginx -d $DOMAIN_NAME -d www.$DOMAIN_NAME \
        --non-interactive --agree-tos --email $EMAIL_ADDRESS --redirect
fi

echo "SSL configured! (Auto-renewal enabled via systemd timer)"
ENDSSH

    log_info "SSL setup completed"
}

print_summary() {
    log_info "Setup completed!"
    echo -e "${GREEN}Your site is accessible at:${NC}"
    echo "  - https://$DOMAIN_NAME"
    echo "  - https://www.$DOMAIN_NAME"
    echo "  - Proxying to localhost:$BACKEND_PORT"
}

# Main
parse_args "$@"

log_info "Setting up nginx + SSL for $DOMAIN_NAME"
echo "=================================================="

setup_dns
setup_nginx
verify_dns
verify_http
setup_ssl

echo ""
print_summary
