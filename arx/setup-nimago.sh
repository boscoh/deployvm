#!/bin/bash

# Full Nimago Deployment
# Creates droplet, deploys Nuxt app, and configures SSL

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
DROPLET_FILE="$SCRIPT_DIR/nimago.droplet.txt"

RED='\033[0;31m'
GREEN='\033[0;32m'
NC='\033[0m'

log_info() { echo -e "${GREEN}[INFO]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }

ensure_droplet() {
if [ ! -f "$DROPLET_FILE" ]; then
        log_info "Creating droplet..."
        "$SCRIPT_DIR/create-droplet.sh" nimago syd1 s-1vcpu-2gb
fi

source "$DROPLET_FILE"

if [ -z "$DROPLET_IP" ]; then
        log_error "DROPLET_IP not set in $DROPLET_FILE"
    exit 1
fi
}

setup_server() {
    log_info "Step 1: Server setup..."
    "$SCRIPT_DIR/setup-server.sh" --ip "$DROPLET_IP" --create-user boscoh
}

deploy_app() {
    log_info "Step 2: Deploying Nuxt..."
    "$SCRIPT_DIR/deploy-nuxt.sh" --ip "$DROPLET_IP" --source "$SCRIPT_DIR/../nimago" --app-user boscoh --local-build
}

setup_ssl() {
    log_info "Step 3: Setting up nginx + SSL..."
    "$SCRIPT_DIR/setup-nginx-ssl.sh" --ip "$DROPLET_IP" --domain tangiblespots.com --port 3000 --email apposite@gmail.com
}

# Main
ensure_droplet

log_info "Setting up nimago at $DROPLET_IP"
echo "=================================================="

echo ""
setup_server

echo ""
deploy_app

echo ""
setup_ssl

echo ""
echo "=================================================="
log_info "Setup complete!"
echo -e "${GREEN}Visit:${NC} https://tangiblespots.com"
