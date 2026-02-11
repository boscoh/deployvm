#!/bin/bash

# Delete a DigitalOcean Droplet
# Usage: ./delete-droplet.sh <name>.droplet.txt [--force]

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

log_info() { echo -e "${GREEN}[INFO]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }

usage() {
  echo "Usage: $0 <name>.droplet.txt [--force]"
  exit 1
}

check_doctl() {
if ! command -v doctl &> /dev/null; then
        log_error "doctl not installed"
  exit 1
fi

if ! doctl auth validate &> /dev/null; then
        log_error "doctl not authenticated. Run: doctl auth init"
        exit 1
    fi
}

load_droplet_file() {
    local file="$1"

    if [ ! -f "$file" ]; then
        log_error "File not found: $file"
  exit 1
fi

    source "$file"

if [ -z "$DROPLET_ID" ]; then
        log_error "DROPLET_ID not found in $file"
  exit 1
fi
}

confirm_delete() {
    local force="$1"

    log_warn "Droplet to delete:"
echo "  Name: $DROPLET_NAME"
    echo "  ID:   $DROPLET_ID"
    echo "  IP:   $DROPLET_IP"
echo ""

    if [ "$force" != "--force" ]; then
  read -p "Delete this droplet? (yes/no): " CONFIRM
  if [ "$CONFIRM" != "yes" ]; then
            log_info "Cancelled."
    exit 0
  fi
fi
}

delete_droplet() {
    local file="$1"

    log_info "Deleting droplet..."
doctl compute droplet delete "$DROPLET_ID" --force

    rm -f "$file"
    log_info "Droplet deleted. Removed $file"
}

# Main
DETAILS_FILE="${1:-}"
FORCE="${2:-}"

if [ -z "$DETAILS_FILE" ]; then
    usage
fi

check_doctl
load_droplet_file "$DETAILS_FILE"
confirm_delete "$FORCE"
delete_droplet "$DETAILS_FILE"
