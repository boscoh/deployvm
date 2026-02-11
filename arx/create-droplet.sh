#!/bin/bash

# Create a DigitalOcean Droplet
# Usage: ./create-droplet.sh <name> [region] [size]

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
NC='\033[0m'

log_info() { echo -e "${GREEN}[INFO]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }

usage() {
  echo "Usage: $0 <name> [region] [size]"
    echo ""
    echo "Arguments:"
    echo "  name    Droplet name (required)"
    echo "  region  syd1 (default), sgp1, nyc1, sfo3, lon1, fra1"
    echo "  size    s-2vcpu-2gb (default), s-1vcpu-1gb, s-1vcpu-2gb, s-4vcpu-8gb"
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

check_droplet_exists() {
    local name="$1"
    if doctl compute droplet list --format Name --no-header | grep -qx "$name"; then
        log_error "Droplet '$name' already exists"
  exit 1
fi
}

get_ssh_key() {
SSH_KEY_ID=$(doctl compute ssh-key list --no-header --format ID | head -1)
if [ -z "$SSH_KEY_ID" ]; then
        log_error "No SSH keys found. Upload one first."
  exit 1
fi
}

create_droplet() {
    local name="$1"
    local region="$2"
    local size="$3"

    log_info "Creating droplet '$name' in $region ($size)..."

    DROPLET_ID=$(doctl compute droplet create "$name" \
        --region "$region" \
        --size "$size" \
  --image ubuntu-24-04-x64 \
  --ssh-keys "$SSH_KEY_ID" \
  --wait \
  --no-header \
  --format ID)

if [ -z "$DROPLET_ID" ]; then
        log_error "Failed to create droplet"
  exit 1
fi

IP=$(doctl compute droplet get "$DROPLET_ID" --no-header --format PublicIPv4)
}

save_details() {
    local name="$1"
    local region="$2"
    local size="$3"

    DETAILS_FILE="${name}.droplet.txt"
cat > "$DETAILS_FILE" << EOF
DROPLET_NAME=$name
DROPLET_ID=$DROPLET_ID
DROPLET_IP=$IP
DROPLET_REGION=$region
DROPLET_SIZE=$size
EOF

    log_info "Droplet created!"
    echo "  Name:   $name"
    echo "  ID:     $DROPLET_ID"
    echo "  IP:     $IP"
    echo "  Region: $region"
    echo "  Size:   $size"
echo ""
echo "Details saved to: $DETAILS_FILE"
echo "SSH: ssh root@$IP"
}

# Main
NAME="${1:-}"
REGION="${2:-syd1}"
SIZE="${3:-s-2vcpu-2gb}"

if [ -z "$NAME" ]; then
    usage
fi

check_doctl
check_droplet_exists "$NAME"
get_ssh_key
create_droplet "$NAME" "$REGION" "$SIZE"
save_details "$NAME" "$REGION" "$SIZE"
