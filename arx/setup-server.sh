#!/bin/bash

# Base Server Setup Script
# Sets up system packages, firewall, and creates users

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
    echo "  --user USER           SSH user (default: root)"
    echo "  --create-user NAME    Create a new sudo user"
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
        --user)
                [[ -z "$2" || "$2" == --* ]] && { log_error "--user requires a value"; exit 1; }
            SSH_USER="$2"
            shift 2
            ;;
        --create-user)
                [[ -z "$2" || "$2" == --* ]] && { log_error "--create-user requires a value"; exit 1; }
            CREATE_USER="$2"
            shift 2
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
SSH_OPTS="-o StrictHostKeyChecking=no -o BatchMode=no"

if [ -z "$SERVER_IP" ]; then
    log_error "Server IP is required. Use --ip"
    exit 1
fi
}

setup_base() {
    log_info "Setting up base system..."

ssh $SSH_OPTS "$SSH_USER@$SERVER_IP" << 'ENDSSH'
set -e

echo "Waiting for cloud-init to finish..."
cloud-init status --wait > /dev/null 2>&1 || true

echo "Updating package lists..."
sudo apt-get update

echo "Installing essential packages..."
sudo apt-get install -y curl wget git ufw

echo "Configuring firewall..."
sudo ufw allow OpenSSH
sudo ufw --force enable

echo "Creating swap if needed..."
if ! swapon --show | grep -q swapfile; then
    sudo fallocate -l 4G /swapfile
    sudo chmod 600 /swapfile
    sudo mkswap /swapfile
    sudo swapon /swapfile
    echo '/swapfile none swap sw 0 0' | sudo tee -a /etc/fstab
    echo "Swap created"
else
    echo "Swap already exists"
fi

echo "Base setup completed!"
ENDSSH
}

create_user() {
    local username="$1"

    log_info "Creating user: $username"
    
    ssh $SSH_OPTS "$SSH_USER@$SERVER_IP" bash -s "$username" << 'ENDSSH'
USERNAME="$1"
set -e

if id "$USERNAME" &>/dev/null; then
    echo "User $USERNAME already exists"
else
    sudo adduser --disabled-password --gecos "" "$USERNAME"
    sudo usermod -aG sudo "$USERNAME"
    
    echo "$USERNAME ALL=(ALL) NOPASSWD:ALL" | sudo tee /etc/sudoers.d/$USERNAME
    sudo chmod 440 /etc/sudoers.d/$USERNAME

    sudo mkdir -p /home/$USERNAME/.ssh
    sudo cp ~/.ssh/authorized_keys /home/$USERNAME/.ssh/
    sudo chown -R $USERNAME:$USERNAME /home/$USERNAME/.ssh
    sudo chmod 700 /home/$USERNAME/.ssh
    sudo chmod 600 /home/$USERNAME/.ssh/authorized_keys
    
    echo "User $USERNAME created with sudo access"
fi
ENDSSH
}

# Main
parse_args "$@"

log_info "Setting up server at $SERVER_IP"
echo "=================================================="

setup_base

if [ -n "$CREATE_USER" ]; then
    create_user "$CREATE_USER"
fi

log_info "Server setup completed!"
