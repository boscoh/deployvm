#!/bin/bash
#
# FastAPI Server Setup Script
#
# Usage examples:
#   # With default SSH key, root login, and boscoh user
#   ./setup_fastapi.sh 192.168.1.100
#
#   # With explicit SSH key
#   ./setup_fastapi.sh 192.168.1.100 ~/.ssh/custom_key.pub
#
#   # With non-root initial user
#   ./setup_fastapi.sh 192.168.1.100 ~/.ssh/id_ed25519.pub ubuntu
#
#   # With custom target username
#   ./setup_fastapi.sh 192.168.1.100 ~/.ssh/id_ed25519.pub root appuser
#
# Parameters:
#   VM_IP           - IP address of target VM (required)
#   PUBLIC_KEY_FILE - Path to SSH public key (optional, tries ~/.ssh/id_ed25519.pub then ~/.ssh/id_rsa.pub)
#   INITIAL_USER    - Initial SSH user (optional, default: root)
#   VM_USER         - Target username to create (optional, default: boscoh)
#

VM_IP="$1"
PUBLIC_KEY_FILE="$2"
INITIAL_USER="${3:-root}"
VM_USER="${4:-boscoh}"

if [ -z "$VM_IP" ]; then
  echo "Usage: $0 <VM_IP> [PUBLIC_KEY_FILE] [INITIAL_USER] [VM_USER]"
  echo ""
  echo "Examples:"
  echo "  $0 192.168.1.100"
  echo "  $0 192.168.1.100 ~/.ssh/custom_key.pub"
  echo "  $0 192.168.1.100 ~/.ssh/id_ed25519.pub ubuntu"
  echo "  $0 192.168.1.100 ~/.ssh/id_ed25519.pub ubuntu appuser"
  exit 1
fi

# Get public key content - use default if not provided
PUBLIC_KEY_FILE="${PUBLIC_KEY_FILE:-}"
if [ -z "$PUBLIC_KEY_FILE" ]; then
  # Try common default locations
  if [ -f "$HOME/.ssh/id_ed25519.pub" ]; then
    PUBLIC_KEY_FILE="$HOME/.ssh/id_ed25519.pub"
  elif [ -f "$HOME/.ssh/id_rsa.pub" ]; then
    PUBLIC_KEY_FILE="$HOME/.ssh/id_rsa.pub"
  else
    echo "Error: No public key found. Please provide PUBLIC_KEY_FILE or generate SSH keys:"
    echo "  ssh-keygen -t ed25519 -f ~/.ssh/id_ed25519 -C 'boscoh'"
    exit 1
  fi
fi
if [ ! -f "$PUBLIC_KEY_FILE" ]; then
  echo "Error: Public key file not found: $PUBLIC_KEY_FILE"
  exit 1
fi
PUBLIC_KEY=$(cat "$PUBLIC_KEY_FILE")
echo "Using SSH public key: $PUBLIC_KEY_FILE"

# Check if local spendit directory exists
LOCAL_SPENDIT=""
if [ -d "$HOME/spendit" ]; then
  LOCAL_SPENDIT="$HOME/spendit"
  echo "Found local spendit directory: $LOCAL_SPENDIT"
elif [ -d "./spendit" ]; then
  LOCAL_SPENDIT="./spendit"
  echo "Found local spendit directory: $LOCAL_SPENDIT"
fi

echo "Setting up FastAPI on $VM_IP using initial user: $INITIAL_USER..."

export PUBLIC_KEY

# If local spendit directory exists, upload it after the main setup
UPLOAD_SPENDIT=""
if [ -n "$LOCAL_SPENDIT" ]; then
  UPLOAD_SPENDIT="yes"
fi

ssh -o SendEnv=PUBLIC_KEY $INITIAL_USER@$VM_IP << 'EOF'
# Prepare system packages first
sudo apt update
sudo apt install -y python3-pip
sudo pip install uv

# Ensure /home exists with correct permissions
sudo mkdir -p /home
sudo chown root:root /home
sudo chmod 755 /home

# Create account (creates home directory automatically)
sudo adduser $VM_USER --disabled-password --gecos "" --shell /bin/bash || true
sudo usermod -aG sudo $VM_USER

# Ensure home directory has correct ownership and permissions
sudo chown $VM_USER:$VM_USER /home/$VM_USER
sudo chmod 755 /home/$VM_USER

# SSH key setup (account and home dir must exist first)
sudo mkdir -p /home/$VM_USER/.ssh
sudo chown $VM_USER:$VM_USER /home/$VM_USER/.ssh
sudo chmod 700 /home/$VM_USER/.ssh
# Write authorized_keys as target user to ensure correct ownership (avoid double-quoting PUBLIC_KEY)
sudo -u $VM_USER tee /home/$VM_USER/.ssh/authorized_keys > /dev/null <<< "$PUBLIC_KEY"
sudo chmod 600 /home/$VM_USER/.ssh/authorized_keys
echo "SSH key configured for $VM_USER"

# Configure passwordless sudo for target user (required for supervisor/systemctl)
echo "$VM_USER ALL=(ALL) NOPASSWD: ALL" | sudo tee /etc/sudoers.d/$VM_USER > /dev/null
sudo chown root:root /etc/sudoers.d/$VM_USER
sudo chmod 440 /etc/sudoers.d/$VM_USER
# Validate sudoers syntax
sudo visudo -c -f /etc/sudoers.d/$VM_USER > /dev/null || (echo "ERROR: Invalid sudoers syntax" && exit 1)
# WARNING: $VM_USER can run any command with sudo without password - ensure SSH keys are secured

# Ensure spendit directory exists and is owned by target user
sudo mkdir -p /home/$VM_USER/spendit/server
sudo chown -R $VM_USER:$VM_USER /home/$VM_USER/spendit

# Create venv (dependencies will be synced by uv run at startup)
sudo -u $VM_USER uv venv /home/$VM_USER/spendit/.venv

# Set consistent permissions on all content (directories and venv)
sudo chmod -R u+rwX,g+rX,o+rX /home/$VM_USER/spendit

# Supervisor
sudo apt install -y supervisor
sudo mkdir -p /var/log/spendit
sudo chown root:root /var/log/spendit
sudo chmod 755 /var/log/spendit
# Note: Log files created by supervisord (running as root) will be readable by all via 755 on directory

# Create supervisor config
# Uses uv run to execute the CLI with project dependencies
sudo tee /etc/supervisor/conf.d/fastapi.conf > /dev/null <<CONF
[program:fastapi]
directory=/home/$VM_USER/spendit
command=/home/$VM_USER/spendit/.venv/bin/uv run --project /home/$VM_USER/spendit python cli.py run --port 9023
autostart=true
user=$VM_USER
autorestart=true
stopasgroup=true
killasgroup=true
stderr_logfile=/var/log/spendit/errors
stdout_logfile=/var/log/spendit/logs
CONF
sudo chown root:root /etc/supervisor/conf.d/fastapi.conf
sudo chmod 644 /etc/supervisor/conf.d/fastapi.conf

# Nginx
sudo apt install -y nginx
sudo tee /etc/nginx/sites-enabled/fastapi > /dev/null <<'NGINX'
server {
    listen 80;
    server_name ~^(.+)$;
    location / {
        proxy_pass http://127.0.0.1:9023;
    }
}
NGINX
sudo chown root:root /etc/nginx/sites-enabled/fastapi
sudo chmod 644 /etc/nginx/sites-enabled/fastapi

# Finalize
sudo ufw allow 'Nginx HTTP' || true
sudo systemctl enable supervisor
sudo systemctl start supervisor
sudo systemctl restart nginx
sudo supervisorctl status fastapi

# Verification
echo ""
echo "=== Verification ==="
echo "Checking $VM_USER account..."
id $VM_USER && echo "✓ Account exists"
[ -f /home/$VM_USER/.ssh/authorized_keys ] && echo "✓ SSH keys configured"
[ -d /home/$VM_USER/spendit/.venv ] && echo "✓ Virtual environment created"
sudo supervisorctl status fastapi | grep -q RUNNING && echo "✓ FastAPI running" || echo "✗ FastAPI not running"
echo ""
echo "FastAPI setup complete on $VM_IP!"
echo "To access: ssh $VM_USER@$VM_IP"
EOF

# Upload local spendit directory if it exists (exclude .venv to preserve the one we created)
if [ "$UPLOAD_SPENDIT" = "yes" ]; then
  echo ""
  echo "Uploading spendit directory from $LOCAL_SPENDIT..."
  rsync -avz --exclude='.venv' "$LOCAL_SPENDIT/" $INITIAL_USER@$VM_IP:/home/$VM_USER/spendit/ || {
    echo "Warning: rsync failed, trying scp..."
    # For scp, we need to exclude .venv manually by only copying specific files/dirs
    ssh $INITIAL_USER@$VM_IP "mkdir -p /home/$VM_USER/spendit/server"
    find "$LOCAL_SPENDIT" -maxdepth 1 -not -name '.venv' -type f -exec scp {} $INITIAL_USER@$VM_IP:/home/$VM_USER/spendit/ \;
  }
  
  # Fix permissions after upload
  ssh $INITIAL_USER@$VM_IP << FIXPERM
sudo chown -R $VM_USER:$VM_USER /home/$VM_USER/spendit
sudo chmod -R u+rwX,g+rX,o+rX /home/$VM_USER/spendit
FIXPERM
fi

echo "Setup complete!"
echo ""
echo "=== Next Steps ==="
echo "1. Test SSH access as $VM_USER:"
echo "   ssh -i ~/.ssh/id_ed25519 $VM_USER@$VM_IP"
echo ""
echo "2. Check FastAPI status:"
echo "   ssh $VM_USER@$VM_IP 'sudo supervisorctl status fastapi'"
echo ""
echo "3. View application logs:"
echo "   ssh $VM_USER@$VM_IP 'tail -f /var/log/spendit/logs'"
echo ""
echo "4. Access the API:"
echo "   curl http://$VM_IP/"
echo ""
echo "5. If FastAPI isn't running, check the logs:"
echo "   ssh $VM_USER@$VM_IP 'sudo supervisorctl tail fastapi'"
echo ""
echo "6. To restart FastAPI:"
echo "   ssh $VM_USER@$VM_IP 'sudo supervisorctl restart fastapi'"
