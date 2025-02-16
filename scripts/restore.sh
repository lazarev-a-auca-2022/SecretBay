#!/bin/bash
set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

print_step() {
    echo -e "${GREEN}==>${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}Warning:${NC} $1"
}

print_error() {
    echo -e "${RED}Error:${NC} $1"
}

# Check root privileges
if [ "$EUID" -ne 0 ]; then 
    print_error "Please run as root"
    exit 1
fi

# Function to list available backups
list_backups() {
    if [ -d "/var/backups/vpn-server" ]; then
        ls -lt /var/backups/vpn-server/backup-*.tar.gz 2>/dev/null || true
    fi
}

# Function to verify backup integrity
verify_backup() {
    local backup_file="$1"
    if ! tar tzf "$backup_file" >/dev/null 2>&1; then
        print_error "Backup file is corrupted or invalid"
        return 1
    fi
    return 0
}

# Help message
if [ "$1" == "-h" ] || [ "$1" == "--help" ]; then
    echo "Usage: $0 [backup_file]"
    echo "If no backup file is specified, will list available backups"
    echo "Options:"
    echo "  -h, --help     Show this help message"
    echo "  -l, --list     List available backups"
    echo "  -f, --force    Force restore without confirmation"
    exit 0
fi

# List backups if requested
if [ "$1" == "-l" ] || [ "$1" == "--list" ]; then
    print_step "Available backups:"
    list_backups
    exit 0
fi

# If no backup file specified, show list and prompt
if [ -z "$1" ] || [ "$1" == "-f" ] || [ "$1" == "--force" ]; then
    print_step "Available backups:"
    list_backups
    echo
    read -p "Enter backup file path to restore: " BACKUP_FILE
else
    BACKUP_FILE="$1"
fi

# Check if backup exists
if [ ! -f "$BACKUP_FILE" ]; then
    print_error "Backup file not found: $BACKUP_FILE"
    exit 1
fi

# Verify backup integrity
print_step "Verifying backup integrity..."
if ! verify_backup "$BACKUP_FILE"; then
    exit 1
fi

# Confirm unless force flag is used
if [ "$1" != "-f" ] && [ "$1" != "--force" ]; then
    print_warning "This will restore VPN configuration from backup and restart services"
    read -p "Are you sure you want to continue? [y/N] " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        print_step "Operation cancelled"
        exit 1
    fi
fi

# Create temporary restoration directory
RESTORE_DIR=$(mktemp -d)
print_step "Extracting backup to temporary location..."
tar xzf "$BACKUP_FILE" -C "$RESTORE_DIR"

# Stop services
print_step "Stopping services..."
systemctl stop secretbay-vpn || true
docker-compose down || true

# Restore configurations
print_step "Restoring configurations..."
if [ -d "$RESTORE_DIR/etc/openvpn" ]; then
    cp -r "$RESTORE_DIR/etc/openvpn"/* /etc/openvpn/
fi
if [ -d "$RESTORE_DIR/etc/ipsec.d" ]; then
    cp -r "$RESTORE_DIR/etc/ipsec.d"/* /etc/ipsec.d/
fi
if [ -f "$RESTORE_DIR/etc/ipsec.conf" ]; then
    cp "$RESTORE_DIR/etc/ipsec.conf" /etc/
fi

# Fix permissions
print_step "Setting correct permissions..."
chmod 600 /etc/openvpn/server.key || true
chmod 600 /etc/ipsec.d/private/* || true
chmod 644 /etc/openvpn/server.conf || true
chmod 644 /etc/ipsec.conf || true

# Cleanup
print_step "Cleaning up..."
rm -rf "$RESTORE_DIR"

# Restart services
print_step "Restarting services..."
systemctl start secretbay-vpn || docker-compose up -d

# Verify services
print_step "Verifying services..."
sleep 5
if systemctl is-active --quiet secretbay-vpn || docker-compose ps | grep -q "Up"; then
    print_step "Restore completed successfully!"
    echo "Please verify your VPN connections are working correctly."
else
    print_error "Services failed to start properly"
    echo "Please check the logs with: journalctl -u secretbay-vpn -n 50"
    exit 1
fi