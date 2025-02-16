#!/bin/bash
set -e

# Configuration
BACKUP_DIR="/var/backups/vpn-server"
MAX_BACKUPS=7  # Keep a week of daily backups
LOG_FILE="/var/log/vpn-backup.log"

# Logging function
log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" | tee -a "$LOG_FILE"
}

# Create backup directory if it doesn't exist
mkdir -p "$BACKUP_DIR"

# Generate backup name with timestamp
BACKUP_NAME="backup-$(date +%Y%m%d-%H%M%S).tar.gz"
BACKUP_PATH="$BACKUP_DIR/$BACKUP_NAME"

log "Starting VPN server backup"

# Create backup of critical directories
tar czf "$BACKUP_PATH" \
    --exclude='*.key' \
    --exclude='*.pem' \
    --exclude='*.secrets' \
    /etc/openvpn/server.conf \
    /etc/openvpn/certs \
    /etc/ipsec.conf \
    /etc/ipsec.d/cacerts \
    /etc/ipsec.d/certs \
    /etc/vpn-configs

# Set secure permissions
chmod 600 "$BACKUP_PATH"

# Remove old backups, keeping only the last MAX_BACKUPS
cd "$BACKUP_DIR" || exit 1
ls -t backup-*.tar.gz | tail -n +$((MAX_BACKUPS + 1)) | xargs -r rm --

# Log completion
log "Backup completed: $BACKUP_NAME"

# Check backup size
BACKUP_SIZE=$(du -h "$BACKUP_PATH" | cut -f1)
log "Backup size: $BACKUP_SIZE"

# List remaining backups
BACKUP_COUNT=$(ls backup-*.tar.gz 2>/dev/null | wc -l)
log "Total backups: $BACKUP_COUNT"