#!/bin/bash
set -e

# Colors for output
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
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

# Function to generate secure random string
generate_secure_string() {
    local length=$1
    tr -dc 'A-Za-z0-9!@#$%^&*' < /dev/urandom | head -c "$length"
}

# Check requirements
print_step "Checking requirements..."
command -v docker >/dev/null 2>&1 || { print_error "Docker is required but not installed. Aborting."; exit 1; }
command -v docker-compose >/dev/null 2>&1 || { print_error "Docker Compose is required but not installed. Aborting."; exit 1; }

# Create required directories
print_step "Creating required directories..."
mkdir -p certs certbot/www certbot/conf backups logs metrics static

# Set up environment
print_step "Setting up environment..."
if [ ! -f .env ]; then
    print_step "Generating secure environment configuration..."
    JWT_SECRET=$(generate_secure_string 64)
    ADMIN_PASSWORD=$(generate_secure_string 32)

    cat > .env <<EOF
ENV=production
SERVER_PORT=9999
JWT_SECRET=${JWT_SECRET}
ADMIN_USERNAME=admin
ADMIN_PASSWORD=${ADMIN_PASSWORD}
ALLOWED_ORIGINS=https://secretbay.me,https://www.secretbay.me
TLS_MIN_VERSION=1.3
MAX_REQUEST_SIZE=1048576
RATE_LIMIT_REQUESTS=100
RATE_LIMIT_DURATION=60
MAX_CONN_AGE=3600
READ_TIMEOUT=30
WRITE_TIMEOUT=30
LOG_LEVEL=info
EOF

    chmod 600 .env
    print_step "Created .env file with secure defaults"
else 
    print_warning "Using existing .env file"
fi

# Ensure correct permissions
print_step "Setting correct permissions..."
chmod -R 755 static
chmod -R 700 certs
chmod -R 700 certbot
chmod -R 755 logs
chmod -R 755 metrics
chmod -R 700 backups

# Check if domain is provided
if [ -z "$1" ]; then
    print_warning "No domain provided. Using self-signed certificates."
    print_step "Generating self-signed certificates..."
    ./generate-certs.sh localhost
else
    print_step "Setting up Let's Encrypt for domain: $1"
    ./init-letsencrypt.sh "$1"
fi

# Build and start services
print_step "Building and starting services..."
docker-compose build
docker-compose up -d

# Wait for services to start
print_step "Waiting for services to start..."
sleep 10

# Verify deployment
print_step "Verifying deployment..."
if curl -sk https://localhost:9999/health | grep -q "healthy"; then
    print_step "Deployment successful!"
    echo -e "\nAdmin credentials:"
    echo "Username: admin"
    echo "Password: ${ADMIN_PASSWORD}"
    echo -e "\n${YELLOW}Important:${NC} Save these credentials securely and change them after first login!"
    
    if [ -n "$1" ]; then
        echo -e "\nYour service should now be available at: https://$1"
    else
        echo -e "\nService is running locally at: https://localhost:9999"
    fi
    
    echo -e "\nTo view logs:"
    echo "docker-compose logs -f"
else
    print_error "Deployment verification failed. Check logs with: docker-compose logs"
    exit 1
fi

# Setup backup cronjob
print_step "Setting up automated backups..."
if ! crontab -l | grep -q "backup-cron.sh"; then
    (crontab -l 2>/dev/null; echo "0 0 * * * $(pwd)/scripts/backup-cron.sh") | crontab -
    print_step "Automated daily backups configured"
fi