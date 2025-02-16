#!/bin/bash
set -e

# Colors for output
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

# Load environment variables
if [ -f .env ]; then
    export $(cat .env | grep -v '^#' | xargs)
fi

# Use DOMAIN from .env or fall back to default
DOMAIN=${DOMAIN:-"secretbay.me"}
EMAIL="admin@${DOMAIN}"

# Function to check DNS records
check_dns() {
    local domain=$1
    # Try multiple DNS resolvers
    for resolver in "8.8.8.8" "1.1.1.1" "9.9.9.9"; do
        if dig @$resolver +short A $domain | grep -q '^[0-9]'; then
            return 0
        fi
    done
    return 1
}

# Create required directories with proper permissions
mkdir -p certbot/conf certbot/www
chmod -R 755 certbot/www

# Validate DNS records with better error handling
echo -e "${YELLOW}Validating DNS records...${NC}"

# Install dig if not present
if ! command -v dig &> /dev/null; then
    echo -e "${YELLOW}Installing dig utility...${NC}"
    apt-get update && apt-get install -y dnsutils
fi

# Check main domain
if ! check_dns ${DOMAIN}; then
    echo -e "${RED}Error: No DNS A record found for ${DOMAIN}${NC}"
    echo "Please ensure:"
    echo "1. You have created an A record pointing to your server IP"
    echo "2. DNS propagation has completed (may take up to 48 hours)"
    echo "3. Your DNS provider is functioning correctly"
    exit 1
fi

# Check www subdomain
if ! check_dns www.${DOMAIN}; then
    echo -e "${RED}Error: No DNS A record found for www.${DOMAIN}${NC}"
    echo "Please ensure:"
    echo "1. You have created an A record for www subdomain pointing to your server IP"
    echo "2. DNS propagation has completed (may take up to 48 hours)"
    echo "3. Your DNS provider is functioning correctly"
    exit 1
fi
#1
# Start nginx with temporary config
echo "Creating temporary nginx config for initial certificate request..."
cat > nginx.temp.conf <<EOF
events {
    worker_connections 1024;
}
http {
    server {
        listen 80;
        listen [::]:80;
        server_name ${DOMAIN} www.${DOMAIN};
        
        location /.well-known/acme-challenge/ {
            allow all;
            root /var/www/certbot;
            try_files \$uri =404;
        }
        
        location / {
            return 301 https://\$host\$request_uri;
        }
    }
}
EOF

# Stop any existing nginx container
docker stop nginx-temp 2>/dev/null || true

# Start nginx with temporary config
docker run --rm -d \
    --name nginx-temp \
    -p 80:80 \
    -v $(pwd)/nginx.temp.conf:/etc/nginx/nginx.conf:ro \
    -v $(pwd)/certbot/www:/var/www/certbot:rw \
    nginx:alpine

# Wait for nginx to start
sleep 5

# Test nginx configuration
echo -e "${YELLOW}Testing nginx configuration...${NC}"
curl -I http://${DOMAIN}/.well-known/acme-challenge/test 2>/dev/null | grep "404"
if [ $? -ne 0 ]; then
    echo "Error: Nginx is not properly serving the challenge directory"
    docker stop nginx-temp
    exit 1
fi

echo -e "${GREEN}Requesting Let's Encrypt certificate for ${DOMAIN}...${NC}"
# Request the certificate
docker run --rm \
    -v $(pwd)/certbot/conf:/etc/letsencrypt \
    -v $(pwd)/certbot/www:/var/www/certbot \
    certbot/certbot certonly \
    --webroot \
    --webroot-path=/var/www/certbot \
    --email ${EMAIL} \
    --agree-tos \
    --no-eff-email \
    -d ${DOMAIN} \
    -d www.${DOMAIN}

# Stop temporary nginx
docker stop nginx-temp
rm nginx.temp.conf

echo -e "${GREEN}SSL Certificate acquired successfully!${NC}"
echo -e "${YELLOW}Next steps:${NC}"
echo "1. Update the .env file with your configuration"
echo "2. Run 'docker-compose up -d' to start the services"

# Create symbolic links for nginx
mkdir -p certs
ln -sf $(pwd)/certbot/conf/live/${DOMAIN}/fullchain.pem $(pwd)/certs/server.crt
ln -sf $(pwd)/certbot/conf/live/${DOMAIN}/privkey.pem $(pwd)/certs/server.key

# Generate DH parameters if they don't exist
if [ ! -f "certs/dhparam.pem" ]; then
    echo -e "${YELLOW}Generating DH parameters (this may take a while)...${NC}"
    openssl dhparam -out certs/dhparam.pem 2048
fi

echo -e "${GREEN}Setup complete! You can now start the services with:${NC}"
echo "docker-compose up -d"