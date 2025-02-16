#!/bin/bash
set -e

# Colors for output
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

# Check if domain name is provided
if [ -z "$1" ]; then
    echo "Usage: $0 <domain>"
    echo "Example: $0 secretbay.me"
    exit 1
fi

DOMAIN="$1"
EMAIL="admin@${DOMAIN}"

# Create required directories
mkdir -p certbot/conf
mkdir -p certbot/www

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
        
        # Disable all restrictions for ACME challenge
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

# Start nginx with temporary config
docker run --rm -d \
    --name nginx-temp \
    -p 80:80 \
    -v $(pwd)/nginx.temp.conf:/etc/nginx/nginx.conf:ro \
    -v $(pwd)/certbot/www:/var/www/certbot/:ro \
    nginx:alpine

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
ln -sf $(pwd)/certbot/conf/live/${DOMAIN}/fullchain.pem $(pwd)/certs/server.crt
ln -sf $(pwd)/certbot/conf/live/${DOMAIN}/privkey.pem $(pwd)/certs/server.key

# Generate DH parameters if they don't exist
if [ ! -f "certs/dhparam.pem" ]; then
    echo -e "${YELLOW}Generating DH parameters (this may take a while)...${NC}"
    openssl dhparam -out certs/dhparam.pem 2048
fi

echo -e "${GREEN}Setup complete! You can now start the services with:${NC}"
echo "docker-compose up -d"