#!/bin/bash
set -e

# Colors for output
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

# Set domain name from argument or default
DOMAIN=${1:-"secretbay.me"}
EMAIL="admin@${DOMAIN}"

# Create required directories with proper permissions
mkdir -p certbot/conf certbot/www
chmod -R 755 certbot/www

# Validate DNS records
echo -e "${YELLOW}Validating DNS records...${NC}"
if ! host ${DOMAIN} > /dev/null 2>&1; then
    echo "Error: No DNS A record found for ${DOMAIN}"
    echo "Please create an A record pointing to your server IP"
    exit 1
fi
if ! host www.${DOMAIN} > /dev/null 2>&1; then
    echo "Error: No DNS A record found for www.${DOMAIN}"
    echo "Please create an A record pointing to your server IP"
    exit 1
fi

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