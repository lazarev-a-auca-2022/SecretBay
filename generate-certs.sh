#!/bin/bash

# Check if hostname/IP is provided
if [ -z "$1" ]; then
    echo "Usage: $0 <hostname_or_ip>"
    exit 1
fi

HOST="$1"

# Create certs directory if it doesn't exist
mkdir -p certs
cd certs

# Determine if input is IP or domain
if [[ $HOST =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
    ALT_NAMES="IP.1 = ${HOST}"
else
    ALT_NAMES="DNS.1 = ${HOST}\nDNS.2 = www.${HOST}"
fi

# Generate DH parameters (this may take a while)
echo "Generating DH parameters (2048 bit) - this may take a few minutes..."
openssl dhparam -out dhparam.pem 2048

# Generate a strong private key
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:4096 -out server.key

# Create certificate configuration
cat > cert.cfg <<EOF
[ req ]
default_bits       = 4096
prompt            = no
default_md        = sha384
req_extensions    = req_ext
distinguished_name = dn
x509_extensions   = v3_ca

[ dn ]
CN = ${HOST}
O = SecretBay VPN
OU = Security
C = US

[ req_ext ]
subjectAltName = @alt_names
basicConstraints = CA:FALSE
keyUsage = digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth

[ alt_names ]
${ALT_NAMES}

[ v3_ca ]
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always,issuer
basicConstraints = critical, CA:true
keyUsage = critical, digitalSignature, cRLSign, keyCertSign
EOF

# Generate certificate
openssl req -x509 -new -nodes \
    -key server.key \
    -sha384 \
    -days 825 \
    -out server.crt \
    -config cert.cfg

# Set secure permissions
chmod 600 server.key dhparam.pem
chmod 644 server.crt

echo "Certificate generation complete:"
echo "- server.crt: SSL certificate"
echo "- server.key: Private key (keep secure!)"
echo "- dhparam.pem: DH parameters"
echo "All files have been placed in the ./certs directory"