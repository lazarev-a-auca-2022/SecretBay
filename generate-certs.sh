#!/bin/bash

# Check if IP address is provided
if [ -z "$1" ]; then
    echo "Usage: $0 <ip_address>"
    exit 1
fi

IP_ADDRESS="$1"

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
CN = ${IP_ADDRESS}
O = SecretBay VPN
OU = Security
C = US

[ req_ext ]
subjectAltName = @alt_names
basicConstraints = CA:FALSE
keyUsage = digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth

[ alt_names ]
IP.1 = ${IP_ADDRESS}

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
chmod 600 server.key
chmod 644 server.crt

echo "Certificate generated successfully for IP: ${IP_ADDRESS}"
echo "Please make sure to keep server.key secure and private"