cat > cert.cfg <<EOF
[ req ]
default_bits       = 2048
prompt             = no
default_md         = sha256
req_extensions     = req_ext
distinguished_name = dn

[ dn ]
CN = 5.101.180.12

[ req_ext ]
subjectAltName = @alt_names

[ alt_names ]
IP.1 = 5.101.180.12
EOF

openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
  -keyout server.key -out server.crt -config cert.cfg