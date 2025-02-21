# SecretBay VPN Server

SecretBay is a high-performance server application for automated VPN configuration on remote Ubuntu servers. It provides secure, automated setup of OpenVPN and IKEv2 (StrongSwan) VPN services with robust security features.

## Features

- **Automated VPN Setup**
  - OpenVPN with secure configuration
  - IKEv2/IPSec (StrongSwan) for native iOS VPN support
  - Automatic security hardening and server configuration
  - Fail2ban integration for brute-force protection

- **Security**
  - HTTPS API with TLS 1.2+ support
  - JWT-based authentication
  - CSRF protection
  - Rate limiting
  - Secure credential handling
  - Automatic cleanup of sensitive data

- **Monitoring & Maintenance**
  - System metrics collection
  - Request logging with sensitive data redaction
  - Automated daily backups
  - Backup restoration functionality

## Architecture

The application is structured into several key packages:

- `cmd/server`: Main application entry point
- `internal/api`: HTTP handlers and middleware
- `internal/auth`: Authentication and JWT handling
- `internal/config`: Configuration management 
- `internal/sshclient`: SSH connection handling
- `internal/utils`: Utility functions
- `internal/vpn`: VPN setup implementations
- `pkg/logger`: Logging with sensitive data redaction
- `pkg/models`: Data models and validation
- `pkg/monitoring`: System metrics collection

## API Endpoints

### Public Endpoints
- `GET /health` - Health check
- `POST /api/auth/login` - Authentication endpoint
- `GET /api/csrf-token` - Get CSRF token

### Protected Endpoints (Require JWT)
- `POST /api/setup` - Setup VPN on remote server
- `GET /api/vpn/status` - Check VPN status
- `GET /api/config/download` - Download VPN configuration
- `POST /api/backup` - Create server backup
- `POST /api/restore` - Restore from backup

## Setup Requirements

- Go 1.19+
- Docker and Docker Compose
- Ubuntu 22.04+ (target servers)
- Domain with SSL certificate (production)

## Quick Start

1. Clone the repository:
\`\`\`bash
git clone https://github.com/lazarev-a-auca-2022/secretbay.git
cd secretbay
\`\`\`

2. Create environment configuration:
\`\`\`bash
cp .env.example .env
# Edit .env with your configuration
\`\`\`

3. Deploy with Docker:
\`\`\`bash
./deploy.sh
\`\`\`

## Manual Deployment Steps

### 1. Environment Configuration
- Create required directories:
  \`\`\`bash
  mkdir -p certs certbot/www certbot/conf backups logs metrics static
  chmod -R 755 static/
  chmod -R 700 certs/
  chmod -R 700 certbot/
  chmod -R 755 logs/
  chmod -R 755 metrics/
  chmod -R 700 backups/
  \`\`\`

### 2. SSL/TLS Configuration
- For production (with domain):
  \`\`\`bash
  ./init-letsencrypt.sh yourdomain.com
  \`\`\`
- For development/testing:
  \`\`\`bash
  ./generate-certs.sh localhost
  \`\`\`

### 3. Security Configuration
- Verify nginx.conf settings:
  - TLS 1.3 only
  - Strong cipher suites
  - Security headers
  - Rate limiting
- Check fail2ban configuration

### 4. Start Services
\`\`\`bash
docker-compose build
docker-compose up -d
\`\`\`

### 5. Verify Deployment
- Check health endpoint: \`https://yourdomain.com/health\`
- Verify services: \`docker-compose ps\`
- Test VPN setup functionality
- Verify backup system

## Monitoring & Maintenance

### Logs
- Application logs: \`docker-compose logs -f\`
- VPN logs: Check \`/var/log/openvpn/\` or \`/var/log/strongswan/\`
- Access logs: \`/var/log/nginx/\`

### Metrics
- System metrics: \`https://localhost:9999/metrics\` (internal only)
- VPN connection status: \`/var/log/openvpn/openvpn-status.log\`

### Backups
- Daily automatic backups in \`/var/backups/vpn-server/\`
- Manual backup: \`./scripts/backup-cron.sh\`
- Restore: \`./scripts/restore.sh /path/to/backup.tar.gz\`

## Security Recommendations

1. Change default admin password after first login
2. Monitor fail2ban logs for potential attacks
3. Regular updates: \`docker-compose pull\`
4. Configure external backup storage
5. Set up monitoring alerts

## Troubleshooting

1. Check container logs: \`docker-compose logs [service]\`
2. Verify permissions on mounted volumes
3. Check SSL certificate validity
4. Monitor resource usage
5. Review error logs in \`./logs/\`

## Scaling

- Adjust \`RATE_LIMIT_REQUESTS\` in .env
- Modify docker-compose.yml resource limits
- Configure load balancer if needed

## Contributing

1. Fork the repository
2. Create a feature branch
3. Commit changes
4. Push to the branch
5. Create a Pull Request

## License

This project is licensed under the MIT License - see the LICENSE file for details.