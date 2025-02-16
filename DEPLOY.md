# Production Deployment Guide

## Quick Start
```bash
# With domain (recommended)
./deploy.sh secretbay.me

# Without domain (development/testing)
./deploy.sh
```

## Manual Deployment Steps

### 1. Environment Configuration
- [ ] Create required directories: `certs/`, `certbot/`, `backups/`, `logs/`, `metrics/`, `static/`
- [ ] Set secure permissions:
  ```bash
  chmod -R 755 static/
  chmod -R 700 certs/
  chmod -R 700 certbot/
  chmod -R 755 logs/
  chmod -R 755 metrics/
  chmod -R 700 backups/
  ```
- [ ] Create secure .env file with:
  - JWT_SECRET (64+ chars)
  - ADMIN_USERNAME and ADMIN_PASSWORD
  - ALLOWED_ORIGINS
  - Other configuration (see .env.example)

### 2. SSL/TLS Configuration
- [ ] For production (with domain):
  ```bash
  ./init-letsencrypt.sh yourdomain.com
  ```
- [ ] For development/testing:
  ```bash
  ./generate-certs.sh localhost
  ```

### 3. Security Measures
- [ ] Verify nginx.conf settings:
  - TLS 1.3 only
  - Strong cipher suites
  - Security headers
  - Rate limiting configuration
- [ ] Check fail2ban configuration in security.go

### 4. Start Services
```bash
docker-compose build
docker-compose up -d
```

### 5. Verify Deployment
- [ ] Check health endpoint: `https://yourdomain.com/health`
- [ ] Verify all services are running: `docker-compose ps`
- [ ] Test VPN setup functionality
- [ ] Verify backup system: `docker-compose exec backup-cron /backup.sh`

### 6. Monitoring & Maintenance
- [ ] Monitor logs: `docker-compose logs -f`
- [ ] Check metrics endpoint (internal only): `https://localhost:9999/metrics`
- [ ] Automated daily backups in /var/backups/vpn-server/
- [ ] Certificate auto-renewal every 12 hours

### 7. Backup & Recovery
- [ ] Backups are stored in ./backups/
- [ ] To restore from backup:
  ```bash
  ./scripts/restore.sh /var/backups/vpn-server/backup-YYYYMMDD-HHMMSS.tar.gz
  ```

### 8. Security Recommendations
- [ ] Change default admin password after first login
- [ ] Monitor fail2ban logs for potential attacks
- [ ] Regularly update base images: `docker-compose pull`
- [ ] Configure external backup storage
- [ ] Set up monitoring alerts

### 9. Troubleshooting
- Check container logs: `docker-compose logs [service]`
- Verify permissions on mounted volumes
- Check SSL certificate validity
- Monitor resource usage
- Review error logs in ./logs/

### 10. Scaling (Optional)
- Adjust RATE_LIMIT_REQUESTS in .env
- Modify docker-compose.yml resource limits
- Configure load balancer if needed