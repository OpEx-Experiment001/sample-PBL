# HealQueue Deployment Guide

## 📋 Table of Contents
1. [System Requirements](#system-requirements)
2. [Development Deployment](#development-deployment)
3. [Production Deployment](#production-deployment)
4. [Security Hardening](#security-hardening)
5. [Performance Optimization](#performance-optimization)
6. [Backup & Recovery](#backup--recovery)
7. [Monitoring](#monitoring)

---

## System Requirements

### Minimum Requirements
- **CPU**: 2 cores @ 2.0 GHz
- **RAM**: 2 GB
- **Storage**: 10 GB SSD
- **OS**: Linux (Ubuntu 20.04+), Windows Server 2019+, macOS 11+
- **Network**: 100 Mbps

### Recommended for Production
- **CPU**: 4 cores @ 3.0 GHz
- **RAM**: 8 GB
- **Storage**: 50 GB SSD (with RAID 1)
- **OS**: Ubuntu Server 22.04 LTS
- **Network**: 1 Gbps

### Software Dependencies
- GCC 9.0+ or Clang 10.0+
- SQLite 3.35+
- OpenSSL 1.1.1+
- Nginx 1.18+ (for reverse proxy)
- Certbot (for SSL certificates)

---

## Development Deployment

### Quick Start (Local Development)

1. **Clone/Extract Project**
   ```bash
   unzip HealQueue.zip
   cd HealQueue
   ```

2. **Setup Database**
   ```bash
   cd database
   sqlite3 healqueue.db < schema.sql
   cd ..
   ```

3. **Compile Backend**
   ```bash
   cd backend
   gcc -o healqueue_backend backend.c -lsqlite3 -lcrypto -lpthread -g -Wall
   cd ..
   ```

4. **Start Backend**
   ```bash
   ./backend/healqueue_backend
   ```

5. **Serve Frontend**
   ```bash
   cd frontend
   python3 -m http.server 3000
   ```

6. **Access Application**
   - Frontend: http://localhost:3000
   - Backend API: http://localhost:8080

---

## Production Deployment

### Architecture Overview

```
Internet
   │
   ▼
[Firewall]
   │
   ▼
[Nginx Reverse Proxy] (Port 443 HTTPS)
   │
   ├─→ [Frontend] (Static Files)
   │
   └─→ [C Backend] (Port 8080)
          │
          ▼
      [SQLite DB] (Persistent Storage)
```

### Step 1: Prepare Server

```bash
# Update system
sudo apt update && sudo apt upgrade -y

# Install dependencies
sudo apt install -y gcc make sqlite3 libsqlite3-dev libssl-dev nginx certbot python3-certbot-nginx

# Create application user
sudo useradd -r -s /bin/false healqueue
sudo mkdir -p /opt/healqueue
sudo chown healqueue:healqueue /opt/healqueue
```

### Step 2: Deploy Application

```bash
# Copy files
sudo cp -r HealQueue/* /opt/healqueue/
cd /opt/healqueue

# Setup database
sudo -u healqueue sqlite3 /opt/healqueue/database/healqueue.db < database/schema.sql

# Set permissions
sudo chmod 600 /opt/healqueue/database/healqueue.db
sudo chown healqueue:healqueue /opt/healqueue/database/healqueue.db
```

### Step 3: Compile Backend (Production Build)

```bash
cd /opt/healqueue/backend
sudo -u healqueue gcc -o healqueue_backend backend.c \
    -lsqlite3 -lcrypto -lpthread \
    -O3 -march=native -DNDEBUG \
    -Wall -Werror
```

**Optimization Flags:**
- `-O3`: Maximum optimization
- `-march=native`: CPU-specific optimization
- `-DNDEBUG`: Disable debug assertions

### Step 4: Create Systemd Service

Create `/etc/systemd/system/healqueue.service`:

```ini
[Unit]
Description=HealQueue Backend Server
After=network.target

[Service]
Type=simple
User=healqueue
Group=healqueue
WorkingDirectory=/opt/healqueue/backend
ExecStart=/opt/healqueue/backend/healqueue_backend
Restart=always
RestartSec=10

# Security
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/opt/healqueue/database

# Limits
LimitNOFILE=65536
LimitNPROC=512

[Install]
WantedBy=multi-user.target
```

Enable and start service:
```bash
sudo systemctl daemon-reload
sudo systemctl enable healqueue
sudo systemctl start healqueue
sudo systemctl status healqueue
```

### Step 5: Configure Nginx

Create `/etc/nginx/sites-available/healqueue`:

```nginx
# Redirect HTTP to HTTPS
server {
    listen 80;
    server_name your-domain.com;
    return 301 https://$server_name$request_uri;
}

# HTTPS configuration
server {
    listen 443 ssl http2;
    server_name your-domain.com;

    # SSL certificates (managed by Certbot)
    ssl_certificate /etc/letsencrypt/live/your-domain.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/your-domain.com/privkey.pem;

    # SSL security settings
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_prefer_server_ciphers on;
    ssl_ciphers ECDHE-RSA-AES256-GCM-SHA512:DHE-RSA-AES256-GCM-SHA512;
    ssl_session_cache shared:SSL:10m;
    ssl_session_timeout 10m;

    # Security headers
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
    add_header X-Frame-Options "SAMEORIGIN" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header X-XSS-Protection "1; mode=block" always;
    add_header Referrer-Policy "no-referrer-when-downgrade" always;

    # Frontend (static files)
    location / {
        root /opt/healqueue/frontend;
        try_files $uri $uri/ /index.html;

        # Cache static assets
        location ~* \.(jpg|jpeg|png|gif|ico|css|js)$ {
            expires 1y;
            add_header Cache-Control "public, immutable";
        }
    }

    # Backend API proxy
    location /api/ {
        proxy_pass http://localhost:8080;
        proxy_http_version 1.1;

        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;

        # Timeouts
        proxy_connect_timeout 60s;
        proxy_send_timeout 60s;
        proxy_read_timeout 60s;

        # Buffer settings
        proxy_buffering on;
        proxy_buffer_size 4k;
        proxy_buffers 8 4k;
        proxy_busy_buffers_size 8k;
    }

    # Logging
    access_log /var/log/nginx/healqueue_access.log;
    error_log /var/log/nginx/healqueue_error.log;
}
```

Enable site:
```bash
sudo ln -s /etc/nginx/sites-available/healqueue /etc/nginx/sites-enabled/
sudo nginx -t
sudo systemctl restart nginx
```

### Step 6: Obtain SSL Certificate

```bash
sudo certbot --nginx -d your-domain.com
```

---

## Security Hardening

### 1. Firewall Configuration

```bash
# UFW (Ubuntu)
sudo ufw allow 22/tcp   # SSH
sudo ufw allow 80/tcp   # HTTP (for Certbot)
sudo ufw allow 443/tcp  # HTTPS
sudo ufw enable

# Verify
sudo ufw status
```

### 2. Change Default Passwords

```bash
sqlite3 /opt/healqueue/database/healqueue.db
```

```sql
-- Change admin password
-- Use the C backend API or manually generate hash
UPDATE users SET password_hash = ?, password_salt = ? WHERE username = 'admin';
```

### 3. Database Security

```bash
# Restrict permissions
sudo chmod 600 /opt/healqueue/database/healqueue.db
sudo chown healqueue:healqueue /opt/healqueue/database/healqueue.db

# Encrypt database (optional, requires SQLite Encryption Extension)
```

### 4. Rate Limiting

Add to Nginx configuration:
```nginx
# Rate limiting zone
limit_req_zone $binary_remote_addr zone=api_limit:10m rate=10r/s;

# Apply to API location
location /api/ {
    limit_req zone=api_limit burst=20 nodelay;
    # ... rest of config
}
```

### 5. Fail2Ban Configuration

Create `/etc/fail2ban/filter.d/healqueue.conf`:
```ini
[Definition]
failregex = ^.*Failed login attempt from <HOST>.*$
ignoreregex =
```

Create `/etc/fail2ban/jail.d/healqueue.conf`:
```ini
[healqueue]
enabled = true
port = 443
filter = healqueue
logpath = /var/log/nginx/healqueue_access.log
maxretry = 5
bantime = 3600
```

---

## Performance Optimization

### 1. Backend Optimization

- **Compile with optimizations**: `-O3 -march=native`
- **Enable threading**: Ensure `-lpthread` is linked
- **Connection pooling**: Modify backend.c to reuse database connections

### 2. Database Optimization

```sql
-- Add indexes for frequently queried columns
CREATE INDEX IF NOT EXISTS idx_patients_registration ON patients(registration_time);
CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON audit_logs(timestamp);

-- Analyze database
ANALYZE;

-- Vacuum to reclaim space
VACUUM;
```

### 3. Nginx Caching

```nginx
# Cache zone
proxy_cache_path /var/cache/nginx/healqueue levels=1:2 keys_zone=healqueue_cache:10m max_size=100m;

location /api/queue {
    proxy_cache healqueue_cache;
    proxy_cache_valid 200 10s;  # Cache for 10 seconds
    # ... rest of config
}
```

### 4. Frontend Optimization

- Minify CSS/JavaScript
- Enable gzip compression
- Use CDN for static assets

---

## Backup & Recovery

### Automated Backup Script

Create `/opt/healqueue/scripts/backup.sh`:

```bash
#!/bin/bash

BACKUP_DIR="/opt/healqueue/backups"
DB_PATH="/opt/healqueue/database/healqueue.db"
DATE=$(date +%Y%m%d_%H%M%S)

# Create backup directory
mkdir -p $BACKUP_DIR

# Backup database
sqlite3 $DB_PATH ".backup '$BACKUP_DIR/healqueue_$DATE.db'"

# Compress
gzip $BACKUP_DIR/healqueue_$DATE.db

# Keep only last 30 days
find $BACKUP_DIR -name "*.gz" -mtime +30 -delete

echo "Backup completed: healqueue_$DATE.db.gz"
```

Make executable:
```bash
chmod +x /opt/healqueue/scripts/backup.sh
```

### Automated Backup with Cron

```bash
sudo crontab -e
```

Add:
```cron
# Daily backup at 2 AM
0 2 * * * /opt/healqueue/scripts/backup.sh >> /var/log/healqueue_backup.log 2>&1
```

### Restore from Backup

```bash
# Stop backend
sudo systemctl stop healqueue

# Restore database
gunzip -c /opt/healqueue/backups/healqueue_YYYYMMDD_HHMMSS.db.gz > /opt/healqueue/database/healqueue.db

# Set permissions
sudo chown healqueue:healqueue /opt/healqueue/database/healqueue.db
sudo chmod 600 /opt/healqueue/database/healqueue.db

# Start backend
sudo systemctl start healqueue
```

---

## Monitoring

### 1. System Logs

```bash
# Backend logs
sudo journalctl -u healqueue -f

# Nginx access logs
sudo tail -f /var/log/nginx/healqueue_access.log

# Nginx error logs
sudo tail -f /var/log/nginx/healqueue_error.log
```

### 2. Performance Monitoring

```bash
# CPU and memory usage
htop

# Backend process
ps aux | grep healqueue_backend

# Database size
du -h /opt/healqueue/database/healqueue.db
```

### 3. Health Check Script

Create `/opt/healqueue/scripts/health_check.sh`:

```bash
#!/bin/bash

# Check if backend is running
if ! systemctl is-active --quiet healqueue; then
    echo "CRITICAL: HealQueue backend is down"
    sudo systemctl restart healqueue
    # Send alert (email, SMS, etc.)
fi

# Check API endpoint
HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" http://localhost:8080/api/queue)
if [ $HTTP_CODE -ne 200 ]; then
    echo "WARNING: API not responding correctly (HTTP $HTTP_CODE)"
fi

# Check database integrity
sqlite3 /opt/healqueue/database/healqueue.db "PRAGMA integrity_check;" | grep -q "ok"
if [ $? -ne 0 ]; then
    echo "CRITICAL: Database integrity check failed"
fi
```

Run every 5 minutes:
```cron
*/5 * * * * /opt/healqueue/scripts/health_check.sh >> /var/log/healqueue_health.log 2>&1
```

### 4. Database Statistics

```sql
-- Queue statistics
SELECT 
    COUNT(*) as total_in_queue,
    AVG(wait_time_minutes) as avg_wait,
    MAX(wait_time_minutes) as max_wait
FROM patients 
WHERE status_id IN (1, 2);

-- Today's activity
SELECT * FROM v_today_stats;

-- Recent audit log
SELECT * FROM audit_logs 
ORDER BY timestamp DESC 
LIMIT 50;
```

---

## Troubleshooting

### Backend Won't Start

```bash
# Check logs
sudo journalctl -u healqueue -n 50

# Check if port is in use
sudo netstat -tlnp | grep 8080

# Check permissions
ls -la /opt/healqueue/database/healqueue.db
```

### Database Locked

```bash
# Check for hanging processes
fuser /opt/healqueue/database/healqueue.db

# Kill if necessary
sudo kill -9 <PID>
```

### High Memory Usage

```bash
# Check process memory
ps aux | grep healqueue_backend

# Restart if needed
sudo systemctl restart healqueue
```

---

## Production Checklist

Before going live:

- [ ] All default passwords changed
- [ ] SSL certificate installed and auto-renewal configured
- [ ] Firewall configured
- [ ] Automated backups scheduled
- [ ] Monitoring and alerting set up
- [ ] Health checks configured
- [ ] Database optimized and indexed
- [ ] Rate limiting enabled
- [ ] Security headers configured
- [ ] Fail2Ban configured
- [ ] Log rotation configured
- [ ] Tested failover/recovery procedures
- [ ] Documentation updated with server-specific details
- [ ] Team trained on system operation

---

**Deployment Guide Version**: 1.0  
**Last Updated**: November 2025
