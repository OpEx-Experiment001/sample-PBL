# HealQueue - Hospital Queue Management System

## 🏥 Overview

HealQueue is a professional-grade, end-to-end hospital queue management system with secure authentication, role-based access control, and real-time queue monitoring.

## 📋 System Architecture

```
┌─────────────────────────────────────────────────────────┐
│                    FRONTEND (Web UI)                    │
│  - Login & Authentication                               │
│  - Role-Based Dashboards (Admin/Doctor/Receptionist/    │
│    Nurse)                                                │
│  - Public Patient Queue Dashboard                       │
│  - Real-time Updates & Notifications                    │
└──────────────────┬──────────────────────────────────────┘
                   │ HTTP/HTTPS
                   │ JSON API
┌──────────────────▼──────────────────────────────────────┐
│                C BACKEND SERVER                          │
│  - HTTP Server (Port 8080)                              │
│  - Authentication & Session Management                   │
│  - Role-Based Access Control (RBAC)                     │
│  - Request Routing & Validation                         │
│  - Business Logic                                        │
│  - Password Hashing (SHA-512 + Salt)                    │
└──────────────────┬──────────────────────────────────────┘
                   │ SQLite C API
┌──────────────────▼──────────────────────────────────────┐
│              SQLite DATABASE                             │
│  - Users & Roles                                        │
│  - Patients & Queue Data                                │
│  - Vitals & Medical Records                             │
│  - Audit Logs                                           │
│  - Analytics & Statistics                               │
└─────────────────────────────────────────────────────────┘
```

## 🎯 Features

### Core Functionality
- ✅ **Secure Authentication**: SHA-512 password hashing with 32-byte salt
- ✅ **Role-Based Access Control (RBAC)**: 4 roles with granular permissions
- ✅ **Queue Management**: Real-time patient queue with auto-generated tokens
- ✅ **Session Management**: Secure session tokens with timeout
- ✅ **Audit Logging**: Complete activity trail for compliance
- ✅ **Public Dashboard**: Login-free patient queue viewing

### User Roles & Capabilities

#### 👨‍💼 Administrator
- User and role management
- System-wide analytics and insights
- Queue monitoring and optimization
- Audit log access
- Database management

#### 👨‍⚕️ Doctor
- View assigned patients
- Mark consultations as complete
- Update patient status
- Access patient history
- Enter consultation notes

#### 👩‍💼 Receptionist
- Register new patients
- Generate queue tokens
- Manage appointment queue
- Update appointment details
- Patient check-in/check-out

#### 👩‍⚕️ Nurse
- Pre-check patient assessment
- Enter patient vitals
- Track patient movement
- Assist in queue progression
- Priority patient flagging

## 📦 Project Structure

```
HealQueue/
├── frontend/
│   ├── index.html          # Main application (SPA)
│   ├── styles.css          # Styling
│   └── app.js              # JavaScript logic
│
├── backend/
│   └── backend.c           # C backend server
│
├── database/
│   └── schema.sql          # Database schema
│
├── docs/
│   ├── README.md           # This file
│   ├── API_DOCUMENTATION.md
│   └── DEPLOYMENT_GUIDE.md
│
└── HealQueue.zip           # Complete deployment package
```

## 🚀 Installation & Setup

### Prerequisites

**For Backend (C Server):**
- GCC compiler (MinGW on Windows, GCC on Linux/Mac)
- SQLite3 library
- OpenSSL library (for cryptography)

**For Frontend:**
- Any modern web browser
- Web server (optional, for production)

### Step 1: Database Setup

```bash
# Navigate to database directory
cd database

# Initialize database
sqlite3 healqueue.db < schema.sql

# Verify database creation
sqlite3 healqueue.db "SELECT COUNT(*) FROM users;"
```

### Step 2: Compile Backend

**On Linux/Mac:**
```bash
cd backend
gcc -o healqueue_backend backend.c -lsqlite3 -lcrypto -lpthread -Wall
```

**On Windows (MinGW):**
```bash
cd backend
gcc -o healqueue_backend.exe backend.c -lsqlite3 -lcrypto -lws2_32 -Wall
```

### Step 3: Run Backend Server

```bash
# Linux/Mac
./healqueue_backend

# Windows
healqueue_backend.exe
```

Server will start on `http://localhost:8080`

### Step 4: Open Frontend

```bash
# Option 1: Direct file access
# Open index.html in your browser

# Option 2: Using Python HTTP server (recommended)
cd frontend
python3 -m http.server 3000

# Then open: http://localhost:3000
```

## 🔐 Default Credentials

For testing purposes, the following accounts are pre-configured:

| Role | Username | Password | Email |
|------|----------|----------|-------|
| Admin | admin | admin123 | admin@healqueue.com |
| Doctor | doctor | doctor123 | doctor@healqueue.com |
| Receptionist | receptionist | recep123 | receptionist@healqueue.com |
| Nurse | nurse | nurse123 | nurse@healqueue.com |

⚠️ **Security Note**: Change these passwords immediately in production!

## 🔧 Configuration

### Backend Configuration

Edit `backend.c` to modify:

```c
#define PORT 8080              // Server port
#define MAX_CONNECTIONS 100    // Max concurrent connections
#define SESSION_TIMEOUT 3600   // Session timeout (seconds)
#define SALT_SIZE 32          // Password salt size
```

### Database Configuration

Edit `backend.c` to change database path:

```c
#define DB_PATH "healqueue.db"
```

## 📡 API Endpoints

### Authentication
- `POST /api/login` - User login
- `POST /api/logout` - User logout

### Patient Management
- `POST /api/patients/register` - Register new patient
- `GET /api/queue` - Get current queue (public)
- `PUT /api/patients/update-status` - Update patient status
- `POST /api/vitals/enter` - Enter patient vitals

### User Management (Admin only)
- `GET /api/users` - List all users
- `POST /api/users/create` - Create new user
- `PUT /api/users/{id}` - Update user
- `DELETE /api/users/{id}` - Delete user

### Analytics & Logs (Admin only)
- `GET /api/analytics` - System analytics
- `GET /api/audit-logs` - Audit logs

**See API_DOCUMENTATION.md for detailed endpoint specifications.**

## 🔒 Security Features

### Password Security
- **SHA-512 hashing**: Industry-standard cryptographic hash
- **32-byte random salt**: Unique per user, cryptographically secure
- **No plaintext storage**: Passwords never stored in readable form

### Session Security
- **Session tokens**: 16-byte random tokens (32 hex characters)
- **Timeout mechanism**: Auto-expiration after 1 hour
- **Server-side validation**: All requests validated
- **CORS support**: Cross-origin requests controlled

### Access Control
- **Role-based permissions**: Granular permission system
- **Permission checking**: Every endpoint validates permissions
- **Audit logging**: All actions logged with user, timestamp, IP

## 📊 Database Schema

### Core Tables
- `users` - User accounts with hashed passwords
- `roles` - User roles (Admin, Doctor, etc.)
- `permissions` - Granular permissions
- `role_permissions` - Role-permission mappings
- `patients` - Patient records and queue
- `patient_vitals` - Patient vital signs
- `consultation_notes` - Doctor consultation records
- `audit_logs` - Complete audit trail
- `announcements` - System announcements

**See schema.sql for complete schema details.**

## 🧪 Testing

### Manual Testing
1. Start backend server
2. Open frontend in browser
3. Login with test credentials
4. Perform role-specific actions
5. Verify in database:
   ```bash
   sqlite3 healqueue.db "SELECT * FROM audit_logs ORDER BY timestamp DESC LIMIT 10;"
   ```

### Verify Password Hashing
```bash
sqlite3 healqueue.db "SELECT username, length(password_hash), length(password_salt) FROM users;"
```

Expected output: hash=64 bytes, salt=32 bytes

## 📈 Monitoring & Maintenance

### View Active Sessions
Sessions are stored in-memory in the C backend. Check logs for session activity.

### View Queue Status
```sql
SELECT token, full_name, department, status, wait_time_minutes 
FROM v_active_queue;
```

### Daily Statistics
```sql
SELECT * FROM v_today_stats;
```

### Audit Log Analysis
```sql
SELECT action, COUNT(*) as count 
FROM audit_logs 
WHERE DATE(timestamp) = DATE('now') 
GROUP BY action;
```

## 🚀 Deployment

### Production Checklist
- [ ] Change all default passwords
- [ ] Enable HTTPS/TLS
- [ ] Configure firewall rules
- [ ] Set up database backups
- [ ] Configure proper CORS policies
- [ ] Enable comprehensive logging
- [ ] Set up monitoring/alerting
- [ ] Review and harden permissions
- [ ] Disable debug output
- [ ] Set secure session timeout

### Recommended Production Setup
```
[Load Balancer] → [Reverse Proxy (Nginx)]
                        ↓
                  [C Backend Cluster]
                        ↓
                  [SQLite Database]
                  (with backup/replication)
```

## 🐛 Troubleshooting

### Backend won't compile
- **Issue**: Missing libraries
- **Solution**: 
  ```bash
  # Ubuntu/Debian
  sudo apt-get install libsqlite3-dev libssl-dev

  # macOS
  brew install sqlite openssl
  ```

### Database connection error
- **Issue**: `healqueue.db` not found
- **Solution**: Run `schema.sql` to create database

### Session timeout too short
- **Solution**: Increase `SESSION_TIMEOUT` in `backend.c` and recompile

### CORS errors in browser
- **Issue**: Frontend on different domain than backend
- **Solution**: Backend already includes CORS headers. Verify frontend URL.

## 📝 Development Roadmap

### Planned Features
- [ ] Email/SMS notifications
- [ ] Multi-language support
- [ ] Mobile applications (iOS/Android)
- [ ] Advanced analytics dashboard
- [ ] Integration with hospital information systems (HIS)
- [ ] Telemedicine queue integration
- [ ] Patient feedback system
- [ ] Automated queue optimization (AI/ML)

## 🤝 Contributing

This is a production-ready demonstration project. For customization:

1. Review code structure
2. Modify according to hospital requirements
3. Extend database schema as needed
4. Add additional API endpoints
5. Enhance frontend UI/UX
6. Implement additional security measures

## 📄 License

**Proprietary Software - For Educational and Demonstration Purposes**

This software is provided as a complete implementation example for learning and evaluation.

## 📞 Support

For issues, customization, or deployment assistance, contact your system administrator.

---

**Built with ❤️ for better healthcare management**

**Version**: 1.0  
**Last Updated**: November 2025  
**Status**: Production Ready
