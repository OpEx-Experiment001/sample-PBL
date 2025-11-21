-- HealQueue Hospital Queue Management System
-- SQLite Database Schema
-- Version 1.0

-- Enable foreign keys
PRAGMA foreign_keys = ON;

-- ============================================
-- ROLES AND PERMISSIONS
-- ============================================

CREATE TABLE IF NOT EXISTS roles (
    id INTEGER PRIMARY KEY,
    name TEXT UNIQUE NOT NULL,
    display_name TEXT NOT NULL,
    description TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- Insert default roles
INSERT OR IGNORE INTO roles (id, name, display_name, description) VALUES
(1, 'admin', 'Administrator', 'Full system access with user and role management'),
(2, 'doctor', 'Doctor', 'Medical professional with patient consultation access'),
(3, 'receptionist', 'Receptionist', 'Front desk staff with patient registration access'),
(4, 'nurse', 'Nurse', 'Nursing staff with vitals entry and patient movement access');

CREATE TABLE IF NOT EXISTS permissions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT UNIQUE NOT NULL,
    description TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- Insert default permissions
INSERT OR IGNORE INTO permissions (name, description) VALUES
('user_management', 'Create, update, and delete users'),
('role_management', 'Manage roles and permissions'),
('system_analytics', 'View system-wide analytics and reports'),
('queue_insights', 'Access detailed queue insights'),
('audit_logs', 'View audit logs'),
('full_control', 'Complete system control'),
('view_assigned_patients', 'View patients assigned to doctor'),
('mark_consultation', 'Mark consultation as complete'),
('update_patient_status', 'Update patient status'),
('view_patient_history', 'Access patient medical history'),
('register_patient', 'Register new patients'),
('issue_token', 'Issue queue tokens'),
('manage_queue', 'Manage patient queue'),
('update_appointment', 'Update appointment details'),
('pre_check_updates', 'Perform pre-check updates'),
('vitals_entry', 'Enter patient vitals'),
('patient_movement', 'Track patient movement'),
('queue_progression', 'Manage queue progression');

CREATE TABLE IF NOT EXISTS role_permissions (
    role_id INTEGER NOT NULL,
    permission_id INTEGER NOT NULL,
    PRIMARY KEY (role_id, permission_id),
    FOREIGN KEY (role_id) REFERENCES roles(id) ON DELETE CASCADE,
    FOREIGN KEY (permission_id) REFERENCES permissions(id) ON DELETE CASCADE
);

-- Assign permissions to Admin role (all permissions)
INSERT OR IGNORE INTO role_permissions (role_id, permission_id)
SELECT 1, id FROM permissions;

-- Assign permissions to Doctor role
INSERT OR IGNORE INTO role_permissions (role_id, permission_id)
SELECT 2, id FROM permissions WHERE name IN (
    'view_assigned_patients', 'mark_consultation', 
    'update_patient_status', 'view_patient_history'
);

-- Assign permissions to Receptionist role
INSERT OR IGNORE INTO role_permissions (role_id, permission_id)
SELECT 3, id FROM permissions WHERE name IN (
    'register_patient', 'issue_token', 
    'manage_queue', 'update_appointment'
);

-- Assign permissions to Nurse role
INSERT OR IGNORE INTO role_permissions (role_id, permission_id)
SELECT 4, id FROM permissions WHERE name IN (
    'pre_check_updates', 'vitals_entry', 
    'patient_movement', 'queue_progression'
);

-- ============================================
-- USER MANAGEMENT
-- ============================================

CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    email TEXT UNIQUE NOT NULL,
    password_hash BLOB NOT NULL,  -- SHA-512 hash
    password_salt BLOB NOT NULL,  -- 32-byte salt
    role_id INTEGER NOT NULL,
    full_name TEXT NOT NULL,
    phone TEXT,
    is_active INTEGER DEFAULT 1,
    last_login DATETIME,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (role_id) REFERENCES roles(id)
);

-- Create index on username for faster login queries
CREATE INDEX IF NOT EXISTS idx_users_username ON users(username);
CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);
CREATE INDEX IF NOT EXISTS idx_users_role ON users(role_id);

-- ============================================
-- PATIENT MANAGEMENT
-- ============================================

CREATE TABLE IF NOT EXISTS queue_status (
    id INTEGER PRIMARY KEY,
    name TEXT UNIQUE NOT NULL,
    display_name TEXT NOT NULL,
    color TEXT NOT NULL,  -- Hex color code
    description TEXT
);

-- Insert queue status types
INSERT OR IGNORE INTO queue_status (id, name, display_name, color, description) VALUES
(1, 'waiting', 'Waiting', '#FFA500', 'Patient is waiting in queue'),
(2, 'in_progress', 'In Progress', '#2196F3', 'Patient is being attended'),
(3, 'completed', 'Completed', '#4CAF50', 'Consultation completed'),
(4, 'cancelled', 'Cancelled', '#F44336', 'Appointment cancelled');

CREATE TABLE IF NOT EXISTS departments (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT UNIQUE NOT NULL,
    description TEXT,
    is_active INTEGER DEFAULT 1,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- Insert default departments
INSERT OR IGNORE INTO departments (name, description) VALUES
('Cardiology', 'Heart and cardiovascular diseases'),
('Pediatrics', 'Child healthcare'),
('Orthopedics', 'Bone and joint disorders'),
('General Medicine', 'General health issues'),
('Emergency', 'Emergency and critical care'),
('Neurology', 'Nervous system disorders'),
('Dermatology', 'Skin conditions'),
('Ophthalmology', 'Eye care');

CREATE TABLE IF NOT EXISTS patients (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    token TEXT UNIQUE NOT NULL,  -- Auto-generated: TOK001, TOK002, etc.
    full_name TEXT NOT NULL,
    age INTEGER,
    gender TEXT CHECK(gender IN ('Male', 'Female', 'Other')),
    contact TEXT,
    email TEXT,
    address TEXT,
    emergency_contact TEXT,
    department_id INTEGER NOT NULL,
    assigned_doctor_id INTEGER,
    chief_complaint TEXT,
    appointment_type TEXT CHECK(appointment_type IN ('New', 'Follow-up')) DEFAULT 'New',
    status_id INTEGER DEFAULT 1,
    priority INTEGER DEFAULT 0,  -- 0 = Normal, 1 = High priority
    registration_time DATETIME DEFAULT CURRENT_TIMESTAMP,
    consultation_start_time DATETIME,
    consultation_end_time DATETIME,
    wait_time_minutes INTEGER DEFAULT 0,
    created_by INTEGER,  -- Receptionist who registered
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (department_id) REFERENCES departments(id),
    FOREIGN KEY (assigned_doctor_id) REFERENCES users(id),
    FOREIGN KEY (status_id) REFERENCES queue_status(id),
    FOREIGN KEY (created_by) REFERENCES users(id)
);

-- Create indexes for faster queries
CREATE INDEX IF NOT EXISTS idx_patients_token ON patients(token);
CREATE INDEX IF NOT EXISTS idx_patients_status ON patients(status_id);
CREATE INDEX IF NOT EXISTS idx_patients_department ON patients(department_id);
CREATE INDEX IF NOT EXISTS idx_patients_doctor ON patients(assigned_doctor_id);
CREATE INDEX IF NOT EXISTS idx_patients_registration ON patients(registration_time);

-- ============================================
-- VITALS AND MEDICAL RECORDS
-- ============================================

CREATE TABLE IF NOT EXISTS patient_vitals (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    patient_id INTEGER NOT NULL,
    blood_pressure_systolic INTEGER,
    blood_pressure_diastolic INTEGER,
    heart_rate INTEGER,  -- bpm
    temperature REAL,  -- in Fahrenheit
    oxygen_saturation INTEGER,  -- percentage
    weight REAL,  -- in kg
    height REAL,  -- in cm
    bmi REAL,  -- calculated
    notes TEXT,
    recorded_by INTEGER NOT NULL,  -- Nurse who recorded
    recorded_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (patient_id) REFERENCES patients(id) ON DELETE CASCADE,
    FOREIGN KEY (recorded_by) REFERENCES users(id)
);

CREATE INDEX IF NOT EXISTS idx_vitals_patient ON patient_vitals(patient_id);
CREATE INDEX IF NOT EXISTS idx_vitals_recorded_at ON patient_vitals(recorded_at);

CREATE TABLE IF NOT EXISTS consultation_notes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    patient_id INTEGER NOT NULL,
    doctor_id INTEGER NOT NULL,
    diagnosis TEXT,
    prescription TEXT,
    recommendations TEXT,
    follow_up_required INTEGER DEFAULT 0,
    follow_up_date DATE,
    notes TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (patient_id) REFERENCES patients(id) ON DELETE CASCADE,
    FOREIGN KEY (doctor_id) REFERENCES users(id)
);

CREATE INDEX IF NOT EXISTS idx_consultation_patient ON consultation_notes(patient_id);
CREATE INDEX IF NOT EXISTS idx_consultation_doctor ON consultation_notes(doctor_id);

-- ============================================
-- PATIENT MOVEMENT TRACKING
-- ============================================

CREATE TABLE IF NOT EXISTS patient_locations (
    id INTEGER PRIMARY KEY,
    name TEXT UNIQUE NOT NULL,
    description TEXT
);

-- Insert default locations
INSERT OR IGNORE INTO patient_locations (id, name, description) VALUES
(1, 'Waiting Area', 'Main waiting area'),
(2, 'Pre-check Room', 'Vitals check room'),
(3, 'Consultation Room', 'Doctor consultation room'),
(4, 'Pharmacy', 'Pharmacy counter'),
(5, 'Laboratory', 'Lab testing area'),
(6, 'Discharged', 'Patient discharged');

CREATE TABLE IF NOT EXISTS patient_movement_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    patient_id INTEGER NOT NULL,
    location_id INTEGER NOT NULL,
    moved_by INTEGER,  -- Staff member who moved patient
    arrival_time DATETIME DEFAULT CURRENT_TIMESTAMP,
    departure_time DATETIME,
    notes TEXT,
    FOREIGN KEY (patient_id) REFERENCES patients(id) ON DELETE CASCADE,
    FOREIGN KEY (location_id) REFERENCES patient_locations(id),
    FOREIGN KEY (moved_by) REFERENCES users(id)
);

CREATE INDEX IF NOT EXISTS idx_movement_patient ON patient_movement_log(patient_id);
CREATE INDEX IF NOT EXISTS idx_movement_location ON patient_movement_log(location_id);

-- ============================================
-- ANNOUNCEMENTS
-- ============================================

CREATE TABLE IF NOT EXISTS announcements (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    title TEXT NOT NULL,
    message TEXT NOT NULL,
    priority TEXT CHECK(priority IN ('low', 'medium', 'high')) DEFAULT 'medium',
    is_active INTEGER DEFAULT 1,
    created_by INTEGER NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    expires_at DATETIME,
    FOREIGN KEY (created_by) REFERENCES users(id)
);

CREATE INDEX IF NOT EXISTS idx_announcements_active ON announcements(is_active);
CREATE INDEX IF NOT EXISTS idx_announcements_created ON announcements(created_at);

-- Insert sample announcements
INSERT OR IGNORE INTO announcements (id, title, message, priority, created_by, created_at) VALUES
(1, 'Emergency Department Delay', 'Due to high patient volume, emergency department wait times may be longer than usual.', 'high', 1, '2025-11-18 09:00:00'),
(2, 'Dr. Rodriguez Unavailable', 'Dr. Emily Rodriguez is currently unavailable. Orthopedics appointments will be rescheduled.', 'medium', 1, '2025-11-18 08:30:00');

-- ============================================
-- AUDIT LOGGING
-- ============================================

CREATE TABLE IF NOT EXISTS audit_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER,
    username TEXT,
    role TEXT,
    action TEXT NOT NULL,  -- LOGIN, LOGOUT, CREATE, UPDATE, DELETE, etc.
    entity_type TEXT,  -- users, patients, etc.
    entity_id INTEGER,
    details TEXT,  -- JSON or text description
    ip_address TEXT,
    user_agent TEXT,
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- Create indexes for faster audit queries
CREATE INDEX IF NOT EXISTS idx_audit_user ON audit_logs(user_id);
CREATE INDEX IF NOT EXISTS idx_audit_action ON audit_logs(action);
CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON audit_logs(timestamp);
CREATE INDEX IF NOT EXISTS idx_audit_entity ON audit_logs(entity_type, entity_id);

-- ============================================
-- ANALYTICS AND STATISTICS
-- ============================================

CREATE TABLE IF NOT EXISTS daily_statistics (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    date DATE UNIQUE NOT NULL,
    total_patients INTEGER DEFAULT 0,
    total_completed INTEGER DEFAULT 0,
    total_cancelled INTEGER DEFAULT 0,
    average_wait_time INTEGER DEFAULT 0,  -- in minutes
    peak_queue_length INTEGER DEFAULT 0,
    total_consultations INTEGER DEFAULT 0,
    calculated_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_stats_date ON daily_statistics(date);

-- ============================================
-- SAMPLE DATA FOR TESTING
-- ============================================

-- Sample doctors (password: doctor123)
-- Note: In production, use proper password hashing from the C backend
INSERT OR IGNORE INTO users (id, username, email, role_id, full_name, is_active) VALUES
(2, 'dr.johnson', '[email protected]', 2, 'Dr. Sarah Johnson', 1),
(3, 'dr.chen', '[email protected]', 2, 'Dr. Michael Chen', 1),
(4, 'dr.rodriguez', '[email protected]', 2, 'Dr. Emily Rodriguez', 0),
(5, 'dr.williams', '[email protected]', 2, 'Dr. James Williams', 1);

-- Sample receptionist (password: recep123)
INSERT OR IGNORE INTO users (id, username, email, role_id, full_name, is_active) VALUES
(6, 'receptionist', '[email protected]', 3, 'Michael Anderson', 1);

-- Sample nurse (password: nurse123)
INSERT OR IGNORE INTO users (id, username, email, role_id, full_name, is_active) VALUES
(7, 'nurse', '[email protected]', 4, 'Emily Chen', 1);

-- Sample patients in queue
INSERT OR IGNORE INTO patients (token, full_name, age, gender, contact, department_id, chief_complaint, status_id, wait_time_minutes, registration_time) VALUES
('TOK001', 'John Doe', 45, 'Male', '555-0101', 1, 'Chest pain and shortness of breath', 1, 25, '2025-11-18 09:15:00'),
('TOK002', 'Jane Smith', 32, 'Female', '555-0102', 2, 'Child fever and cough', 2, 10, '2025-11-18 09:30:00'),
('TOK003', 'Robert Brown', 58, 'Male', '555-0103', 4, 'Persistent headache', 1, 15, '2025-11-18 09:45:00');

-- ============================================
-- VIEWS FOR COMMON QUERIES
-- ============================================

-- View for active queue with full details
CREATE VIEW IF NOT EXISTS v_active_queue AS
SELECT 
    p.id,
    p.token,
    p.full_name,
    p.age,
    p.gender,
    p.contact,
    d.name AS department,
    p.chief_complaint,
    qs.display_name AS status,
    qs.color AS status_color,
    p.wait_time_minutes,
    p.priority,
    u.full_name AS assigned_doctor,
    p.registration_time
FROM patients p
LEFT JOIN departments d ON p.department_id = d.id
LEFT JOIN queue_status qs ON p.status_id = qs.id
LEFT JOIN users u ON p.assigned_doctor_id = u.id
WHERE p.status_id IN (1, 2)  -- Waiting or In Progress
ORDER BY p.priority DESC, p.registration_time ASC;

-- View for user details with role information
CREATE VIEW IF NOT EXISTS v_user_details AS
SELECT 
    u.id,
    u.username,
    u.email,
    u.full_name,
    u.phone,
    r.display_name AS role,
    u.is_active,
    u.last_login,
    u.created_at
FROM users u
LEFT JOIN roles r ON u.role_id = r.id;

-- View for daily statistics
CREATE VIEW IF NOT EXISTS v_today_stats AS
SELECT 
    COUNT(*) AS total_patients,
    SUM(CASE WHEN status_id = 3 THEN 1 ELSE 0 END) AS completed,
    SUM(CASE WHEN status_id = 4 THEN 1 ELSE 0 END) AS cancelled,
    SUM(CASE WHEN status_id IN (1, 2) THEN 1 ELSE 0 END) AS waiting,
    AVG(CASE WHEN status_id = 3 THEN wait_time_minutes END) AS avg_wait_time
FROM patients
WHERE DATE(registration_time) = DATE('now');

-- ============================================
-- TRIGGERS FOR AUTOMATIC UPDATES
-- ============================================

-- Update patient updated_at timestamp on any change
CREATE TRIGGER IF NOT EXISTS trg_patients_updated_at
AFTER UPDATE ON patients
BEGIN
    UPDATE patients SET updated_at = CURRENT_TIMESTAMP WHERE id = NEW.id;
END;

-- Calculate wait time when consultation ends
CREATE TRIGGER IF NOT EXISTS trg_calculate_wait_time
AFTER UPDATE OF consultation_start_time ON patients
WHEN NEW.consultation_start_time IS NOT NULL AND OLD.consultation_start_time IS NULL
BEGIN
    UPDATE patients 
    SET wait_time_minutes = (
        CAST((julianday(NEW.consultation_start_time) - julianday(NEW.registration_time)) * 24 * 60 AS INTEGER)
    )
    WHERE id = NEW.id;
END;

-- Log patient movement
CREATE TRIGGER IF NOT EXISTS trg_log_status_change
AFTER UPDATE OF status_id ON patients
WHEN NEW.status_id != OLD.status_id
BEGIN
    INSERT INTO audit_logs (user_id, action, entity_type, entity_id, details)
    VALUES (
        NULL,
        'STATUS_CHANGE',
        'patients',
        NEW.id,
        'Status changed from ' || OLD.status_id || ' to ' || NEW.status_id
    );
END;

-- ============================================
-- INITIALIZATION COMPLETE
-- ============================================

-- Create a log entry for successful initialization
INSERT INTO audit_logs (user_id, action, details) 
VALUES (NULL, 'SYSTEM_INIT', 'Database schema initialized successfully');

SELECT 'HealQueue database schema created successfully!' AS status;
