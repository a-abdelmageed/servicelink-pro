-- ============================================================
-- ServiceLink Pro - Intentionally Vulnerable Lab Database
-- FOR CONTROLLED IDS TESTING ONLY
-- ============================================================

CREATE DATABASE IF NOT EXISTS servicelink;
USE servicelink;

-- ============================================================
-- Table: users
-- Vulnerability: passwords stored as plain MD5 (no salt)
-- ============================================================
CREATE TABLE IF NOT EXISTS users (
    id          INT AUTO_INCREMENT PRIMARY KEY,
    username    VARCHAR(100) NOT NULL,
    email       VARCHAR(150) NOT NULL UNIQUE,
    password    VARCHAR(255) NOT NULL,  -- MD5 hash, no salt
    full_name   VARCHAR(200),
    phone       VARCHAR(30),
    address     TEXT,
    role        ENUM('client','admin') DEFAULT 'client',
    created_at  DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- ============================================================
-- Table: services
-- ============================================================
CREATE TABLE IF NOT EXISTS services (
    id          INT AUTO_INCREMENT PRIMARY KEY,
    name        VARCHAR(150) NOT NULL,
    description TEXT,
    price       DECIMAL(10,2),
    category    VARCHAR(100)
);

-- ============================================================
-- Table: service_requests
-- Vulnerability: IDOR — user_id tied directly to URL param
-- ============================================================
CREATE TABLE IF NOT EXISTS service_requests (
    id          INT AUTO_INCREMENT PRIMARY KEY,
    user_id     INT NOT NULL,
    service_id  INT NOT NULL,
    status      ENUM('pending','in_progress','completed','cancelled') DEFAULT 'pending',
    notes       TEXT,
    requested_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id),
    FOREIGN KEY (service_id) REFERENCES services(id)
);

-- ============================================================
-- Table: messages (reflects user input → XSS surface)
-- ============================================================
CREATE TABLE IF NOT EXISTS messages (
    id          INT AUTO_INCREMENT PRIMARY KEY,
    user_id     INT NOT NULL,
    subject     VARCHAR(255),
    body        TEXT,
    sent_at     DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id)
);

-- ============================================================
-- Dummy Data: users
-- Passwords are MD5 of the plaintext shown in comments
-- admin    → MD5("admin123")      = 0192023a7bbd73250516f069df18b500
-- alice    → MD5("password")      = 5f4dcc3b5aa765d61d8327deb882cf99
-- bob      → MD5("bob2024")       = 3a4736b5024ff5e3f3d47a9b0e98b3e2  (approx)
-- charlie  → MD5("charlie!")      = approx hash below
-- ============================================================
INSERT INTO users (id, username, email, password, full_name, phone, address, role) VALUES
(1, 'admin',   'admin@servicelink.local',   '0192023a7bbd73250516f069df18b500', 'System Administrator', '+20-10-0000-0000', '1 Server Farm Road, Cairo', 'admin'),
(2, 'alice',   'alice@example.com',         '5f4dcc3b5aa765d61d8327deb882cf99', 'Alice Johnson',        '+20-11-1234-5678', '42 Nile View St, Giza', 'client'),
(3, 'bob',     'bob@example.com',           MD5('bob2024'),                      'Bob Martinez',         '+20-12-9876-5432', '17 Desert Rose Ave, Alexandria', 'client'),
(4, 'charlie', 'charlie@example.com',       MD5('charlie!'),                     'Charlie Nguyen',       '+20-10-5555-1212', '88 Pyramids Blvd, Cairo', 'client'),
(5, 'diana',   'diana@example.com',         MD5('diana2024'),                    'Diana Khalil',         '+20-11-3333-7777', '5 Tahrir Square, Cairo', 'client');

-- ============================================================
-- Dummy Data: services
-- ============================================================
INSERT INTO services (id, name, description, price, category) VALUES
(1, 'Basic IT Support',       'Remote troubleshooting and help-desk for hardware/software issues.',     150.00, 'IT Support'),
(2, 'Network Setup',          'Full LAN/WAN setup including switches, routers, and cabling.',           850.00, 'Networking'),
(3, 'Security Audit',         'Comprehensive vulnerability assessment and penetration testing report.',  2500.00, 'Cybersecurity'),
(4, 'Cloud Migration',        'Migrate on-premise infrastructure to AWS/Azure with full documentation.',5000.00, 'Cloud'),
(5, 'Web Development',        'Custom business website — 5 pages, responsive, with contact form.',      1200.00, 'Development'),
(6, 'Data Backup & Recovery', 'Automated daily backups with 30-day retention and recovery SLA.',        400.00,  'Storage'),
(7, 'CCTV Installation',      '8-camera IP-CCTV system with NVR, remote viewing and 2-week retention.', 3200.00, 'Physical Security'),
(8, 'Software Training',      'On-site staff training for MS Office 365, 2 days, up to 20 employees.',  700.00,  'Training');

-- ============================================================
-- Dummy Data: service_requests
-- ============================================================
INSERT INTO service_requests (user_id, service_id, status, notes) VALUES
(2, 1, 'completed',    'Laptop fan issue resolved remotely.'),
(2, 5, 'in_progress',  'Client wants dark theme, delivery end of month.'),
(3, 2, 'completed',    'Office network of 30 nodes, all up and running.'),
(3, 3, 'pending',      'Awaiting signed NDA before starting audit.'),
(4, 4, 'cancelled',    'Client postponed migration to next quarter.'),
(4, 6, 'in_progress',  'Backup configured, monitoring phase active.'),
(5, 7, 'pending',      'Site survey scheduled for next Tuesday.'),
(5, 8, 'completed',    'Training delivered. 18 employees attended.');

-- ============================================================
-- Dummy Data: messages
-- ============================================================
INSERT INTO messages (user_id, subject, body) VALUES
(2, 'Status Update Request', 'Hi, can you update me on the website project timeline?'),
(3, 'Invoice Question',      'I received invoice #1042 but the amount looks incorrect.'),
(4, 'Cloud Migration Query', 'We are ready to proceed, when can we reschedule?'),
(5, 'CCTV Follow-up',        'Will the technician call before arriving for the survey?');
