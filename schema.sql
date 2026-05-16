-- ============================================================
-- SecurAI NetLabs / ServiceLink Pro - Lab Database
-- FOR CONTROLLED IDS/SECURITY TESTING ONLY
-- ============================================================

-- 1. إعداد قاعدة البيانات وتصفيرها إذا كانت موجودة
DROP DATABASE IF EXISTS servicelink_db;
CREATE DATABASE servicelink_db;
USE servicelink_db;

-- ============================================================
-- Table: users (تم تصفيره وإعادة بنائه بالهيكل الصحيح)
-- ============================================================
DROP TABLE IF EXISTS users;
CREATE TABLE users (
    id          INT AUTO_INCREMENT PRIMARY KEY,
    username    VARCHAR(100) NOT NULL UNIQUE,
    email       VARCHAR(150) NOT NULL UNIQUE,
    password    VARCHAR(255) NOT NULL,  -- MD5 hash, no salt
    full_name   VARCHAR(200),
    phone       VARCHAR(30),
    address     TEXT,
    role        ENUM('client','admin') DEFAULT 'client',
    created_at  DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- ============================================================
-- Table: services (تم تعديل الحقول لتطابق استعلام index.php)
-- ============================================================
DROP TABLE IF EXISTS services;
CREATE TABLE services (
    id           INT AUTO_INCREMENT PRIMARY KEY,
    service_name VARCHAR(150) NOT NULL, -- متوافق مع الكود المتوقع
    price        DECIMAL(10,2) NOT NULL,
    description  TEXT,
    category     VARCHAR(100)
);

-- ============================================================
-- Table: service_requests (تأمين الربط مع الجداول المحدثة)
-- ============================================================
DROP TABLE IF EXISTS service_requests;
CREATE TABLE service_requests (
    id           INT AUTO_INCREMENT PRIMARY KEY,
    user_id      INT NOT NULL,
    service_id   INT NOT NULL,
    status       ENUM('pending','in_progress','completed','cancelled') DEFAULT 'pending',
    notes        TEXT,
    requested_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    FOREIGN KEY (service_id) REFERENCES services(id) ON DELETE CASCADE
);

-- ============================================================
-- Table: messages (سطح هجوم لثغرات الـ Stored XSS)
-- ============================================================
DROP TABLE IF EXISTS messages;
CREATE TABLE messages (
    id          INT AUTO_INCREMENT PRIMARY KEY,
    user_id     INT NOT NULL,
    subject     VARCHAR(255),
    body        TEXT,
    sent_at     DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

-- ============================================================
-- Dummy Data: users (تم إزالة المعرفات اليدوية لتجنب Duplicate Entry)
-- ============================================================
INSERT INTO users (username, email, password, full_name, phone, address, role) VALUES
('admin',   'admin@servicelink.local',   '0192023a7bbd73250516f069df18b500', 'System Administrator', '+20-10-0000-0000', '1 Server Farm Road, Cairo', 'admin'),
('alice',   'alice@example.com',         '5f4dcc3b5aa765d61d8327deb882cf99', 'Alice Johnson',        '+20-11-1234-5678', '42 Nile View St, Giza', 'client'),
('bob',     'bob@example.com',           MD5('bob2024'),                       'Bob Martinez',         '+20-12-9876-5432', '17 Desert Rose Ave, Alexandria', 'client'),
('charlie', 'charlie@example.com',       MD5('charlie!'),                      'Charlie Nguyen',       '+20-10-5555-1212', '88 Pyramids Blvd, Cairo', 'client'),
('diana',   'diana@example.com',         MD5('diana2024'),                     'Diana Khalil',         '+20-11-3333-7777', '5 Tahrir Square, Cairo', 'client');

-- ============================================================
-- Dummy Data: services (الأسماء متوافقة مع تخصص الـ Security والـ AI والـ Networks)
-- ============================================================
INSERT INTO services (service_name, description, price, category) VALUES
('AI-Driven Intrusion Detection', 'Next-gen IDS monitoring with automated ML threat analysis.', 2500.00, 'Cybersecurity'),
('Next-Gen Firewall Deployment',  'Enterprise security architecture installation and rule configuration.', 3500.00, 'Networking'),
('Vulnerability Assessment',     'Comprehensive dynamic and static analysis of corporate assets.', 1800.00, 'Cybersecurity'),
('Secured Cloud Architecture',   'Migration to hardened AWS/Azure environments with strict access control.', 5000.00, 'Cloud'),
('Network Diagnostics & Pentest','Internal network scanning and vulnerability verification.', 1200.00, 'Networking');

-- ============================================================
-- Dummy Data: service_requests
-- ============================================================
INSERT INTO service_requests (user_id, service_id, status, notes) VALUES
(2, 1, 'in_progress', 'Analyzing corporate perimeter logs using machine learning.'),
(3, 2, 'completed',  'Deployed primary and secondary firewall rulesets.'),
(4, 3, 'pending',    'Awaiting authorization credentials for asset auditing.'),
(5, 5, 'completed',  'Comprehensive internal scanning completed successfully.');

-- ============================================================
-- Dummy Data: messages
-- ============================================================
INSERT INTO messages (user_id, subject, body) VALUES
(2, 'IDS Log Query', 'Are the machine learning logs accessible via the dashboard?'),
(3, 'Rule Update', 'Can we add a custom rule to block specific traffic on Port 443?'),
(5, 'Scan Report', 'The penetration testing report needs to be sent encrypted.');
