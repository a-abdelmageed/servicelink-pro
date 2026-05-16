<?php
// ============================================================
// ServiceLink Pro — Database Configuration
// FOR CONTROLLED IDS/SECURITY TESTING ONLY
// ============================================================

define('DB_HOST', getenv('DB_HOST') ?: 'db');
define('DB_USER', getenv('DB_USER') ?: 'servicelink_user');
define('DB_PASS', getenv('DB_PASS') ?: 'servicelink_pass');
define('DB_NAME', getenv('DB_NAME') ?: 'servicelink');

// Intentionally uses old mysqli — no PDO, no prepared statements by default
$conn = mysqli_connect(DB_HOST, DB_USER, DB_PASS, DB_NAME);

if (!$conn) {
    // Verbose error output — intentionally leaks DB info (misconfiguration vuln)
    die("DATABASE CONNECTION FAILED: " . mysqli_connect_error() .
        " | Host: " . DB_HOST . " | User: " . DB_USER);
}

mysqli_set_charset($conn, "utf8");

// No error suppression — full MySQL errors will be exposed to the browser
mysqli_report(MYSQLI_REPORT_OFF);
