<?php
// ============================================================
// ServiceLink Pro — Login Page (login.php)
// Vulnerabilities present:
//   - SQL Injection: raw string concatenation in login query
//   - Broken Auth: MD5 password comparison in SQL, no rate limiting
//   - Session fixation: session_id never regenerated on login
//   - Verbose error disclosure: SQL errors printed to page
//   - No CSRF protection
// ============================================================
require_once 'db_config.php';
session_start();  // No session_regenerate_id() — session fixation possible

$error   = '';
$success = '';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $username = $_POST['username'];  // !! No trim, no sanitization
    $password = $_POST['password'];

    // !! VULNERABILITY: SQL INJECTION
    // Classic bypass: username = admin'-- / password = anything
    // Or: username = ' OR '1'='1'-- 
    $sql = "SELECT * FROM users 
            WHERE username = '" . $username . "' 
            AND password = '" . md5($password) . "'";

    $result = mysqli_query($conn, $sql);

    if ($result === false) {
        // !! VULNERABILITY: Raw SQL error + full query exposed
        $error = "SQL Error: " . mysqli_error($conn) . "<br><small>Query: " . htmlspecialchars($sql) . "</small>";
    } elseif (mysqli_num_rows($result) > 0) {
        $user = mysqli_fetch_assoc($result);

        // !! VULNERABILITY: Broken Auth — no session_regenerate_id()
        // Session ID stays the same before and after login → Session Fixation
        $_SESSION['user_id']   = $user['id'];
        $_SESSION['username']  = $user['username'];
        $_SESSION['full_name'] = $user['full_name'];
        $_SESSION['role']      = $user['role'];
        // !! No session timeout ever set

        // Redirect to dashboard with ID in URL (IDOR surface)
        header("Location: dashboard.php?user_id=" . $user['id']);
        exit;
    } else {
        $error = "Invalid username or password.";
    }
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>ServiceLink Pro — Login</title>
    <style>
        * { box-sizing: border-box; margin: 0; padding: 0; }
        body { font-family: 'Segoe UI', Arial, sans-serif;
               background: linear-gradient(135deg, #1a237e, #3949ab);
               min-height: 100vh; display: flex; flex-direction: column; }
        nav { background: rgba(0,0,0,.25); color: #fff; padding: 14px 40px;
              display: flex; justify-content: space-between; align-items: center; }
        nav .brand { font-size: 1.4rem; font-weight: 700; }
        nav a { color: #c5cae9; text-decoration: none; margin-left: 18px; }
        nav a:hover { color: #fff; }

        .login-wrapper { flex: 1; display: flex; align-items: center; justify-content: center; padding: 40px 20px; }
        .login-card { background: #fff; border-radius: 10px; padding: 40px 36px;
                      width: 100%; max-width: 420px; box-shadow: 0 8px 32px rgba(0,0,0,.25); }
        .login-card h2 { color: #1a237e; margin-bottom: 6px; }
        .login-card .subtitle { color: #777; font-size: 0.9rem; margin-bottom: 26px; }

        label { display: block; font-size: 0.88rem; color: #444; margin-bottom: 5px; font-weight: 600; }
        input[type=text], input[type=password] {
            width: 100%; padding: 11px 14px; border: 1px solid #c5cae9;
            border-radius: 5px; font-size: 0.97rem; margin-bottom: 18px; outline: none; }
        input:focus { border-color: #3949ab; }

        .btn-login { width: 100%; padding: 13px; background: #1a237e; color: #fff;
                     border: none; border-radius: 5px; font-size: 1rem;
                     font-weight: 600; cursor: pointer; letter-spacing: .5px; }
        .btn-login:hover { background: #283593; }

        .error-box { background: #ffebee; border-left: 4px solid #c62828;
                     padding: 10px 14px; margin-bottom: 18px; border-radius: 4px;
                     font-size: 0.88rem; color: #b71c1c; font-family: monospace; }
        .success-box { background: #e8f5e9; border-left: 4px solid #2e7d32;
                       padding: 10px 14px; margin-bottom: 18px; border-radius: 4px;
                       font-size: 0.88rem; color: #1b5e20; }
        .footer-link { text-align: center; margin-top: 20px; font-size: 0.88rem; color: #666; }
        .footer-link a { color: #3949ab; text-decoration: none; }

        /* Hint box — shows test credentials for lab use */
        .lab-hint { background: #fffde7; border: 1px dashed #f9a825; padding: 12px 14px;
                    border-radius: 5px; font-size: 0.82rem; color: #555; margin-bottom: 18px; }
        .lab-hint strong { color: #e65100; }
        .lab-hint code { background: #fff8e1; padding: 1px 5px; border-radius: 3px;
                         font-size: 0.85rem; }
    </style>
</head>
<body>
<nav>
    <div class="brand">🔗 ServiceLink Pro</div>
    <div>
        <a href="index.php">Home</a>
        <a href="register.php">Register</a>
    </div>
</nav>

<div class="login-wrapper">
    <div class="login-card">
        <h2>Client Login</h2>
        <p class="subtitle">Access your service dashboard</p>

        <!-- Lab hint panel — intentional information disclosure for testers -->
        <div class="lab-hint">
            <strong>🧪 Lab Credentials:</strong><br>
            Admin: <code>admin</code> / <code>admin123</code><br>
            Client: <code>alice</code> / <code>password</code><br>
            Client: <code>bob</code> / <code>bob2024</code><br>
            <strong>SQLi Test:</strong> Username: <code>' OR '1'='1'--</code>
        </div>

        <?php if ($error): ?>
            <!-- !! VULNERABILITY: Raw SQL error output, no escaping -->
            <div class="error-box">❌ <?php echo $error; ?></div>
        <?php endif; ?>

        <?php if (isset($_GET['registered'])): ?>
            <div class="success-box">✅ Registration successful! Please log in.</div>
        <?php endif; ?>

        <!-- !! No CSRF token in form -->
        <form method="POST" action="login.php">
            <label for="username">Username</label>
            <!-- !! VULNERABILITY: value echoed back unescaped — XSS in error state -->
            <input type="text" id="username" name="username"
                   value="<?php echo isset($_POST['username']) ? $_POST['username'] : ''; ?>"
                   placeholder="Enter your username">

            <label for="password">Password</label>
            <input type="password" id="password" name="password" placeholder="Enter your password">

            <button type="submit" class="btn-login">Sign In →</button>
        </form>

        <div class="footer-link">
            Don't have an account? <a href="register.php">Register here</a>
        </div>
    </div>
</div>
</body>
</html>
