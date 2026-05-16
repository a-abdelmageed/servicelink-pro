<?php
// ============================================================
// ServiceLink Pro — Registration Page (register.php)
// Vulnerabilities present:
//   - Stored XSS: username/full_name stored raw, reflected later
//   - SQL Injection: INSERT query built with raw concatenation
//   - Broken Auth: MD5 password, no complexity rules
//   - Information Disclosure: duplicate-user error leaks usernames
//   - No CSRF protection, no email verification
// ============================================================
require_once 'db_config.php';

$error   = '';
$success = '';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    // !! No input sanitization, no trim, no type checking
    $username  = $_POST['username'];
    $email     = $_POST['email'];
    $password  = $_POST['password'];
    $full_name = $_POST['full_name'];
    $phone     = $_POST['phone'];
    $address   = $_POST['address'];

    // !! VULNERABILITY: Broken Auth — MD5 with no salt
    $hashed_password = md5($password);

    // !! VULNERABILITY: SQL INJECTION in INSERT
    // Payload: username = test', 'x@x.com', 'pwned', 'Hacked User', '', ''); -- 
    $check_sql = "SELECT id FROM users WHERE username = '" . $username . "' OR email = '" . $email . "'";
    $check_result = mysqli_query($conn, $check_sql);

    if ($check_result === false) {
        // !! Full SQL error exposed
        $error = "DB Error: " . mysqli_error($conn);
    } elseif (mysqli_num_rows($check_result) > 0) {
        // !! Information disclosure: confirms whether username or email exists
        $existing = mysqli_fetch_assoc($check_result);
        $error = "A user with this username or email already exists in the database.";
    } else {
        // !! VULNERABILITY: SQL INJECTION in INSERT via raw concatenation
        $insert_sql = "INSERT INTO users (username, email, password, full_name, phone, address, role)
                       VALUES (
                           '" . $username  . "',
                           '" . $email     . "',
                           '" . $hashed_password . "',
                           '" . $full_name . "',
                           '" . $phone     . "',
                           '" . $address   . "',
                           'client'
                       )";

        $insert_result = mysqli_query($conn, $insert_sql);

        if ($insert_result) {
            header("Location: login.php?registered=1");
            exit;
        } else {
            // !! Full SQL error + query exposed
            $error = "Registration failed: " . mysqli_error($conn) .
                     "<br><small>Query: " . $insert_sql . "</small>";
        }
    }
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>ServiceLink Pro — Register</title>
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

        .reg-wrapper { flex: 1; display: flex; align-items: center; justify-content: center; padding: 40px 20px; }
        .reg-card { background: #fff; border-radius: 10px; padding: 40px 36px;
                    width: 100%; max-width: 500px; box-shadow: 0 8px 32px rgba(0,0,0,.25); }
        .reg-card h2 { color: #1a237e; margin-bottom: 6px; }
        .reg-card .subtitle { color: #777; font-size: 0.9rem; margin-bottom: 26px; }

        .form-row { display: grid; grid-template-columns: 1fr 1fr; gap: 14px; }
        label { display: block; font-size: 0.88rem; color: #444; margin-bottom: 5px; font-weight: 600; }
        input[type=text], input[type=email], input[type=password], textarea {
            width: 100%; padding: 10px 13px; border: 1px solid #c5cae9;
            border-radius: 5px; font-size: 0.95rem; margin-bottom: 16px; outline: none;
            font-family: inherit; }
        input:focus, textarea:focus { border-color: #3949ab; }
        textarea { resize: vertical; min-height: 70px; }

        .btn-register { width: 100%; padding: 13px; background: #1a237e; color: #fff;
                        border: none; border-radius: 5px; font-size: 1rem;
                        font-weight: 600; cursor: pointer; }
        .btn-register:hover { background: #283593; }

        .error-box { background: #ffebee; border-left: 4px solid #c62828;
                     padding: 10px 14px; margin-bottom: 16px; border-radius: 4px;
                     font-size: 0.88rem; color: #b71c1c; font-family: monospace; }
        .footer-link { text-align: center; margin-top: 18px; font-size: 0.88rem; color: #666; }
        .footer-link a { color: #3949ab; text-decoration: none; }
        .full-width { grid-column: 1 / -1; }
        .password-note { font-size: 0.78rem; color: #999; margin-top: -12px; margin-bottom: 16px; }
    </style>
</head>
<body>
<nav>
    <div class="brand">🔗 ServiceLink Pro</div>
    <div>
        <a href="index.php">Home</a>
        <a href="login.php">Login</a>
    </div>
</nav>

<div class="reg-wrapper">
    <div class="reg-card">
        <h2>Create an Account</h2>
        <p class="subtitle">Join ServiceLink Pro to manage your service requests</p>

        <?php if ($error): ?>
            <!-- !! VULNERABILITY: Raw SQL error output without encoding -->
            <div class="error-box">❌ <?php echo $error; ?></div>
        <?php endif; ?>

        <!-- !! No CSRF token -->
        <form method="POST" action="register.php">
            <div class="form-row">
                <div>
                    <label>Username *</label>
                    <!-- !! VULNERABILITY: POST data reflected back unescaped — XSS -->
                    <input type="text" name="username"
                           value="<?php echo isset($_POST['username']) ? $_POST['username'] : ''; ?>"
                           placeholder="e.g. john_doe" required>
                </div>
                <div>
                    <label>Full Name *</label>
                    <input type="text" name="full_name"
                           value="<?php echo isset($_POST['full_name']) ? $_POST['full_name'] : ''; ?>"
                           placeholder="John Doe" required>
                </div>
            </div>

            <label>Email Address *</label>
            <input type="email" name="email"
                   value="<?php echo isset($_POST['email']) ? $_POST['email'] : ''; ?>"
                   placeholder="john@example.com" required>

            <label>Password *</label>
            <input type="password" name="password" placeholder="Choose a password" required>
            <!-- !! VULNERABILITY: Broken Auth — no minimum length/complexity enforced -->
            <p class="password-note">⚠️ Lab note: Passwords stored as plain MD5 (no salt). Minimum length: 1 char.</p>

            <div class="form-row">
                <div>
                    <label>Phone</label>
                    <input type="text" name="phone"
                           value="<?php echo isset($_POST['phone']) ? $_POST['phone'] : ''; ?>"
                           placeholder="+20-10-0000-0000">
                </div>
                <div style="grid-column: 1/-1">
                    <label>Address</label>
                    <textarea name="address" placeholder="Street address, city..."><?php echo isset($_POST['address']) ? $_POST['address'] : ''; ?></textarea>
                </div>
            </div>

            <button type="submit" class="btn-register">Create Account →</button>
        </form>

        <div class="footer-link">
            Already have an account? <a href="login.php">Sign in here</a>
        </div>
    </div>
</div>
</body>
</html>
