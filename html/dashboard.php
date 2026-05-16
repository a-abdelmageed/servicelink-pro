<?php
// ============================================================
// ServiceLink Pro — Client Dashboard (dashboard.php)
// Vulnerabilities present:
//   - IDOR: user_id taken from GET param — no ownership check
//   - Stored XSS: username, full_name, address echoed without encoding
//   - Broken Auth: no session timeout, role check is bypassable
//   - SQL Injection: message submit uses raw concatenation
//   - Information Disclosure: all user fields (incl. MD5 hash) exposed in admin view
// ============================================================
require_once 'db_config.php';
session_start();

// !! VULNERABILITY: Broken Auth — only checks if session key exists, no timeout
if (!isset($_SESSION['user_id'])) {
    header("Location: login.php");
    exit;
}

// !! VULNERABILITY: IDOR — user_id comes from GET parameter
// Any logged-in user can view ANY other user's dashboard by changing ?user_id=X
// There is NO check that $_GET['user_id'] == $_SESSION['user_id']
$viewed_user_id = isset($_GET['user_id']) ? (int)$_GET['user_id'] : $_SESSION['user_id'];

// Fetch the viewed user's profile
// !! VULNERABILITY: integer cast still allows IDOR (just not string SQLi here)
$profile_sql = "SELECT * FROM users WHERE id = " . $viewed_user_id;
$profile_result = mysqli_query($conn, $profile_sql);
$profile = mysqli_fetch_assoc($profile_result);

if (!$profile) {
    // !! Information disclosure: confirms user doesn't exist
    die("<h3 style='color:red;font-family:sans-serif;padding:40px'>
         Error: No user found with ID <strong>" . $viewed_user_id . "</strong>.
         <a href='dashboard.php?user_id=1'>Try ID 1</a> | 
         <a href='dashboard.php?user_id=2'>Try ID 2</a> |
         <a href='dashboard.php?user_id=3'>Try ID 3</a>
         </h3>");
}

// Fetch service requests for viewed user
$requests_sql = "SELECT sr.*, s.name AS service_name, s.category, s.price
                 FROM service_requests sr
                 JOIN services s ON sr.service_id = s.id
                 WHERE sr.user_id = " . $viewed_user_id . "
                 ORDER BY sr.requested_at DESC";
$requests_result = mysqli_query($conn, $requests_sql);
$requests = [];
while ($row = mysqli_fetch_assoc($requests_result)) {
    $requests[] = $row;
}

// Fetch messages for viewed user
$msgs_sql = "SELECT * FROM messages WHERE user_id = " . $viewed_user_id . " ORDER BY sent_at DESC";
$msgs_result = mysqli_query($conn, $msgs_sql);
$messages = [];
while ($row = mysqli_fetch_assoc($msgs_result)) {
    $messages[] = $row;
}

// Fetch all users list (only shown to admin — but check is weak)
$all_users = [];
// !! VULNERABILITY: Role check uses session variable that was set from DB at login
// But since IDOR lets you view any dashboard, attacker viewing admin's page
// would see this list if they could forge the session role.
if ($_SESSION['role'] === 'admin') {
    $users_sql = "SELECT id, username, email, full_name, password, role, created_at FROM users ORDER BY id";
    $users_result = mysqli_query($conn, $users_sql);
    while ($row = mysqli_fetch_assoc($users_result)) {
        $all_users[] = $row;
    }
}

// Handle message submission
$msg_success = '';
$msg_error   = '';
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['send_message'])) {
    $subject = $_POST['subject'];
    $body    = $_POST['body'];

    // !! VULNERABILITY: SQL INJECTION + Stored XSS
    // subject and body stored raw — will be reflected without encoding later
    $insert_msg = "INSERT INTO messages (user_id, subject, body)
                   VALUES (" . $_SESSION['user_id'] . ", '" . $subject . "', '" . $body . "')";
    if (mysqli_query($conn, $insert_msg)) {
        $msg_success = "Message sent successfully!";
        // Refresh messages list
        $msgs_result2 = mysqli_query($conn, $msgs_sql);
        $messages = [];
        while ($row = mysqli_fetch_assoc($msgs_result2)) {
            $messages[] = $row;
        }
    } else {
        $msg_error = "Failed to send: " . mysqli_error($conn);
    }
}

$is_own_profile = ($viewed_user_id == $_SESSION['user_id']);
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>ServiceLink Pro — Dashboard</title>
    <style>
        * { box-sizing: border-box; margin: 0; padding: 0; }
        body { font-family: 'Segoe UI', Arial, sans-serif; background: #f0f2f5; color: #222; }

        nav { background: #1a237e; color: #fff; padding: 14px 40px;
              display: flex; justify-content: space-between; align-items: center; }
        nav .brand { font-size: 1.4rem; font-weight: 700; }
        nav a { color: #c5cae9; text-decoration: none; margin-left: 18px; font-size: 0.93rem; }
        nav a:hover { color: #fff; }
        nav .user-badge { background: #283593; padding: 6px 14px; border-radius: 20px;
                          font-size: 0.88rem; color: #c5cae9; }

        .layout { display: grid; grid-template-columns: 260px 1fr; min-height: calc(100vh - 54px); }

        /* SIDEBAR */
        .sidebar { background: #fff; border-right: 1px solid #e8eaf6; padding: 28px 0; }
        .sidebar .avatar { text-align: center; padding: 0 20px 24px; border-bottom: 1px solid #e8eaf6; }
        .avatar-circle { width: 72px; height: 72px; border-radius: 50%; background: #3949ab;
                         color: #fff; font-size: 2rem; display: flex; align-items: center;
                         justify-content: center; margin: 0 auto 10px; }
        /* !! VULNERABILITY: XSS — full_name echoed directly, no htmlspecialchars() */
        .avatar h4 { color: #1a237e; font-size: 1rem; }
        .avatar .role-badge { background: #e8eaf6; color: #3949ab; padding: 3px 10px;
                              border-radius: 12px; font-size: 0.78rem; margin-top: 5px; display: inline-block; }

        .sidebar-nav { padding: 16px 0; }
        .sidebar-nav a { display: block; padding: 10px 28px; color: #555; text-decoration: none;
                         font-size: 0.92rem; border-left: 3px solid transparent; }
        .sidebar-nav a:hover { background: #f5f5ff; color: #1a237e; border-left-color: #3949ab; }
        .sidebar-nav a.active { background: #e8eaf6; color: #1a237e; border-left-color: #1a237e; font-weight: 600; }

        /* IDOR navigation — lets any user jump to any profile ID */
        .idor-box { margin: 20px; padding: 12px; background: #fff8e1;
                    border: 1px dashed #f9a825; border-radius: 6px; font-size: 0.8rem; }
        .idor-box strong { color: #e65100; display: block; margin-bottom: 6px; }
        .idor-box input { width: 60px; padding: 4px 8px; border: 1px solid #ddd; border-radius: 4px; }
        .idor-box button { padding: 4px 10px; background: #e65100; color: #fff;
                           border: none; border-radius: 4px; cursor: pointer; font-size: 0.8rem; }

        /* MAIN CONTENT */
        .main { padding: 32px 36px; }
        .page-header { margin-bottom: 28px; }
        .page-header h2 { font-size: 1.7rem; color: #1a237e; }
        .page-header p  { color: #777; margin-top: 4px; font-size: 0.9rem; }

        /* IDOR WARNING BANNER */
        .idor-warning { background: #ff6f00; color: #fff; padding: 10px 18px; border-radius: 6px;
                        margin-bottom: 22px; font-size: 0.88rem; }

        /* CARDS */
        .cards-row { display: grid; grid-template-columns: repeat(3, 1fr); gap: 18px; margin-bottom: 30px; }
        .stat-card { background: #fff; border-radius: 8px; padding: 20px 22px;
                     box-shadow: 0 2px 6px rgba(0,0,0,.08); border-top: 4px solid #3949ab; }
        .stat-card .num { font-size: 2rem; font-weight: 700; color: #1a237e; }
        .stat-card .label { font-size: 0.82rem; color: #888; margin-top: 4px; }

        /* PROFILE */
        .section-card { background: #fff; border-radius: 8px; padding: 24px 26px;
                        box-shadow: 0 2px 6px rgba(0,0,0,.08); margin-bottom: 24px; }
        .section-card h3 { color: #1a237e; margin-bottom: 18px; font-size: 1.1rem;
                           border-bottom: 2px solid #e8eaf6; padding-bottom: 10px; }
        .profile-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 10px 24px; }
        .field-row label { font-size: 0.8rem; color: #999; font-weight: 600; text-transform: uppercase; }
        /* !! VULNERABILITY: XSS — all profile fields echoed without htmlspecialchars() */
        .field-row .val { font-size: 0.95rem; color: #333; margin-top: 2px;
                          word-break: break-all; padding: 4px 0; }

        /* TABLES */
        table { width: 100%; border-collapse: collapse; }
        th { background: #f5f5ff; color: #3949ab; font-size: 0.8rem; text-transform: uppercase;
             padding: 10px 14px; text-align: left; border-bottom: 2px solid #e8eaf6; }
        td { padding: 11px 14px; border-bottom: 1px solid #f0f2f5; font-size: 0.88rem; }
        tr:last-child td { border-bottom: none; }
        tr:hover td { background: #fafafa; }

        .badge { padding: 3px 9px; border-radius: 12px; font-size: 0.76rem; font-weight: 600; }
        .badge-pending     { background: #fff3e0; color: #e65100; }
        .badge-in_progress { background: #e3f2fd; color: #1565c0; }
        .badge-completed   { background: #e8f5e9; color: #2e7d32; }
        .badge-cancelled   { background: #fce4ec; color: #c62828; }

        /* MESSAGE FORM */
        .msg-form input, .msg-form textarea {
            width: 100%; padding: 10px 13px; border: 1px solid #c5cae9;
            border-radius: 5px; font-size: 0.93rem; margin-bottom: 12px;
            outline: none; font-family: inherit; }
        .msg-form textarea { min-height: 80px; resize: vertical; }
        .msg-form button { padding: 10px 24px; background: #1a237e; color: #fff;
                           border: none; border-radius: 5px; cursor: pointer; font-size: 0.92rem; }
        .msg-form button:hover { background: #283593; }

        .success-box { background: #e8f5e9; border-left: 4px solid #2e7d32; padding: 10px 14px;
                       border-radius: 4px; font-size: 0.88rem; color: #1b5e20; margin-bottom: 12px; }
        .error-box   { background: #ffebee; border-left: 4px solid #c62828; padding: 10px 14px;
                       border-radius: 4px; font-size: 0.88rem; color: #b71c1c;
                       font-family: monospace; margin-bottom: 12px; }

        /* ADMIN USER TABLE */
        .admin-section { background: #fff; border-radius: 8px; padding: 24px 26px;
                         box-shadow: 0 2px 6px rgba(0,0,0,.08); margin-bottom: 24px;
                         border-top: 4px solid #c62828; }
        .admin-section h3 { color: #c62828; margin-bottom: 18px; border-bottom: 2px solid #ffcdd2;
                            padding-bottom: 10px; }
        .hash-cell { font-family: monospace; font-size: 0.78rem; color: #888; }

        .logout-btn { background: #c62828; color: #fff; padding: 7px 16px; border-radius: 4px;
                      text-decoration: none; font-size: 0.85rem; }
    </style>
</head>
<body>

<nav>
    <div class="brand">🔗 ServiceLink Pro</div>
    <div style="display:flex;align-items:center;gap:16px">
        <!-- !! VULNERABILITY: Stored/Reflected XSS — username from session echoed raw -->
        <span class="user-badge">👤 <?php echo $_SESSION['username']; ?> (<?php echo $_SESSION['role']; ?>)</span>
        <a href="logout.php">Logout</a>
        <a href="index.php">Home</a>
    </div>
</nav>

<div class="layout">
    <!-- SIDEBAR -->
    <aside class="sidebar">
        <div class="avatar">
            <div class="avatar-circle">
                <!-- !! VULNERABILITY: XSS — first char of username echoed raw -->
                <?php echo strtoupper(substr($profile['username'], 0, 1)); ?>
            </div>
            <!-- !! VULNERABILITY: Stored XSS — full_name stored raw, echoed raw -->
            <h4><?php echo $profile['full_name']; ?></h4>
            <span class="role-badge"><?php echo $profile['role']; ?></span>
        </div>

        <nav class="sidebar-nav">
            <a href="dashboard.php?user_id=<?php echo $_SESSION['user_id']; ?>" class="active">📊 My Dashboard</a>
            <a href="dashboard.php?user_id=<?php echo $_SESSION['user_id']; ?>">📋 Service History</a>
            <a href="dashboard.php?user_id=<?php echo $_SESSION['user_id']; ?>">✉️ Messages</a>
        </nav>

        <!-- !! VULNERABILITY: IDOR helper — directly exposed in UI for testing -->
        <div class="idor-box">
            <strong>🔓 IDOR Test Panel</strong>
            View any user's profile by ID:
            <form method="GET" style="margin-top:8px;display:flex;gap:6px;align-items:center">
                <input type="number" name="user_id" value="<?php echo $viewed_user_id; ?>" min="1">
                <button type="submit">Go</button>
            </form>
            <div style="margin-top:8px">
                Quick:
                <?php for ($i = 1; $i <= 5; $i++): ?>
                <a href="dashboard.php?user_id=<?php echo $i; ?>"
                   style="color:#e65100;font-weight:600"><?php echo $i; ?></a>
                <?php endfor; ?>
            </div>
        </div>
    </aside>

    <!-- MAIN -->
    <main class="main">

        <?php if (!$is_own_profile): ?>
        <!-- !! VULNERABILITY: IDOR — viewing another user's data, no access control -->
        <div class="idor-warning">
            ⚠️ <strong>IDOR TRIGGERED:</strong> You are viewing User ID <strong><?php echo $viewed_user_id; ?></strong>
            (<?php echo $profile['username']; ?>) — not your own profile.
            Session belongs to user ID <strong><?php echo $_SESSION['user_id']; ?></strong>.
        </div>
        <?php endif; ?>

        <div class="page-header">
            <!-- !! VULNERABILITY: Stored XSS — full_name echoed without encoding -->
            <h2>Welcome, <?php echo $profile['full_name']; ?> 👋</h2>
            <p>User ID: <strong><?php echo $profile['id']; ?></strong> &mdash;
               Account created: <?php echo $profile['created_at']; ?></p>
        </div>

        <!-- STAT CARDS -->
        <div class="cards-row">
            <div class="stat-card">
                <div class="num"><?php echo count($requests); ?></div>
                <div class="label">Total Service Requests</div>
            </div>
            <div class="stat-card">
                <div class="num">
                    <?php echo count(array_filter($requests, fn($r) => $r['status'] === 'in_progress')); ?>
                </div>
                <div class="label">In Progress</div>
            </div>
            <div class="stat-card">
                <div class="num">
                    <?php echo count(array_filter($requests, fn($r) => $r['status'] === 'completed')); ?>
                </div>
                <div class="label">Completed</div>
            </div>
        </div>

        <!-- PROFILE DETAILS -->
        <div class="section-card">
            <h3>📇 Profile Information</h3>
            <div class="profile-grid">
                <div class="field-row">
                    <label>Username</label>
                    <!-- !! VULNERABILITY: Stored XSS — username echoed raw -->
                    <div class="val"><?php echo $profile['username']; ?></div>
                </div>
                <div class="field-row">
                    <label>Full Name</label>
                    <!-- !! VULNERABILITY: Stored XSS — full_name echoed raw -->
                    <div class="val"><?php echo $profile['full_name']; ?></div>
                </div>
                <div class="field-row">
                    <label>Email</label>
                    <!-- !! VULNERABILITY: XSS — email echoed raw -->
                    <div class="val"><?php echo $profile['email']; ?></div>
                </div>
                <div class="field-row">
                    <label>Phone</label>
                    <div class="val"><?php echo $profile['phone']; ?></div>
                </div>
                <div class="field-row" style="grid-column:1/-1">
                    <label>Address</label>
                    <!-- !! VULNERABILITY: XSS — address echoed raw -->
                    <div class="val"><?php echo $profile['address']; ?></div>
                </div>
                <div class="field-row">
                    <label>Password Hash (MD5)</label>
                    <!-- !! VULNERABILITY: Password hash exposed in UI — information disclosure -->
                    <div class="val" style="font-family:monospace;font-size:0.82rem;color:#c62828">
                        <?php echo $profile['password']; ?>
                    </div>
                </div>
                <div class="field-row">
                    <label>Role</label>
                    <div class="val"><?php echo $profile['role']; ?></div>
                </div>
            </div>
        </div>

        <!-- SERVICE REQUESTS -->
        <div class="section-card">
            <h3>🛠️ Service Request History</h3>
            <?php if (empty($requests)): ?>
                <p style="color:#aaa;font-size:0.9rem">No service requests found for this account.</p>
            <?php else: ?>
            <table>
                <tr>
                    <th>Request ID</th>
                    <th>Service</th>
                    <th>Category</th>
                    <th>Price</th>
                    <th>Status</th>
                    <th>Notes</th>
                    <th>Date</th>
                </tr>
                <?php foreach ($requests as $req): ?>
                <tr>
                    <td>#<?php echo $req['id']; ?></td>
                    <!-- !! VULNERABILITY: Stored XSS — service name echoed raw -->
                    <td><?php echo $req['service_name']; ?></td>
                    <td><?php echo $req['category']; ?></td>
                    <td>$<?php echo number_format($req['price'], 2); ?></td>
                    <td><span class="badge badge-<?php echo $req['status']; ?>"><?php echo $req['status']; ?></span></td>
                    <!-- !! VULNERABILITY: Stored XSS — notes echoed raw -->
                    <td><?php echo $req['notes']; ?></td>
                    <td><?php echo $req['requested_at']; ?></td>
                </tr>
                <?php endforeach; ?>
            </table>
            <?php endif; ?>
        </div>

        <!-- MESSAGES -->
        <div class="section-card">
            <h3>✉️ Messages</h3>

            <?php if ($msg_success): ?>
                <div class="success-box">✅ <?php echo $msg_success; ?></div>
            <?php endif; ?>
            <?php if ($msg_error): ?>
                <div class="error-box">❌ <?php echo $msg_error; ?></div>
            <?php endif; ?>

            <!-- !! No CSRF token on message form -->
            <!-- !! VULNERABILITY: SQL Injection + Stored XSS via subject/body fields -->
            <form method="POST" class="msg-form" style="margin-bottom:20px">
                <input type="text" name="subject" placeholder="Message subject (XSS payload welcome in lab)">
                <textarea name="body" placeholder="Message body..."></textarea>
                <button type="submit" name="send_message">Send Message</button>
            </form>

            <?php if (!empty($messages)): ?>
            <table>
                <tr><th>ID</th><th>Subject</th><th>Body</th><th>Sent</th></tr>
                <?php foreach ($messages as $msg): ?>
                <tr>
                    <td>#<?php echo $msg['id']; ?></td>
                    <!-- !! VULNERABILITY: Stored XSS — subject and body echoed raw -->
                    <td><?php echo $msg['subject']; ?></td>
                    <td><?php echo $msg['body']; ?></td>
                    <td><?php echo $msg['sent_at']; ?></td>
                </tr>
                <?php endforeach; ?>
            </table>
            <?php else: ?>
                <p style="color:#aaa;font-size:0.9rem">No messages yet.</p>
            <?php endif; ?>
        </div>

        <!-- ADMIN PANEL — shows all users with password hashes -->
        <?php if (!empty($all_users)): ?>
        <div class="admin-section">
            <h3>🔴 Admin Panel — All Users (Password Hashes Exposed)</h3>
            <table>
                <tr>
                    <th>ID</th><th>Username</th><th>Email</th>
                    <th>Full Name</th><th>Role</th>
                    <!-- !! VULNERABILITY: MD5 hashes exposed — trivially crackable -->
                    <th>Password Hash (MD5)</th><th>Created</th>
                </tr>
                <?php foreach ($all_users as $u): ?>
                <tr>
                    <!-- !! VULNERABILITY: IDOR link — admin can jump to any user -->
                    <td><a href="dashboard.php?user_id=<?php echo $u['id']; ?>"><?php echo $u['id']; ?></a></td>
                    <!-- !! VULNERABILITY: Stored XSS — all fields echoed raw -->
                    <td><?php echo $u['username']; ?></td>
                    <td><?php echo $u['email']; ?></td>
                    <td><?php echo $u['full_name']; ?></td>
                    <td><?php echo $u['role']; ?></td>
                    <td class="hash-cell"><?php echo $u['password']; ?></td>
                    <td><?php echo $u['created_at']; ?></td>
                </tr>
                <?php endforeach; ?>
            </table>
        </div>
        <?php endif; ?>

    </main>
</div>

</body>
</html>
