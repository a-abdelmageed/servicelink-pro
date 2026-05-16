<?php
// ============================================================
// ServiceLink Pro — Landing Page (index.php)
// Vulnerabilities present:
//   - Reflected XSS via 'search' GET parameter (unencoded output)
//   - SQL Injection via search query (raw string interpolation)
//   - Verbose MySQL errors exposed to browser
// ============================================================
require_once 'db_config.php';

$search_term   = isset($_GET['search']) ? $_GET['search'] : '';
$search_results = [];
$search_error   = '';

if ($search_term !== '') {
    // !! VULNERABILITY: SQL INJECTION — raw user input in query string
    $sql = "SELECT * FROM services WHERE name LIKE '%" . $search_term . "%' OR description LIKE '%" . $search_term . "%'";
    $result = mysqli_query($conn, $sql);
    if ($result) {
        while ($row = mysqli_fetch_assoc($result)) {
            $search_results[] = $row;
        }
    } else {
        // !! VULNERABILITY: Full MySQL error exposed
        $search_error = "Query error: " . mysqli_error($conn);
    }
}

// Fetch all services for the landing page listing
$all_services = [];
$res = mysqli_query($conn, "SELECT * FROM services ORDER BY category");
while ($row = mysqli_fetch_assoc($res)) {
    $all_services[] = $row;
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>ServiceLink Pro — Professional IT Services</title>
    <style>
        * { box-sizing: border-box; margin: 0; padding: 0; }
        body { font-family: 'Segoe UI', Arial, sans-serif; background: #f0f2f5; color: #222; }

        /* NAV */
        nav { background: #1a237e; color: #fff; padding: 14px 40px; display: flex; justify-content: space-between; align-items: center; }
        nav .brand { font-size: 1.5rem; font-weight: 700; letter-spacing: 1px; }
        nav a { color: #c5cae9; text-decoration: none; margin-left: 20px; font-size: 0.95rem; }
        nav a:hover { color: #fff; }

        /* HERO */
        .hero { background: linear-gradient(135deg, #1a237e 0%, #283593 60%, #3949ab 100%);
                color: #fff; text-align: center; padding: 80px 20px; }
        .hero h1 { font-size: 2.8rem; margin-bottom: 14px; }
        .hero p  { font-size: 1.15rem; opacity: 0.88; margin-bottom: 30px; }

        /* SEARCH */
        .search-bar { display: flex; justify-content: center; gap: 10px; margin-top: 10px; }
        .search-bar input { padding: 12px 20px; width: 420px; border: none; border-radius: 4px;
                            font-size: 1rem; outline: none; }
        .search-bar button { padding: 12px 28px; background: #ff6f00; color: #fff; border: none;
                             border-radius: 4px; font-size: 1rem; cursor: pointer; }
        .search-bar button:hover { background: #e65100; }

        /* SEARCH RESULTS */
        .results { max-width: 900px; margin: 30px auto; padding: 0 20px; }
        .results h3 { margin-bottom: 14px; color: #1a237e; }
        .error-box { background: #ffebee; border-left: 4px solid #c62828; padding: 12px 16px;
                     font-family: monospace; font-size: 0.9rem; color: #b71c1c; }

        /* SERVICES GRID */
        .section { max-width: 1100px; margin: 50px auto; padding: 0 20px; }
        .section h2 { font-size: 1.9rem; color: #1a237e; margin-bottom: 26px; text-align: center; }
        .services-grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(280px, 1fr)); gap: 22px; }
        .service-card { background: #fff; border-radius: 8px; padding: 24px;
                        box-shadow: 0 2px 8px rgba(0,0,0,.10); border-top: 4px solid #3949ab; }
        .service-card h4 { font-size: 1.1rem; color: #1a237e; margin-bottom: 8px; }
        .service-card .cat { font-size: 0.78rem; background: #e8eaf6; color: #3949ab;
                             padding: 3px 8px; border-radius: 12px; display: inline-block; margin-bottom: 10px; }
        .service-card p { font-size: 0.9rem; color: #555; line-height: 1.55; }
        .service-card .price { margin-top: 14px; font-size: 1.05rem; font-weight: 700; color: #e65100; }

        /* FOOTER */
        footer { background: #0d1333; color: #9fa8da; text-align: center; padding: 28px;
                 margin-top: 60px; font-size: 0.88rem; }

        /* CTA BUTTONS */
        .cta-group { display: flex; justify-content: center; gap: 16px; margin-top: 28px; }
        .btn-primary { background: #ff6f00; color: #fff; padding: 13px 32px; border-radius: 4px;
                       text-decoration: none; font-weight: 600; }
        .btn-secondary { background: transparent; color: #fff; padding: 13px 32px; border-radius: 4px;
                         text-decoration: none; font-weight: 600; border: 2px solid #c5cae9; }
        .btn-primary:hover { background: #e65100; }
        .btn-secondary:hover { background: rgba(255,255,255,.1); }

        table { width: 100%; border-collapse: collapse; background: #fff; border-radius: 8px;
                overflow: hidden; box-shadow: 0 2px 8px rgba(0,0,0,.08); }
        th { background: #1a237e; color: #fff; padding: 12px 16px; text-align: left; }
        td { padding: 11px 16px; border-bottom: 1px solid #e8eaf6; font-size: 0.9rem; }
        tr:last-child td { border-bottom: none; }
        tr:hover td { background: #f5f5ff; }
    </style>
</head>
<body>

<nav>
    <div class="brand">🔗 ServiceLink Pro</div>
    <div>
        <a href="index.php">Home</a>
        <a href="login.php">Login</a>
        <a href="register.php">Register</a>
    </div>
</nav>

<!-- HERO -->
<div class="hero">
    <h1>Professional IT & Business Services</h1>
    <p>Connecting organizations with trusted technology solutions since 2018.</p>

    <!-- !! VULNERABILITY: Reflected XSS — $search_term echoed directly, no htmlspecialchars() -->
    <form method="GET" action="index.php" class="search-bar">
        <input type="text" name="search" placeholder="Search services (e.g. network, cloud, security...)"
               value="<?php echo $search_term; ?>">
        <button type="submit">Search</button>
    </form>

    <div class="cta-group">
        <a href="register.php" class="btn-primary">Get Started</a>
        <a href="login.php" class="btn-secondary">Client Login</a>
    </div>
</div>

<!-- SEARCH RESULTS -->
<?php if ($search_term !== ''): ?>
<div class="results">
    <?php if ($search_error): ?>
        <!-- !! VULNERABILITY: Raw SQL error printed to page -->
        <div class="error-box">⚠️ <?php echo $search_error; ?></div>
    <?php elseif (count($search_results) === 0): ?>
        <!-- !! VULNERABILITY: XSS — search term reflected without encoding -->
        <p>No results found for: <strong><?php echo $search_term; ?></strong></p>
    <?php else: ?>
        <!-- !! VULNERABILITY: XSS — search term reflected in heading without encoding -->
        <h3>Search results for: "<?php echo $search_term; ?>"</h3>
        <table>
            <tr>
                <th>Service</th><th>Category</th><th>Description</th><th>Price (USD)</th>
            </tr>
            <?php foreach ($search_results as $svc): ?>
            <tr>
                <!-- !! VULNERABILITY: XSS — DB content reflected without encoding -->
                <td><?php echo $svc['name']; ?></td>
                <td><?php echo $svc['category']; ?></td>
                <td><?php echo $svc['description']; ?></td>
                <td>$<?php echo $svc['price']; ?></td>
            </tr>
            <?php endforeach; ?>
        </table>
    <?php endif; ?>
</div>
<?php endif; ?>

<!-- ALL SERVICES -->
<div class="section">
    <h2>Our Services</h2>
    <div class="services-grid">
        <?php foreach ($all_services as $svc): ?>
        <div class="service-card">
            <!-- !! VULNERABILITY: XSS — DB-stored content echoed without encoding -->
            <span class="cat"><?php echo $svc['category']; ?></span>
            <h4><?php echo $svc['name']; ?></h4>
            <p><?php echo $svc['description']; ?></p>
            <div class="price">$<?php echo number_format($svc['price'], 2); ?></div>
        </div>
        <?php endforeach; ?>
    </div>
</div>

<footer>
    &copy; 2024 ServiceLink Pro &mdash; IT & Business Solutions |
    <a href="login.php" style="color:#7986cb">Client Portal</a> |
    <a href="register.php" style="color:#7986cb">Register</a>
</footer>

</body>
</html>
