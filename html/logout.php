<?php
// logout.php — destroys session and redirects
session_start();
session_destroy();
// !! No session cookie invalidation — old cookie may still be usable briefly
header("Location: login.php");
exit;
