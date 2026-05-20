<?php
session_start();

if (isset($_GET['logout'])) {
    session_destroy();
    header("Location: homepage.php");
    exit();
}

$error_message = "";
$max_attempts = 5;

// If already logged in, redirect to report (or dashboard)
if (isset($_SESSION['admin_logged_in']) && $_SESSION['admin_logged_in'] === true) {
            header("Location: report.php");
    exit();
}

// Initialize session variables
if (!isset($_SESSION['login_attempts'])) {
    $_SESSION['login_attempts'] = 0;
}
if (!isset($_SESSION['last_attempt_time'])) {
    $_SESSION['last_attempt_time'] = time();
}

// Global cooldown: Reset attempts if inactive for more than 5 minutes
if (time() - $_SESSION['last_attempt_time'] > 300) {
    $_SESSION['login_attempts'] = 0;
    unset($_SESSION['locked_time']);
}

// Check lock duration
if (isset($_SESSION['locked_time'])) {
    $seconds_left = 300 - (time() - $_SESSION['locked_time']);
    if ($seconds_left > 0) {
        $minutes = ceil($seconds_left / 60);
        $error_message = "Account locked. Please try again in $minutes minute(s).";
    } else {
        // Reset after 5 minutes
        $_SESSION['login_attempts'] = 0;
        unset($_SESSION['locked_time']);
    }
}

if ($_SERVER["REQUEST_METHOD"] == "POST" && !isset($_SESSION['locked_time'])) {
    $_SESSION['last_attempt_time'] = time();
    $username = $_POST['username'] ?? '';
    $password = $_POST['password'] ?? '';

    // Expected credentials
    $expected_username = "admin_Izzat";
    // Derived hash from "Izzat@123"
    $expected_password_hash = '$2y$10$7GeeAHG2gQw3XTKEIW77PeMWxcRZfz3hC1fs2Urc5DH7hj1SHhpKi'; 

    // Validate password length 8-12 characters
    if (strlen($password) < 8 || strlen($password) > 12) {
        $_SESSION['login_attempts']++;
        $remaining = $max_attempts - $_SESSION['login_attempts'];
        $error_message = "Password must be between 8 and 12 characters. ($remaining attempts remaining)";
    } else {
        if ($username === $expected_username && password_verify($password, $expected_password_hash)) {
            // Login successful
            $_SESSION['admin_logged_in'] = true;
            $_SESSION['login_attempts'] = 0; // Reset attempts on success
                    header("Location: report.php");
            exit();
        } else {
            // Login failed
            $_SESSION['login_attempts']++;
            $remaining = $max_attempts - $_SESSION['login_attempts'];
            if ($remaining > 0) {
                $error_message = "Wrong Username Or Password! ($remaining attempts remaining)";
            } else {
                $error_message = "Wrong Username Or Password!";
            }
        }
    }

    if ($_SESSION['login_attempts'] >= $max_attempts && !isset($_SESSION['locked_time'])) {
        $_SESSION['locked_time'] = time();
        $error_message = "Account locked due to too many failed attempts. Try again later.";
    }
}
?>
<!DOCTYPE html>
<html lang="en">

<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Administrator Login - USB Malware Detection</title>
    <link rel="stylesheet" href="admin-style.css">
    <script src="https://unpkg.com/@phosphor-icons/web"></script>
</head>

<body class="admin-page">

    <div class="back-nav">
        <a href="homepage.php"><i class="ph ph-arrow-left"></i> Back to Scanner</a>
    </div>

    <div class="login-card">
        <div class="login-header">
            <div class="mascot-container">
                <img src="sentinel-mascot.png" alt="Sentinel">
            </div>
            <h2>Administrator Login</h2>
            <p>Access reports, analytics, and system settings</p>
        </div>

        <?php if (!empty($error_message)): ?>
            <div class="error-text">
                <i class="ph-fill ph-warning-circle"></i>
                <?php echo htmlspecialchars($error_message); ?>
            </div>
        <?php endif; ?>

        <form class="login-form" id="loginForm" method="POST" action="admin.php">
            <div class="input-group">
                <label for="username">Username</label>
                <div class="input-wrapper">
                    <i class="ph ph-user"></i>
                    <input type="text" id="username" name="username" placeholder="Username required" required>
                </div>
            </div>

            <div class="input-group">
                <label for="password">Password</label>
                <div class="input-wrapper">
                    <i class="ph ph-lock"></i>
                    <input type="password" id="password" name="password" placeholder="••••••••" required>
                </div>
            </div>

            <button type="submit" class="login-btn" <?php echo isset($_SESSION['locked_time']) ? 'disabled' : ''; ?>>
                <i class="ph ph-sign-in"></i> Login to Admin Portal
            </button>
        </form>
    </div>

</body>

</html>
