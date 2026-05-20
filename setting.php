<?php
require 'admin_auth_check.php';
require 'db.php';

$saved = false;

// Save Settings logic
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if (isset($_POST['update_settings'])) {
        $auto_scan = isset($_POST['auto_scan']) ? '1' : '0';
        $real_time = isset($_POST['real_time']) ? '1' : '0';
        $auto_quarantine = isset($_POST['auto_quarantine']) ? '1' : '0';
        $scan_depth = $conn->real_escape_string($_POST['scan_depth']);
        $max_file_size = (int)$_POST['max_file_size'];

        $conn->query("UPDATE settings SET setting_value='$auto_scan' WHERE setting_key='auto_scan'");
        $conn->query("UPDATE settings SET setting_value='$real_time' WHERE setting_key='real_time'");
        $conn->query("UPDATE settings SET setting_value='$auto_quarantine' WHERE setting_key='auto_quarantine'");
        $conn->query("UPDATE settings SET setting_value='$scan_depth' WHERE setting_key='scan_depth'");
        $conn->query("UPDATE settings SET setting_value='$max_file_size' WHERE setting_key='max_file_size'");
        
        $saved = true;
    }
}

// Fetch Settings
$settings = [];
$res = $conn->query("SELECT * FROM settings");
if ($res) {
    while ($row = $res->fetch_assoc()) {
        $settings[$row['setting_key']] = $row['setting_value'];
    }
}

function checkBool($val) {
    return ($val === '1' || $val === 1) ? 'checked' : '';
}
function checkSel($val, $target) {
    return ($val === $target) ? 'selected' : '';
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1.0" />
    <title>Settings - Administrator Portal</title>
    <link rel="stylesheet" href="setting.css">
    <script src="https://unpkg.com/@phosphor-icons/web"></script>
</head>
<body>

    <!-- ===== TOP HEADER ===== -->
    <header class="topbar">
        <div class="top-left">
            <button class="back-btn" onclick="window.location.href='admin.php?logout=1'">
                <i class="ph ph-arrow-left"></i> Back
            </button>

            <!-- LOGO -->
            <div class="logo-box" style="display: flex; align-items: center; gap: 15px;">
                <div class="logo-icon">
                    <i class="ph-fill ph-shield-check" style="color: white; font-size: 24px;"></i>
                </div>
                <div>
                    <div class="portal-title">Administrator Portal</div>
                    <div class="portal-sub">System Configuration & Policy Enforcement</div>
                </div>
            </div>
        </div>

        <div class="top-right">
            <div class="admin-info">
                <div class="admin-name">Administrator Area</div>
                <div class="admin-role">System Settings</div>
            </div>
            <i class="ph ph-gear-six" style="font-size: 32px; color: #3b82f6;"></i>
        </div>
    </header>

    <!-- ===== NAVBAR ===== -->
    <nav class="menu-bar">
        <a class="menu-item" href="report.php">Report</a>
        <a class="menu-item" href="allscans.php">All Scans</a>
        <a class="menu-item" href="sandbox.php">Sandbox</a>
        <a class="menu-item" href="threatAnalysis.php">Threat Analysis</a>
        <a class="menu-item" href="usermanagement.php">User Management</a>
        <a class="menu-item active" href="setting.php">Settings</a>
    </nav>

    <main class="container">
        <form method="POST" action="setting.php">
            <input type="hidden" name="update_settings" value="1">
            
            <?php if ($saved): ?>
                <div class="alert-success">
                    <i class="ph-fill ph-check-circle"></i>
                    Settings updated successfully! Changes are applied immediately.
                </div>
            <?php endif; ?>

            <section class="settings-section">
                <h2><i class="ph ph-scan"></i> Scan Configuration</h2>
                
                <div class="setting-item">
                    <span><i class="ph ph-usb" style="margin-right: 8px;"></i> Automatic USB Scanning</span>
                    <label class="switch">
                        <input type="checkbox" name="auto_scan" <?= checkBool($settings['auto_scan'] ?? '1') ?>>
                        <span class="slider"></span>
                    </label>
                </div>

                <div class="setting-item">
                    <span><i class="ph ph-shield-check" style="margin-right: 8px;"></i> Real-time Protection</span>
                    <label class="switch">
                        <input type="checkbox" name="real_time" <?= checkBool($settings['real_time'] ?? '1') ?>>
                        <span class="slider"></span>
                    </label>
                </div>

                <div class="setting-item">
                    <span><i class="ph ph-magnifying-glass-plus" style="margin-right: 8px;"></i> Deep Scan Depth</span>
                    <select name="scan_depth">
                        <option value="Quick Scan" <?= checkSel($settings['scan_depth'] ?? '', 'Quick Scan') ?>>Quick Mode (File Header Only)</option>
                        <option value="Full Scan" <?= checkSel($settings['scan_depth'] ?? '', 'Full Scan') ?>>Enhanced Mode (Full Signature Scan)</option>
                        <option value="Heuristic" <?= checkSel($settings['scan_depth'] ?? '', 'Heuristic') ?>>Heuristic (Behavioral Analysis)</option>
                    </select>
                </div>

                <div class="setting-item">
                    <span><i class="ph ph-file-zip" style="margin-right: 8px;"></i> Maximum File Size Analysis</span>
                    <div style="display: flex; align-items: center; gap: 10px;">
                        <input type="number" name="max_file_size" value="<?= htmlspecialchars($settings['max_file_size'] ?? '100') ?>" style="width: 100px;">
                        <span style="font-size: 0.8rem; color: #64748b;">MB</span>
                    </div>
                </div>
            </section>

            <section class="settings-section">
                <h2><i class="ph ph-warning-octagon"></i> Automated Threat Response</h2>
                <div class="setting-item">
                    <div>
                        <span style="display: block;">Auto-Quarantine Threats</span>
                        <small style="color: #64748b; font-size: 0.75rem;">Automatically isolate suspicious files in the sandbox</small>
                    </div>
                    <label class="switch">
                        <input type="checkbox" name="auto_quarantine" <?= checkBool($settings['auto_quarantine'] ?? '1') ?>>
                        <span class="slider"></span>
                    </label>
                </div>
                
                <div class="setting-item">
                    <div>
                        <span style="display: block;">Admin Email Alerts</span>
                        <small style="color: #64748b; font-size: 0.75rem;">Notify administrator when high-risk malware is detected</small>
                    </div>
                    <label class="switch">
                        <input type="checkbox" checked disabled>
                        <span class="slider"></span>
                    </label>
                </div>
            </section>
            
            <div style="display: flex; justify-content: flex-end; margin-top: 30px;">
                <button type="submit" class="save-btn">
                    <i class="ph ph-floppy-disk"></i> Save Global Settings
                </button>
            </div>

        </form>
    </main>
    
</body>
</html>
