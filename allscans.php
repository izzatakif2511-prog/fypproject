<?php
require 'admin_auth_check.php';
require 'db.php';

// Fetch stats
$stats = [
    'total' => 0,
    'safe' => 0,
    'suspicious' => 0,
    'malicious' => 0,
    'total_threats' => 0
];

$res = $conn->query("SELECT status, COUNT(*) as count, SUM(threat_count) as total_threats FROM usb_scans GROUP BY status");
if ($res) {
    while ($row = $res->fetch_assoc()) {
        $stats['total'] += $row['count'];
        $st = strtoupper($row['status']);
        if ($st === 'SAFE' || $st === 'CLEAN') {
            $stats['safe'] += $row['count'];
        } else if ($st === 'SUSPICIOUS') {
            $stats['suspicious'] += $row['count'];
            $stats['total_threats'] += $row['total_threats'];
        } else {
            $stats['malicious'] += $row['count'];
            $stats['total_threats'] += $row['total_threats'];
        }
    }
}

// Fetch all scans
$scans = [];
$res = $conn->query("SELECT * FROM usb_scans ORDER BY scanned_at DESC");
if ($res) {
    while ($row = $res->fetch_assoc()) {
        $scans[] = $row;
    }
}
?>
<!DOCTYPE html>
<html lang="en">

<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>All Scans - Administrator Portal</title>
    <link rel="stylesheet" href="allscans.css">
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
            <div class="logo-box">
                <div class="logo-icon">
                    <i class="ph-fill ph-shield-check" style="color: white; font-size: 24px;"></i>
                </div>
                <div>
                    <div class="portal-title">Administrator Portal</div>
                    <div class="portal-sub">Scan Records & Digital Forensics</div>
                </div>
            </div>
        </div>

        <div class="top-right">
            <div class="admin-info">
                <div class="admin-name">Administrator Area</div>
                <div class="admin-role">System Monitoring</div>
            </div>
            <i class="ph ph-activity" style="font-size: 32px; color: #3b82f6;"></i>
        </div>
    </header>

    <!-- ===== NAVBAR ===== -->
    <nav class="menu-bar">
        <a class="menu-item" href="report.php">Report</a>
        <a class="menu-item active" href="allscans.php">All Scans</a>
        <a class="menu-item" href="sandbox.php">Sandbox</a>
        <a class="menu-item" href="threatAnalysis.php">Threat Analysis</a>
        <a class="menu-item" href="usermanagement.php">User Management</a>
        <a class="menu-item" href="setting.php">Settings</a>
    </nav>

    <!-- ===== STATS CARDS ===== -->
    <section class="cards">
        <div class="card blue">
            <h2><?= $stats['total'] ?></h2>
            <p>Total Scan Sessions</p>
        </div>

        <div class="card green">
            <h2><?= $stats['safe'] ?></h2>
            <p>Safe Devices</p>
        </div>

        <div class="card orange">
            <h2><?= $stats['suspicious'] ?></h2>
            <p>Suspicious Devices</p>
        </div>

        <div class="card red">
            <h2><?= $stats['malicious'] ?></h2>
            <p>Malicious Devices</p>
        </div>
    </section>

    <!-- ===== SEARCH & FILTER ===== -->
    <section class="search-section">
        <input type="text" id="scanSearch" placeholder="Search by user, device name or status..." onkeyup="filterBySearch()">

        <div style="display: flex; gap: 10px;">
            <button class="filter-btn active" onclick="filterByStatus('all', this)">All</button>
            <button class="filter-btn" onclick="filterByStatus('safe', this)">Safe</button>
            <button class="filter-btn" onclick="filterByStatus('suspicious', this)">Suspicious</button>
            <button class="filter-btn" onclick="filterByStatus('malicious', this)">Malicious</button>
        </div>
    </section>

    <!-- ===== TABLE ===== -->
    <section class="table-section">
        <div class="table-wrapper">
            <table>
                <thead>
                    <tr>
                        <th>User</th>
                        <th>Device Signature</th>
                        <th>Timestamp</th>
                        <th>Files</th>
                        <th>Threats</th>
                        <th>Analysis Time</th>
                        <th>Outcome</th>
                        <th style="text-align: center;">Actions</th>
                    </tr>
                </thead>

                <tbody id="scanTableBody">
                    <?php if (empty($scans)): ?>
                        <tr><td colspan="8" style="text-align: center; padding: 40px; color: #64748b;">No scan records found.</td></tr>
                    <?php else: ?>
                        <?php foreach ($scans as $row): ?>
                        <tr class="scan-row" data-status="<?= strtolower($row['status']) ?>">
                            <td style="font-weight: 700;"><?= htmlspecialchars($row['user_name']) ?></td>
                            <td>
                                <div style="display: flex; align-items: center; gap: 10px;">
                                    <i class="ph ph-usb" style="font-size: 18px; color: #3b82f6;"></i>
                                    <?= htmlspecialchars($row['device_name']) ?>
                                </div>
                            </td>
                            <td>
                                <?php $dt = strtotime($row['scanned_at']); ?>
                                <?= date('M d, Y', $dt) ?>
                                <span><?= date('h:i A', $dt) ?></span>
                            </td>
                            <td><span style="color: white; font-weight: 600;"><?= $row['file_count'] ?></span></td>
                            <td>
                                <?php 
                                    $stClass = strtolower($row['status']);
                                    if ($stClass === 'clean') $stClass = 'safe';
                                    if ($stClass === 'threat') $stClass = 'malicious';
                                    $tcClass = ($row['threat_count'] > 0) ? (($stClass==='suspicious') ? 'suspicious-text' : 'malicious-text') : 'safe-text';
                                ?>
                                <span class="<?= $tcClass ?>">
                                    <?= $row['threat_count'] ?> threats
                                </span>
                            </td>
                            <td style="color: #64748b;"><?= htmlspecialchars($row['duration'] ?: '0.5s') ?></td>
                            <td>
                                <span class="status <?= $stClass ?>">
                                    <?php 
                                        $icon = 'ph-check-circle';
                                        if ($stClass === 'suspicious') $icon = 'ph-warning';
                                        if ($stClass === 'malicious') $icon = 'ph-warning-circle';
                                    ?>
                                    <i class="ph <?= $icon ?>" style="margin-right: 6px;"></i>
                                    <?= $row['status'] ?>
                                </span>
                            </td>
                            <td>
                                <button class="delete-btn" onclick="deleteScan(<?= $row['id'] ?>)" title="Delete record">
                                    <i class="ph ph-trash"></i>
                                </button>
                            </td>
                        </tr>
                        <?php endforeach; ?>
                    <?php endif; ?>
                </tbody>
            </table>
        </div>
    </section>

    <script>
        let currentFilter = 'all';

        function filterByStatus(status, btn) {
            currentFilter = status;
            
            // Update buttons
            const buttons = document.querySelectorAll('.filter-btn');
            buttons.forEach(b => b.classList.remove('active'));
            btn.classList.add('active');

            applyFilters();
        }

        function filterBySearch() {
            applyFilters();
        }

        function applyFilters() {
            const searchValue = document.getElementById('scanSearch').value.toLowerCase();
            const rows = document.querySelectorAll('.scan-row');

            rows.forEach(row => {
                let rstat = row.dataset.status;
                if (rstat === 'clean') rstat = 'safe';
                if (rstat === 'threat') rstat = 'malicious';
                
                const statusMatch = (currentFilter === 'all' || rstat === currentFilter);
                const textMatch = row.innerText.toLowerCase().includes(searchValue);

                if (statusMatch && textMatch) {
                    row.style.display = '';
                } else {
                    row.style.display = 'none';
                }
            });
        }

        async function deleteScan(id) {
            if (!confirm('Are you sure you want to delete this scan record? This action cannot be undone.')) {
                return;
            }

            try {
                const resp = await fetch('delete_usb_scan.php', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ id: id })
                });
                
                const result = await resp.json();
                
                if (result.success) {
                    // Show success state then reload
                    const row = document.querySelector(`button[onclick="deleteScan(${id})"]`).closest('tr');
                    row.style.transition = 'all 0.5s ease';
                    row.style.opacity = '0';
                    row.style.transform = 'translateX(20px)';
                    
                    setTimeout(() => {
                        location.reload();
                    }, 500);
                } else {
                    alert('Error: ' + (result.error || 'Unknown error occurred'));
                }
            } catch (err) {
                console.error('Delete failed:', err);
                alert('Failed to connect to the server. Please try again.');
            }
        }
    </script>

</body>

</html>
