<?php
require 'admin_auth_check.php';
require 'db.php';

// Fetch summary stats from usb_scans
$stats = [
    'total_scans' => 0,
    'threats_detected' => 0,
    'clean_devices' => 0,
    'active_usb' => 0 // Mocked for now, or could count scans in last 1 hour
];

$res = $conn->query("SELECT status, COUNT(*) as count, SUM(threat_count) as total_threats FROM usb_scans GROUP BY status");
if ($res) {
    while ($row = $res->fetch_assoc()) {
        $stats['total_scans'] += $row['count'];
        if ($row['status'] === 'Clean') {
            $stats['clean_devices'] = $row['count'];
        }
        $stats['threats_detected'] += $row['total_threats'];
    }
}

// Active USB devices - count scans in the last 24 hours as a proxy if no real-time telemetry
$res = $conn->query("SELECT COUNT(*) as count FROM usb_scans WHERE scanned_at >= NOW() - INTERVAL 1 DAY");
if ($res) {
    $row = $res->fetch_assoc();
    $stats['active_usb'] = $row['count'];
}

// Fetch threat timeline (last 7 days)
$timeline = [];
for($i=6; $i>=0; $i--) {
    $date = date('Y-m-d', strtotime("-$i days"));
    $timeline[$date] = 0;
}

$res = $conn->query("SELECT DATE(scanned_at) as date, SUM(threat_count) as count FROM usb_scans WHERE scanned_at >= NOW() - INTERVAL 7 DAY GROUP BY DATE(scanned_at)");
if ($res) {
    while ($row = $res->fetch_assoc()) {
        $timeline[$row['date']] = (int)$row['count'];
    }
}

$timeline_json = json_encode(array_values($timeline));
$labels_json = json_encode(array_map(function($d) { return date('M d', strtotime($d)); }, array_keys($timeline)));

?>
<!DOCTYPE html>
<html lang="en">

<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>Administrator Dashboard - Administrator Portal</title>
  <link rel="stylesheet" href="report.css">

  <!-- Google Font -->
  <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap" rel="stylesheet">
  <script src="https://unpkg.com/@phosphor-icons/web"></script>
  <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
</head>

<body>

  <!-- ===== TOP HEADER ===== -->
  <header class="topbar">

    <div class="top-left">
      <button onclick="window.location.href='admin.php?logout=1'">
        Back
      </button>

      <!-- LOGO -->
      <div class="logo-box">
        <div class="logo-icon">🛡️</div>
        <div>
          <div class="portal-title">Administrator Portal</div>
          <div class="portal-sub">
            Reports, Analytics & System Management
          </div>
        </div>
      </div>
    </div>

    <div class="top-right">
      <div class="admin-info">
        <div class="admin-name">admin</div>
        <div class="admin-role">Administrator</div>
      </div>
      <button class="admin-btn">Admin Access</button>
    </div>

  </header>

  <!-- ===== NAVBAR ===== -->
  <nav class="menu-bar">
    <a class="menu-item active" href="report.php">Report</a>
    <a class="menu-item" href="allscans.php">All Scans</a>
    <a class="menu-item" href="sandbox.php">Sandbox</a>
    <a class="menu-item" href="threatAnalysis.php">Threat Analysis</a>
    <a class="menu-item" href="usermanagement.php">User Management</a>
    <a class="menu-item" href="setting.php">Settings</a>
  </nav>

  <main class="dashboard-container">

    <div class="stats-grid">
      <div class="stat-card">
        <div class="card-header">
          <div class="icon-box blue"><i class="ph ph-file-text"></i></div>
          <span class="trend neutral">0%</span>
        </div>
        <div class="card-body">
          <h2 class="stat-number"><?= $stats['total_scans'] ?></h2>
          <p class="stat-label">Total Scans</p>
        </div>
      </div>

      <div class="stat-card">
        <div class="card-header">
          <div class="icon-box red"><i class="ph ph-warning"></i></div>
          <span class="trend neutral">0%</span>
        </div>
        <div class="card-body">
          <h2 class="stat-number"><?= $stats['threats_detected'] ?></h2>
          <p class="stat-label">Threats Detected</p>
        </div>
      </div>

      <div class="stat-card">
        <div class="card-header">
          <div class="icon-box green"><i class="ph ph-check-circle"></i></div>
          <span class="trend neutral">0%</span>
        </div>
        <div class="card-body">
          <h2 class="stat-number"><?= $stats['clean_devices'] ?></h2>
          <p class="stat-label">Clean Devices</p>
        </div>
      </div>

      <div class="stat-card">
        <div class="card-header">
          <div class="icon-box purple"><i class="ph ph-usb"></i></div>
          <span class="trend neutral">0%</span>
        </div>
        <div class="card-body">
          <h2 class="stat-number"><?= $stats['active_usb'] ?></h2>
          <p class="stat-label">Scans (Last 24h)</p>
        </div>
      </div>
    </div>

    <div class="chart-section">
      <div class="chart-header">
        <h3>Threat Detection Activity (Last 7 Days)</h3>
      </div>
      <div class="chart-container" style="position: relative; height:300px; width:100%">
        <canvas id="threatChart"></canvas>
      </div>
    </div>

  </main>

  <script>
    const ctx = document.getElementById('threatChart').getContext('2d');
    new Chart(ctx, {
      type: 'line',
      data: {
        labels: <?= $labels_json ?>,
        datasets: [{
          label: 'Threats Detected',
          data: <?= $timeline_json ?>,
          borderColor: '#ef4444',
          backgroundColor: 'rgba(239, 68, 68, 0.1)',
          fill: true,
          tension: 0.4,
          pointBackgroundColor: '#ef4444',
          pointBorderColor: '#fff',
          pointBorderWidth: 2,
          pointRadius: 5
        }]
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        plugins: {
          legend: {
            display: false
          }
        },
        scales: {
          y: {
            beginAtZero: true,
            grid: {
              color: 'rgba(255, 255, 255, 0.05)'
            },
            ticks: {
              color: '#94a3b8',
              stepSize: 1
            }
          },
          x: {
            grid: {
              display: false
            },
            ticks: {
              color: '#94a3b8'
            }
          }
        }
      }
    });
  </script>

</body>

</html>
