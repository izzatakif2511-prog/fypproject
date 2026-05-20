<?php
require 'admin_auth_check.php';
require 'db.php';

// ── Fetch threats from DB ──
$threats = [];
$result  = $conn->query("SELECT * FROM threats ORDER BY id ASC");
if ($result) {
    while ($row = $result->fetch_assoc()) {
        $threats[] = $row;
    }
}

// ── Aggregate stats from threats table ──
$total_malware    = 0;
$threat_signatures = count($threats);
$type_counts      = [];
$blocked_attacks  = 0;

foreach ($threats as $threat) {
    if (!isset($threat['detections']) || !isset($threat['type'])) continue;
    $detections = (int)$threat['detections'];
    $total_malware += $detections;
    $type = $threat['type'];
    if (!isset($type_counts[$type])) $type_counts[$type] = 0;
    $type_counts[$type] += $detections;
    if (isset($threat['severity']) && $threat['severity'] === 'High') $blocked_attacks += $detections;
}

// ── ADD DATA FROM SANDBOX SCANS TO TYPE COUNTS ──
$mitre_counts = [];
$sb_res = $conn->query("SELECT malware_types, mitre_ids FROM sandbox_scans WHERE (malware_types IS NOT NULL AND malware_types != '') OR (mitre_ids IS NOT NULL AND mitre_ids != '')");
if ($sb_res) {
    while ($row = $sb_res->fetch_assoc()) {
        // Count by Malware Types
        if (!empty($row['malware_types'])) {
            $types = explode(',', $row['malware_types']);
            foreach ($types as $t) {
                $t = trim($t);
                if (empty($t)) continue;
                $t = preg_replace('/[\x{1F600}-\x{1F64F}\x{1F300}-\x{1F5FF}\x{1F680}-\x{1F6FF}\x{1F700}-\x{1F77F}\x{1F780}-\x{1F7FF}\x{1F800}-\x{1F8FF}\x{1F900}-\x{1F9FF}\x{1FA00}-\x{1FA6F}\x{1FA70}-\x{1FAFF}\x{2600}-\x{26FF}\x{2700}-\x{27BF}]/u', '', $t);
                $t = trim($t);
                if (!isset($type_counts[$t])) $type_counts[$t] = 0;
                $type_counts[$t]++;
                $total_malware++;
            }
        }
        
        // Count by MITRE IDs for the intelligence table
        if (!empty($row['mitre_ids'])) {
            $ids = explode(',', $row['mitre_ids']);
            foreach ($ids as $id) {
                $id = trim($id);
                if (!empty($id)) {
                    if (!isset($mitre_counts[$id])) $mitre_counts[$id] = 0;
                    $mitre_counts[$id]++;
                }
            }
        }
    }
}
$threat_types = count($type_counts);

// ── Pie Chart ──
arsort($type_counts);
$colors        = ['#ef4444', '#f97316', '#eab308', '#a855f7', '#3b82f6', '#10b981', '#ec4899', '#06b6d4'];
$color_classes = ['red-text', 'orange-text', 'yellow-text', 'purple-text', 'blue-text', 'green-text', 'pink-text', 'cyan-text'];

$gradient_parts   = [];
$pie_labels_html  = "";
$current_pct      = 0;
$i                = 0;

if ($total_malware > 0) {
    foreach ($type_counts as $type => $count) {
        $pct  = round(($count / $total_malware) * 100);
        $next = $current_pct + $pct;
        $color  = $colors[$i % count($colors)];
        $class  = $color_classes[$i % count($color_classes)];
        $gradient_parts[] = "$color $current_pct% $next%";
        $pie_labels_html .= "<span class='$class'>" . htmlspecialchars($type) . " $pct%</span>\n        ";
        $current_pct = $next;
        $i++;
    }
} else {
    $gradient_parts[] = "#1f2a44 0% 100%";
    $pie_labels_html  = "<span style='color:#8b9bb4;'>No Threat Data Found</span>";
}
$pie_gradient = "conic-gradient(" . implode(", ", $gradient_parts) . ")";

// ── Dynamic bar chart: monthly sandbox scan detections ──
$months_labels  = ['Jan','Feb','Mar','Apr','May','Jun','Jul','Aug','Sep','Oct','Nov','Dec'];
$monthly_counts = array_fill(0, 12, 0);
$max_bar_px     = 160;

$month_res = $conn->query(
    "SELECT MONTH(scanned_at) AS m, COUNT(*) AS cnt
     FROM sandbox_scans
     WHERE YEAR(scanned_at) = YEAR(CURDATE())
     GROUP BY MONTH(scanned_at)"
);
if ($month_res) {
    while ($row = $month_res->fetch_assoc()) {
        $monthly_counts[(int)$row['m'] - 1] = (int)$row['cnt'];
    }
}

$max_count = max($monthly_counts) ?: 1;  // avoid div/0
$bar_html  = "";
$bar_colors = ['#ef4444','#f97316','#eab308','#22c55e','#3b82f6','#a855f7',
               '#ef4444','#f97316','#eab308','#22c55e','#3b82f6','#a855f7'];
foreach ($monthly_counts as $idx => $cnt) {
    $px    = (int)round(($cnt / $max_count) * $max_bar_px);
    $px    = max($px, 8);
    $color = $bar_colors[$idx];
    $label = $months_labels[$idx];
    $bar_html .= "<div class='bar' style='height:{$px}px; background:{$color};'><span>{$label}</span></div>\n        ";
}

// ── MITRE info helper ──
if (!function_exists('get_mitre_info')) {
    function get_mitre_info($mitre_id, $mitre_data) {
        return ['threat_name' => 'MITRE Info', 'description' => 'Detailed MITRE info for ' . $mitre_id];
    }
}
$mitre_data = [];

// ── Sandbox scan summary for cards ──
$sandbox_total    = 0;
$sandbox_malicious = 0;
$sb_res = $conn->query("SELECT verdict, COUNT(*) as c FROM sandbox_scans GROUP BY verdict");
if ($sb_res) {
    while ($row = $sb_res->fetch_assoc()) {
        $sandbox_total += $row['c'];
        if ($row['verdict'] === 'MALICIOUS') $sandbox_malicious = $row['c'];
    }
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Threat Analysis — Administrator Portal</title>
  <link rel="stylesheet" href="threat-analysis.css">
  <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap" rel="stylesheet">
  <style>
    /* Extra sandbox stats row */
    .sandbox-row {
      display: flex;
      gap: 16px;
      max-width: 1200px;
      margin: 0 auto 20px;
      padding: 0 20px;
    }
    .sb-card {
      flex: 1;
      background: rgba(11,23,54,.4);
      border: 1px solid rgba(37,99,235,.2);
      border-radius: 10px;
      padding: 14px 18px;
      display: flex;
      align-items: center;
      gap: 12px;
      backdrop-filter: blur(8px);
    }
    .sb-icon {
      width: 36px; height: 36px;
      border-radius: 10px;
      display: flex; align-items: center; justify-content: center;
      font-size: 17px;
    }
    .sb-icon.teal   { background: rgba(20,184,166,.15); }
    .sb-icon.indigo { background: rgba(99,102,241,.15); }
    .sb-num  { font-size: 20px; font-weight: 700; }
    .sb-lbl  { font-size: 11px; color: #64748b; }

    /* Modal Styles */
    .modal {
      display: none;
      position: fixed;
      z-index: 1000;
      left: 0; top: 0; width: 100%; height: 100%;
      background: rgba(2, 8, 23, 0.85);
      backdrop-filter: blur(5px);
      align-items: center;
      justify-content: center;
    }
    .modal-content {
      background: #0f172a;
      border: 1px solid #1e293b;
      border-radius: 12px;
      width: 500px;
      max-width: 90%;
      padding: 24px;
      box-shadow: 0 20px 25px -5px rgba(0, 0, 0, 0.5);
    }
    .modal-header {
      display: flex;
      justify-content: space-between;
      align-items: center;
      margin-bottom: 20px;
    }
    .modal-title { font-size: 18px; font-weight: 600; color: #f8fafc; }
    .close-modal { font-size: 24px; color: #94a3b8; cursor: pointer; }
    
    .form-group { margin-bottom: 16px; }
    .form-group label { display: block; font-size: 13px; color: #94a3b8; margin-bottom: 6px; }
    .form-group input, .form-group select, .form-group textarea {
      width: 100%;
      background: #020817;
      border: 1px solid #1e293b;
      color: #f1f5f9;
      padding: 8px 12px;
      border-radius: 6px;
      font-size: 14px;
    }
    .modal-footer {
      display: flex;
      justify-content: flex-end;
      gap: 12px;
      margin-top: 24px;
    }
    .btn-cancel { background: #334155; }
    .btn-save { background: #2563eb; }
    
    .action-btn {
      background: none;
      border: none;
      cursor: pointer;
      font-size: 14px;
      padding: 4px;
      border-radius: 4px;
      transition: all 0.2s;
    }
    .edit-btn { color: #3b82f6; }
    .edit-btn:hover { background: rgba(59, 130, 246, 0.1); }
    .del-btn { color: #ef4444; }
    .del-btn:hover { background: rgba(239, 68, 68, 0.1); }
    
    .mitre-link {
      color: #60a5fa;
      text-decoration: none;
      display: flex;
      align-items: center;
      gap: 4px;
    }
    .mitre-link:hover { text-decoration: underline; color: #93c5fd; }
  </style>
</head>
<body>

<!-- ===== TOP HEADER ===== -->
<header class="topbar">
  <div class="top-left">
    <button onclick="window.location.href='admin.php?logout=1'">Back</button>
    <div class="logo-box">
      <div class="logo-icon"></div>
      <div>
        <div class="portal-title">Administrator Portal</div>
        <div class="portal-sub">Reports, Analytics &amp; System Management</div>
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
  <a class="menu-item" href="report.php">Report</a>
  <a class="menu-item" href="allscans.php">All Scans</a>
  <a class="menu-item" href="sandbox.php">Sandbox</a>
  <a class="menu-item active" href="threatAnalysis.php">Threat Analysis</a>
  <a class="menu-item" href="usermanagement.php">User Management</a>
  <a class="menu-item" href="setting.php">Settings</a>
</nav>

<!-- ===== MAIN CONTENT ===== -->
<main class="container">

  <!-- ===== STAT CARDS ===== -->
  <section class="cards">
    <div class="card">
      <div class="icon red"></div>
      <h2><?= $total_malware ?></h2>
      <p>Total Threats (Malware)</p>
    </div>

    <div class="card">
      <div class="icon orange">!</div>
      <h2><?= $threat_types ?></h2>
      <p>Threat Types</p>
    </div>

    <div class="card">
      <div class="icon green"></div>
      <h2><?= $blocked_attacks ?></h2>
      <p>High-Severity Detections</p>
    </div>

    <div class="card">
      <div class="icon blue"></div>
      <h2><?= $threat_signatures ?></h2>
      <p>Threat Signatures</p>
    </div>
  </section>

  <!-- ===== SANDBOX SUMMARY ROW ===== -->
  <div class="sandbox-row">
    <div class="sb-card">
      <div class="sb-icon teal">🔬</div>
      <div>
        <div class="sb-num"><?= $sandbox_total ?></div>
        <div class="sb-lbl">Sandbox Scans (All Time)</div>
      </div>
    </div>
    <div class="sb-card">
      <div class="sb-icon indigo">☠️</div>
      <div>
        <div class="sb-num"><?= $sandbox_malicious ?></div>
        <div class="sb-lbl">Malicious Files Detected</div>
      </div>
    </div>
    <div class="sb-card">
      <div class="sb-icon" style="background:rgba(245,158,11,.15);">📅</div>
      <div>
        <div class="sb-num"><?= array_sum($monthly_counts) ?></div>
        <div class="sb-lbl">Scans This Year</div>
      </div>
    </div>
    <div class="sb-card">
      <div class="sb-icon" style="background:rgba(34,197,94,.15);">📊</div>
      <div>
        <div class="sb-num">
          <?= $sandbox_total > 0 ? round(($sandbox_malicious / $sandbox_total) * 100) : 0 ?>%
        </div>
        <div class="sb-lbl">Malicious Detection Rate</div>
      </div>
    </div>
  </div>

  <!-- ===== CHARTS ===== -->
  <section class="charts">

    <!-- Pie -->
    <div class="chart-box">
      <h3>Threat Distribution</h3>
      <div class="pie" style="background: <?= $pie_gradient ?>;"></div>
      <div class="pie-labels">
        <?= $pie_labels_html ?>
      </div>
    </div>

    <!-- Bar — now dynamic from sandbox_scans -->
    <div class="chart-box">
      <h3>Monthly Sandbox Scans (<?= date('Y') ?>)</h3>
      <div class="bars">
        <?= $bar_html ?>
      </div>
    </div>

  </section>

  <!-- ===== TABLE ===== -->
  <section class="table-box">
    <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 15px;">
      <h3 style="margin: 0;">Threat Intelligence Database</h3>
      <button onclick="openAddModal()" style="background: #1e293b; border: 1px solid #334155; display: flex; align-items: center; gap: 8px;">
        <span>➕</span> Add New Threat Signature
      </button>
    </div>

    <table>
      <tr>
        <th>ID</th>
        <th>Threat Name</th>
        <th>Type</th>
        <th>Severity</th>
        <th>Description</th>
        <th>Total Detections</th>
        <th>MITRE ATT&CK ID</th>
        <th>Actions</th>
      </tr>

      <?php if (empty($threats)): ?>
      <tr><td colspan="8" style="text-align:center; color:#64748b; padding:30px;">No threats in database yet.</td></tr>
      <?php else: ?>
      <?php foreach($threats as $threat):
        $mitre_info = get_mitre_info($threat['mitree_id'], $mitre_data);
        $sev_map = [
            'High'   => 'MALICIOUS',
            'Medium' => 'SUSPICIOUS',
            'Low'    => 'SAFE'
        ];
        $verdict = $sev_map[$threat['severity']] ?? 'UNKNOWN';

        $sev_colors = [
            'High'   => 'color:#ef4444;font-weight:700;',
            'Medium' => 'color:#f97316;font-weight:600;',
            'Low'    => 'color:#22c55e;',
        ];
        $sev_style = $sev_colors[$threat['severity']] ?? '';
        $mitre_id = trim($threat['mitree_id']);
        $mitre_url = "https://attack.mitre.org/techniques/" . str_replace('.', '/', $mitre_id);
        
        $sb_detections = $mitre_counts[$mitre_id] ?? 0;
        $total_dets    = (int)$threat['detections'] + $sb_detections;
      ?>
      <tr id="<?= htmlspecialchars($mitre_id) ?>">
        <td><?= $threat['id'] ?></td>
        <td><?= htmlspecialchars($threat['threat_name']) ?></td>
        <td><?= htmlspecialchars($threat['type']) ?></td>
        <td style="<?= $sev_style ?>">
          <div style="font-size: 13px; font-weight: 800;"><?= $verdict ?></div>
          <div style="font-size: 10px; opacity: 0.7;"><?= htmlspecialchars($threat['severity']) ?> Severity</div>
        </td>
        <td><?= htmlspecialchars($threat['description']) ?></td>
        <td>
          <span title="Initial DB: <?= $threat['detections'] ?> | Sandbox: <?= $sb_detections ?>">
            <?= $total_dets ?>
            <?php if ($sb_detections > 0): ?>
              <small style="color: #60a5fa; margin-left: 4px;">(+<?= $sb_detections ?> live)</small>
            <?php endif; ?>
          </span>
        </td>
        <td>
          <?php if (!empty($mitre_id)): ?>
          <a href="<?= $mitre_url ?>" target="_blank" class="mitre-link">
            <?= htmlspecialchars($mitre_id) ?> <span>🔗</span>
          </a>
          <?php else: ?>
          —
          <?php endif; ?>
        </td>
        <td>
          <button class="action-btn edit-btn" onclick='openEditModal(<?= json_encode($threat) ?>)' title="Edit">✏️</button>
          <button class="action-btn del-btn" onclick="deleteThreat(<?= $threat['id'] ?>)" title="Delete">🗑️</button>
        </td>
      </tr>
      <?php endforeach; ?>
      <?php endif; ?>
    </table>
  </section>

</main>

<!-- ===== MODAL ===== -->
<div id="threatModal" class="modal">
  <div class="modal-content">
    <div class="modal-header">
      <h4 class="modal-title" id="modalTitle">Add New Threat</h4>
      <span class="close-modal" onclick="closeModal()">&times;</span>
    </div>
    <form id="threatForm">
      <input type="hidden" id="threatId" name="id">
      <input type="hidden" id="formAction" name="action" value="add">
      
      <div class="form-group">
        <label>Threat Name</label>
        <input type="text" id="threatName" name="threat_name" required placeholder="e.g. Process Injection">
      </div>
      
      <div class="form-group">
        <label>Malware Type</label>
        <select id="threatType" name="type" required>
          <option value="Trojan">Trojan</option>
          <option value="Ransomware">Ransomware</option>
          <option value="Backdoor">Backdoor</option>
          <option value="Rootkit">Rootkit</option>
          <option value="Spyware">Spyware</option>
          <option value="Dropper">Dropper</option>
          <option value="Potentially Unwanted">Potentially Unwanted</option>
        </select>
      </div>
      
      <div class="form-group">
        <label>Severity</label>
        <select id="threatSev" name="severity" required>
          <option value="High">High</option>
          <option value="Medium">Medium</option>
          <option value="Low">Low</option>
        </select>
      </div>
      
      <div class="form-group">
        <label>MITRE ATT&CK ID</label>
        <input type="text" id="threatMitre" name="mitre_id" placeholder="e.g. T1055">
      </div>
      
      <div class="form-group">
        <label>Description</label>
        <textarea id="threatDesc" name="description" rows="3"></textarea>
      </div>
      
      <div class="form-group">
        <label>Initial Detections</label>
        <input type="number" id="threatDet" name="detections" value="0">
      </div>
      
      <div class="modal-footer">
        <button type="button" class="btn-cancel" onclick="closeModal()">Cancel</button>
        <button type="submit" class="btn-save">Save Signature</button>
      </div>
    </form>
  </div>
</div>

<script>
  const modal = document.getElementById('threatModal');
  const form  = document.getElementById('threatForm');

  function openAddModal() {
    document.getElementById('modalTitle').textContent = 'Add New Threat Signature';
    document.getElementById('formAction').value = 'add';
    document.getElementById('threatId').value = '';
    form.reset();
    modal.style.display = 'flex';
  }

  function openEditModal(threat) {
    document.getElementById('modalTitle').textContent = 'Edit Threat Signature';
    document.getElementById('formAction').value = 'edit';
    document.getElementById('threatId').value = threat.id;
    
    document.getElementById('threatName').value = threat.threat_name;
    document.getElementById('threatType').value = threat.type;
    document.getElementById('threatSev').value = threat.severity;
    document.getElementById('threatMitre').value = threat.mitree_id;
    document.getElementById('threatDesc').value = threat.description;
    document.getElementById('threatDet').value = threat.detections;
    
    modal.style.display = 'flex';
  }

  function closeModal() {
    modal.style.display = 'none';
  }

  form.onsubmit = async (e) => {
    e.preventDefault();
    const formData = new FormData(form);
    
    try {
      const resp = await fetch('manage_threats.php', {
        method: 'POST',
        body: formData
      });
      const res = await resp.json();
      if (res.success) {
        location.reload();
      } else {
        alert('Error saving threat: ' + res.error);
      }
    } catch (err) {
      alert('Failed to connect to server.');
    }
  };

  async function deleteThreat(id) {
    if (!confirm('Are you sure you want to delete this threat signature?')) return;
    
    const formData = new FormData();
    formData.append('action', 'delete');
    formData.append('id', id);
    
    try {
      const resp = await fetch('manage_threats.php', {
        method: 'POST',
        body: formData
      });
      const res = await resp.json();
      if (res.success) {
        location.reload();
      } else {
        alert('Error deleting: ' + res.error);
      }
    } catch (err) {
      alert('Failed to connect to server.');
    }
  }

  // Close modal when clicking outside
  window.onclick = function(event) {
    if (event.target == modal) closeModal();
  }
</script>

</body>
</html>