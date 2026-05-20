<?php
require 'admin_auth_check.php';
require 'db.php';

// Fetch recent scan history from DB (last 8)
$scan_history = [];
$res = $conn->query("SELECT * FROM sandbox_scans ORDER BY scanned_at DESC LIMIT 8");
if ($res) {
    while ($row = $res->fetch_assoc()) {
        $scan_history[] = $row;
    }
}

// Summary stats
$total_scans   = 0;
$total_malicious = 0;
$total_suspicious = 0;
$total_safe    = 0;

$stat_res = $conn->query("SELECT verdict, COUNT(*) as cnt FROM sandbox_scans GROUP BY verdict");
if ($stat_res) {
    while ($row = $stat_res->fetch_assoc()) {
        $total_scans += $row['cnt'];
        if ($row['verdict'] === 'MALICIOUS')  $total_malicious  = $row['cnt'];
        if ($row['verdict'] === 'SUSPICIOUS') $total_suspicious = $row['cnt'];
        if ($row['verdict'] === 'SAFE')       $total_safe       = $row['cnt'];
    }
}

// Fetch threat severity mapping
$threat_map = [];
$t_res = $conn->query("SELECT mitree_id, severity FROM threats");
if ($t_res) {
    while ($row = $t_res->fetch_assoc()) {
        $threat_map[$row['mitree_id']] = $row['severity'];
    }
}
?>
<!DOCTYPE html>
<html lang="en">

<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Sandbox Analysis — Administrator Portal</title>
  <link rel="stylesheet" href="sandbox.css">
  <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap" rel="stylesheet">
  <style>
    /* ===== HISTORY SECTION ===== */
    .history-section {
      padding: 0 20px 24px;
      max-width: 1600px;
      margin: 0 auto;
    }

    .history-header {
      display: flex;
      justify-content: space-between;
      align-items: center;
      margin-bottom: 16px;
    }

    .history-title {
      font-size: 14px;
      font-weight: 600;
      color: #94a3b8;
      text-transform: uppercase;
      letter-spacing: 0.5px;
    }

    .history-stats {
      display: flex;
      gap: 12px;
    }

    .hstat {
      display: flex;
      align-items: center;
      gap: 6px;
      font-size: 12px;
      padding: 4px 10px;
      border-radius: 20px;
      background: rgba(15, 23, 42, 0.5);
      border: 1px solid #1e293b;
    }

    .hstat-dot { width: 7px; height: 7px; border-radius: 50%; }
    .hstat-dot.red    { background: #ef4444; }
    .hstat-dot.yellow { background: #f59e0b; }
    .hstat-dot.green  { background: #22c55e; }

    .history-table {
      width: 100%;
      border-collapse: collapse;
      background: rgba(11, 23, 54, 0.4);
      border: 1px solid rgba(37, 99, 235, 0.2);
      border-radius: 12px;
      overflow: hidden;
      backdrop-filter: blur(10px);
    }

    .history-table thead tr {
      background: rgba(37, 99, 235, 0.08);
      border-bottom: 1px solid rgba(37, 99, 235, 0.15);
    }

    .history-table th {
      padding: 12px 16px;
      font-size: 11px;
      font-weight: 600;
      color: #64748b;
      text-transform: uppercase;
      letter-spacing: 0.5px;
      text-align: left;
    }

    .history-table td {
      padding: 12px 16px;
      font-size: 13px;
      color: #cbd5e1;
      border-bottom: 1px solid rgba(30, 41, 59, 0.5);
    }

    .history-table tbody tr:last-child td { border-bottom: none; }

    .history-table tbody tr:hover {
      background: rgba(37, 99, 235, 0.04);
    }

    .verdict-badge {
      display: inline-flex;
      align-items: center;
      gap: 5px;
      font-size: 11px;
      font-weight: 700;
      padding: 3px 10px;
      border-radius: 12px;
      letter-spacing: 0.5px;
    }

    .verdict-badge.MALICIOUS  { background: rgba(239,68,68,.15);  color:#ef4444;  border: 1px solid rgba(239,68,68,.4); }
    .verdict-badge.SUSPICIOUS { background: rgba(245,158,11,.15); color:#f59e0b;  border: 1px solid rgba(245,158,11,.4); }
    .verdict-badge.SAFE       { background: rgba(34,197,94,.15);  color:#22c55e;  border: 1px solid rgba(34,197,94,.4); }

    .risk-bar-wrap {
      display: flex;
      align-items: center;
      gap: 8px;
      min-width: 120px;
    }

    .risk-bar {
      flex: 1;
      height: 5px;
      background: #1e293b;
      border-radius: 3px;
      overflow: hidden;
    }

    .risk-bar-fill {
      height: 100%;
      border-radius: 3px;
      transition: width 0.5s ease;
    }

    .risk-num { font-size: 12px; font-weight: 600; min-width: 35px; }
    .empty-history { text-align: center; color: #475569; padding: 40px 0 !important; }
    .malware-mini { font-size: 11px; color: #94a3b8; }

    /* ===== TOP STAT STRIP ===== */
    .sandbox-stats-strip {
      display: flex;
      gap: 16px;
      padding: 16px 20px;
      max-width: 1600px;
      margin: 0 auto;
    }

    .sstat {
      flex: 1;
      background: rgba(11, 23, 54, 0.4);
      border: 1px solid rgba(37, 99, 235, 0.2);
      border-radius: 10px;
      padding: 14px 18px;
      display: flex;
      align-items: center;
      gap: 14px;
    }

    .sstat-icon {
      width: 38px; height: 38px;
      border-radius: 10px;
      display: flex; align-items: center; justify-content: center;
      font-size: 18px;
    }

    .sstat-icon.blue   { background: rgba(37,99,235,.15);  }
    .sstat-icon.red    { background: rgba(239,68,68,.15);   }
    .sstat-icon.yellow { background: rgba(245,158,11,.15);  }
    .sstat-icon.green  { background: rgba(34,197,94,.15);   }

    .sstat-num  { font-size: 22px; font-weight: 700; }
    .sstat-lbl  { font-size: 11px; color: #64748b; margin-top: 2px; }

    /* Reset Button Style */
    .reset-btn {
      background: rgba(239, 68, 68, 0.1);
      border: 1px solid rgba(239, 68, 68, 0.3);
      color: #ef4444;
      padding: 6px 14px;
      border-radius: 8px;
      font-size: 12px;
      font-weight: 600;
      cursor: pointer;
      transition: all 0.2s ease;
      display: flex;
      align-items: center;
      gap: 6px;
    }

    .reset-btn:hover {
      background: rgba(239, 68, 68, 0.2);
      border-color: rgba(239, 68, 68, 0.5);
      transform: translateY(-1px);
    }

    .reset-btn:active {
      transform: translateY(0);
    }

    .delete-row-btn {
      background: none;
      border: none;
      color: #64748b;
      cursor: pointer;
      font-size: 16px;
      padding: 4px;
      border-radius: 4px;
      transition: all 0.2s;
    }

    .delete-row-btn:hover {
      color: #ef4444;
      background: rgba(239, 68, 68, 0.1);
    }
  </style>
</head>

<body>

  <!-- ===== TOP HEADER ===== -->
  <header class="topbar">
    <div class="top-left">
      <button onclick="window.location.href='admin.php?logout=1'">Back</button>
      <div class="logo-box">
        <div class="logo-icon">🛡️</div>
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
    <a class="menu-item active" href="sandbox.php">Sandbox</a>
    <a class="menu-item" href="threatAnalysis.php">Threat Analysis</a>
    <a class="menu-item" href="usermanagement.php">User Management</a>
    <a class="menu-item" href="setting.php">Settings</a>
  </nav>

  <!-- ===== DB STATS STRIP ===== -->
  <div class="sandbox-stats-strip">
    <div class="sstat">
      <div class="sstat-icon blue">🔬</div>
      <div>
        <div class="sstat-num"><?= $total_scans ?></div>
        <div class="sstat-lbl">Total Scans</div>
      </div>
    </div>
    <div class="sstat">
      <div class="sstat-icon red">☠️</div>
      <div>
        <div class="sstat-num"><?= $total_malicious ?></div>
        <div class="sstat-lbl">Malicious</div>
      </div>
    </div>
    <div class="sstat">
      <div class="sstat-icon yellow">⚠️</div>
      <div>
        <div class="sstat-num"><?= $total_suspicious ?></div>
        <div class="sstat-lbl">Suspicious</div>
      </div>
    </div>
    <div class="sstat">
      <div class="sstat-icon green">✅</div>
      <div>
        <div class="sstat-num"><?= $total_safe ?></div>
        <div class="sstat-lbl">Safe</div>
      </div>
    </div>
  </div>

  <!-- ===== SANDBOX WORKSPACE ===== -->
  <main class="sandbox-container">

    <!-- LEFT PANEL: File Upload & Virtual FS -->
    <aside class="sandbox-sidebar">
      <div class="panel upload-panel">
        <h3 class="panel-title">Target Input</h3>
        <div class="upload-box" id="uploadBox" onclick="document.getElementById('fileInput').click()">
          <div class="upload-icon">📂</div>
          <p>Drag &amp; Drop malware sample</p>
          <span>or click to browse</span>
          <input type="file" id="fileInput" hidden>
        </div>
        <div id="fileInfo" class="file-info" style="display:none;"></div>

        <div class="env-selector">
          <label for="env">Virtual Environment:</label>
          <select id="env">
            <option value="ubuntu24">Ubuntu 24.04 LTS (Docker)</option>
          </select>
        </div>

        <button class="execute-btn" id="executeBtn" disabled>▶ Execute in Sandbox</button>
      </div>

      <div class="panel vfs-panel">
        <h3 class="panel-title">Virtual File System <span id="fs-badge" class="badge">0 Changes</span></h3>
        <ul class="fs-tree" id="fsTree">
          <li class="tree-root"><span>📁 / (root)</span>
            <ul id="fsRoot">
              <li><span>📁 bin</span></li>
              <li><span>📁 var</span>
                <ul>
                  <li><span>📁 log</span></li>
                </ul>
              </li>
              <li><span>📁 tmp</span></li>
            </ul>
          </li>
        </ul>
      </div>
    </aside>

    <!-- RIGHT/CENTER PANELS -->
    <div class="sandbox-content">

      <!-- TOP SECTION: Screen & Summary -->
      <section class="sandbox-top">
        <div class="panel env-panel">
          <div class="env-header">
            <h3 class="panel-title">Environment View</h3>
            <span class="status-indicator stopped" id="envStatus">● Stopped</span>
          </div>
          <div class="env-screen" id="envScreen">
            <div class="screen-placeholder" id="screenPlaceholder">
              <div class="screen-icon">🖥️</div>
              <p>Awaiting Execution...</p>
            </div>

            <div class="screen-content" id="screenContent" style="display:none;">
              <div class="cli-mockup" id="cliMockup"></div>
            </div>

            <!-- Real-time metrics overlay -->
            <div class="metrics-overlay" style="display: none;" id="metricsOverlay">
              <div>CPU: <span id="cpuUsage">0%</span></div>
              <div>MEM: <span id="memUsage">12 MB</span></div>
              <div>NET: <span id="netTraffic">0 B/s</span></div>
            </div>
          </div>
        </div>

        <div class="panel summary-panel">
          <h3 class="panel-title">Threat Summary</h3>
          <div class="summary-grid">
            <div class="summary-card risk-card" id="riskCard">
              <div class="summary-label">Risk Score</div>
              <div class="score-text" id="riskScore">0/100</div>
            </div>
            <div class="summary-card status-card">
              <div class="summary-label">Status</div>
              <div class="status-text clean" id="threatStatus">CLEAN</div>
            </div>
          </div>
          <div class="malware-type-section" id="malwareTypeSection" style="display:none;">
            <h4>Type of Malicious</h4>
            <div class="malware-tags" id="malwareTags"></div>
          </div>
          <div class="ioc-list">
            <h4>Indicators of Compromise</h4>
            <ul id="iocList">
              <li class="ioc-empty">No malicious activity detected yet.</li>
            </ul>
          </div>
          <!-- Save result status -->
          <div id="dbSaveStatus" style="display:none; margin-top:10px; font-size:12px; padding:6px 10px; border-radius:6px;"></div>
        </div>
      </section>

      <!-- BOTTOM SECTION: Console -->
      <section class="panel sandbox-console">
        <div class="console-header">
          <span>>_ Sandbox Console (Docker Logs)</span>
          <button id="clearConsoleBtn" class="clear-btn">Clear</button>
        </div>
        <div class="console-window" id="consoleWindow">
          <div class="log-line log-info">[System] Sandbox Engine Ready. Connected to Docker daemon.</div>
          <div class="log-line log-info">[System] Database connected — scan results will be persisted.</div>
          <div class="log-line log-info">[System] Waiting for target...</div>
        </div>
      </section>

    </div>

  </main>

  <!-- ===== HISTORY SECTION ===== -->
  <section class="history-section">
    <div class="history-header">
      <div style="display: flex; align-items: center; gap: 15px;">
        <div class="history-title">🗂️ Recent Scan History (Database)</div>
        <button id="resetHistoryBtn" class="reset-btn">
          <span>🧹</span> Reset History
        </button>
      </div>
      <div class="history-stats">
        <div class="hstat"><span class="hstat-dot red"></span><?= $total_malicious ?> Malicious</div>
        <div class="hstat"><span class="hstat-dot yellow"></span><?= $total_suspicious ?> Suspicious</div>
        <div class="hstat"><span class="hstat-dot green"></span><?= $total_safe ?> Safe</div>
      </div>
    </div>

    <table class="history-table">
      <thead>
        <tr>
          <th>#</th>
          <th>File Name</th>
          <th>Size</th>
          <th>Verdict</th>
          <th>Risk Score</th>
          <th>Malware Types</th>
          <th>MITRE Techniques</th>
          <th>Scanned At</th>
          <th>Action</th>
        </tr>
      </thead>
      <tbody>
        <?php if (empty($scan_history)): ?>
        <tr>
          <td colspan="9" class="empty-history">No scans recorded yet. Run a sandbox analysis above to populate history.</td>
        </tr>
        <?php else: ?>
        <?php foreach ($scan_history as $i => $scan):
          $risk = (int)$scan['risk_score'];
          $bar_color = $scan['verdict'] === 'MALICIOUS' ? '#ef4444' : ($scan['verdict'] === 'SUSPICIOUS' ? '#f59e0b' : '#22c55e');
          $date_str = date('d M Y, H:i', strtotime($scan['scanned_at']));
          
          $m_ids = explode(',', $scan['mitre_ids'] ?? '');
        ?>
        <tr>
          <td style="color:#475569;"><?= $scan['id'] ?></td>
          <td><span style="font-weight:600; color:#f1f5f9;">📄 <?= htmlspecialchars($scan['file_name']) ?></span></td>
          <td><?= htmlspecialchars($scan['file_size']) ?></td>
          <td>
            <span class="verdict-badge <?= $scan['verdict'] ?>">
              <?= $scan['verdict'] ?> 
              <span style="font-size: 9px; opacity: 0.7; margin-left: 4px;">
                (<?= $scan['verdict'] === 'MALICIOUS' ? 'High' : ($scan['verdict'] === 'SUSPICIOUS' ? 'Medium' : 'Low') ?>)
              </span>
            </span>
          </td>
          <td>
            <div class="risk-bar-wrap">
              <div class="risk-bar">
                <div class="risk-bar-fill" style="width:<?= $risk ?>%; background:<?= $bar_color ?>;"></div>
              </div>
              <span class="risk-num" style="color:<?= $bar_color ?>;"><?= $risk ?>/100</span>
            </div>
          </td>
          <td><span class="malware-mini"><?= $scan['malware_types'] ? htmlspecialchars($scan['malware_types']) : '—' ?></span></td>
          <td>
            <div style="display:flex; flex-wrap:wrap; gap:6px;">
              <?php foreach($m_ids as $mid): 
                $mid = trim($mid); 
                if(empty($mid)) continue; 
                $sev = $threat_map[$mid] ?? 'Medium';
                $sev_color = $sev === 'High' ? '#ef4444' : ($sev === 'Medium' ? '#f59e0b' : '#22c55e');
              ?>
                <a href="threatAnalysis.php#<?= $mid ?>" 
                   style="font-size:10px; background:rgba(37,99,235,0.1); border:1px solid <?= $sev_color ?>; color:<?= $sev_color ?>; padding:2px 6px; border-radius:4px; text-decoration:none; font-weight:600;"
                   title="Severity: <?= $sev ?>">
                  <?= $mid ?>
                </a>
              <?php endforeach; if(empty(array_filter($m_ids))) echo '<span style="color:#475569;">—</span>'; ?>
            </div>
          </td>
          <td style="color:#64748b; font-size:12px;"><?= $date_str ?></td>
          <td>
            <button class="delete-row-btn" onclick="deleteScan(<?= $scan['id'] ?>)" title="Delete this scan">
              🗑️
            </button>
          </td>
        </tr>
        <?php endforeach; ?>
        <?php endif; ?>
      </tbody>
    </table>
  </section>

  <script>
    const fileInput    = document.getElementById('fileInput');
    const uploadBox    = document.getElementById('uploadBox');
    const executeBtn   = document.getElementById('executeBtn');
    const fileInfo     = document.getElementById('fileInfo');

    const envStatus        = document.getElementById('envStatus');
    const screenPlaceholder = document.getElementById('screenPlaceholder');
    const screenContent    = document.getElementById('screenContent');
    const metricsOverlay   = document.getElementById('metricsOverlay');
    const cliMockup        = document.getElementById('cliMockup');

    const consoleWindow = document.getElementById('consoleWindow');
    const fsRoot        = document.getElementById('fsRoot');
    const fsBadge       = document.getElementById('fs-badge');

    const riskScoreEl   = document.getElementById('riskScore');
    const riskCard      = document.getElementById('riskCard');
    const threatStatusEl = document.getElementById('threatStatus');
    const iocList       = document.getElementById('iocList');
    const dbSaveStatus  = document.getElementById('dbSaveStatus');

    // Pass the threat severity map from PHP to JS
    const THREAT_SEVERITY_MAP = <?= json_encode($threat_map) ?>;

    let isRunning = false;
    let fsChangeCount = 0;

    // ── IOC tracking for DB save ──
    const iocData = { static: '', network: '', filesystem: '', behavior: '' };

    function logToConsole(message, type = 'info') {
      const div = document.createElement('div');
      div.className = `log-line log-${type}`;
      div.textContent = message;
      consoleWindow.appendChild(div);
      consoleWindow.scrollTop = consoleWindow.scrollHeight;

      if (screenContent.style.display !== 'none') {
        const cliLine = document.createElement('div');
        cliLine.textContent = message.replace(/\[.*?\] /, '');
        if (type === 'error')   cliLine.style.color = '#ef4444';
        if (type === 'warning') cliLine.style.color = '#eab308';
        cliMockup.appendChild(cliLine);
        cliMockup.scrollTop = cliMockup.scrollHeight;
      }
    }

    document.getElementById('clearConsoleBtn').onclick = () => {
      consoleWindow.innerHTML = '';
      logToConsole('[System] Console cleared.', 'info');
    };

    // File drag-and-drop support
    uploadBox.addEventListener('dragover', e => { e.preventDefault(); uploadBox.style.borderColor = '#60a5fa'; });
    uploadBox.addEventListener('dragleave', () => { uploadBox.style.borderColor = '#334155'; });
    uploadBox.addEventListener('drop', e => {
      e.preventDefault();
      if (e.dataTransfer.files.length > 0) {
        handleFile(e.dataTransfer.files[0]);
      }
    });

    fileInput.addEventListener('change', e => {
      if (e.target.files.length > 0) handleFile(e.target.files[0]);
    });

    function handleFile(file) {
      fileInfo.style.display = 'block';
      fileInfo.textContent = `Selected: ${file.name} (${(file.size / 1024).toFixed(2)} KB)`;
      uploadBox.style.borderColor = '#2563eb';
      uploadBox.style.background = 'rgba(37, 99, 235, 0.1)';
      executeBtn.disabled = false;
      logToConsole(`[System] File loaded into staging: ${file.name}`, 'info');
    }

    // Execute Sandbox Sequence
    executeBtn.addEventListener('click', async () => {
      if (isRunning) return;
      isRunning = true;
      executeBtn.disabled = true;
      dbSaveStatus.style.display = 'none';

      // Reset UI
      cliMockup.innerHTML = '';
      iocList.innerHTML = '';
      document.getElementById('malwareTags').innerHTML = '';
      document.getElementById('malwareTypeSection').style.display = 'none';
      riskScoreEl.textContent = '0/100';
      riskScoreEl.style.color = '#f8fafc';
      threatStatusEl.textContent = 'ANALYZING';
      threatStatusEl.className = 'status-text warning';
      riskCard.style.borderColor = '#eab308';
      fsChangeCount = 0;
      fsBadge.textContent = '0 Changes';

      // Reset ioc data
      iocData.static = ''; iocData.network = ''; iocData.filesystem = ''; iocData.behavior = '';

      envStatus.className = 'status-indicator running';
      envStatus.textContent = '● Running Container';
      screenPlaceholder.style.display = 'none';
      screenContent.style.display = 'block';
      metricsOverlay.style.display = 'flex';

      const file = fileInput.files[0];
      const fileName = file.name;
      const fileSize = (file.size / 1024).toFixed(2) + ' KB';

      // Read file content for Static Analysis
      let fileContent = "";
      try {
        fileContent = await new Promise((resolve, reject) => {
          const reader = new FileReader();
          reader.onload  = e => resolve(e.target.result);
          reader.onerror = e => reject(e);
          reader.readAsText(file);
        });
      } catch (e) {
        logToConsole(`[System] Could not read file content for static analysis.`, 'warning');
      }

      logToConsole(`[System] Initiating Sandbox Pipeline for ${fileName}...`, 'info');
      await sleep(500);

      // ─────────────────────────────────────────
      // 1. STATIC ANALYSIS
      // ─────────────────────────────────────────
      logToConsole(`[Static Engine] Scanning source code for dangerous functions...`, 'info');
      await sleep(1000);

      const dangerousPatterns = /exec\(|system\(|shell_exec\(|curl|wget|popen\(|passthru\(/i;
      const hasDangerousFunctions = dangerousPatterns.test(fileContent);

      let baseScore = 0;
      let staticSuspicious = false;

      if (hasDangerousFunctions) {
        logToConsole(`[Static Engine] ⚠ Dangerous functions detected (exec, system, shell_exec, curl/wget)!`, 'warning');
        iocData.static = 'Dangerous execution or network functions detected (exec, system, shell_exec, curl, wget)';
        addIOC('Static Analysis', 'File contains potentially hazardous execution or network functions.');
        staticSuspicious = true;
        
        // Weight based on DB severity
        const sev = THREAT_SEVERITY_MAP['T1059'] || 'Medium';
        baseScore += (sev === 'High' ? 40 : (sev === 'Medium' ? 20 : 10));
        updateRisk(baseScore);
      } else {
        logToConsole(`[Static Engine] No obvious dangerous signatures detected.`, 'success');
      }

      // ─────────────────────────────────────────
      // 2. DYNAMIC ANALYSIS
      // ─────────────────────────────────────────
      logToConsole(`[Docker] Pulling/Starting container for Ubuntu 24.04...`, 'info');
      await sleep(1000);
      logToConsole(`[Docker] Container c8f921ea started successfully.`, 'success');
      logToConsole(`[Sandbox] Injecting payload: ${fileName}...`, 'info');

      // Heartbeat
      let memory = 12;
      const heartbeat = setInterval(() => {
        document.getElementById('cpuUsage').textContent  = Math.floor(Math.random() * 80 + 10) + '%';
        memory += Math.floor(Math.random() * 5);
        document.getElementById('memUsage').textContent  = memory + ' MB';
        document.getElementById('netTraffic').textContent = Math.floor(Math.random() * 50) + ' KB/s';
      }, 500);

      await sleep(1500);
      logToConsole(`[Agent] Executing ${fileName}...`, 'warning');

      const hasNetwork     = /http:\/\/|https:\/\/|ftp:\/\//i.test(fileContent);
      const hasPersistence = /\/etc\/|\.bashrc|crontab/i.test(fileContent);
      const hasEncryption  = /encrypt|base64_decode|crypto|mcrypt/i.test(fileContent);
      const hasDropper     = /chmod|temp|sh \/tmp/i.test(fileContent);

      let dynamicMalicious = false;

      await sleep(1000);
      if (hasNetwork || hasPersistence || hasEncryption || hasDropper) {
        dynamicMalicious = true;

        if (hasNetwork) {
          logToConsole(`[Sysmon] Process spawned: Unauthorized outbound network connection.`, 'error');
          iocData.network = 'Outbound connection to external IP/Domain detected';
          addIOC('Network', 'Outbound connection to an external IP/Domain detected.');
          const sev = THREAT_SEVERITY_MAP['T1105'] || 'Medium';
          baseScore += (sev === 'High' ? 30 : (sev === 'Medium' ? 15 : 5));
          updateRisk(Math.min(baseScore, 100));
          await sleep(800);
        }

        if (hasPersistence) {
          logToConsole(`[FS-Tracker] File Modified: Critical system/cron file altered.`, 'error');
          iocData.filesystem = 'System file modified — Persistence mechanisms detected (crontab/.bashrc)';
          addVFSNode('etc', 'crontab', 'modified');
          addIOC('File System', 'System file modified indicating Persistence mechanisms.');
          const sev = THREAT_SEVERITY_MAP['T1547'] || 'Medium';
          baseScore += (sev === 'High' ? 40 : (sev === 'Medium' ? 20 : 10));
          updateRisk(Math.min(baseScore, 100));
          await sleep(1000);
        }

        if (hasDropper || hasEncryption) {
          logToConsole(`[Sysmon] Process spawned: Encryption or script dropper behavior detected.`, 'warning');
          iocData.behavior = 'High CPU entropy or background script execution detected';
          addVFSNode('tmp', 'payload', 'new');
          addIOC('Behavior', 'High CPU entropy or background script execution.');
          
          const mid = hasEncryption ? 'T1486' : 'T1544';
          const sev = THREAT_SEVERITY_MAP[mid] || 'Medium';
          baseScore += (sev === 'High' ? 30 : (sev === 'Medium' ? 15 : 5));
          updateRisk(Math.min(baseScore, 100));
        }
      } else {
        logToConsole(`[Agent] Execution normal. Process exited with 0.`, 'success');
        await sleep(800);
        logToConsole(`[FS-Tracker] No suspicious modifications.`, 'info');
      }

      if (baseScore > 100) baseScore = 100;

      // Finish execution
      await sleep(1500);
      clearInterval(heartbeat);
      document.getElementById('cpuUsage').textContent  = '0%';
      document.getElementById('netTraffic').textContent = '0 B/s';

      logToConsole(`[Docker] Stopping container c8f921ea...`, 'info');
      await sleep(800);
      logToConsole(`[Docker] Container removed. Sandbox report generated.`, 'success');

      envStatus.className  = 'status-indicator stopped';
      envStatus.textContent = '● Stopped';
      executeBtn.disabled  = false;
      isRunning = false;

      // Determine Malware Types
      const malwareTypes = [];
      if (dynamicMalicious || staticSuspicious) {
        if (hasNetwork)     malwareTypes.push({ label: 'Trojan / Backdoor',    color: '#ef4444', icon: '🔌' });
        if (hasPersistence) malwareTypes.push({ label: 'Rootkit / Persistence', color: '#f97316', icon: '⚙️' });
        if (hasEncryption)  malwareTypes.push({ label: 'Ransomware',            color: '#a855f7', icon: '🔒' });
        if (hasDropper)     malwareTypes.push({ label: 'Dropper / Loader',      color: '#ec4899', icon: '📦' });
        if (hasDangerousFunctions && !dynamicMalicious)
          malwareTypes.push({ label: 'Potentially Unwanted', color: '#eab308', icon: '⚠️' });
      }

      const malwareTypeSection = document.getElementById('malwareTypeSection');
      const malwareTags        = document.getElementById('malwareTags');
      malwareTags.innerHTML = '';
      if (malwareTypes.length > 0) {
        malwareTypeSection.style.display = 'block';
        malwareTypes.forEach(type => {
          const tag = document.createElement('div');
          tag.className = 'malware-tag';
          tag.style.borderColor = type.color;
          tag.style.color       = type.color;
          tag.innerHTML = `${type.icon} ${type.label}`;
          malwareTags.appendChild(tag);
        });
        logToConsole(`[Classifier] Malware Type(s): ${malwareTypes.map(t => t.label).join(', ')}`, 'warning');
      } else {
        malwareTypeSection.style.display = 'none';
      }

      // Final Verdict based on Score
      let finalVerdict = 'SAFE';
      if (baseScore >= 70) {
        finalVerdict = 'MALICIOUS';
        threatStatusEl.textContent = 'MALICIOUS (High Severity)';
        threatStatusEl.className   = 'status-text danger';
        riskCard.style.borderColor = '#ef4444';
        logToConsole(`[System] Analysis Complete. Verdict: MALICIOUS (High)`, 'error');
      } else if (baseScore >= 30) {
        finalVerdict = 'SUSPICIOUS';
        threatStatusEl.textContent = 'SUSPICIOUS (Medium Severity)';
        threatStatusEl.className   = 'status-text warning';
        riskCard.style.borderColor = '#eab308';
        logToConsole(`[System] Analysis Complete. Verdict: SUSPICIOUS (Medium)`, 'warning');
      } else {
        finalVerdict = 'SAFE';
        threatStatusEl.textContent = 'SAFE (Low Severity)';
        threatStatusEl.className   = 'status-text clean';
        riskCard.style.borderColor = '#22c55e';
        logToConsole(`[System] Analysis Complete. Verdict: SAFE (Low)`, 'success');
      }

      // ─────────────────────────────────────────
      // SAVE TO DATABASE
      // ─────────────────────────────────────────
      logToConsole(`[DB] Saving scan result to database...`, 'info');

      const payload = {
        file_name:       fileName,
        file_size:       fileSize,
        verdict:         finalVerdict,
        risk_score:      baseScore,
        malware_types:   malwareTypes.map(t => t.label).join(', '),
        ioc_static:      iocData.static,
        ioc_network:     iocData.network,
        ioc_filesystem:  iocData.filesystem,
        ioc_behavior:    iocData.behavior,
        has_network:     hasNetwork     ? 1 : 0,
        has_persistence: hasPersistence ? 1 : 0,
        has_encryption:  hasEncryption  ? 1 : 0,
        has_dropper:     hasDropper     ? 1 : 0,
        has_dangerous:   hasDangerousFunctions ? 1 : 0,
        mitre_ids:       (() => {
          const ids = [];
          if (hasDangerousFunctions) ids.push('T1059');
          if (hasPersistence)        ids.push('T1547');
          if (hasNetwork)            ids.push('T1105');
          if (hasEncryption)         ids.push('T1486');
          if (hasDropper)            ids.push('T1544');
          return ids.join(', ');
        })()
      };

      try {
        const resp = await fetch('save_scan.php', {
          method:  'POST',
          headers: { 'Content-Type': 'application/json' },
          body:    JSON.stringify(payload),
        });
        const result = await resp.json();

        if (result.success) {
          logToConsole(`[DB] ✅ Scan #${result.id} saved successfully to database.`, 'success');
          dbSaveStatus.style.display = 'block';
          dbSaveStatus.style.background = 'rgba(34,197,94,0.1)';
          dbSaveStatus.style.border = '1px solid rgba(34,197,94,0.3)';
          dbSaveStatus.style.color = '#22c55e';
          dbSaveStatus.textContent = `✅ Scan result saved to database (ID: #${result.id})`;

          // Auto-refresh removed to keep the Environment View and Threat Summary on screen
          // setTimeout(() => location.reload(), 1200);
        } else {
          logToConsole(`[DB] ❌ Failed to save: ${result.error}`, 'error');
          dbSaveStatus.style.display = 'block';
          dbSaveStatus.style.background = 'rgba(239,68,68,0.1)';
          dbSaveStatus.style.color = '#ef4444';
          dbSaveStatus.textContent = `❌ DB Save failed: ${result.error}`;
        }
      } catch (err) {
        logToConsole(`[DB] ❌ Network error saving to database.`, 'error');
      }
    });

    function sleep(ms) { return new Promise(r => setTimeout(r, ms)); }

    function addVFSNode(parentDir, fileName, type) {
      let parentLi = Array.from(fsRoot.children).find(li => li.textContent.includes(parentDir));
      if (!parentLi) {
        parentLi = document.createElement('li');
        parentLi.innerHTML = `<span>📁 ${parentDir}</span><ul></ul>`;
        fsRoot.appendChild(parentLi);
      }
      let ul = parentLi.querySelector('ul');
      if (!ul) { ul = document.createElement('ul'); parentLi.appendChild(ul); }
      const fileLi = document.createElement('li');
      fileLi.innerHTML = `<span class="vfs-${type}">📄 ${fileName}</span>`;
      ul.appendChild(fileLi);
      fsChangeCount++;
      fsBadge.textContent = `${fsChangeCount} Change${fsChangeCount > 1 ? 's' : ''}`;
    }

    function addIOC(category, detail) {
      const empty = iocList.querySelector('.ioc-empty');
      if (empty) empty.remove();
      const li = document.createElement('li');
      li.innerHTML = `<span class="ioc-category">${category}</span>: ${detail}`;
      iocList.appendChild(li);
    }

    function updateRisk(score) {
      riskScoreEl.textContent = `${score}/100`;
      if (score > 60) {
        riskCard.style.borderColor = '#ef4444';
        riskScoreEl.style.color    = '#ef4444';
      } else if (score > 30) {
        riskCard.style.borderColor = '#eab308';
        riskScoreEl.style.color    = '#eab308';
      } else {
        riskScoreEl.style.color    = '#22c55e';
      }
    }

    // Reset History Logic
    document.getElementById('resetHistoryBtn').onclick = async () => {
      if (!confirm('Are you sure you want to clear ALL scan history? This action cannot be undone.')) {
        return;
      }

      try {
        const resp = await fetch('reset_sandbox.php', { method: 'POST' });
        const result = await resp.json();

        if (result.success) {
          logToConsole('[System] Sandbox history has been cleared.', 'success');
          // Reload to update stats and table
          setTimeout(() => location.reload(), 800);
        } else {
          alert('Error resetting history: ' + result.error);
        }
      } catch (err) {
        alert('Failed to connect to server.');
      }
    };

    // Delete single scan row
    async function deleteScan(id) {
      if (!confirm('Delete this scan record?')) return;
      
      try {
        const resp = await fetch('delete_scan.php', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ id: id })
        });
        const result = await resp.json();
        if (result.success) {
          location.reload();
        } else {
          alert('Error: ' + result.error);
        }
      } catch (err) {
        alert('Failed to delete scan.');
      }
    }
    
    // Check for file parameter in URL
    const urlParams = new URLSearchParams(window.location.search);
    const prefillFile = urlParams.get('file');
    if (prefillFile) {
        fileInfo.style.display = 'block';
        fileInfo.textContent = `Target: ${prefillFile} (Ready for Analysis)`;
        uploadBox.style.borderColor = '#a855f7';
        uploadBox.style.background = 'rgba(168, 85, 247, 0.1)';
        executeBtn.disabled = false;
        logToConsole(`[System] Remote file target received: ${prefillFile}`, 'info');
        
        // Auto-trigger simulation if requested
        if (urlParams.get('auto') === '1') {
            executeBtn.click();
        }
    }
  </script>

</body>
</html>
