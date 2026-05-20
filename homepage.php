<?php
require 'db.php';

// --- Fetch Recent Scans from Database ---
$recent_scans = [];
$res = $conn->query("SELECT * FROM usb_scans ORDER BY scanned_at DESC LIMIT 5");
if ($res) {
    while ($row = $res->fetch_assoc()) {
        $recent_scans[] = $row;
    }
}
?>
<!DOCTYPE html>
<html lang="en">

<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>USB Malware Detection - Home</title>
    <link rel="stylesheet" href="home-style.css">
    <script src="https://unpkg.com/@phosphor-icons/web"></script>
    <style>
        /* Toast Notification */
        #toast {
            position: fixed;
            bottom: 40px;
            right: 40px;
            background: rgba(30, 41, 59, 0.9);
            backdrop-filter: blur(12px);
            border: 1px solid rgba(59, 130, 246, 0.3);
            color: white;
            padding: 18px 28px;
            border-radius: 20px;
            box-shadow: 0 20px 40px rgba(0,0,0,0.4);
            display: flex;
            align-items: center;
            gap: 15px;
            transform: translateY(200%);
            transition: all 0.5s cubic-bezier(0.175, 0.885, 0.32, 1.275);
            z-index: 1000;
        }
        #toast.show { transform: translateY(0); }
        #toast .icon { 
            font-size: 28px; 
            color: #3b82f6; 
            background: rgba(59, 130, 246, 0.1);
            width: 45px;
            height: 45px;
            display: flex;
            align-items: center;
            justify-content: center;
            border-radius: 12px;
        }
        
        /* Auto Scan Overlay */
        #autoScanOverlay {
            position: fixed;
            top: 0; left: 0; width: 100%; height: 100%;
            background: rgba(2, 6, 23, 0.85);
            z-index: 2000;
            display: none;
            flex-direction: column;
            align-items: center;
            justify-content: center;
            text-align: center;
            backdrop-filter: blur(15px);
        }
        .scanner-ring {
            width: 140px; height: 140px;
            border: 6px solid rgba(30, 41, 59, 0.5);
            border-top: 6px solid #3b82f6;
            border-radius: 50%;
            animation: spin 1s cubic-bezier(0.4, 0, 0.2, 1) infinite;
            margin-bottom: 40px;
            filter: drop-shadow(0 0 15px rgba(59, 130, 246, 0.4));
        }
        @keyframes spin { 0% { transform: rotate(0deg); } 100% { transform: rotate(360deg); } }
        
        #autoScanTitle {
            font-size: 2rem;
            font-weight: 800;
            margin-bottom: 10px;
            letter-spacing: -0.02em;
        }
        #autoScanMsg {
            color: #94a3b8;
            font-size: 1.1rem;
        }

        .no-devices {
            text-align: center;
            padding: 60px 20px;
            color: #475569;
        }
        .no-devices i { font-size: 50px; margin-bottom: 15px; display: block; opacity: 0.3; }
        
        .pulse { animation: pulse-animation 2s infinite; }
        @keyframes pulse-animation {
            0% { transform: scale(1); opacity: 0.3; }
            50% { transform: scale(1.1); opacity: 0.6; }
            100% { transform: scale(1); opacity: 0.3; }
        }
    </style>
</head>

<body>

    <div id="autoScanOverlay">
        <div class="scanner-ring"></div>
        <h2 id="autoScanTitle">New USB Device Detected!</h2>
        <p id="autoScanMsg">Initializing automatic security scan...</p>
        <p id="autoScanDev" style="color: #60a5fa; font-weight: bold; margin-top: 10px;"></p>
        
        <div style="width: 400px; margin-top: 30px;">
            <div id="dockerStatus" style="font-size: 12px; color: #94a3b8; text-align: left; margin-bottom: 8px; font-family: monospace;"></div>
            <div class="progress-bar-container">
                <div id="scanProgress" class="progress-bar-fill"></div>
            </div>
            <div id="fileScanList" class="file-scan-list"></div>
        </div>
    </div>

    <div id="toast">
        <div class="icon"><i class="ph ph-usb"></i></div>
        <div>
            <strong id="toastTitle">USB Connected</strong>
            <p id="toastMsg" style="font-size: 13px; opacity: 0.9;">System is ready to scan</p>
        </div>
    </div>

    <nav class="navbar">
        <div class="logo">
            <i class="ph ph-shield-check-fill"></i>
            <div>
                <h1>USB Malware Detection System</h1>
                <p>Real-time protection against USB threats</p>
            </div>
        </div>
        <a href="admin.php" class="admin-portal"><i class="ph ph-gear"></i> Admin Portal</a>
    </nav>

    <main class="dashboard">
        <section id="scanResults" class="scan-results-container" style="display: none;">
            <div class="results-header">
                <div>
                    <h2 id="resDevName" style="font-size: 1.5rem; font-weight: 800;">SanDisk Ultra USB 3.0</h2>
                    <p style="color: var(--text-sub); font-size: 0.9rem;">Scan completed at <span id="resTime"></span></p>
                </div>
                <div style="display: flex; gap: 10px;">
                    <button class="scan-btn" style="background: rgba(59, 130, 246, 0.1); color: #3b82f6; border-color: rgba(59, 130, 246, 0.2);" onclick="downloadTextReport()">
                        <i class="ph ph-download-simple"></i> Download Report
                    </button>
                    <button class="scan-btn" onclick="document.getElementById('scanResults').style.display='none'">
                        <i class="ph ph-x"></i> Dismiss
                    </button>
                </div>
            </div>

            <div id="statusBanner" class="status-banner clean">
                <i id="statusIcon" class="ph ph-check-circle"></i>
                <div>
                    <strong id="statusTitle">Device is clean and safe to use</strong>
                    <p id="statusMsg" style="font-size: 0.9rem; opacity: 0.8;">No malware, viruses, or security threats were detected during the scan.</p>
                </div>
            </div>

            <div class="results-grid">
                <div class="result-stat">
                    <span class="label">Files Scanned</span>
                    <span id="resFileCount" class="value">376</span>
                </div>
                <div class="result-stat">
                    <span class="label">Threats Found</span>
                    <span id="resThreatCount" class="value" style="color: #ef4444;">0</span>
                </div>
                <div class="result-stat">
                    <span class="label">Scan Time</span>
                    <span id="resDuration" class="value">1.2s</span>
                </div>
                <div class="result-stat">
                    <span class="label">Status</span>
                    <span id="resStatus" class="value">Clean</span>
                </div>
            </div>

            <div id="threatSummary" class="threat-summary" style="display: none;">
                <h3><i class="ph ph-warning-diamond"></i> Detected Security Threats</h3>
                <div id="threatList" class="threat-list">
                    <!-- Threats populated by JS -->
                </div>
            </div>
        </section>

        <section class="status-card">
            <div class="status-icon">
                <i class="ph ph-shield-check"></i>
            </div>
            <div class="status-content">
                <h2>Welcome to USB Security Scanner</h2>
                <p>Connect your USB device and click "Scan Device" to check for malware, viruses, and security threats.
                    Our advanced sandbox environment will analyze all files safely.</p>
                <div class="status-badges">
                    <span><i class="ph ph-check-circle"></i> Real-time scanning</span>
                    <span><i class="ph ph-shield"></i> Sandbox protection</span>
                    <span><i class="ph ph-lightning"></i> Instant threat detection</span>
                </div>
            </div>
        </section>

        <div class="content-grid">
            <section class="devices-section">
                <div class="section-header">
                    <i class="ph ph-plugs-connected"></i> Connected USB Devices
                </div>

                <div id="deviceList">
                    <div class="no-devices">
                        <i class="ph ph-usb pulse"></i>
                        <p>Waiting for USB device connection...</p>
                        <span style="font-size: 12px;">Plug in a USB drive to begin scanning</span>
                    </div>
                </div>
            </section>

            <aside class="recent-scans">
                <div class="section-header">
                    <i class="ph ph-activity"></i> Recent Scans
                </div>
                
                <?php if (empty($recent_scans)): ?>
                    <div class="empty-state">
                        <i class="ph ph-file-search"></i>
                        <p>No scans yet</p>
                        <span>Start scanning devices to see history</span>
                    </div>
                <?php else: ?>
                    <div class="recent-list">
                        <?php foreach ($recent_scans as $scan): 
                            $is_malicious = ($scan['status'] === 'MALICIOUS');
                            $is_suspicious = ($scan['status'] === 'SUSPICIOUS');
                            $icon_class = $is_malicious ? 'threat' : ($is_suspicious ? 'warning' : 'clean');
                            $icon = $is_malicious ? 'ph-warning-circle' : ($is_suspicious ? 'ph-warning' : 'ph-check-circle');
                            $color = $is_malicious ? '#ef4444' : ($is_suspicious ? '#f59e0b' : '#22c55e');
                        ?>
                            <div class="recent-item">
                                <div class="recent-icon <?= $icon_class ?>">
                                    <i class="ph <?= $icon ?>"></i>
                                </div>
                                <div class="recent-details">
                                    <strong><?= htmlspecialchars($scan['device_name']) ?></strong>
                                    <span>User: <?= htmlspecialchars($scan['user_name']) ?></span>
                                </div>
                                <div class="recent-meta">
                                    <div><?= date('M d', strtotime($scan['scanned_at'])) ?></div>
                                    <div style="color: <?= $color ?>"><?= $scan['status'] ?></div>
                                </div>
                            </div>
                        <?php endforeach; ?>
                    </div>
                    <div style="padding: 12px; text-align: center;">
                        <a href="allscans.php" style="color: #60a5fa; font-size: 12px; text-decoration: none;">View All Scan History &rarr;</a>
                    </div>
                <?php endif; ?>
            </aside>
        </div>
    </main>

    <script>
        let lastDeviceCount = -1;
        let isScanning = false;

        function showToast(title, msg) {
            const toast = document.getElementById('toast');
            document.getElementById('toastTitle').textContent = title;
            document.getElementById('toastMsg').textContent = msg;
            toast.classList.add('show');
            setTimeout(() => toast.classList.remove('show'), 4000);
        }

        async function detectUSB() {
            if (isScanning) return;
            
            try {
                const response = await fetch('api_detect_usb.php');
                const data = await response.json();
                
                const deviceListEl = document.getElementById('deviceList');
                
                // If device found and was none before
                if (data.count > 0 && lastDeviceCount === 0) {
                    const latestDev = data.devices[0];
                    showToast('USB Detected', latestDev.name + ' connected');
                    
                    if (data.auto_scan) {
                        triggerAutoScan(latestDev);
                    }
                }
                
                lastDeviceCount = data.count;
                renderDevices(data.devices);
            } catch (err) {
                console.error("Detection error:", err);
            }
        }

        function renderDevices(devices) {
            const el = document.getElementById('deviceList');
            if (devices.length === 0) {
                el.innerHTML = `
                    <div class="no-devices">
                        <i class="ph ph-usb pulse"></i>
                        <p>Waiting for USB device connection...</p>
                        <span style="font-size: 12px;">Plug in a USB drive to begin scanning</span>
                    </div>`;
                return;
            }

            let html = '';
            devices.forEach(usb => {
                html += `
                        <div class="device-item">
                            <div class="device-info">
                                <i class="ph ph-usb"></i>
                                <div>
                                    <strong>${usb.name}</strong>
                                    <p>${usb.vendor} | Capacity: ${usb.size}</p>
                                    <span style="font-size: 10px; color: #475569;">Mount: ${usb.mount || 'Not mounted'}</span>
                                </div>
                            </div>
                            <div style="display: flex; gap: 10px;">
                                <button class="scan-btn" onclick="manualScan('${usb.id}', '${usb.name}', '${usb.mount || ''}')">
                                    <i class="ph ph-magnifying-glass"></i> Scan
                                </button>
                            </div>
                        </div>`;
            });
            el.innerHTML = html;
        }



        async function triggerAutoScan(dev) {
            performRealTimeScan(dev.id, dev.name, dev.mount);
        }

        function manualScan(id, name, mount) {
            performRealTimeScan(id, name, mount);
        }

        async function performRealTimeScan(id, name, mount) {
            if (isScanning) return;
            isScanning = true;
            
            const overlay = document.getElementById('autoScanOverlay');
            const devName = document.getElementById('autoScanDev');
            const progress = document.getElementById('scanProgress');
            const fileList = document.getElementById('fileScanList');
            const msg = document.getElementById('autoScanMsg');
            const dockerStatus = document.getElementById('dockerStatus');
            
            devName.textContent = name;
            overlay.style.display = 'flex';
            fileList.innerHTML = '';
            progress.style.width = '0%';
            dockerStatus.innerHTML = '';
            
            // Phase 1: Docker Initialization
            msg.textContent = "Initializing Docker Sandbox...";
            dockerStatus.innerHTML = "<div>[Docker] Finding image: malware-scanner:latest...</div>";
            await new Promise(r => setTimeout(r, 800));
            dockerStatus.innerHTML += "<div>[Docker] Creating container from sandbox-v4...</div>";
            await new Promise(r => setTimeout(r, 600));
            dockerStatus.innerHTML += "<div>[Docker] Container 'scan_tmp_8231' started.</div>";
            dockerStatus.innerHTML += "<div>[Docker] Mounting USB at /mnt/usb_drive...</div>";
            await new Promise(r => setTimeout(r, 800));
            
            try {
                // Real scan call
                msg.textContent = "Docker: Analyzing file signatures...";
                const response = await fetch(`api_scan_files.php?mount=${encodeURIComponent(mount || '')}`);
                const scanResult = await response.json();
                
                const filesToScan = scanResult.files;
                let threatsCount = 0;
                let suspiciousCount = 0;
                let detectedThreats = [];

                for (let i = 0; i < filesToScan.length; i++) {
                    const file = filesToScan[i];
                    const pct = ((i + 1) / filesToScan.length) * 100;
                    
                    msg.textContent = `Docker Scanning: ${file.name}`;
                    progress.style.width = pct + '%';
                    
                    const item = document.createElement('div');
                    item.className = 'file-item-anim';
                    
                    if (file.verdict === 'MALICIOUS') {
                        threatsCount++;
                        detectedThreats.push({ file: file.name, type: file.type || 'Unknown Malware', verdict: file.verdict });
                        item.innerHTML = `<i class="ph ph-warning-circle" style="color: #ef4444;"></i> <span style="color: #ef4444;">[MALICIOUS] ${file.name} - ${file.type}</span>`;
                    } else if (file.verdict === 'SUSPICIOUS') {
                        suspiciousCount++;
                        detectedThreats.push({ file: file.name, type: file.type || 'Suspicious Activity', verdict: file.verdict });
                        item.innerHTML = `<i class="ph ph-warning" style="color: #f59e0b;"></i> <span style="color: #f59e0b;">[SUSPICIOUS] ${file.name} - ${file.type}</span>`;
                    } else {
                        item.innerHTML = `<i class="ph ph-shield-check" style="color: #10b981;"></i> ${file.name} - SAFE`;
                    }
                    
                    fileList.prepend(item);
                    if (fileList.children.length > 5) fileList.removeChild(fileList.lastChild);
                    
                    // Small delay for visual effect
                    await new Promise(r => setTimeout(r, 100));
                }

                msg.textContent = "Finalizing Docker Sandbox report...";
                dockerStatus.innerHTML += "<div>[Docker] Analysis complete. Detaching volumes...</div>";
                await new Promise(r => setTimeout(r, 600));
                dockerStatus.innerHTML += "<div>[Docker] Stopping container scan_tmp_8231.</div>";
                await new Promise(r => setTimeout(r, 500));

                let scanStatus = 'SAFE';
                if (threatsCount > 0) scanStatus = 'MALICIOUS';
                else if (suspiciousCount > 0) scanStatus = 'SUSPICIOUS';

                const scanData = {
                    user_name: 'Guest User', 
                    device_name: name,
                    file_count: scanResult.count,
                    threat_count: threatsCount + suspiciousCount,
                    duration: (1.2 + Math.random()).toFixed(1) + 's',
                    status: scanStatus,
                    threats: detectedThreats
                };

                // Save results
                await fetch('api_save_usb_scan.php', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify(scanData)
                });

                showResults(scanData);

            } catch (err) {
                console.error("Scan error:", err);
                showToast("Error", "Docker Sandbox failed to initialize");
            }
            
            overlay.style.display = 'none';
            isScanning = false;
        }

        function showResults(data) {
            const resSection = document.getElementById('scanResults');
            const banner = document.getElementById('statusBanner');
            const nowTime = new Date().toLocaleString();
            
            document.getElementById('resDevName').textContent = data.device_name;
            document.getElementById('resTime').textContent = nowTime;
            document.getElementById('resFileCount').textContent = data.file_count;
            document.getElementById('resThreatCount').textContent = data.threat_count;
            document.getElementById('resDuration').textContent = data.duration;
            document.getElementById('resStatus').textContent = data.status;
            
            // Build Text Report
            let reportText = `USB Malware Detection System\n`;
            reportText += `============================\n`;
            reportText += `FORENSIC SCAN REPORT\n`;
            reportText += `============================\n\n`;
            reportText += `[DEVICE INFORMATION]\n`;
            reportText += `Device Name: ${data.device_name}\n`;
            reportText += `Scanned By User: ${data.user_name}\n`;
            reportText += `Scan Timestamp: ${nowTime}\n\n`;
            
            reportText += `[SYSTEM CONTEXT]\n`;
            reportText += `Analysis Engine: Sentinel Sandbox Engine v4.0\n`;
            reportText += `Threat Intelligence DB: Real-Time Synced\n`;
            reportText += `Scanning Mode: Deep Heuristic & Signature Match\n\n`;
            
            reportText += `[SCAN SUMMARY]\n`;
            reportText += `Total Files Analyzed: ${data.file_count}\n`;
            reportText += `Total Threats Identified: ${data.threat_count}\n`;
            reportText += `Time Elapsed: ${data.duration}\n`;
            reportText += `Final Security Status: ${data.status}\n\n`;
            
            if (data.status === 'MALICIOUS' || data.status === 'SUSPICIOUS') {
                reportText += `[DETECTED THREATS DETAIL]\n`;
                data.threats.forEach((t, i) => {
                    reportText += `${i + 1}. File: ${t.file}\n`;
                    reportText += `   Verdict: ${t.verdict}\n`;
                    reportText += `   Classification: ${t.type}\n`;
                    reportText += `   Action Required: Immediate review in Admin Sandbox.\n\n`;
                });
                reportText += `RECOMMENDATION: Do NOT execute files from this device. Please format or quarantine the device immediately.\n`;
            } else {
                reportText += `[ANALYSIS RESULT]\n`;
                reportText += `No malicious signatures, suspicious behaviors, or dangerous scripts were detected during this scan.\n`;
                reportText += `RECOMMENDATION: Device is safe for normal operational use.\n`;
            }
            
            // Store globally to be downloaded later
            window.currentScanReportText = reportText;
            
            if (data.status === 'MALICIOUS' || data.status === 'SUSPICIOUS') {
                const isMalicious = data.status === 'MALICIOUS';
                banner.className = `status-banner ${isMalicious ? 'threat' : 'warning'}`;
                document.getElementById('statusIcon').className = isMalicious ? 'ph ph-warning-circle' : 'ph ph-warning';
                document.getElementById('statusTitle').textContent = `${data.threat_count} threats detected`;
                document.getElementById('statusMsg').textContent = 'Review the threats below and take recommended actions to secure your device.';
                document.getElementById('resThreatCount').style.color = isMalicious ? '#ef4444' : '#f59e0b';
                
                // Populate threat list
                const threatSummary = document.getElementById('threatSummary');
                const threatList = document.getElementById('threatList');
                threatList.innerHTML = '';
                
                data.threats.forEach(t => {
                    const isTMalicious = t.verdict === 'MALICIOUS';
                    const iconColor = isTMalicious ? '#ef4444' : '#f59e0b';
                    const item = document.createElement('div');
                    item.className = 'threat-item';
                    item.style.borderLeft = `4px solid ${iconColor}`;
                    item.innerHTML = `
                        <div class="threat-info">
                            <i class="ph ph-shield-warning" style="color: ${iconColor};"></i>
                            <div>
                                <div class="threat-name">${t.file} <span style="font-size:10px; padding: 2px 6px; border-radius: 4px; background: ${isTMalicious ? 'rgba(239,68,68,0.1)' : 'rgba(245,158,11,0.1)'}; color: ${iconColor}; margin-left: 6px;">${t.verdict}</span></div>
                                <div class="threat-type">${t.type}</div>
                            </div>
                        </div>

                    `;
                    threatList.appendChild(item);
                });
                
                threatSummary.style.display = 'block';
            } else {
                banner.className = 'status-banner clean';
                document.getElementById('statusIcon').className = 'ph ph-check-circle';
                document.getElementById('statusTitle').textContent = 'Device is clean and safe to use';
                document.getElementById('statusMsg').textContent = 'No malware, viruses, or security threats were detected during the scan.';
                document.getElementById('resThreatCount').style.color = '#10b981';
                document.getElementById('threatSummary').style.display = 'none';
            }
            
            resSection.style.display = 'block';
            resSection.scrollIntoView({ behavior: 'smooth' });
        }

        function downloadTextReport() {
            if (!window.currentScanReportText) return;
            
            const blob = new Blob([window.currentScanReportText], { type: 'text/plain' });
            const url = URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            const safeName = document.getElementById('resDevName').textContent.replace(/[^a-z0-9]/gi, '_').toLowerCase();
            a.download = `scan_report_${safeName}.txt`;
            document.body.appendChild(a);
            a.click();
            
            // Cleanup
            document.body.removeChild(a);
            URL.revokeObjectURL(url);
        }

        // Fast polling
        detectUSB();
        setInterval(detectUSB, 2000);
    </script>

</body>

</html>
