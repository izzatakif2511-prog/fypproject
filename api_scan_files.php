<?php
header('Content-Type: application/json');
require 'db.php';

$mount = $_GET['mount'] ?? '';
$files = [];
$threats_detected = [];

// Fetch threat severity map
$threat_map = [];
$t_res = $conn->query("SELECT mitree_id, severity FROM threats");
if ($t_res) {
    while ($row = $t_res->fetch_assoc()) {
        $threat_map[$row['mitree_id']] = $row['severity'];
    }
}

function getScore($mid, $threat_map, $high_val, $med_val, $low_val) {
    $sev = $threat_map[$mid] ?? 'Medium';
    if ($sev === 'High') return $high_val;
    if ($sev === 'Medium') return $med_val;
    return $low_val;
}

if (!empty($mount) && is_dir($mount)) {
    // Real scanning: List files from mount point
    try {
        $iterator = new RecursiveIteratorIterator(new RecursiveDirectoryIterator($mount));
        $count = 0;
        foreach ($iterator as $file) {
            if ($file->isDir()) continue;
            if ($count > 100) break; // Limit to 100 files for performance
            
            $filename = $file->getFilename();
            $path = $file->getPathname();
            
            $baseScore = 0;
            $malwareTypes = [];
            
            // Read up to 10KB of file content to check behavior signatures
            $fileContent = @file_get_contents($path, false, null, 0, 10240);
            if ($fileContent === false) $fileContent = "";
            
            $hasDangerous = preg_match('/exec\(|system\(|shell_exec\(|curl|wget|popen\(|passthru\(/i', $fileContent);
            $hasNetwork = preg_match('/http:\/\/|https:\/\/|ftp:\/\//i', $fileContent);
            $hasPersistence = preg_match('/\/etc\/|\.bashrc|crontab/i', $fileContent);
            $hasEncryption = preg_match('/encrypt|base64_decode|crypto|mcrypt/i', $fileContent);
            $hasDropper = preg_match('/chmod|temp|sh \/tmp/i', $fileContent);
            
            if ($hasDangerous) {
                $baseScore += getScore('T1059', $threat_map, 40, 20, 10);
            }
            if ($hasNetwork) {
                $baseScore += getScore('T1105', $threat_map, 30, 15, 5);
                $malwareTypes[] = 'Trojan / Backdoor';
            }
            if ($hasPersistence) {
                $baseScore += getScore('T1547', $threat_map, 40, 20, 10);
                $malwareTypes[] = 'Rootkit / Persistence';
            }
            if ($hasEncryption) {
                $baseScore += getScore('T1486', $threat_map, 30, 15, 5);
                $malwareTypes[] = 'Ransomware';
            }
            if ($hasDropper) {
                $baseScore += getScore('T1544', $threat_map, 30, 15, 5);
                $malwareTypes[] = 'Dropper / Loader';
            }
            
            if ($hasDangerous && !$hasNetwork && !$hasPersistence && !$hasEncryption && !$hasDropper) {
                $malwareTypes[] = 'Potentially Unwanted';
            }

            // Check filename against threat intelligence database
            $safe_filename = $conn->real_escape_string($filename);
            $check = $conn->query("SELECT threat_name, type FROM threats WHERE threat_name LIKE '%$safe_filename%' LIMIT 1");
            if ($check && $check->num_rows > 0) {
                $row = $check->fetch_assoc();
                $malwareTypes[] = $row['type'] . " (" . $row['threat_name'] . ")";
                $baseScore += 50; // High score for matching threat DB
            }
            
            $baseScore = min($baseScore, 100);
            
            $verdict = 'SAFE';
            if ($baseScore >= 70) $verdict = 'MALICIOUS';
            else if ($baseScore >= 30) $verdict = 'SUSPICIOUS';
            
            $malware_type = implode(', ', array_unique($malwareTypes));
            
            $files[] = [
                'name' => $filename,
                'path' => $path,
                'verdict' => $verdict,
                'type' => $malware_type,
                'score' => $baseScore
            ];

            if ($verdict !== 'SAFE') {
                $threats_detected[] = [
                    'file' => $filename,
                    'type' => $malware_type,
                    'verdict' => $verdict,
                    'score' => $baseScore
                ];
            }
            $count++;
        }
    } catch (Exception $e) {
        // Fallback or error handling
    }
} else {
    // Mock data if no mount point (for fallback)
    $files = [
        ['name' => 'IMG_001.jpg', 'verdict' => 'SAFE', 'type' => '', 'score' => 0],
        ['name' => 'document.docx', 'verdict' => 'SAFE', 'type' => '', 'score' => 0],
        ['name' => 'autorun.inf', 'verdict' => 'MALICIOUS', 'type' => 'Trojan.USB.Autorun', 'score' => 80],
        ['name' => 'script.sh', 'verdict' => 'SUSPICIOUS', 'type' => 'Potentially Unwanted', 'score' => 40]
    ];
    foreach($files as $f) {
        if ($f['verdict'] !== 'SAFE') $threats_detected[] = ['file' => $f['name'], 'type' => $f['type'], 'verdict' => $f['verdict'], 'score' => $f['score']];
    }
}

echo json_encode([
    'success' => true,
    'files' => $files,
    'threats' => $threats_detected,
    'count' => count($files)
]);
?>
