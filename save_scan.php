<?php
header('Content-Type: application/json');
require 'db.php';

if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    http_response_code(405);
    echo json_encode(['error' => 'Method not allowed']);
    exit();
}

$data = json_decode(file_get_contents('php://input'), true);
if (!$data) {
    http_response_code(400);
    echo json_encode(['error' => 'Invalid JSON']);
    exit();
}

$file_name    = $conn->real_escape_string($data['file_name']    ?? 'unknown');
$file_size    = $conn->real_escape_string($data['file_size']    ?? '0 KB');
$verdict      = $conn->real_escape_string($data['verdict']      ?? 'SAFE');
$risk_score   = (int)($data['risk_score']   ?? 0);
$malware_types = $conn->real_escape_string($data['malware_types'] ?? '');
$ioc_static   = $conn->real_escape_string($data['ioc_static']   ?? '');
$ioc_network  = $conn->real_escape_string($data['ioc_network']  ?? '');
$ioc_filesystem = $conn->real_escape_string($data['ioc_filesystem'] ?? '');
$ioc_behavior = $conn->real_escape_string($data['ioc_behavior'] ?? '');
$has_network     = (int)($data['has_network']     ?? 0);
$has_persistence = (int)($data['has_persistence'] ?? 0);
$has_encryption  = (int)($data['has_encryption']  ?? 0);
$has_dropper     = (int)($data['has_dropper']     ?? 0);
$has_dangerous   = (int)($data['has_dangerous']   ?? 0);
$mitre_ids       = $conn->real_escape_string($data['mitre_ids']   ?? '');

// Validate verdict
$allowed_verdicts = ['SAFE', 'SUSPICIOUS', 'MALICIOUS'];
if (!in_array($verdict, $allowed_verdicts)) $verdict = 'SAFE';
if ($risk_score < 0) $risk_score = 0;
if ($risk_score > 100) $risk_score = 100;

$sql = "INSERT INTO sandbox_scans 
        (file_name, file_size, verdict, risk_score, malware_types, mitre_ids,
         ioc_static, ioc_network, ioc_filesystem, ioc_behavior,
         has_network, has_persistence, has_encryption, has_dropper, has_dangerous)
        VALUES 
        ('$file_name', '$file_size', '$verdict', $risk_score, '$malware_types', '$mitre_ids',
         '$ioc_static', '$ioc_network', '$ioc_filesystem', '$ioc_behavior',
         $has_network, $has_persistence, $has_encryption, $has_dropper, $has_dangerous)";

if ($conn->query($sql)) {
    $inserted_id = $conn->insert_id;

    // --- AUTO-POPULATE THREATS TABLE WITH MISSING MITRE IDs ---
    if (!empty($mitre_ids)) {
        $ids = explode(',', $mitre_ids);
        foreach ($ids as $mid) {
            $mid = trim($mid);
            if (empty($mid)) continue;

            // Check if this MITRE ID already exists in threats table
            $check = $conn->query("SELECT id FROM threats WHERE mitree_id = '$mid' LIMIT 1");
            if ($check && $check->num_rows === 0) {
                // Determine a friendly name based on ID (optional mapping)
                $default_names = [
                    'T1059' => 'Command and Scripting Interpreter',
                    'T1547' => 'Boot or Logon Autostart Execution',
                    'T1105' => 'Ingress Tool Transfer',
                    'T1486' => 'Data Encrypted for Impact',
                    'T1544' => 'Transfer Data to Cloud Account'
                ];
                $name = $default_names[$mid] ?? "Detected Technique ($mid)";
                
                // Determine severity based on verdict
                $auto_sev = 'Medium';
                if ($verdict === 'MALICIOUS')  $auto_sev = 'High';
                if ($verdict === 'SAFE')       $auto_sev = 'Low';

                // Auto-insert missing technique
                $conn->query("INSERT INTO threats (threat_name, type, severity, description, detections, mitree_id) 
                              VALUES ('$name', 'Sandbox Detected', '$auto_sev', 'Automatically identified during sandbox analysis.', 0, '$mid')");
            }
        }
    }

    echo json_encode(['success' => true, 'id' => $inserted_id]);
} else {
    http_response_code(500);
    echo json_encode(['error' => $conn->error]);
}
?>
