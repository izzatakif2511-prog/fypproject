<?php
header('Content-Type: application/json');
require 'db.php';

if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    http_response_code(405);
    echo json_encode(['success' => false, 'error' => 'Method not allowed']);
    exit();
}

// Support both JSON and Form Data
$data = json_decode(file_get_contents('php://input'), true);
if (!$data) {
    $data = $_POST;
}

if (!$data) {
    http_response_code(400);
    echo json_encode(['success' => false, 'error' => 'Invalid data']);
    exit();
}

$user_name   = $conn->real_escape_string($data['user_name']   ?? 'Guest User');
$device_name = $conn->real_escape_string($data['device_name'] ?? 'Unknown USB');
$file_count  = (int)($data['file_count']  ?? 0);
$threat_count = (int)($data['threat_count'] ?? 0);
$duration    = $conn->real_escape_string($data['duration']    ?? '0.5s');
$status      = $conn->real_escape_string($data['status']      ?? 'Clean');

// Basic validation for status enum
if (!in_array($status, ['SAFE', 'SUSPICIOUS', 'MALICIOUS'])) {
    $status = ($threat_count > 0) ? 'MALICIOUS' : 'SAFE';
}

$sql = "INSERT INTO usb_scans (user_name, device_name, file_count, threat_count, duration, status) 
        VALUES ('$user_name', '$device_name', $file_count, $threat_count, '$duration', '$status')";

if ($conn->query($sql)) {
    echo json_encode([
        'success' => true, 
        'id' => $conn->insert_id,
        'message' => 'Scan recorded successfully'
    ]);
} else {
    http_response_code(500);
    echo json_encode([
        'success' => false, 
        'error' => $conn->error
    ]);
}
?>
