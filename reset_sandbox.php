<?php
require 'admin_auth_check.php';
require 'db.php';

header('Content-Type: application/json');

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    // Truncate the table to reset all history and auto-increment
    $sql = "TRUNCATE TABLE sandbox_scans";
    
    if ($conn->query($sql)) {
        echo json_encode(['success' => true, 'message' => 'Sandbox scan history reset successfully.']);
    } else {
        echo json_encode(['success' => false, 'error' => $conn->error]);
    }
} else {
    echo json_encode(['success' => false, 'error' => 'Invalid request method.']);
}
?>
