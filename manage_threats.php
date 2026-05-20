<?php
require 'admin_auth_check.php';
require 'db.php';

header('Content-Type: application/json');

$action = $_POST['action'] ?? '';

if ($action === 'add') {
    $name = $_POST['threat_name'] ?? '';
    $type = $_POST['type'] ?? '';
    $sev  = $_POST['severity'] ?? '';
    $desc = $_POST['description'] ?? '';
    $det  = $_POST['detections'] ?? 0;
    $mitre = $_POST['mitre_id'] ?? '';

    $stmt = $conn->prepare("INSERT INTO threats (threat_name, type, severity, description, detections, mitree_id) VALUES (?, ?, ?, ?, ?, ?)");
    $stmt->bind_param("ssssis", $name, $type, $sev, $desc, $det, $mitre);
    
    if ($stmt->execute()) {
        echo json_encode(['success' => true]);
    } else {
        echo json_encode(['success' => false, 'error' => $conn->error]);
    }
    $stmt->close();

} elseif ($action === 'edit') {
    $id   = $_POST['id'] ?? 0;
    $name = $_POST['threat_name'] ?? '';
    $type = $_POST['type'] ?? '';
    $sev  = $_POST['severity'] ?? '';
    $desc = $_POST['description'] ?? '';
    $det  = $_POST['detections'] ?? 0;
    $mitre = $_POST['mitre_id'] ?? '';

    $stmt = $conn->prepare("UPDATE threats SET threat_name=?, type=?, severity=?, description=?, detections=?, mitree_id=? WHERE id=?");
    $stmt->bind_param("ssssisi", $name, $type, $sev, $desc, $det, $mitre, $id);
    
    if ($stmt->execute()) {
        echo json_encode(['success' => true]);
    } else {
        echo json_encode(['success' => false, 'error' => $conn->error]);
    }
    $stmt->close();

} elseif ($action === 'delete') {
    $id = $_POST['id'] ?? 0;
    $stmt = $conn->prepare("DELETE FROM threats WHERE id = ?");
    $stmt->bind_param("i", $id);
    
    if ($stmt->execute()) {
        echo json_encode(['success' => true]);
    } else {
        echo json_encode(['success' => false, 'error' => $conn->error]);
    }
    $stmt->close();

} else {
    echo json_encode(['success' => false, 'error' => 'Invalid action.']);
}
?>
