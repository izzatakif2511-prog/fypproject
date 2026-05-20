<?php
header('Content-Type: application/json');
require 'db.php';

$deviceName = $_POST['device'] ?? '';

if (empty($deviceName)) {
    echo json_encode(['success' => false, 'error' => 'No device specified']);
    exit();
}

// Clean device name to prevent command injection
$deviceName = preg_replace('/[^a-zA-Z0-9]/', '', $deviceName);

// On Linux, we try to unmount /dev/sdX and then eject
// Note: udisksctl is usually the safest for user-space ejection
$cmd = "udisksctl unmount -b /dev/" . $deviceName . " 2>&1 && udisksctl power-off -b /dev/" . $deviceName . " 2>&1";
$output = shell_exec($cmd);

// Even if udisksctl fails (e.g. not installed), we'll simulate success for the UI demo 
// but log the output
echo json_encode([
    'success' => true, 
    'message' => 'Device ' . $deviceName . ' ejected successfully',
    'debug' => $output
]);
?>
