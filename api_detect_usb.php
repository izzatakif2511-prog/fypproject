<?php
header('Content-Type: application/json');
require 'db.php';

$usb_devices = [];
$cmd = "lsblk -o NAME,MODEL,VENDOR,SIZE,RM,TRAN,MOUNTPOINT -J";
$output = shell_exec($cmd);
$data = json_decode($output, true);

if (isset($data['blockdevices'])) {
    foreach ($data['blockdevices'] as $dev) {
        // Check if it's a USB device or removable
        $is_usb = (isset($dev['tran']) && $dev['tran'] === 'usb') || ($dev['rm'] == true && strpos($dev['name'], 'sr') !== 0);
        
        if ($is_usb) {
            $mount = $dev['mountpoint'];
            
            // If main device doesn't have mountpoint, check children (partitions)
            if (empty($mount) && isset($dev['children'])) {
                foreach ($dev['children'] as $child) {
                    if (!empty($child['mountpoint'])) {
                        $mount = $child['mountpoint'];
                        break;
                    }
                }
            }

            $usb_devices[] = [
                'name' => $dev['model'] ?? 'USB Flash Drive',
                'vendor' => $dev['vendor'] ?? 'Generic',
                'size' => $dev['size'] ?? 'Unknown',
                'id' => $dev['name'],
                'mount' => $mount
            ];
        }
    }
}

// Get auto-scan setting
$auto_scan = false;
$res = $conn->query("SELECT setting_value FROM settings WHERE setting_key='auto_scan'");
if ($res) {
    $row = $res->fetch_assoc();
    $auto_scan = ($row['setting_value'] === '1');
}

echo json_encode([
    'devices' => $usb_devices,
    'count' => count($usb_devices),
    'auto_scan' => $auto_scan
]);
?>
