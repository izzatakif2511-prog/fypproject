<?php
require 'db.php';

// Drop if exists
$conn->query("DROP TABLE IF EXISTS users");

// Create table
$sql = "CREATE TABLE users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    name VARCHAR(100) NOT NULL,
    email VARCHAR(100) NOT NULL,
    role ENUM('Administrator', 'Standard User') DEFAULT 'Standard User',
    status ENUM('active', 'inactive') DEFAULT 'active',
    last_active VARCHAR(50) DEFAULT 'Just now',
    scans INT DEFAULT 0,
    threats INT DEFAULT 0
)";

if ($conn->query($sql) === TRUE) {
    echo "Table users created successfully\n";
} else {
    echo "Error creating table: " . $conn->error . "\n";
}

// Seed data
$seed_data = [
    ['Izzat', 'izzat@company.com', 'Administrator', 'active', '2 minutes ago', 156, 12],
    ['Akif', 'akif@company.com', 'Standard User', 'active', '1 hour ago', 89, 5],
    ['Kamal', 'kamal@company.com', 'Standard User', 'active', '3 hours ago', 45, 2],
    ['Aliff', 'aliff@company.com', 'Standard User', 'active', '5 hours ago', 23, 1],
    ['Shamsul', 'shamsul@company.com', 'Standard User', 'active', '1 day ago', 67, 4]
];

$stmt = $conn->prepare("INSERT INTO users (name, email, role, status, last_active, scans, threats) VALUES (?, ?, ?, ?, ?, ?, ?)");
foreach ($seed_data as $row) {
    $stmt->bind_param("sssssii", $row[0], $row[1], $row[2], $row[3], $row[4], $row[5], $row[6]);
    $stmt->execute();
}

echo "Seed data inserted.\n";
?>
