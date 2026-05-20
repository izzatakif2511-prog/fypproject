<?php
$host = "localhost";
$user = "phpmyadmin";
$password = "Izz@t2511"; // kosong kalau XAMPP
$database = "phpmyadmin";

$conn = new mysqli($host, $user, $password, $database);

// check connection
if ($conn->connect_error) {
    die("Connection failed: " . $conn->connect_error);
}

// echo "Connected successfully"; // test
?>