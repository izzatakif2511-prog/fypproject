<?php
require 'admin_auth_check.php';
require 'db.php';

// Handle Delete
if (isset($_GET['delete_id'])) {
    $del_id = (int)$_GET['delete_id'];
    $conn->query("DELETE FROM users WHERE id = $del_id");
    header("Location: usermanagement.php");
    exit();
}

// Handle Edit
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['edit_id'])) {
    $edit_id = (int)$_POST['edit_id'];
    $new_name = $conn->real_escape_string($_POST['new_name']);
    $new_role = $conn->real_escape_string($_POST['new_role']);
    $conn->query("UPDATE users SET name = '$new_name', role = '$new_role' WHERE id = $edit_id");
    header("Location: usermanagement.php");
    exit();
}

// Fetch Users and Count Data
$users = [];
$total_users = 0;
$active_users = 0;
$admins = 0;
$standards = 0;

$result = $conn->query("SELECT * FROM users ORDER BY id ASC");
if ($result) {
    while($row = $result->fetch_assoc()) {
        $users[] = $row;
        $total_users++;
        if ($row['status'] === 'active') $active_users++;
        if ($row['role'] === 'Administrator') $admins++;
        if ($row['role'] === 'Standard User') $standards++;
    }
}
?>
<!DOCTYPE html>
<html lang="en">

<head>
    <meta charset="UTF-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1.0" />
    <title>User Management - Administrator Portal</title>
    <link rel="stylesheet" href="usermanagement.css">
    <script src="https://unpkg.com/@phosphor-icons/web"></script>
</head>

<body>

    <!-- ===== TOP HEADER ===== -->
    <header class="topbar">
        <div class="top-left">
            <button class="back-btn" onclick="window.location.href='admin.php?logout=1'">
                <i class="ph ph-arrow-left"></i> Back
            </button>

            <!-- LOGO -->
            <div class="logo-box">
                <div class="logo-icon">
                    <i class="ph-fill ph-shield-check" style="color: white; font-size: 24px;"></i>
                </div>
                <div>
                    <div class="portal-title">Administrator Portal</div>
                    <div class="portal-sub">System Information & Security Cabinet</div>
                </div>
            </div>
        </div>

        <div class="top-right">
            <div class="admin-info">
                <div class="admin-name">Administrator Area</div>
                <div class="admin-role">Security Level 10</div>
            </div>
            <i class="ph ph-user-circle" style="font-size: 32px; color: #3b82f6;"></i>
        </div>
    </header>

    <!-- ===== NAVBAR ===== -->
    <nav class="menu-bar">
        <a class="menu-item" href="report.php">Report</a>
        <a class="menu-item" href="allscans.php">All Scans</a>
        <a class="menu-item" href="sandbox.php">Sandbox</a>
        <a class="menu-item" href="threatAnalysis.php">Threat Analysis</a>
        <a class="menu-item active" href="usermanagement.php">User Management</a>
        <a class="menu-item" href="setting.php">Settings</a>
    </nav>

    <!-- ===== MAIN ===== -->
    <div class="container">

        <!-- title -->
        <div class="section-header">
            <div>
                <h1>User Management</h1>
                <p>Manage system users, roles, and security permissions</p>
            </div>
            <button class="btn-primary" onclick="alert('Add user feature coming soon!')">
                <i class="ph ph-plus"></i> Add New User
            </button>
        </div>

        <!-- search -->
        <div class="search-box">
            <input type="text" id="userSearch" placeholder="Search users by name, email or role..." onkeyup="filterTable()">
        </div>

        <!-- stats -->
        <div class="stats-grid">
            <div class="stat-card">
                <h2><?= $total_users ?></h2>
                <span>Total Users</span>
            </div>
            <div class="stat-card" style="border-left: 4px solid #10b981;">
                <h2><?= $active_users ?></h2>
                <span>Active Users</span>
            </div>
            <div class="stat-card" style="border-left: 4px solid #3b82f6;">
                <h2><?= $admins ?></h2>
                <span>Administrators</span>
            </div>
            <div class="stat-card" style="border-left: 4px solid #94a3b8;">
                <h2><?= $standards ?></h2>
                <span>Standard Users</span>
            </div>
        </div>

        <!-- table -->
        <div class="table-wrapper">
            <table>
                <thead>
                    <tr>
                        <th>User</th>
                        <th>Role</th>
                        <th>Status</th>
                        <th>Last Active</th>
                        <th>Scans</th>
                        <th>Threats</th>
                        <th>Actions</th>
                    </tr>
                </thead>

                <tbody>
                    <?php if (empty($users)): ?>
                        <tr><td colspan="7" style="text-align: center; padding: 40px; color: #64748b;">No users found in system.</td></tr>
                    <?php else: ?>
                        <?php foreach($users as $u): 
                            $initial = strtoupper(substr($u['name'], 0, 1));
                            $isAdmin = ($u['role'] === 'Administrator');
                            $role_class = $isAdmin ? 'role admin-role' : 'role';
                            $avatar_class = $isAdmin ? 'avatar admin' : 'avatar';
                        ?>
                        <tr>
                            <td>
                                <div class="user-cell">
                                    <div class="<?= $avatar_class ?>"><?= $initial ?></div>
                                    <div>
                                        <div class="name"><?= htmlspecialchars($u['name']) ?></div>
                                        <div class="email"><?= htmlspecialchars($u['email']) ?></div>
                                    </div>
                                </div>
                            </td>
                            <td><span class="<?= $role_class ?>"><?= htmlspecialchars($u['role']) ?></span></td>
                            <td><span class="status <?= htmlspecialchars($u['status']) ?>">● <?= ucfirst(htmlspecialchars($u['status'])) ?></span></td>
                            <td style="color: #64748b; font-size: 0.8rem;"><?= htmlspecialchars($u['last_active']) ?></td>
                            <td><span style="font-weight: 600;"><?= $u['scans'] ?></span></td>
                            <td><span class="threat"><?= $u['threats'] ?></span></td>
                            <td class="actions">
                                <button class="action-btn" onclick="openEditModal(<?= $u['id'] ?>, '<?= addslashes($u['name']) ?>', '<?= addslashes($u['role']) ?>')">
                                    <i class="ph ph-note-pencil"></i> Edit
                                </button>
                                <button class="action-btn delete" onclick="if(confirm('Are you sure you want to delete <?= addslashes($u['name']) ?>?')) { window.location.href='usermanagement.php?delete_id=<?= $u['id'] ?>'; }">
                                    <i class="ph ph-trash"></i> Delete
                                </button>
                            </td>
                        </tr>
                        <?php endforeach; ?>
                    <?php endif; ?>
                </tbody>
            </table>
        </div>

    </div>

    <!-- Edit Modal -->
    <div id="editModal" class="modal">
        <div class="modal-content">
            <h3 style="margin-bottom: 20px; font-weight: 800;">Edit User Context</h3>
            <form method="POST" action="usermanagement.php">
                <input type="hidden" name="edit_id" id="edit_id">
                
                <label style="font-size: 13px; font-weight: 600; color: #94a3b8;">User Display Name</label>
                <input type="text" name="new_name" id="edit_name" required>
                
                <label style="font-size: 13px; font-weight: 600; color: #94a3b8;">System Role</label>
                <select name="new_role" id="edit_role">
                    <option value="Standard User">Standard User Account</option>
                    <option value="Administrator">Administrator Access</option>
                </select>
                
                <button type="submit" class="save">Apply Changes</button>
                <button type="button" class="cancel" onclick="closeEditModal()">Dismiss</button>
            </form>
        </div>
    </div>

    <script>
        function openEditModal(id, name, role) {
            document.getElementById('edit_id').value = id;
            document.getElementById('edit_name').value = name;
            document.getElementById('edit_role').value = role;
            document.getElementById('editModal').style.display = 'flex';
        }

        function closeEditModal() {
            document.getElementById('editModal').style.display = 'none';
        }

        function filterTable() {
            let input = document.getElementById("userSearch");
            let filter = input.value.toLowerCase();
            let table = document.querySelector("table");
            let tr = table.getElementsByTagName("tr");

            for (let i = 1; i < tr.length; i++) {
                let nameCell = tr[i].getElementsByClassName("name")[0];
                let emailCell = tr[i].getElementsByClassName("email")[0];
                let roleCell = tr[i].getElementsByClassName("role")[0];
                
                if (nameCell || emailCell || roleCell) {
                    let txtValue = (nameCell ? nameCell.textContent : "") + " " + 
                                   (emailCell ? emailCell.textContent : "") + " " + 
                                   (roleCell ? roleCell.textContent : "");
                                   
                    if (txtValue.toLowerCase().indexOf(filter) > -1) {
                        tr[i].style.display = "";
                    } else {
                        tr[i].style.display = "none";
                    }
                }
            }
        }
        
        // Close modal when clicking outside
        window.onclick = function(event) {
            let modal = document.getElementById('editModal');
            if (event.target == modal) {
                closeEditModal();
            }
        }
    </script>
</body>
</html>
