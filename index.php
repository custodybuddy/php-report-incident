<?php
// config.php - Database Configuration
class Database {
    private $db;
    
    public function __construct() {
        try {
            $this->db = new PDO('sqlite:' . __DIR__ . '/custodybuddy.db');
            $this->db->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
            $this->createTables();
        } catch(PDOException $e) {
            die("Database Error: " . $e->getMessage());
        }
    }
    
    private function createTables() {
        // Main incidents table
        $this->db->exec("
            CREATE TABLE IF NOT EXISTS incidents (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                incident_date DATETIME NOT NULL,
                incident_type VARCHAR(100) NOT NULL,
                location TEXT,
                communication_method VARCHAR(50),
                witnesses TEXT,
                children_present TEXT,
                description TEXT NOT NULL,
                direct_quotes TEXT,
                child_impact TEXT,
                your_response TEXT,
                evidence_list TEXT,
                legal_violations TEXT,
                pattern_notes TEXT,
                status VARCHAR(20) DEFAULT 'open',
                follow_up_at DATETIME,
                urgency_level VARCHAR(20) DEFAULT 'medium',
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        ");

        $this->addColumnIfMissing('incidents', 'status', "VARCHAR(20) DEFAULT 'open'");
        $this->addColumnIfMissing('incidents', 'follow_up_at', 'DATETIME');

        $this->db->exec("
            CREATE TABLE IF NOT EXISTS incident_evidence (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                incident_id INTEGER NOT NULL,
                file_name TEXT NOT NULL,
                original_name TEXT NOT NULL,
                mime_type TEXT NOT NULL,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (incident_id) REFERENCES incidents(id) ON DELETE CASCADE
            )
        ");

        $this->db->exec("
            CREATE TABLE IF NOT EXISTS shared_access (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                invite_token TEXT UNIQUE NOT NULL,
                incident_id INTEGER NOT NULL,
                role TEXT NOT NULL,
                expires_at DATETIME,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (incident_id) REFERENCES incidents(id) ON DELETE CASCADE
            )
        ");
        
        // Follow-up notes table
        $this->db->exec("
            CREATE TABLE IF NOT EXISTS incident_updates (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                incident_id INTEGER NOT NULL,
                update_text TEXT NOT NULL,
                update_type VARCHAR(50) DEFAULT 'general',
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (incident_id) REFERENCES incidents(id) ON DELETE CASCADE
            )
        ");
        
        // Pattern tracking table
        $this->db->exec("
            CREATE TABLE IF NOT EXISTS behavior_patterns (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                pattern_name VARCHAR(200) NOT NULL,
                pattern_description TEXT,
                incident_count INTEGER DEFAULT 0,
                first_occurrence DATE,
                last_occurrence DATE,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        ");

        // Users table for simple authentication
        $this->db->exec("
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password TEXT NOT NULL,
                email TEXT,
                must_reset INTEGER DEFAULT 0,
                reset_token TEXT,
                reset_expires DATETIME,
                failed_attempts INTEGER DEFAULT 0,
                last_failed_at DATETIME,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        ");

        $this->addColumnIfMissing('users', 'email', 'TEXT');
        $this->addColumnIfMissing('users', 'must_reset', 'INTEGER DEFAULT 0');
        $this->addColumnIfMissing('users', 'reset_token', 'TEXT');
        $this->addColumnIfMissing('users', 'reset_expires', 'DATETIME');
        $this->addColumnIfMissing('users', 'failed_attempts', 'INTEGER DEFAULT 0');
        $this->addColumnIfMissing('users', 'last_failed_at', 'DATETIME');

        $this->seedDefaultUser();
    }

    public function getConnection() {
        return $this->db;
    }

    private function seedDefaultUser(): void {
        $stmt = $this->db->query("SELECT COUNT(*) FROM users");
        if ((int) $stmt->fetchColumn() === 0) {
            $passwordHash = password_hash('password', PASSWORD_DEFAULT);
            $insert = $this->db->prepare("INSERT INTO users (username, password, must_reset) VALUES (?, ?, 1)");
            $insert->execute(['admin', $passwordHash]);
        }
    }

    private function addColumnIfMissing(string $table, string $column, string $definition): void
    {
        $stmt = $this->db->prepare("PRAGMA table_info($table)");
        $stmt->execute();
        $columns = $stmt->fetchAll(PDO::FETCH_ASSOC);
        foreach ($columns as $col) {
            if ($col['name'] === $column) {
                return;
            }
        }

        $this->db->exec("ALTER TABLE $table ADD COLUMN $column $definition");
    }
}

// index.php - Main Application
session_start();
$db = new Database();
$conn = $db->getConnection();
$uploadDir = __DIR__ . '/uploads';
if (!is_dir($uploadDir)) {
    mkdir($uploadDir, 0755, true);
}

$view = $_GET['view'] ?? 'dashboard';
$action = $_POST['action'] ?? null;
$shareToken = $_GET['share_token'] ?? ($_POST['share_token'] ?? '');
$shareAccess = null;

function validateShareAccess(PDO $conn, string $token): ?array {
    if ($token === '') {
        return null;
    }

    $stmt = $conn->prepare("SELECT * FROM shared_access WHERE invite_token = ?");
    $stmt->execute([$token]);
    $share = $stmt->fetch(PDO::FETCH_ASSOC);

    if (!$share) {
        return null;
    }

    if (!empty($share['expires_at']) && strtotime($share['expires_at']) < time()) {
        return null;
    }

    return $share;
}

$shareAccess = validateShareAccess($conn, $shareToken);

function currentUser(PDO $conn): ?array {
    if (empty($_SESSION['user_id'])) {
        return null;
    }

    $stmt = $conn->prepare("SELECT id, username FROM users WHERE id = ?");
    $stmt->execute([$_SESSION['user_id']]);
    return $stmt->fetch(PDO::FETCH_ASSOC) ?: null;
}

function requireAuth(PDO $conn): void {
    if (!currentUser($conn)) {
        header('Location: index.php?view=login');
        exit;
    }
}

$publicViews = ['login', 'reset'];
$publicActions = ['login', 'request_reset', 'complete_reset'];
$incidentScopeId = isset($_GET['id']) ? (int) $_GET['id'] : (isset($_GET['export']) ? (int) $_GET['export'] : (isset($_GET['download_evidence']) ? (int) $_GET['download_evidence'] : null));

function canUseSharedAccess(?array $shareAccess, string $view, ?int $incidentId = null): bool
{
    if (!$shareAccess) {
        return false;
    }

    $allowedViews = ['detail'];
    $isDownload = isset($_GET['download_evidence']);
    $isExport = isset($_GET['export']);

    if ($isDownload || $isExport) {
        return true;
    }

    return in_array($view, $allowedViews, true) && ($incidentId === null || $shareAccess['incident_id'] === $incidentId);
}

if (!in_array($view, $publicViews, true) && !in_array($action, $publicActions, true) && !canUseSharedAccess($shareAccess, $view, $incidentScopeId)) {
    requireAuth($conn);
}

function validateIncident(array $data): array {
    $errors = [];

    $incidentDate = trim($data['incident_date'] ?? '');
    $incidentType = trim($data['incident_type'] ?? '');
    $description = trim($data['description'] ?? '');
    $urgency = $data['urgency_level'] ?? '';
    $status = $data['status'] ?? 'open';

    if ($incidentDate === '') {
        $errors[] = 'Incident date is required.';
    } else {
        $date = DateTime::createFromFormat('Y-m-d\TH:i', $incidentDate);
        if (!$date || $date->format('Y-m-d\TH:i') !== $incidentDate) {
            $errors[] = 'Incident date must be in ISO datetime format.';
        }
    }

    if ($incidentType === '') {
        $errors[] = 'Incident type is required.';
    }

    if ($description === '') {
        $errors[] = 'Description is required.';
    }

    $allowedStatus = ['open', 'in-progress', 'resolved', 'escalated'];
    if (!in_array($status, $allowedStatus, true)) {
        $errors[] = 'Status is invalid.';
    }

    $allowedUrgency = ['low', 'medium', 'high'];
    if (!in_array($urgency, $allowedUrgency, true)) {
        $errors[] = 'Urgency level is invalid.';
    }

    return $errors;
}

function deriveFollowUpAt(string $urgency): string
{
    $intervals = [
        'low' => '+7 days',
        'medium' => '+3 days',
        'high' => '+1 day',
    ];

    $target = $intervals[$urgency] ?? '+3 days';
    return (new DateTime($target))->format('Y-m-d\TH:i');
}

function isAllowedMime(string $mime): bool
{
    $allowed = [
        'image/jpeg', 'image/png', 'image/gif',
        'application/pdf',
    ];
    return in_array($mime, $allowed, true);
}

function handleEvidenceUploads(PDO $conn, int $incidentId, string $uploadDir): array
{
    if (empty($_FILES['evidence_files']) || !is_array($_FILES['evidence_files']['name'])) {
        return [];
    }

    $stored = [];
    $fileCount = count($_FILES['evidence_files']['name']);
    $finfo = new finfo(FILEINFO_MIME_TYPE);

    for ($i = 0; $i < $fileCount; $i++) {
        $error = $_FILES['evidence_files']['error'][$i];
        if ($error === UPLOAD_ERR_NO_FILE) {
            continue;
        }

        if ($error !== UPLOAD_ERR_OK) {
            throw new RuntimeException('Upload failed for evidence file.');
        }

        $tmpName = $_FILES['evidence_files']['tmp_name'][$i];
        $size = (int) $_FILES['evidence_files']['size'][$i];
        $originalName = basename($_FILES['evidence_files']['name'][$i]);
        $mime = $finfo->file($tmpName) ?: '';

        if ($size > 10 * 1024 * 1024) {
            throw new RuntimeException('Evidence file exceeds 10MB limit.');
        }

        if (!isAllowedMime($mime)) {
            throw new RuntimeException('Unsupported evidence type: ' . $mime);
        }

        $ext = pathinfo($originalName, PATHINFO_EXTENSION);
        $randomName = bin2hex(random_bytes(16)) . ($ext ? ('.' . $ext) : '');
        $targetPath = rtrim($uploadDir, DIRECTORY_SEPARATOR) . DIRECTORY_SEPARATOR . $randomName;

        if (!move_uploaded_file($tmpName, $targetPath)) {
            throw new RuntimeException('Failed to store evidence file.');
        }

        $stmt = $conn->prepare("INSERT INTO incident_evidence (incident_id, file_name, original_name, mime_type) VALUES (?, ?, ?, ?)");
        $stmt->execute([$incidentId, $randomName, $originalName, $mime]);
        $stored[] = $randomName;
    }

    return $stored;
}

function validateUpdate(array $data): array {
    $errors = [];

    $updateText = trim($data['update_text'] ?? '');
    $updateType = $data['update_type'] ?? '';
    $allowedTypes = ['general', 'escalation', 'resolution', 'legal_action', 'follow_up'];

    if ($updateText === '') {
        $errors[] = 'Update text is required.';
    }

    if (!in_array($updateType, $allowedTypes, true)) {
        $errors[] = 'Update type is invalid.';
    }

    return $errors;
}

// Handle form submissions
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if (isset($_POST['action'])) {
        switch ($_POST['action']) {
            case 'login':
                $username = trim($_POST['username'] ?? '');
                $password = $_POST['password'] ?? '';

                if ($username === '' || $password === '') {
                    $_SESSION['message'] = '❌ Username and password are required.';
                    $_SESSION['message_type'] = 'error';
                    header('Location: index.php?view=login');
                    exit;
                }

                $stmt = $conn->prepare("SELECT * FROM users WHERE username = ?");
                $stmt->execute([$username]);
                $user = $stmt->fetch(PDO::FETCH_ASSOC);

                if ($user) {
                    $cooldownMinutes = 15;
                    if ((int) $user['failed_attempts'] >= 5 && !empty($user['last_failed_at'])) {
                        $lastFailure = new DateTime($user['last_failed_at']);
                        $window = (new DateTime())->modify('-' . $cooldownMinutes . ' minutes');
                        if ($lastFailure > $window) {
                            $_SESSION['message'] = '⏳ Too many attempts. Please wait a few minutes before trying again.';
                            $_SESSION['message_type'] = 'error';
                            header('Location: index.php?view=login');
                            exit;
                        }
                    }
                }

                if (!$user || !password_verify($password, $user['password'])) {
                    if ($user) {
                        $conn->prepare("UPDATE users SET failed_attempts = failed_attempts + 1, last_failed_at = CURRENT_TIMESTAMP WHERE id = ?")
                            ->execute([$user['id']]);
                    }
                    $_SESSION['message'] = '❌ Invalid credentials. Try admin/password to begin.';
                    $_SESSION['message_type'] = 'error';
                    header('Location: index.php?view=login');
                    exit;
                }

                $conn->prepare("UPDATE users SET failed_attempts = 0, last_failed_at = NULL WHERE id = ?")
                    ->execute([$user['id']]);
                $_SESSION['user_id'] = $user['id'];
                $_SESSION['message'] = '✅ Welcome back, ' . htmlspecialchars($user['username']) . '!';
                $_SESSION['message_type'] = 'success';
                if ((int) $user['must_reset'] === 1) {
                    header('Location: index.php?view=settings');
                } else {
                    header('Location: index.php');
                }
                exit;

            case 'update_password':
                requireAuth($conn);
                $current = $_POST['current_password'] ?? '';
                $new = $_POST['new_password'] ?? '';
                $confirm = $_POST['confirm_password'] ?? '';

                $user = currentUser($conn);
                $stmt = $conn->prepare('SELECT password FROM users WHERE id = ?');
                $stmt->execute([$user['id']]);
                $hashed = $stmt->fetchColumn();

                if (!$hashed || !password_verify($current, $hashed)) {
                    $_SESSION['message'] = '❌ Current password is incorrect.';
                    $_SESSION['message_type'] = 'error';
                    header('Location: index.php?view=settings');
                    exit;
                }

                if ($new === '' || $new !== $confirm) {
                    $_SESSION['message'] = '❌ New password and confirmation must match.';
                    $_SESSION['message_type'] = 'error';
                    header('Location: index.php?view=settings');
                    exit;
                }

                $conn->prepare('UPDATE users SET password = ?, must_reset = 0, reset_token = NULL, reset_expires = NULL WHERE id = ?')
                    ->execute([password_hash($new, PASSWORD_DEFAULT), $user['id']]);

                $_SESSION['message'] = '✅ Password updated successfully.';
                $_SESSION['message_type'] = 'success';
                header('Location: index.php?view=settings');
                exit;

            case 'create_user':
                requireAuth($conn);
                $username = trim($_POST['new_username'] ?? '');
                $email = trim($_POST['new_email'] ?? '');
                $password = $_POST['new_password'] ?? '';
                $confirm = $_POST['new_password_confirm'] ?? '';

                if ($username === '' || $password === '') {
                    $_SESSION['message'] = '❌ Username and password are required for new accounts.';
                    $_SESSION['message_type'] = 'error';
                    header('Location: index.php?view=settings');
                    exit;
                }

                if ($password !== $confirm) {
                    $_SESSION['message'] = '❌ Passwords do not match for new account.';
                    $_SESSION['message_type'] = 'error';
                    header('Location: index.php?view=settings');
                    exit;
                }

                try {
                    $conn->prepare('INSERT INTO users (username, email, password) VALUES (?, ?, ?)')->execute([
                        $username,
                        $email,
                        password_hash($password, PASSWORD_DEFAULT)
                    ]);
                    $_SESSION['message'] = '✅ User created.';
                    $_SESSION['message_type'] = 'success';
                } catch (PDOException $e) {
                    $_SESSION['message'] = '❌ Unable to create user: ' . $e->getMessage();
                    $_SESSION['message_type'] = 'error';
                }
                header('Location: index.php?view=settings');
                exit;

            case 'request_reset':
                $username = trim($_POST['username'] ?? '');
                if ($username === '') {
                    $_SESSION['message'] = '❌ Username is required to request a reset.';
                    $_SESSION['message_type'] = 'error';
                    header('Location: index.php?view=login');
                    exit;
                }

                $stmt = $conn->prepare('SELECT id, email FROM users WHERE username = ?');
                $stmt->execute([$username]);
                $user = $stmt->fetch(PDO::FETCH_ASSOC);
                if ($user) {
                    $token = bin2hex(random_bytes(16));
                    $expires = (new DateTime('+30 minutes'))->format('Y-m-d H:i:s');
                    $conn->prepare('UPDATE users SET reset_token = ?, reset_expires = ?, must_reset = 1 WHERE id = ?')->execute([
                        $token,
                        $expires,
                        $user['id']
                    ]);
                    $_SESSION['message'] = '📨 Reset link generated. Use the token: ' . htmlspecialchars($token) . ' within 30 minutes.';
                    $_SESSION['message_type'] = 'success';
                } else {
                    $_SESSION['message'] = '❌ Account not found.';
                    $_SESSION['message_type'] = 'error';
                }
                header('Location: index.php?view=login');
                exit;

            case 'complete_reset':
                $token = trim($_POST['token'] ?? '');
                $new = $_POST['new_password'] ?? '';
                $confirm = $_POST['confirm_password'] ?? '';

                $stmt = $conn->prepare('SELECT id, reset_expires FROM users WHERE reset_token = ?');
                $stmt->execute([$token]);
                $user = $stmt->fetch(PDO::FETCH_ASSOC);
                if (!$user || empty($token)) {
                    $_SESSION['message'] = '❌ Invalid reset token.';
                    $_SESSION['message_type'] = 'error';
                    header('Location: index.php?view=login');
                    exit;
                }

                if (strtotime($user['reset_expires']) < time()) {
                    $_SESSION['message'] = '❌ Reset token expired.';
                    $_SESSION['message_type'] = 'error';
                    header('Location: index.php?view=login');
                    exit;
                }

                if ($new === '' || $new !== $confirm) {
                    $_SESSION['message'] = '❌ Passwords must match for reset.';
                    $_SESSION['message_type'] = 'error';
                    header('Location: index.php?view=reset&token=' . urlencode($token));
                    exit;
                }

                $conn->prepare('UPDATE users SET password = ?, reset_token = NULL, reset_expires = NULL, must_reset = 0, failed_attempts = 0, last_failed_at = NULL WHERE id = ?')
                    ->execute([password_hash($new, PASSWORD_DEFAULT), $user['id']]);
                $_SESSION['message'] = '✅ Password reset. You can log in now.';
                $_SESSION['message_type'] = 'success';
                header('Location: index.php?view=login');
                exit;

            case 'send_reminder_email':
                requireAuth($conn);
                $incidentId = (int) ($_POST['incident_id'] ?? 0);
                $email = trim($_POST['email'] ?? '');
                if ($incidentId === 0 || $email === '') {
                    $_SESSION['message'] = '❌ Email address is required.';
                    $_SESSION['message_type'] = 'error';
                    header('Location: index.php?view=dashboard');
                    exit;
                }
                $stmt = $conn->prepare('SELECT incident_type, follow_up_at FROM incidents WHERE id = ?');
                $stmt->execute([$incidentId]);
                $incident = $stmt->fetch(PDO::FETCH_ASSOC);
                if (!$incident) {
                    $_SESSION['message'] = '❌ Incident not found for reminder.';
                    $_SESSION['message_type'] = 'error';
                    header('Location: index.php?view=dashboard');
                    exit;
                }
                $subject = 'Incident #' . $incidentId . ' follow-up reminder';
                $body = 'Reminder: Incident "' . $incident['incident_type'] . '" follow-up due ' . $incident['follow_up_at'];
                @mail($email, $subject, $body);
                $_SESSION['message'] = '✅ Reminder email triggered to ' . htmlspecialchars($email);
                $_SESSION['message_type'] = 'success';
                header('Location: index.php?view=dashboard');
                exit;

            case 'create_incident':
                requireAuth($conn);
                $incidentData = [
                    'incident_date' => $_POST['incident_date'] ?? '',
                    'incident_type' => $_POST['incident_type'] ?? '',
                    'location' => $_POST['location'] ?? '',
                    'communication_method' => $_POST['communication_method'] ?? '',
                    'witnesses' => $_POST['witnesses'] ?? '',
                    'children_present' => $_POST['children_present'] ?? '',
                    'description' => $_POST['description'] ?? '',
                    'direct_quotes' => $_POST['direct_quotes'] ?? '',
                    'child_impact' => $_POST['child_impact'] ?? '',
                    'your_response' => $_POST['your_response'] ?? '',
                    'evidence_list' => $_POST['evidence_list'] ?? '',
                    'legal_violations' => $_POST['legal_violations'] ?? '',
                    'pattern_notes' => $_POST['pattern_notes'] ?? '',
                    'urgency_level' => $_POST['urgency_level'] ?? '',
                    'status' => $_POST['status'] ?? 'open',
                    'follow_up_at' => $_POST['follow_up_at'] ?? ''
                ];

                $incidentData = array_map(function ($value) {
                    return is_string($value) ? trim($value) : $value;
                }, $incidentData);

                $errors = validateIncident($incidentData);
                if (!empty($errors)) {
                    $_SESSION['message'] = '❌ Unable to create incident: ' . implode(' ', $errors);
                    $_SESSION['message_type'] = 'error';
                    header('Location: index.php');
                    exit;
                }

                $followUpAt = $incidentData['follow_up_at'] !== '' ? $incidentData['follow_up_at'] : deriveFollowUpAt($incidentData['urgency_level']);

                $stmt = $conn->prepare("
                    INSERT INTO incidents (incident_date, incident_type, location, communication_method,
                                         witnesses, children_present, description, direct_quotes,
                                         child_impact, your_response, evidence_list, legal_violations,
                                         pattern_notes, urgency_level, status, follow_up_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ");

                $stmt->execute([
                    $incidentData['incident_date'],
                    $incidentData['incident_type'],
                    $incidentData['location'],
                    $incidentData['communication_method'],
                    $incidentData['witnesses'],
                    $incidentData['children_present'],
                    $incidentData['description'],
                    $incidentData['direct_quotes'],
                    $incidentData['child_impact'],
                    $incidentData['your_response'],
                    $incidentData['evidence_list'],
                    $incidentData['legal_violations'],
                    $incidentData['pattern_notes'],
                    $incidentData['urgency_level'],
                    $incidentData['status'],
                    $followUpAt
                ]);

                $incidentId = (int) $conn->lastInsertId();
                try {
                    handleEvidenceUploads($conn, $incidentId, $uploadDir);
                } catch (Throwable $e) {
                    $_SESSION['message'] = '⚠️ Incident saved but evidence upload failed: ' . $e->getMessage();
                    $_SESSION['message_type'] = 'error';
                    header('Location: index.php?view=detail&id=' . $incidentId);
                    exit;
                }

                $_SESSION['message'] = "✅ Incident #" . $incidentId . " documented successfully!";
                $_SESSION['message_type'] = "success";
                header('Location: index.php');
                exit;

            case 'add_update':
                requireAuth($conn);
                $updateData = [
                    'incident_id' => $_POST['incident_id'] ?? '',
                    'update_text' => $_POST['update_text'] ?? '',
                    'update_type' => $_POST['update_type'] ?? ''
                ];

                $updateData = array_map(function ($value) {
                    return is_string($value) ? trim($value) : $value;
                }, $updateData);

                $errors = validateUpdate($updateData);
                if (!empty($errors)) {
                    $_SESSION['message'] = '❌ Unable to add update: ' . implode(' ', $errors);
                    $_SESSION['message_type'] = 'error';
                    header('Location: index.php?view=detail&id=' . $updateData['incident_id']);
                    exit;
                }

                $stmt = $conn->prepare("
                    INSERT INTO incident_updates (incident_id, update_text, update_type)
                    VALUES (?, ?, ?)
                ");
                $stmt->execute([
                    $updateData['incident_id'],
                    $updateData['update_text'],
                    $updateData['update_type']
                ]);
                
                $stmt = $conn->prepare("UPDATE incidents SET updated_at = CURRENT_TIMESTAMP WHERE id = ?");
                $stmt->execute([$_POST['incident_id']]);
                
                $_SESSION['message'] = "✅ Update added successfully!";
                $_SESSION['message_type'] = "success";
                header('Location: index.php?view=detail&id=' . $_POST['incident_id']);
                exit;

            case 'update_status':
                requireAuth($conn);
                $incidentId = (int) ($_POST['incident_id'] ?? 0);
                $status = $_POST['status'] ?? 'open';
                $allowedStatus = ['open', 'in-progress', 'resolved', 'escalated'];
                if (!in_array($status, $allowedStatus, true)) {
                    $_SESSION['message'] = '❌ Invalid status selection';
                    $_SESSION['message_type'] = 'error';
                    header('Location: index.php?view=detail&id=' . $incidentId);
                    exit;
                }

                $stmt = $conn->prepare("UPDATE incidents SET status = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?");
                $stmt->execute([$status, $incidentId]);

                $_SESSION['message'] = '✅ Status updated to ' . strtoupper($status);
                $_SESSION['message_type'] = 'success';
                header('Location: index.php?view=detail&id=' . $incidentId);
                exit;

            case 'create_share':
                requireAuth($conn);
                $incidentId = (int) ($_POST['incident_id'] ?? 0);
                $role = $_POST['role'] ?? 'viewer';
                $expiresAt = $_POST['expires_at'] ?? '';
                $token = bin2hex(random_bytes(16));

                $stmt = $conn->prepare("INSERT INTO shared_access (invite_token, incident_id, role, expires_at) VALUES (?, ?, ?, ?)");
                $stmt->execute([$token, $incidentId, $role, $expiresAt]);

                $_SESSION['message'] = '✅ Share link created';
                $_SESSION['message_type'] = 'success';
                header('Location: index.php?view=detail&id=' . $incidentId);
                exit;

            case 'revoke_share':
                requireAuth($conn);
                $incidentId = (int) ($_POST['incident_id'] ?? 0);
                $shareId = (int) ($_POST['share_id'] ?? 0);
                $stmt = $conn->prepare("DELETE FROM shared_access WHERE id = ?");
                $stmt->execute([$shareId]);

                $_SESSION['message'] = '🛡️ Share link revoked';
                $_SESSION['message_type'] = 'info';
                header('Location: index.php?view=detail&id=' . $incidentId);
                exit;

            case 'delete_incident':
                requireAuth($conn);
                $stmt = $conn->prepare("DELETE FROM incidents WHERE id = ?");
                $stmt->execute([$_POST['incident_id']]);
                $_SESSION['message'] = "🗑️ Incident deleted";
                $_SESSION['message_type'] = "info";
                header('Location: index.php');
                exit;
        }
    }
}

if ($view === 'logout') {
    session_destroy();
    session_start();
    $_SESSION['message'] = '👋 You have been logged out.';
    $_SESSION['message_type'] = 'info';
    header('Location: index.php?view=login');
    exit;
}

if (isset($_GET['download_evidence'])) {
    $evidenceId = (int) $_GET['download_evidence'];
    $stmt = $conn->prepare("SELECT * FROM incident_evidence WHERE id = ?");
    $stmt->execute([$evidenceId]);
    $file = $stmt->fetch(PDO::FETCH_ASSOC);

    if (!$file) {
        http_response_code(404);
        echo 'Evidence not found';
        exit;
    }

    if ($shareAccess && (int) $shareAccess['incident_id'] !== (int) $file['incident_id']) {
        http_response_code(403);
        echo 'This share link is not authorized for this evidence item.';
        exit;
    }

    $filePath = $uploadDir . '/' . $file['file_name'];
    if (!is_readable($filePath)) {
        http_response_code(404);
        echo 'File is missing from storage.';
        exit;
    }

    header('Content-Type: ' . $file['mime_type']);
    header('Content-Disposition: attachment; filename="' . basename($file['original_name']) . '"');
    readfile($filePath);
    exit;
}

// Export functionality
function pdfEscape(string $text): string {
    $escaped = str_replace(['\\', '(', ')'], ['\\\\', '\\(', '\\)'], $text);
    return preg_replace('/[\r\n]+/', ' ', $escaped);
}

function generateSimplePdf(array $lines): string {
    $content = "BT\n/F1 12 Tf\n12 TL\n50 760 Td\n";

    foreach ($lines as $index => $line) {
        if ($index !== 0) {
            $content .= "T*\n";
        }
        $content .= "(" . pdfEscape($line) . ") Tj\n";
    }

    $content .= "ET";
    $length = strlen($content);

    $objects = [];
    $objects[] = "1 0 obj << /Type /Catalog /Pages 2 0 R >> endobj\n";
    $objects[] = "2 0 obj << /Type /Pages /Kids [3 0 R] /Count 1 >> endobj\n";
    $objects[] = "3 0 obj << /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Contents 4 0 R /Resources << /Font << /F1 5 0 R >> >> >> endobj\n";
    $objects[] = "4 0 obj << /Length $length >> stream\n" . $content . "\nendstream endobj\n";
    $objects[] = "5 0 obj << /Type /Font /Subtype /Type1 /BaseFont /Helvetica >> endobj\n";

    $pdf = "%PDF-1.4\n";
    $offsets = [];
    $running = strlen($pdf);
    foreach ($objects as $object) {
        $offsets[] = $running;
        $pdf .= $object;
        $running += strlen($object);
    }

    $xref = "xref\n0 " . (count($offsets) + 1) . "\n0000000000 65535 f \n";
    foreach ($offsets as $offset) {
        $xref .= sprintf("%010d 00000 n \n", $offset);
    }

    $startxref = $running;
    $trailer = "trailer << /Size " . (count($offsets) + 1) . " /Root 1 0 R >>\nstartxref\n" . $startxref . "\n%%EOF";

    return $pdf . $xref . $trailer;
}

function formatIncidentText(array $incident, array $updates, array $evidence): array {
    $lines = [];
    $lines[] = "═══════════════════════════════════════════════════════════════";
    $lines[] = "           CO-PARENTING INCIDENT REPORT - OFFICIAL";
    $lines[] = "═══════════════════════════════════════════════════════════════";
    $lines[] = "";
    $lines[] = "REPORT INFORMATION";
    $lines[] = str_repeat("─", 63);
    $lines[] = "Report ID:           #" . str_pad($incident['id'], 6, '0', STR_PAD_LEFT);
    $lines[] = "Generated:           " . date('F j, Y \a\t g:i A T');
    $lines[] = "Report Created:      " . date('F j, Y \a\t g:i A', strtotime($incident['created_at']));
    $lines[] = "Last Updated:        " . date('F j, Y \a\t g:i A', strtotime($incident['updated_at']));
    $lines[] = "Urgency Level:       " . strtoupper($incident['urgency_level']);
    $lines[] = "Status:              " . strtoupper($incident['status']);
    $lines[] = "Follow-Up Due:       " . ($incident['follow_up_at'] ? date('F j, Y \a\t g:i A', strtotime($incident['follow_up_at'])) : 'Not set');
    $lines[] = "";
    $lines[] = "INCIDENT DETAILS";
    $lines[] = str_repeat("─", 63);
    $lines[] = "Date/Time:           " . date('F j, Y \a\t g:i A', strtotime($incident['incident_date']));
    $lines[] = "Incident Type:       " . $incident['incident_type'];
    $lines[] = "Location:            " . $incident['location'];
    $lines[] = "Communication Via:   " . ($incident['communication_method'] ?: 'N/A');
    $lines[] = "Children Present:    " . ($incident['children_present'] ?: 'N/A');
    $lines[] = "Witnesses:           " . ($incident['witnesses'] ?: 'None');
    $lines[] = "";
    $lines[] = "DETAILED DESCRIPTION";
    $lines[] = str_repeat("─", 63);
    $lines[] = wordwrap($incident['description'], 63);
    $lines[] = "";

    if (!empty($incident['direct_quotes'])) {
        $lines[] = "DIRECT QUOTES / VERBATIM STATEMENTS";
        $lines[] = str_repeat("─", 63);
        $lines[] = wordwrap($incident['direct_quotes'], 63);
        $lines[] = "";
    }

    if (!empty($incident['child_impact'])) {
        $lines[] = "IMPACT ON CHILD(REN)";
        $lines[] = str_repeat("─", 63);
        $lines[] = wordwrap($incident['child_impact'], 63);
        $lines[] = "";
    }

    if (!empty($incident['your_response'])) {
        $lines[] = "YOUR RESPONSE";
        $lines[] = str_repeat("─", 63);
        $lines[] = wordwrap($incident['your_response'], 63);
        $lines[] = "";
    }

    if (!empty($incident['evidence_list']) || !empty($evidence)) {
        $lines[] = "SUPPORTING EVIDENCE";
        $lines[] = str_repeat("─", 63);
        if (!empty($incident['evidence_list'])) {
            $lines[] = wordwrap($incident['evidence_list'], 63);
        }
        foreach ($evidence as $ev) {
            $lines[] = "File: " . $ev['original_name'] . " (" . $ev['mime_type'] . ")";
            $lines[] = "Saved As: " . $ev['file_name'];
            $lines[] = '';
        }
        $lines[] = "";
    }

    if (!empty($incident['legal_violations'])) {
        $lines[] = "POTENTIAL LEGAL VIOLATIONS / COURT ORDER BREACHES";
        $lines[] = str_repeat("─", 63);
        $lines[] = wordwrap($incident['legal_violations'], 63);
        $lines[] = "";
    }

    if (!empty($incident['pattern_notes'])) {
        $lines[] = "PATTERN ANALYSIS";
        $lines[] = str_repeat("─", 63);
        $lines[] = wordwrap($incident['pattern_notes'], 63);
        $lines[] = "";
    }

    if (!empty($updates)) {
        $lines[] = "FOLLOW-UP DOCUMENTATION";
        $lines[] = str_repeat("─", 63);
        foreach ($updates as $i => $update) {
            $lines[] = '';
            $lines[] = "[Update #" . ($i + 1) . " - " . date('F j, Y \a\t g:i A', strtotime($update['created_at'])) . "]";
            $lines[] = "Type: " . ucfirst($update['update_type']);
            $lines[] = wordwrap($update['update_text'], 63);
        }
        $lines[] = '';
    }

    $lines[] = str_repeat("═", 63);
    $lines[] = "END OF REPORT";
    $lines[] = "";
    $lines[] = "This document was generated by CustodyBuddy Incident Reporting System";
    $lines[] = "Document is timestamped and suitable for legal proceedings.";
    $lines[] = "Please consult with your attorney regarding use of this documentation.";
    $lines[] = str_repeat("═", 63);

    return $lines;
}

function exportIncident(PDO $conn, int $id, string $format): void {
    $stmt = $conn->prepare("SELECT * FROM incidents WHERE id = ?");
    $stmt->execute([$id]);
    $incident = $stmt->fetch(PDO::FETCH_ASSOC);

    if (!$incident) {
        http_response_code(404);
        echo "Incident not found.";
        exit;
    }

    $stmt = $conn->prepare("SELECT * FROM incident_updates WHERE incident_id = ? ORDER BY created_at ASC");
    $stmt->execute([$id]);
    $updates = $stmt->fetchAll(PDO::FETCH_ASSOC);

    $stmt = $conn->prepare("SELECT * FROM incident_evidence WHERE incident_id = ? ORDER BY created_at ASC");
    $stmt->execute([$id]);
    $evidence = $stmt->fetchAll(PDO::FETCH_ASSOC);

    $lines = formatIncidentText($incident, $updates, $evidence);

    switch ($format) {
        case 'txt':
            header('Content-Type: text/plain; charset=utf-8');
            header('Content-Disposition: attachment; filename="custody_incident_' . $id . '_' . date('Y-m-d') . '.txt"');
            echo implode("\n", $lines);
            break;
        case 'csv':
            header('Content-Type: text/csv; charset=utf-8');
            header('Content-Disposition: attachment; filename="custody_incident_' . $id . '_' . date('Y-m-d') . '.csv"');
            $out = fopen('php://output', 'w');
            fputcsv($out, ['Section', 'Field', 'Value']);
            fputcsv($out, ['Incident', 'Report ID', '#' . str_pad($incident['id'], 6, '0', STR_PAD_LEFT)]);
            fputcsv($out, ['Incident', 'Generated', date('c')]);
            fputcsv($out, ['Incident', 'Report Created', $incident['created_at']]);
            fputcsv($out, ['Incident', 'Last Updated', $incident['updated_at']]);
            fputcsv($out, ['Incident', 'Urgency Level', strtoupper($incident['urgency_level'])]);
            fputcsv($out, ['Incident', 'Status', strtoupper($incident['status'])]);
            fputcsv($out, ['Incident', 'Follow-Up Due', $incident['follow_up_at'] ?: 'Not set']);
            fputcsv($out, ['Details', 'Incident Date/Time', $incident['incident_date']]);
            fputcsv($out, ['Details', 'Incident Type', $incident['incident_type']]);
            fputcsv($out, ['Details', 'Location', $incident['location']]);
            fputcsv($out, ['Details', 'Communication Via', $incident['communication_method'] ?: 'N/A']);
            fputcsv($out, ['Details', 'Children Present', $incident['children_present'] ?: 'N/A']);
            fputcsv($out, ['Details', 'Witnesses', $incident['witnesses'] ?: 'None']);
            fputcsv($out, ['Narrative', 'Description', $incident['description']]);
            if (!empty($incident['direct_quotes'])) {
                fputcsv($out, ['Narrative', 'Direct Quotes', $incident['direct_quotes']]);
            }
            if (!empty($incident['child_impact'])) {
                fputcsv($out, ['Narrative', 'Impact on Child(ren)', $incident['child_impact']]);
            }
            if (!empty($incident['your_response'])) {
                fputcsv($out, ['Narrative', 'Your Response', $incident['your_response']]);
            }
            if (!empty($incident['evidence_list'])) {
                fputcsv($out, ['Evidence', 'Supporting Evidence', $incident['evidence_list']]);
            }
            if (!empty($incident['legal_violations'])) {
                fputcsv($out, ['Legal', 'Potential Violations', $incident['legal_violations']]);
            }
            if (!empty($incident['pattern_notes'])) {
                fputcsv($out, ['Analysis', 'Pattern Notes', $incident['pattern_notes']]);
            }
            foreach ($evidence as $ev) {
                fputcsv($out, ['Evidence', 'File', $ev['original_name'] . ' (' . $ev['mime_type'] . ')']);
                fputcsv($out, ['Evidence', 'Stored Name', $ev['file_name']]);
            }
            foreach ($updates as $i => $update) {
                fputcsv($out, ['Updates', 'Update #' . ($i + 1), $update['update_type'] . ' - ' . $update['created_at']]);
                fputcsv($out, ['Updates', 'Details', $update['update_text']]);
            }
            fclose($out);
            break;
        case 'pdf':
            header('Content-Type: application/pdf');
            header('Content-Disposition: attachment; filename="custody_incident_' . $id . '_' . date('Y-m-d') . '.pdf"');
            echo generateSimplePdf($lines);
            break;
        default:
            header('Content-Type: text/plain; charset=utf-8');
            http_response_code(400);
            echo 'Unsupported format requested.';
    }

    exit;
}

if (isset($_GET['export'])) {
    $id = (int) $_GET['export'];
    $format = $_GET['format'] ?? 'txt';

    if ($shareAccess && $shareAccess['incident_id'] !== $id) {
        http_response_code(403);
        echo 'This share link is not authorized for this incident.';
        exit;
    }

    if ($shareAccess && $shareAccess['role'] !== 'export') {
        http_response_code(403);
        echo 'Exports are disabled for this share link.';
        exit;
    }

    if ($format === 'timeline') {
        // Get all incidents for timeline view
        $stmt = $conn->query("SELECT * FROM incidents ORDER BY incident_date ASC");
        $all_incidents = $stmt->fetchAll(PDO::FETCH_ASSOC);
        
        header('Content-Type: text/plain; charset=utf-8');
        header('Content-Disposition: attachment; filename="custody_timeline_' . date('Y-m-d') . '.txt"');
        
        echo "═══════════════════════════════════════════════════════════════\n";
        echo "           CO-PARENTING INCIDENT TIMELINE\n";
        echo "═══════════════════════════════════════════════════════════════\n\n";
        echo "Generated: " . date('F j, Y \a\t g:i A T') . "\n";
        echo "Total Incidents: " . count($all_incidents) . "\n\n";
        
        foreach ($all_incidents as $inc) {
            echo str_repeat("─", 63) . "\n";
            echo date('M j, Y g:i A', strtotime($inc['incident_date'])) . " - Incident #" . $inc['id'] . "\n";
            echo "Type: " . $inc['incident_type'] . " | Urgency: " . strtoupper($inc['urgency_level']) . "\n";
            echo wordwrap(substr($inc['description'], 0, 200), 63) . "...\n\n";
        }
        
        echo str_repeat("═", 63) . "\n";
        echo "End of Timeline\n";
        exit;
    }

    exportIncident($conn, $id, $format);
}

// Get statistics
$stats = [
    'total' => $conn->query("SELECT COUNT(*) FROM incidents")->fetchColumn(),
    'high_urgency' => $conn->query("SELECT COUNT(*) FROM incidents WHERE urgency_level = 'high'")->fetchColumn(),
    'this_month' => $conn->query("SELECT COUNT(*) FROM incidents WHERE strftime('%Y-%m', incident_date) = strftime('%Y-%m', 'now')")->fetchColumn(),
    'open' => $conn->query("SELECT COUNT(*) FROM incidents WHERE status = 'open'")->fetchColumn(),
    'in_progress' => $conn->query("SELECT COUNT(*) FROM incidents WHERE status = 'in-progress'")->fetchColumn(),
    'resolved' => $conn->query("SELECT COUNT(*) FROM incidents WHERE status = 'resolved'")->fetchColumn(),
    'overdue' => $conn->query("SELECT COUNT(*) FROM incidents WHERE status NOT IN ('resolved','escalated') AND follow_up_at IS NOT NULL AND datetime(follow_up_at) < datetime('now')")->fetchColumn(),
];

$filterValues = [
    'from' => $_GET['from'] ?? '',
    'to' => $_GET['to'] ?? '',
    'type' => $_GET['type'] ?? '',
    'status' => $_GET['status'] ?? '',
    'urgency' => $_GET['urgency'] ?? '',
    'keyword' => trim($_GET['keyword'] ?? ''),
    'sort' => $_GET['sort'] ?? 'incident_date_desc',
];

$conditions = [];
$params = [];
if ($filterValues['from'] !== '') {
    $conditions[] = 'datetime(incident_date) >= datetime(?)';
    $params[] = $filterValues['from'];
}
if ($filterValues['to'] !== '') {
    $conditions[] = 'datetime(incident_date) <= datetime(?)';
    $params[] = $filterValues['to'];
}
if ($filterValues['type'] !== '') {
    $conditions[] = 'incident_type = ?';
    $params[] = $filterValues['type'];
}
if ($filterValues['status'] !== '') {
    $conditions[] = 'status = ?';
    $params[] = $filterValues['status'];
}
if ($filterValues['urgency'] !== '') {
    $conditions[] = 'urgency_level = ?';
    $params[] = $filterValues['urgency'];
}
if ($filterValues['keyword'] !== '') {
    $conditions[] = '(description LIKE ? OR direct_quotes LIKE ?)';
    $params[] = '%' . $filterValues['keyword'] . '%';
    $params[] = '%' . $filterValues['keyword'] . '%';
}

$whereSql = '';
if (!empty($conditions)) {
    $whereSql = 'WHERE ' . implode(' AND ', $conditions);
}

$sortMap = [
    'incident_date_desc' => 'incident_date DESC',
    'incident_date_asc' => 'incident_date ASC',
    'urgency_desc' => 'CASE urgency_level WHEN "high" THEN 3 WHEN "medium" THEN 2 ELSE 1 END DESC, incident_date DESC',
    'urgency_asc' => 'CASE urgency_level WHEN "high" THEN 3 WHEN "medium" THEN 2 ELSE 1 END ASC, incident_date DESC',
    'status' => 'status ASC, incident_date DESC',
];
$orderSql = $sortMap[$filterValues['sort']] ?? $sortMap['incident_date_desc'];

$incidentStmt = $conn->prepare("SELECT * FROM incidents $whereSql ORDER BY $orderSql");
$incidentStmt->execute($params);
$incidents = $incidentStmt->fetchAll(PDO::FETCH_ASSOC);

$incidentTypes = $conn->query("SELECT DISTINCT incident_type FROM incidents ORDER BY incident_type ASC")->fetchAll(PDO::FETCH_COLUMN);
$dueFollowUps = $conn->query("SELECT * FROM incidents WHERE follow_up_at IS NOT NULL AND status NOT IN ('resolved','escalated') AND datetime(follow_up_at) <= datetime('now', '+3 days') ORDER BY follow_up_at ASC")->fetchAll(PDO::FETCH_ASSOC);
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>CustodyBuddy - Co-Parenting Incident Reporter</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, Cantarell, sans-serif;
            background: linear-gradient(135deg, #1e3c72 0%, #2a5298 50%, #667eea 100%);
            min-height: 100vh;
            padding: 20px;
        }
        
        .container {
            max-width: 1400px;
            margin: 0 auto;
            background: white;
            border-radius: 20px;
            box-shadow: 0 25px 70px rgba(0,0,0,0.4);
            overflow: hidden;
        }
        
        header {
            background: linear-gradient(135deg, #1a1a2e 0%, #16213e 100%);
            color: white;
            padding: 40px;
            text-align: center;
            position: relative;
            overflow: hidden;
        }
        
        header::before {
            content: '';
            position: absolute;
            top: 0;
            left: 0;
            right: 0;
            bottom: 0;
            background: url('data:image/svg+xml,<svg width="100" height="100" xmlns="http://www.w3.org/2000/svg"><defs><pattern id="grid" width="50" height="50" patternUnits="userSpaceOnUse"><path d="M 50 0 L 0 0 0 50" fill="none" stroke="rgba(255,255,255,0.05)" stroke-width="1"/></pattern></defs><rect width="100" height="100" fill="url(%23grid)"/></svg>');
            opacity: 0.3;
        }
        
        header .content {
            position: relative;
            z-index: 1;
        }
        
        header h1 {
            font-size: 2.5em;
            margin-bottom: 10px;
            text-shadow: 2px 2px 4px rgba(0,0,0,0.3);
        }
        
        header p {
            opacity: 0.95;
            font-size: 1.2em;
            margin-bottom: 5px;
        }
        
        .tagline {
            font-size: 0.95em;
            opacity: 0.8;
            font-style: italic;
        }
        
        .alert {
            padding: 18px 30px;
            margin: 25px;
            border-radius: 12px;
            font-weight: 500;
            display: flex;
            align-items: center;
            gap: 12px;
        }
        
        .alert.success {
            background: linear-gradient(135deg, #d4edda 0%, #c3e6cb 100%);
            border-left: 5px solid #28a745;
            color: #155724;
        }

        .alert.info {
            background: linear-gradient(135deg, #d1ecf1 0%, #bee5eb 100%);
            border-left: 5px solid #17a2b8;
            color: #0c5460;
        }

        .alert.error {
            background: linear-gradient(135deg, #f8d7da 0%, #f5c6cb 100%);
            border-left: 5px solid #dc3545;
            color: #721c24;
        }
        
        .nav-tabs {
            display: flex;
            background: linear-gradient(to right, #f8f9fa, #e9ecef);
            border-bottom: 3px solid #dee2e6;
            overflow-x: auto;
        }
        
        .nav-tab {
            flex: 1;
            min-width: 150px;
            padding: 18px 20px;
            text-align: center;
            background: none;
            border: none;
            cursor: pointer;
            font-size: 1em;
            font-weight: 600;
            color: #495057;
            transition: all 0.3s;
            border-bottom: 3px solid transparent;
            white-space: nowrap;
        }
        
        .nav-tab:hover {
            background: rgba(102, 126, 234, 0.1);
            color: #2a5298;
        }
        
        .nav-tab.active {
            background: white;
            color: #2a5298;
            border-bottom: 3px solid #667eea;
        }
        
        .content {
            padding: 35px;
        }
        
        .dashboard-stats {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 25px;
            margin-bottom: 35px;
        }
        
        .stat-card {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 30px;
            border-radius: 15px;
            text-align: center;
            box-shadow: 0 8px 20px rgba(102, 126, 234, 0.3);
            transition: transform 0.3s;
        }
        
        .stat-card:hover {
            transform: translateY(-5px);
        }
        
        .stat-card h3 {
            font-size: 3em;
            margin-bottom: 10px;
        }
        
        .stat-card p {
            font-size: 1.1em;
            opacity: 0.95;
        }
        
        .stat-card.danger {
            background: linear-gradient(135deg, #dc3545 0%, #c82333 100%);
        }
        
        .stat-card.success {
            background: linear-gradient(135deg, #28a745 0%, #218838 100%);
        }
        
        .form-group {
            margin-bottom: 25px;
        }
        
        label {
            display: block;
            font-weight: 700;
            margin-bottom: 8px;
            color: #2c3e50;
            font-size: 0.95em;
        }
        
        .label-hint {
            font-weight: 400;
            color: #6c757d;
            font-size: 0.85em;
            margin-top: 3px;
        }
        
        input[type="text"],
        input[type="datetime-local"],
        select,
        textarea {
            width: 100%;
            padding: 14px;
            border: 2px solid #e1e8ed;
            border-radius: 10px;
            font-size: 1em;
            transition: all 0.3s;
            font-family: inherit;
        }
        
        input:focus,
        select:focus,
        textarea:focus {
            outline: none;
            border-color: #667eea;
            box-shadow: 0 0 0 4px rgba(102, 126, 234, 0.1);
        }
        
        textarea {
            min-height: 120px;
            resize: vertical;
        }
        
        .form-row {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 20px;
        }
        
        .btn {
            padding: 14px 32px;
            border: none;
            border-radius: 10px;
            font-size: 1em;
            cursor: pointer;
            transition: all 0.3s;
            font-weight: 700;
            display: inline-flex;
            align-items: center;
            gap: 8px;
        }
        
        .btn-primary {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            box-shadow: 0 5px 15px rgba(102, 126, 234, 0.3);
        }
        
        .btn-primary:hover {
            transform: translateY(-2px);
            box-shadow: 0 8px 25px rgba(102, 126, 234, 0.4);
        }
        
        .btn-secondary {
            background: #6c757d;
            color: white;
        }
        
        .btn-danger {
            background: #dc3545;
            color: white;
        }
        
        .btn-success {
            background: #28a745;
            color: white;
        }
        
        .btn-outline {
            background: white;
            color: #667eea;
            border: 2px solid #667eea;
        }
        
        .incident-card {
            background: linear-gradient(to right, #f8f9fa, #ffffff);
            border-radius: 15px;
            padding: 25px;
            margin-bottom: 25px;
            border-left: 6px solid #667eea;
            transition: all 0.3s;
            box-shadow: 0 3px 10px rgba(0,0,0,0.08);
        }
        
        .incident-card:hover {
            transform: translateX(8px);
            box-shadow: 0 8px 25px rgba(0,0,0,0.15);
        }
        
        .incident-card.high-urgency {
            border-left-color: #dc3545;
            background: linear-gradient(to right, #fff5f5, #ffffff);
        }
        
        .incident-header {
            display: flex;
            justify-content: space-between;
            align-items: start;
            margin-bottom: 20px;
            flex-wrap: wrap;
            gap: 15px;
        }
        
        .incident-badges {
            display: flex;
            gap: 10px;
            flex-wrap: wrap;
        }
        
        .badge {
            display: inline-block;
            padding: 6px 16px;
            border-radius: 20px;
            font-size: 0.85em;
            font-weight: 700;
            text-transform: uppercase;
        }
        
        .badge-type {
            background: #667eea;
            color: white;
        }
        
        .badge-urgency {
            background: #ffc107;
            color: #000;
        }
        
        .badge-urgency.high {
            background: #dc3545;
            color: white;
        }
        
        .incident-date {
            color: #6c757d;
            font-size: 0.95em;
            font-weight: 600;
        }
        
        .incident-actions {
            display: flex;
            gap: 10px;
            margin-top: 20px;
            flex-wrap: wrap;
        }
        
        .update-item {
            background: white;
            padding: 20px;
            border-radius: 12px;
            margin-bottom: 15px;
            border-left: 4px solid #28a745;
            box-shadow: 0 2px 8px rgba(0,0,0,0.08);
        }
        
        .update-header {
            display: flex;
            justify-content: space-between;
            margin-bottom: 12px;
            align-items: center;
        }
        
        .update-date {
            color: #6c757d;
            font-size: 0.9em;
            font-weight: 600;
        }
        
        .update-type-badge {
            background: #e9ecef;
            padding: 4px 12px;
            border-radius: 12px;
            font-size: 0.8em;
            font-weight: 600;
            color: #495057;
        }
        
        .detail-section {
            margin-bottom: 35px;
            background: #f8f9fa;
            padding: 25px;
            border-radius: 12px;
        }
        
        .detail-section h3 {
            color: #2a5298;
            margin-bottom: 15px;
            padding-bottom: 12px;
            border-bottom: 3px solid #667eea;
            font-size: 1.3em;
        }
        
        .detail-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 15px;
            margin-top: 15px;
        }
        
        .detail-item {
            background: white;
            padding: 15px;
            border-radius: 8px;
        }
        
        .detail-item strong {
            display: block;
            color: #495057;
            font-size: 0.9em;
            margin-bottom: 5px;
        }
        
        .back-link {
            display: inline-block;
            margin-bottom: 25px;
            color: #667eea;
            text-decoration: none;
            font-weight: 700;
            font-size: 1.1em;
        }
        
        .back-link:hover {
            text-decoration: underline;
        }
        
        .tab-content {
            display: none;
        }
        
        .tab-content.active {
            display: block;
        }
        
        .empty-state {
            text-align: center;
            padding: 80px 20px;
            color: #6c757d;
        }
        
        .empty-state h3 {
            font-size: 1.8em;
            margin-bottom: 15px;
            color: #495057;
        }
        
        .tips-box {
            background: linear-gradient(135deg, #fff3cd 0%, #ffeaa7 100%);
            border-left: 5px solid #ffc107;
            padding: 20px;
            border-radius: 10px;
            margin: 25px 0;
        }
        
        .tips-box h4 {
            color: #856404;
            margin-bottom: 12px;
        }
        
        .tips-box ul {
            margin-left: 20px;
            color: #856404;
        }
        
        .tips-box li {
            margin-bottom: 8px;
        }

        .auth-card {
            max-width: 420px;
            margin: 60px auto;
            padding: 30px;
            background: white;
            border-radius: 16px;
            box-shadow: 0 15px 40px rgba(0,0,0,0.15);
        }

        .auth-card h2 {
            margin-bottom: 10px;
            color: #1a1a2e;
        }

        .auth-card p {
            color: #6c757d;
            margin-bottom: 20px;
        }

        .auth-field {
            display: flex;
            flex-direction: column;
            gap: 8px;
            margin-bottom: 16px;
        }

        .auth-field input {
            padding: 12px;
            border-radius: 10px;
            border: 1px solid #dee2e6;
            font-size: 1em;
        }

        @media (max-width: 768px) {
            .incident-header {
                flex-direction: column;
            }
            
            .form-row {
                grid-template-columns: 1fr;
            }
            
            .nav-tabs {
                flex-direction: column;
            }
        }
    </style>
</head>
<body>
    <div class="container">
        <header>
            <div class="content">
                <h1>🛡️ CustodyBuddy</h1>
                <p>Co-Parenting Incident Documentation System</p>
                <p class="tagline">"Catch Them Red-Handed" - Transform Toxic Behavior Into Court-Ready Evidence</p>
            </div>
        </header>
        
        <?php if (isset($_SESSION['message'])): ?>
            <div class="alert <?php echo $_SESSION['message_type'] ?? 'info'; ?>">
                <span><?php echo htmlspecialchars($_SESSION['message']); ?></span>
            </div>
            <?php unset($_SESSION['message'], $_SESSION['message_type']); ?>
        <?php endif; ?>

        <?php if ($view === 'login'): ?>
            <div class="auth-card">
                <h2>Sign In</h2>
                <p>Use the starter account <strong>admin</strong> / <strong>password</strong> to log in.</p>
                <form method="POST">
                    <input type="hidden" name="action" value="login">
                    <div class="auth-field">
                        <label for="username">Username</label>
                        <input id="username" type="text" name="username" required>
                    </div>
                    <div class="auth-field">
                        <label for="password">Password</label>
                        <input id="password" type="password" name="password" required>
                    </div>
                    <button type="submit" class="btn btn-primary" style="width: 100%;">Login</button>
                    <a href="?view=reset" style="display:block; text-align:center; margin-top:10px;">Forgot password?</a>
                </form>
            </div>
        <?php elseif ($view === 'reset'): ?>
            <div class="auth-card">
                <h2>Password Reset</h2>
                <form method="POST" style="margin-bottom: 16px;">
                    <input type="hidden" name="action" value="request_reset">
                    <div class="auth-field">
                        <label>Username</label>
                        <input type="text" name="username" required>
                    </div>
                    <button type="submit" class="btn btn-primary" style="width:100%;">Send reset token</button>
                </form>
                <form method="POST">
                    <input type="hidden" name="action" value="complete_reset">
                    <div class="auth-field">
                        <label>Reset Token</label>
                        <input type="text" name="token" required>
                    </div>
                    <div class="auth-field">
                        <label>New Password</label>
                        <input type="password" name="new_password" required>
                    </div>
                    <div class="auth-field">
                        <label>Confirm Password</label>
                        <input type="password" name="confirm_password" required>
                    </div>
                    <button type="submit" class="btn btn-secondary" style="width:100%;">Update Password</button>
                </form>
                <a href="index.php?view=login" style="display:block; text-align:center;">Back to login</a>
            </div>
        <?php else: ?>

        <div style="padding: 16px 35px 0 35px; display: flex; justify-content: flex-end; gap: 10px; align-items: center;">
            <div style="color: white; font-weight: 600;">👤 <?php echo htmlspecialchars(currentUser($conn)['username'] ?? ''); ?></div>
            <a href="?view=logout" class="btn btn-outline">Logout</a>
        </div>

        <?php if ($view === 'dashboard'): ?>
        <div class="nav-tabs">
            <button class="nav-tab active" onclick="showTab('dashboard')">📊 Dashboard</button>
            <button class="nav-tab" onclick="showTab('list')">📋 All Incidents</button>
            <button class="nav-tab" onclick="showTab('new')">➕ Report Incident</button>
            <button class="nav-tab" onclick="showTab('tips')">💡 Tips & Guide</button>
            <button class="nav-tab" onclick="showTab('reminders')">⏰ Reminders</button>
            <button class="nav-tab" onclick="showTab('settings')">⚙️ Settings</button>
        </div>
        
        <div class="content">
            <div id="dashboard-tab" class="tab-content active">
                <h2 style="margin-bottom: 25px;">Your Documentation Dashboard</h2>
                
                <div class="dashboard-stats">
                    <div class="stat-card">
                        <h3><?php echo $stats['total']; ?></h3>
                        <p>Total Incidents Documented</p>
                    </div>
                    <div class="stat-card danger">
                        <h3><?php echo $stats['high_urgency']; ?></h3>
                        <p>High Urgency Incidents</p>
                    </div>
                    <div class="stat-card success">
                        <h3><?php echo $stats['this_month']; ?></h3>
                        <p>Incidents This Month</p>
                    </div>
                    <div class="stat-card" style="background: linear-gradient(135deg, #17a2b8 0%, #138496 100%);">
                        <h3><?php echo $stats['open'] + $stats['in_progress']; ?></h3>
                        <p>Open / In-Progress</p>
                    </div>
                    <div class="stat-card danger">
                        <h3><?php echo $stats['overdue']; ?></h3>
                        <p>Overdue Follow-Ups</p>
                    </div>
                    <div class="stat-card" style="border: 1px solid #ffc107; color: #856404;">
                        <h3><?php echo count($dueFollowUps); ?></h3>
                        <p>Upcoming Follow-ups (3 days)</p>
                    </div>
                </div>
                
                <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(300px, 1fr)); gap: 20px;">
                    <div class="detail-section">
                        <h3>📄 Quick Actions</h3>
                        <div style="display: flex; flex-direction: column; gap: 12px;">
                            <button class="btn btn-primary" onclick="showTab('new')">Report New Incident</button>
                            <button class="btn btn-outline" onclick="showTab('list')">View All Reports</button>
                            <a href="?export=0&format=timeline" class="btn btn-secondary">📅 Export Timeline (All)</a>
                        </div>
                    </div>
                    
                    <div class="detail-section">
                        <h3>🎯 Recent Activity</h3>
                        <?php
                        $recent = $conn->query("SELECT * FROM incidents ORDER BY created_at DESC LIMIT 3")->fetchAll(PDO::FETCH_ASSOC);
                        if (empty($recent)): ?>
                            <p style="color: #6c757d;">No incidents yet</p>
                        <?php else: ?>
                            <?php foreach ($recent as $r): ?>
                                <div style="padding: 10px 0; border-bottom: 1px solid #dee2e6;">
                                    <strong>Incident #<?php echo $r['id']; ?></strong> - <?php echo $r['incident_type']; ?>
                                    <br>
                                    <small style="color: #6c757d;"><?php echo date('M j, Y', strtotime($r['incident_date'])); ?></small>
                                </div>
                            <?php endforeach; ?>
                        <?php endif; ?>
                    </div>
                </div>
            </div>
            
            <div id="list-tab" class="tab-content">
                <h2>All Documented Incidents</h2>
                <p style="color: #6c757d; margin-bottom: 25px;">Comprehensive record of all co-parenting incidents with timestamps</p>

                <form method="GET" class="incident-filters" style="display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 12px; align-items: end; margin-bottom: 12px;">
                    <input type="hidden" name="view" value="dashboard">
                    <div class="form-group">
                        <label>From</label>
                        <input type="datetime-local" name="from" value="<?php echo htmlspecialchars($filterValues['from']); ?>">
                    </div>
                    <div class="form-group">
                        <label>To</label>
                        <input type="datetime-local" name="to" value="<?php echo htmlspecialchars($filterValues['to']); ?>">
                    </div>
                    <div class="form-group">
                        <label>Type</label>
                        <select name="type">
                            <option value="">Any</option>
                            <?php foreach ($incidentTypes as $type): ?>
                                <option value="<?php echo htmlspecialchars($type); ?>" <?php echo $filterValues['type'] === $type ? 'selected' : ''; ?>><?php echo htmlspecialchars($type); ?></option>
                            <?php endforeach; ?>
                        </select>
                    </div>
                    <div class="form-group">
                        <label>Status</label>
                        <select name="status">
                            <option value="">Any</option>
                            <?php foreach (['open','in-progress','resolved','escalated'] as $status): ?>
                                <option value="<?php echo $status; ?>" <?php echo $filterValues['status'] === $status ? 'selected' : ''; ?>><?php echo ucfirst($status); ?></option>
                            <?php endforeach; ?>
                        </select>
                    </div>
                    <div class="form-group">
                        <label>Urgency</label>
                        <select name="urgency">
                            <option value="">Any</option>
                            <?php foreach (['low','medium','high'] as $urgency): ?>
                                <option value="<?php echo $urgency; ?>" <?php echo $filterValues['urgency'] === $urgency ? 'selected' : ''; ?>><?php echo ucfirst($urgency); ?></option>
                            <?php endforeach; ?>
                        </select>
                    </div>
                    <div class="form-group">
                        <label>Keyword</label>
                        <input type="text" name="keyword" placeholder="Search description or quotes" value="<?php echo htmlspecialchars($filterValues['keyword']); ?>">
                    </div>
                    <div class="form-group">
                        <label>Sort</label>
                        <select name="sort">
                            <option value="incident_date_desc" <?php echo $filterValues['sort'] === 'incident_date_desc' ? 'selected' : ''; ?>>Newest first</option>
                            <option value="incident_date_asc" <?php echo $filterValues['sort'] === 'incident_date_asc' ? 'selected' : ''; ?>>Oldest first</option>
                            <option value="urgency_desc" <?php echo $filterValues['sort'] === 'urgency_desc' ? 'selected' : ''; ?>>Highest urgency</option>
                            <option value="urgency_asc" <?php echo $filterValues['sort'] === 'urgency_asc' ? 'selected' : ''; ?>>Lowest urgency</option>
                            <option value="status" <?php echo $filterValues['sort'] === 'status' ? 'selected' : ''; ?>>Status A-Z</option>
                        </select>
                    </div>
                    <div class="form-group" style="display:flex; gap: 8px;">
                        <button class="btn btn-primary" type="submit">Apply Filters</button>
                        <a class="btn btn-secondary" href="index.php?view=dashboard">Clear filters</a>
                    </div>
                </form>

                <?php if (!empty($conditions)): ?>
                    <div style="margin-bottom: 15px; display: flex; gap: 8px; flex-wrap: wrap;">
                        <?php foreach (['from' => 'From', 'to' => 'To', 'type' => 'Type', 'status' => 'Status', 'urgency' => 'Urgency', 'keyword' => 'Keyword'] as $key => $label): ?>
                            <?php if ($filterValues[$key] !== ''): ?>
                                <span class="badge" style="background: #e9ecef; color: #495057;"><?php echo $label; ?>: <?php echo htmlspecialchars($filterValues[$key]); ?></span>
                            <?php endif; ?>
                        <?php endforeach; ?>
                        <a href="index.php?view=dashboard" class="btn btn-outline">Clear filters</a>
                    </div>
                <?php endif; ?>
                
                <?php if (empty($incidents)): ?>
                    <div class="empty-state">
                        <h3>📝 No Incidents Documented Yet</h3>
                        <p>Start building your case by documenting the first incident</p>
                        <button class="btn btn-primary" onclick="showTab('new')" style="margin-top: 20px;">Report First Incident</button>
                    </div>
                <?php else: ?>
                    <?php foreach ($incidents as $inc): ?>
                    <div class="incident-card <?php echo $inc['urgency_level'] === 'high' ? 'high-urgency' : ''; ?>">
                        <div class="incident-header">
                            <div class="incident-badges">
                                <span class="badge badge-type"><?php echo htmlspecialchars($inc['incident_type']); ?></span>
                                <span class="badge badge-urgency <?php echo $inc['urgency_level']; ?>">
                                    <?php echo strtoupper($inc['urgency_level']); ?> PRIORITY
                                </span>
                                <span class="badge" style="background: #343a40; color: white;">
                                    <?php echo strtoupper($inc['status']); ?>
                                </span>
                            </div>
                            <div class="incident-date">
                                📅 <?php echo date('F j, Y • g:i A', strtotime($inc['incident_date'])); ?>
                            </div>
                        </div>
                        
                        <h3 style="margin-bottom: 12px;">Incident #<?php echo str_pad($inc['id'], 4, '0', STR_PAD_LEFT); ?></h3>
                        
                        <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 15px; margin-bottom: 15px;">
                            <div><strong>📍 Location:</strong> <?php echo htmlspecialchars($inc['location']); ?></div>
                            <?php if ($inc['children_present']): ?>
                            <div><strong>👨‍👩‍👧 Children:</strong> <?php echo htmlspecialchars($inc['children_present']); ?></div>
                            <?php endif; ?>
                        </div>
                        
                        <p><?php echo htmlspecialchars(substr($inc['description'], 0, 200)); ?>...</p>
                        
                        <div class="incident-actions">
                            <a href="?view=detail&id=<?php echo $inc['id']; ?>" class="btn btn-primary">View Full Report</a>
                            <a href="?export=<?php echo $inc['id']; ?>&format=txt" class="btn btn-success">📄 Export Document</a>
                            <form method="POST" style="display: inline;" onsubmit="return confirm('Permanently delete this incident?');">
                                <input type="hidden" name="action" value="delete_incident">
                                <input type="hidden" name="incident_id" value="<?php echo $inc['id']; ?>">
                                <button type="submit" class="btn btn-danger">🗑️ Delete</button>
                            </form>
                        </div>
                    </div>
                    <?php endforeach; ?>
                <?php endif; ?>
            </div>
            
            <div id="new-tab" class="tab-content">
                <h2>Report New Incident</h2>
                <p style="color: #6c757d; margin-bottom: 25px;">Document toxic co-parenting behavior with precise detail for court proceedings</p>
                
                <form method="POST" enctype="multipart/form-data">
                    <input type="hidden" name="action" value="create_incident">

                    <div class="form-row">
                        <div class="form-group">
                            <label>
                                📅 Date & Time of Incident *
                                <div class="label-hint">When exactly did this occur?</div>
                            </label>
                            <input type="datetime-local" name="incident_date" required>
                        </div>
                        
                        <div class="form-group">
                            <label>
                                ⚠️ Urgency Level *
                                <div class="label-hint">How serious is this incident?</div>
                            </label>
                            <select name="urgency_level" required>
                                <option value="low">Low - Minor Issue</option>
                                <option value="medium" selected>Medium - Significant Issue</option>
                                <option value="high">High - Severe/Dangerous</option>
                            </select>
                        </div>
                        <div class="form-group">
                            <label>
                                📌 Status
                                <div class="label-hint">Track progress of this incident</div>
                            </label>
                            <select name="status">
                                <option value="open" selected>Open</option>
                                <option value="in-progress">In Progress</option>
                                <option value="resolved">Resolved</option>
                                <option value="escalated">Escalated</option>
                            </select>
                        </div>
                    </div>
                    
                    <div class="form-row">
                        <div class="form-group">
                            <label>
                                🏷️ Incident Type *
                                <div class="label-hint">Category of toxic behavior</div>
                            </label>
                            <select name="incident_type" required>
                                <option value="">Select type...</option>
                                <option value="Harassment">Harassment</option>
                                <option value="Verbal Abuse">Verbal Abuse</option>
                                <option value="Threats/Intimidation">Threats/Intimidation</option>
                                <option value="Parental Alienation">Parental Alienation</option>
                                <option value="Court Order Violation">Court Order Violation</option>
                                <option value="Denied Visitation">Denied Visitation</option>
                                <option value="Late/No-Show">Late Pickup/Drop-off or No-Show</option>
                                <option value="Child Neglect">Child Neglect Concerns</option>
                                <option value="Substance Abuse">Substance Abuse</option>
                                <option value="False Accusations">False Accusations</option>
                                <option value="Manipulation">Manipulation/Gaslighting</option>
                                <option value="Other">Other</option>
                            </select>
                        </div>
                        
                        <div class="form-group">
                            <label>
                                💬 Communication Method
                                <div class="label-hint">How did this incident occur?</div>
                            </label>
                            <select name="communication_method">
                                <option value="">Select method...</option>
                                <option value="In-Person">In-Person</option>
                                <option value="Text Message">Text Message</option>
                                <option value="Phone Call">Phone Call</option>
                                <option value="Email">Email</option>
                                <option value="Social Media">Social Media</option>
                                <option value="Co-Parenting App">Co-Parenting App</option>
                                <option value="Third Party">Through Third Party</option>
                                <option value="Other">Other</option>
                            </select>
                        </div>
                    </div>
                    
                    <div class="form-row">
                        <div class="form-group">
                            <label>
                                📍 Location *
                                <div class="label-hint">Where did this occur?</div>
                            </label>
                            <input type="text" name="location" placeholder="e.g., Outside school, during pickup, at my home" required>
                        </div>
                        
                        <div class="form-group">
                            <label>
                                👨‍👩‍👧 Children Present
                                <div class="label-hint">Were children present? Who?</div>
                            </label>
                            <input type="text" name="children_present" placeholder="e.g., Both children, Sarah (age 8)">
                        </div>
                    </div>
                    
                    <div class="form-group">
                        <label>
                            👥 Witnesses
                            <div class="label-hint">Anyone who saw/heard this incident</div>
                        </label>
                        <input type="text" name="witnesses" placeholder="Names and relationships of witnesses">
                    </div>
                    
                    <div class="form-group">
                        <label>
                            📝 Detailed Description *
                            <div class="label-hint">What happened? Be specific and objective. Use facts, not emotions.</div>
                        </label>
                        <textarea name="description" placeholder="Describe exactly what happened in chronological order. Include who said what, actions taken, body language, tone of voice, etc." required></textarea>
                    </div>
                    
                    <div class="form-group">
                        <label>
                            💬 Direct Quotes
                            <div class="label-hint">Exact words spoken (use quotation marks)</div>
                        </label>
                        <textarea name="direct_quotes" placeholder='e.g., They said: "You\'ll never see the kids again" and "I\'ll make sure the judge knows what a terrible parent you are"'></textarea>
                    </div>
                    
                    <div class="form-group">
                        <label>
                            👶 Impact on Child(ren)
                            <div class="label-hint">How did this affect the children?</div>
                        </label>
                        <textarea name="child_impact" placeholder="Did children witness it? How did they react? Any statements they made? Emotional impact observed?"></textarea>
                    </div>
                    
                    <div class="form-group">
                        <label>
                            ✋ Your Response
                            <div class="label-hint">How did you respond to this incident?</div>
                        </label>
                        <textarea name="your_response" placeholder="What you said or did in response. Include if you stayed calm, left the situation, called police, etc."></textarea>
                    </div>
                    
                    <div class="form-group">
                        <label>
                            📎 Evidence List
                            <div class="label-hint">What documentation do you have?</div>
                        </label>
                        <textarea name="evidence_list" placeholder="List: Screenshots, text messages, voicemails, photos, videos, police reports, medical records, etc."></textarea>
                    </div>

                    <div class="form-group">
                        <label>
                            📅 Follow-Up By
                            <div class="label-hint">Set a reminder for follow-up actions</div>
                        </label>
                        <input type="datetime-local" name="follow_up_at" value="<?php echo deriveFollowUpAt('medium'); ?>">
                    </div>

                    <div class="form-group">
                        <label>
                            📎 Upload Evidence Files
                            <div class="label-hint">Images (JPG/PNG/GIF) and PDFs up to 10MB</div>
                        </label>
                        <input type="file" name="evidence_files[]" multiple accept="image/*,application/pdf">
                    </div>
                    
                    <div class="form-group">
                        <label>
                            ⚖️ Legal Violations / Court Order Breaches
                            <div class="label-hint">Does this violate any court orders or laws?</div>
                        </label>
                        <textarea name="legal_violations" placeholder="e.g., Violated custody agreement section 3.2 regarding pickup times. Harassment may violate restraining order."></textarea>
                    </div>
                    
                    <div class="form-group">
                        <label>
                            🔄 Pattern Analysis
                            <div class="label-hint">Is this part of a recurring pattern?</div>
                        </label>
                        <textarea name="pattern_notes" placeholder="e.g., This is the 5th time they've been late this month. Similar to incidents #12 and #15."></textarea>
                    </div>
                    
                    <div class="tips-box">
                        <h4>💡 Documentation Tips</h4>
                        <ul>
                            <li><strong>Be objective:</strong> Stick to facts, not emotions or interpretations</li>
                            <li><strong>Be specific:</strong> Include exact times, locations, and quotes</li>
                            <li><strong>Be detailed:</strong> More detail is better than less</li>
                            <li><strong>Document immediately:</strong> Memory fades quickly</li>
                            <li><strong>Save evidence:</strong> Screenshots, recordings, witnesses</li>
                        </ul>
                    </div>
                    
                    <button type="submit" class="btn btn-primary" style="font-size: 1.1em; padding: 16px 40px;">
                        📝 Submit Incident Report
                    </button>
                </form>
            </div>
            
            <div id="tips-tab" class="tab-content">
                <h2>📚 Documentation Best Practices</h2>
                
                <div class="detail-section">
                    <h3>Why Documentation Matters</h3>
                    <p>In custody battles, <strong>documentation is everything</strong>. Courts rely on factual evidence, not he-said-she-said. A well-documented pattern of behavior can:</p>
                    <ul style="margin: 15px 0 15px 25px; line-height: 1.8;">
                        <li>Support modification of custody arrangements</li>
                        <li>Prove parental alienation or harassment</li>
                        <li>Demonstrate violation of court orders</li>
                        <li>Protect you from false accusations</li>
                        <li>Show your commitment to co-parenting</li>
                    </ul>
                </div>
                
                <div class="detail-section">
                    <h3>What Makes Good Documentation</h3>
                    <div style="display: grid; gap: 15px;">
                        <div style="background: white; padding: 15px; border-left: 4px solid #28a745; border-radius: 8px;">
                            <strong style="color: #28a745;">✓ DO:</strong>
                            <ul style="margin: 10px 0 0 20px;">
                                <li>Document immediately while details are fresh</li>
                                <li>Use exact quotes with quotation marks</li>
                                <li>Include dates, times, and locations</li>
                                <li>Note who was present (especially children)</li>
                                <li>Stay factual and objective</li>
                                <li>Save all evidence (texts, emails, voicemails)</li>
                                <li>Document your calm, appropriate responses</li>
                            </ul>
                        </div>
                        
                        <div style="background: white; padding: 15px; border-left: 4px solid #dc3545; border-radius: 8px;">
                            <strong style="color: #dc3545;">✗ DON'T:</strong>
                            <ul style="margin: 10px 0 0 20px;">
                                <li>Use emotional language or name-calling</li>
                                <li>Include your interpretations or assumptions</li>
                                <li>Exaggerate or embellish</li>
                                <li>Wait days/weeks to document</li>
                                <li>Leave out important context</li>
                                <li>Only document "big" incidents (pattern matters)</li>
                            </ul>
                        </div>
                    </div>
                </div>
                
                <div class="detail-section">
                    <h3>Common Incidents to Document</h3>
                    <div style="columns: 2; column-gap: 20px;">
                        <ul style="margin: 0 0 0 20px; line-height: 1.8;">
                            <li>Late pickups/drop-offs</li>
                            <li>No-shows for visitation</li>
                            <li>Verbal abuse or threats</li>
                            <li>Badmouthing you to children</li>
                            <li>Denying agreed-upon visitation</li>
                            <li>Refusing to communicate</li>
                            <li>Showing up intoxicated</li>
                            <li>Violating court orders</li>
                            <li>Harassment or stalking</li>
                            <li>Withholding information about children</li>
                            <li>Making unilateral decisions</li>
                            <li>False accusations</li>
                        </ul>
                    </div>
                </div>
                
                <div class="detail-section" style="background: linear-gradient(135deg, #fff3cd 0%, #ffeaa7 100%); border-left: 5px solid #ffc107;">
                    <h3 style="color: #856404;">⚖️ Legal Disclaimer</h3>
                    <p style="color: #856404;"><strong>This tool helps you organize documentation. It is not legal advice.</strong> Always consult with a qualified family law attorney about your specific situation. Laws vary by jurisdiction.</p>
                </div>
            </div>

            <div id="reminders-tab" class="tab-content">
                <h2>⏰ Reminders & Follow-ups</h2>
                <p style="color: #6c757d; margin-bottom: 20px;">Due and upcoming follow-ups in the next 72 hours.</p>
                <?php if (empty($dueFollowUps)): ?>
                    <div class="empty-state">No follow-ups due.</div>
                <?php else: ?>
                    <?php foreach ($dueFollowUps as $due): ?>
                        <div class="incident-card" style="border-left-color: #ffc107;">
                            <div class="incident-header">
                                <div>
                                    <strong>Incident #<?php echo $due['id']; ?></strong> - <?php echo htmlspecialchars($due['incident_type']); ?>
                                    <div style="color: #6c757d;">Follow-up by <?php echo date('M j, Y g:i A', strtotime($due['follow_up_at'])); ?></div>
                                </div>
                                <span class="badge" style="background: #343a40; color: white;">Status: <?php echo strtoupper($due['status']); ?></span>
                            </div>
                            <p><?php echo htmlspecialchars(substr($due['description'], 0, 160)); ?>...</p>
                            <div class="incident-actions">
                                <form method="POST" style="display:inline;">
                                    <input type="hidden" name="action" value="add_update">
                                    <input type="hidden" name="incident_id" value="<?php echo $due['id']; ?>">
                                    <input type="hidden" name="update_type" value="follow_up">
                                    <input type="hidden" name="update_text" value="Follow-up touched from reminders tab">
                                    <button class="btn btn-secondary" type="submit">Add Update Note</button>
                                </form>
                                <form method="POST" style="display:inline;">
                                    <input type="hidden" name="action" value="update_status">
                                    <input type="hidden" name="incident_id" value="<?php echo $due['id']; ?>">
                                    <input type="hidden" name="status" value="resolved">
                                    <button class="btn btn-success" type="submit">Mark Resolved</button>
                                </form>
                                <form method="POST" style="display:inline;">
                                    <input type="hidden" name="action" value="send_reminder_email">
                                    <input type="hidden" name="incident_id" value="<?php echo $due['id']; ?>">
                                    <input type="email" name="email" placeholder="notify@example.com" required style="padding:8px; border-radius:8px; border:1px solid #dee2e6;">
                                    <button class="btn btn-outline" type="submit">Send Email</button>
                                </form>
                            </div>
                        </div>
                    <?php endforeach; ?>
                <?php endif; ?>
            </div>

            <div id="settings-tab" class="tab-content">
                <h2>⚙️ Account Settings</h2>
                <div class="detail-section">
                    <h3>Change Password</h3>
                    <form method="POST" style="display:grid; gap:12px; max-width:420px;">
                        <input type="hidden" name="action" value="update_password">
                        <input type="password" name="current_password" placeholder="Current password" required>
                        <input type="password" name="new_password" placeholder="New password" required>
                        <input type="password" name="confirm_password" placeholder="Confirm new password" required>
                        <button class="btn btn-primary" type="submit">Update Password</button>
                    </form>
                </div>
                <div class="detail-section">
                    <h3>Invite Additional User</h3>
                    <form method="POST" style="display:grid; gap:12px; max-width:420px;">
                        <input type="hidden" name="action" value="create_user">
                        <input type="text" name="new_username" placeholder="Username" required>
                        <input type="email" name="new_email" placeholder="Email (optional)">
                        <input type="password" name="new_password" placeholder="Password" required>
                        <input type="password" name="new_password_confirm" placeholder="Confirm password" required>
                        <button class="btn btn-secondary" type="submit">Create User</button>
                    </form>
                </div>
            </div>
        </div>

        <?php elseif ($view === 'detail' && isset($_GET['id'])): ?>
        <?php
        $stmt = $conn->prepare("SELECT * FROM incidents WHERE id = ?");
        $stmt->execute([$_GET['id']]);
        $incident = $stmt->fetch(PDO::FETCH_ASSOC);

        if (!$incident) {
            echo '<div class="content"><p>Incident not found.</p><a href="index.php" class="btn btn-primary">Back to Dashboard</a></div>';
        } else {
            $stmt = $conn->prepare("SELECT * FROM incident_updates WHERE incident_id = ? ORDER BY created_at ASC");
            $stmt->execute([$_GET['id']]);
            $updates = $stmt->fetchAll(PDO::FETCH_ASSOC);
            $stmt = $conn->prepare("SELECT * FROM incident_evidence WHERE incident_id = ? ORDER BY created_at ASC");
            $stmt->execute([$_GET['id']]);
            $evidenceFiles = $stmt->fetchAll(PDO::FETCH_ASSOC);
            $shareLinks = [];
            if (currentUser($conn)) {
                $stmt = $conn->prepare("SELECT * FROM shared_access WHERE incident_id = ? ORDER BY created_at DESC");
                $stmt->execute([$_GET['id']]);
                $shareLinks = $stmt->fetchAll(PDO::FETCH_ASSOC);
            }

            if ($shareAccess && (int) $shareAccess['incident_id'] !== (int) $incident['id']) {
                echo '<div class="content"><p>Share link is not authorized for this incident.</p></div>';
                exit;
            }
        ?>

        <div class="content">
            <a href="index.php" class="back-link">← Back to Dashboard</a>
            <?php $shareQuery = $shareToken ? '&share_token=' . urlencode($shareToken) : ''; ?>

            <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 30px; flex-wrap: wrap; gap: 15px;">
                <div>
                    <h2>Incident #<?php echo str_pad($incident['id'], 4, '0', STR_PAD_LEFT); ?> - Full Report</h2>
                    <div style="display: flex; gap: 10px; margin-top: 10px;">
                        <span class="badge badge-type"><?php echo htmlspecialchars($incident['incident_type']); ?></span>
                        <span class="badge badge-urgency <?php echo $incident['urgency_level']; ?>">
                            <?php echo strtoupper($incident['urgency_level']); ?> PRIORITY
                        </span>
                    </div>
                </div>
                <div style="display: flex; gap: 10px; flex-wrap: wrap;">
                    <a href="?export=<?php echo $incident['id']; ?>&format=txt<?php echo $shareQuery; ?>" class="btn btn-success">📄 Export Full Report</a>
                    <?php if (!$shareAccess): ?>
                        <form method="POST">
                            <input type="hidden" name="action" value="update_status">
                            <input type="hidden" name="incident_id" value="<?php echo $incident['id']; ?>">
                            <input type="hidden" name="status" value="resolved">
                            <button type="submit" class="btn btn-primary">✅ Mark Resolved</button>
                        </form>
                    <?php endif; ?>
                </div>
            </div>
            
            <div class="detail-section">
                <h3>📋 Incident Information</h3>
                <div class="detail-grid">
                    <div class="detail-item">
                        <strong>Date/Time</strong>
                        <?php echo date('F j, Y @ g:i A', strtotime($incident['incident_date'])); ?>
                    </div>
                    <div class="detail-item">
                        <strong>Location</strong>
                        <?php echo htmlspecialchars($incident['location']); ?>
                    </div>
                    <div class="detail-item">
                        <strong>Communication Method</strong>
                        <?php echo htmlspecialchars($incident['communication_method'] ?: 'Not specified'); ?>
                    </div>
                    <div class="detail-item">
                        <strong>Children Present</strong>
                        <?php echo htmlspecialchars($incident['children_present'] ?: 'No'); ?>
                    </div>
                    <div class="detail-item">
                        <strong>Witnesses</strong>
                        <?php echo htmlspecialchars($incident['witnesses'] ?: 'None'); ?>
                    </div>
                    <div class="detail-item">
                        <strong>Reported</strong>
                        <?php echo date('F j, Y @ g:i A', strtotime($incident['created_at'])); ?>
                    </div>
                    <div class="detail-item">
                        <strong>Status</strong>
                        <?php echo strtoupper($incident['status']); ?>
                    </div>
                    <div class="detail-item">
                        <strong>Follow-Up Due</strong>
                        <?php echo $incident['follow_up_at'] ? date('F j, Y @ g:i A', strtotime($incident['follow_up_at'])) : 'Not set'; ?>
                    </div>
                </div>
            </div>

            <?php if (!$shareAccess): ?>
            <div class="detail-section">
                <h3>⚙️ Status & Follow-Up</h3>
                <div style="display: flex; gap: 10px; flex-wrap: wrap;">
                    <form method="POST">
                        <input type="hidden" name="action" value="update_status">
                        <input type="hidden" name="incident_id" value="<?php echo $incident['id']; ?>">
                        <input type="hidden" name="status" value="in-progress">
                        <button class="btn btn-secondary" type="submit">🚧 Mark In-Progress</button>
                    </form>
                    <form method="POST">
                        <input type="hidden" name="action" value="update_status">
                        <input type="hidden" name="incident_id" value="<?php echo $incident['id']; ?>">
                        <input type="hidden" name="status" value="escalated">
                        <button class="btn btn-danger" type="submit">🚨 Escalate</button>
                    </form>
                    <form method="POST">
                        <input type="hidden" name="action" value="update_status">
                        <input type="hidden" name="incident_id" value="<?php echo $incident['id']; ?>">
                        <input type="hidden" name="status" value="resolved">
                        <button class="btn btn-success" type="submit">✅ Resolve</button>
                    </form>
                </div>
            </div>
            <?php endif; ?>
            
            <div class="detail-section">
                <h3>📝 Detailed Description</h3>
                <p style="white-space: pre-wrap; line-height: 1.8;"><?php echo htmlspecialchars($incident['description']); ?></p>
            </div>
            
            <?php if (!empty($incident['direct_quotes'])): ?>
            <div class="detail-section">
                <h3>💬 Direct Quotes</h3>
                <p style="white-space: pre-wrap; line-height: 1.8; font-style: italic; background: white; padding: 15px; border-radius: 8px;">
                    <?php echo htmlspecialchars($incident['direct_quotes']); ?>
                </p>
            </div>
            <?php endif; ?>
            
            <?php if (!empty($incident['child_impact'])): ?>
            <div class="detail-section">
                <h3>👶 Impact on Child(ren)</h3>
                <p style="white-space: pre-wrap; line-height: 1.8;"><?php echo htmlspecialchars($incident['child_impact']); ?></p>
            </div>
            <?php endif; ?>
            
            <?php if (!empty($incident['your_response'])): ?>
            <div class="detail-section">
                <h3>✋ Your Response</h3>
                <p style="white-space: pre-wrap; line-height: 1.8;"><?php echo htmlspecialchars($incident['your_response']); ?></p>
            </div>
            <?php endif; ?>
            
            <?php if (!empty($incident['evidence_list'])): ?>
            <div class="detail-section">
                <h3>📎 Evidence</h3>
                <p style="white-space: pre-wrap; line-height: 1.8;"><?php echo htmlspecialchars($incident['evidence_list']); ?></p>
            </div>
            <?php endif; ?>

            <?php if (!empty($evidenceFiles)): ?>
            <div class="detail-section">
                <h3>🖼️ Evidence Files</h3>
                <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(240px, 1fr)); gap: 15px;">
                    <?php foreach ($evidenceFiles as $file): ?>
                        <div class="detail-item" style="background: white;">
                            <strong><?php echo htmlspecialchars($file['original_name']); ?></strong>
                            <div style="margin: 8px 0; color: #6c757d; font-size: 0.9em;">Type: <?php echo htmlspecialchars($file['mime_type']); ?></div>
                            <a href="?download_evidence=<?php echo $file['id']; ?><?php echo $shareQuery; ?>" class="btn btn-outline" style="margin-bottom: 10px;">⬇️ Download</a>
                            <?php if (strpos($file['mime_type'], 'image/') === 0): ?>
                                <img src="uploads/<?php echo urlencode($file['file_name']); ?>" alt="Evidence image" style="width: 100%; max-height: 200px; object-fit: cover; border-radius: 8px;">
                            <?php elseif ($file['mime_type'] === 'application/pdf'): ?>
                                <embed src="uploads/<?php echo urlencode($file['file_name']); ?>" type="application/pdf" style="width: 100%; height: 200px; border: 1px solid #dee2e6; border-radius: 6px;" />
                            <?php else: ?>
                                <p style="color: #6c757d;">Preview not available</p>
                            <?php endif; ?>
                        </div>
                    <?php endforeach; ?>
                </div>
            </div>
            <?php endif; ?>

            <?php if (!$shareAccess && currentUser($conn)): ?>
            <div class="detail-section">
                <h3>🔗 Shared Access</h3>
                <form method="POST" style="margin-bottom: 20px; display: grid; grid-template-columns: repeat(auto-fit, minmax(240px, 1fr)); gap: 12px;">
                    <input type="hidden" name="action" value="create_share">
                    <input type="hidden" name="incident_id" value="<?php echo $incident['id']; ?>">
                    <div>
                        <label>Role</label>
                        <select name="role">
                            <option value="viewer">Viewer (read-only)</option>
                            <option value="export">Viewer + Export</option>
                        </select>
                    </div>
                    <div>
                        <label>Expires At</label>
                        <input type="datetime-local" name="expires_at" value="<?php echo date('Y-m-d\\TH:i', strtotime('+7 days')); ?>">
                    </div>
                    <div style="display: flex; align-items: flex-end;">
                        <button type="submit" class="btn btn-primary">Generate Share Link</button>
                    </div>
                </form>

                <?php if (!empty($shareLinks)): ?>
                    <div style="overflow-x: auto;">
                        <table style="width: 100%; border-collapse: collapse;">
                            <thead>
                                <tr style="background: #e9ecef;">
                                    <th style="text-align: left; padding: 8px;">Role</th>
                                    <th style="text-align: left; padding: 8px;">Expires</th>
                                    <th style="text-align: left; padding: 8px;">Share Link</th>
                                    <th></th>
                                </tr>
                            </thead>
                            <tbody>
                                <?php foreach ($shareLinks as $link): ?>
                                <?php $shareUrl = (isset($_SERVER['HTTP_HOST']) ? ((isset($_SERVER['HTTPS']) && $_SERVER['HTTPS'] === 'on' ? 'https' : 'http') . '://' . $_SERVER['HTTP_HOST'] . $_SERVER['PHP_SELF']) : 'index.php') . '?view=detail&id=' . $incident['id'] . '&share_token=' . urlencode($link['invite_token']); ?>
                                <tr>
                                    <td style="padding: 8px;"><?php echo htmlspecialchars($link['role']); ?></td>
                                    <td style="padding: 8px;"><?php echo $link['expires_at'] ? htmlspecialchars($link['expires_at']) : 'No expiry'; ?></td>
                                    <td style="padding: 8px;"><a href="<?php echo htmlspecialchars($shareUrl); ?>" target="_blank">Open Link</a></td>
                                    <td style="padding: 8px;">
                                        <form method="POST" onsubmit="return confirm('Revoke this link?');">
                                            <input type="hidden" name="action" value="revoke_share">
                                            <input type="hidden" name="incident_id" value="<?php echo $incident['id']; ?>">
                                            <input type="hidden" name="share_id" value="<?php echo $link['id']; ?>">
                                            <button type="submit" class="btn btn-danger">Revoke</button>
                                        </form>
                                    </td>
                                </tr>
                                <?php endforeach; ?>
                            </tbody>
                        </table>
                    </div>
                <?php else: ?>
                    <p style="color: #6c757d;">No active shared links.</p>
                <?php endif; ?>
            </div>
            <?php elseif ($shareAccess): ?>
                <div class="alert info" style="margin-bottom: 20px;">🔒 Read-only shared link access</div>
            <?php endif; ?>
            
            <?php if (!empty($incident['legal_violations'])): ?>
            <div class="detail-section">
                <h3>⚖️ Legal Violations / Court Order Breaches</h3>
                <p style="white-space: pre-wrap; line-height: 1.8; background: #fff5f5; padding: 15px; border-radius: 8px; border-left: 4px solid #dc3545;">
                    <?php echo htmlspecialchars($incident['legal_violations']); ?>
                </p>
            </div>
            <?php endif; ?>
            
            <?php if (!empty($incident['pattern_notes'])): ?>
            <div class="detail-section">
                <h3>🔄 Pattern Analysis</h3>
                <p style="white-space: pre-wrap; line-height: 1.8;"><?php echo htmlspecialchars($incident['pattern_notes']); ?></p>
            </div>
            <?php endif; ?>
            
            <div class="detail-section">
                <h3>📌 Follow-Up Documentation</h3>
                
                <?php if (empty($updates)): ?>
                    <p style="color: #6c757d;">No follow-up notes yet</p>
                <?php else: ?>
                    <?php foreach ($updates as $update): ?>
                    <div class="update-item">
                        <div class="update-header">
                            <div class="update-date">
                                📅 <?php echo date('F j, Y @ g:i A', strtotime($update['created_at'])); ?>
                            </div>
                            <span class="update-type-badge"><?php echo ucfirst($update['update_type']); ?></span>
                        </div>
                        <p style="white-space: pre-wrap; line-height: 1.7;"><?php echo htmlspecialchars($update['update_text']); ?></p>
                    </div>
                    <?php endforeach; ?>
                <?php endif; ?>
                
                <?php if (!$shareAccess): ?>
                <form method="POST" style="margin-top: 25px;">
                    <input type="hidden" name="action" value="add_update">
                    <input type="hidden" name="incident_id" value="<?php echo $incident['id']; ?>">

                    <div class="form-group">
                        <label>Update Type</label>
                        <select name="update_type">
                            <option value="general">General Update</option>
                            <option value="escalation">Escalation</option>
                            <option value="resolution">Resolution</option>
                            <option value="legal_action">Legal Action Taken</option>
                            <option value="follow_up">Follow-Up Incident</option>
                        </select>
                    </div>

                    <div class="form-group">
                        <label>Add Follow-Up Note</label>
                        <textarea name="update_text" placeholder="Document new developments, follow-up actions, similar incidents, legal steps taken, etc." required></textarea>
                    </div>
                    <button type="submit" class="btn btn-primary">➕ Add Follow-Up</button>
                </form>
                <?php endif; ?>
            </div>
        </div>
        <?php } endif; ?>
        <?php endif; ?>
    </div>

    <script>
        function showTab(tab) {
            document.querySelectorAll('.tab-content').forEach(t => t.classList.remove('active'));
            document.querySelectorAll('.nav-tab').forEach(t => t.classList.remove('active'));
            
            const tabContent = document.getElementById(tab + '-tab');
            if (tabContent) {
                tabContent.classList.add('active');
            }
            
            event.target.classList.add('active');
        }
    </script>
</body>
</html>
