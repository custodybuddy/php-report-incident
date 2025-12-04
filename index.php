<?php
// config.php - Database Configuration
class Database {
    private $db;
    
    public function __construct() {
        try {
            $this->db = new PDO('sqlite:' . __DIR__ . '/incidents.db');
            $this->db->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
            $this->createTables();
        } catch(PDOException $e) {
            die("Database Error: " . $e->getMessage());
        }
    }
    
    private function createTables() {
        $this->db->exec("
            CREATE TABLE IF NOT EXISTS incidents (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                incident_date DATETIME NOT NULL,
                incident_type VARCHAR(100) NOT NULL,
                location TEXT,
                witnesses TEXT,
                description TEXT NOT NULL,
                immediate_impact TEXT,
                evidence_files TEXT,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        ");
        
        $this->db->exec("
            CREATE TABLE IF NOT EXISTS incident_updates (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                incident_id INTEGER NOT NULL,
                update_text TEXT NOT NULL,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (incident_id) REFERENCES incidents(id) ON DELETE CASCADE
            )
        ");
    }
    
    public function getConnection() {
        return $this->db;
    }
}

// index.php - Main Application
session_start();
$db = new Database();
$conn = $db->getConnection();

// Handle form submissions
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if (isset($_POST['action'])) {
        switch ($_POST['action']) {
            case 'create_incident':
                $stmt = $conn->prepare("
                    INSERT INTO incidents (incident_date, incident_type, location, witnesses, 
                                         description, immediate_impact, evidence_files)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                ");
                
                $evidence = '';
                if (!empty($_POST['evidence_files'])) {
                    $evidence = $_POST['evidence_files'];
                }
                
                $stmt->execute([
                    $_POST['incident_date'],
                    $_POST['incident_type'],
                    $_POST['location'],
                    $_POST['witnesses'],
                    $_POST['description'],
                    $_POST['immediate_impact'],
                    $evidence
                ]);
                
                $_SESSION['message'] = "Incident reported successfully! ID: " . $conn->lastInsertId();
                header('Location: index.php');
                exit;
                
            case 'add_update':
                $stmt = $conn->prepare("
                    INSERT INTO incident_updates (incident_id, update_text)
                    VALUES (?, ?)
                ");
                $stmt->execute([$_POST['incident_id'], $_POST['update_text']]);
                
                $stmt = $conn->prepare("UPDATE incidents SET updated_at = CURRENT_TIMESTAMP WHERE id = ?");
                $stmt->execute([$_POST['incident_id']]);
                
                $_SESSION['message'] = "Update added successfully!";
                header('Location: index.php?view=detail&id=' . $_POST['incident_id']);
                exit;
                
            case 'delete_incident':
                $stmt = $conn->prepare("DELETE FROM incidents WHERE id = ?");
                $stmt->execute([$_POST['incident_id']]);
                $_SESSION['message'] = "Incident deleted successfully!";
                header('Location: index.php');
                exit;
        }
    }
}

// Handle exports
if (isset($_GET['export'])) {
    $id = $_GET['export'];
    $stmt = $conn->prepare("SELECT * FROM incidents WHERE id = ?");
    $stmt->execute([$id]);
    $incident = $stmt->fetch(PDO::FETCH_ASSOC);
    
    $stmt = $conn->prepare("SELECT * FROM incident_updates WHERE incident_id = ? ORDER BY created_at ASC");
    $stmt->execute([$id]);
    $updates = $stmt->fetchAll(PDO::FETCH_ASSOC);
    
    header('Content-Type: text/plain');
    header('Content-Disposition: attachment; filename="incident_report_' . $id . '.txt"');
    
    echo "=== INCIDENT REPORT ===\n\n";
    echo "Report ID: " . $incident['id'] . "\n";
    echo "Generated: " . date('Y-m-d H:i:s') . "\n";
    echo str_repeat("=", 50) . "\n\n";
    
    echo "INCIDENT DETAILS\n";
    echo str_repeat("-", 50) . "\n";
    echo "Date/Time of Incident: " . date('F j, Y g:i A', strtotime($incident['incident_date'])) . "\n";
    echo "Type: " . $incident['incident_type'] . "\n";
    echo "Location: " . $incident['location'] . "\n";
    echo "Witnesses: " . $incident['witnesses'] . "\n\n";
    
    echo "DESCRIPTION\n";
    echo str_repeat("-", 50) . "\n";
    echo $incident['description'] . "\n\n";
    
    echo "IMMEDIATE IMPACT\n";
    echo str_repeat("-", 50) . "\n";
    echo $incident['immediate_impact'] . "\n\n";
    
    if (!empty($incident['evidence_files'])) {
        echo "EVIDENCE FILES\n";
        echo str_repeat("-", 50) . "\n";
        echo $incident['evidence_files'] . "\n\n";
    }
    
    if (!empty($updates)) {
        echo "INCIDENT UPDATES\n";
        echo str_repeat("-", 50) . "\n";
        foreach ($updates as $update) {
            echo "[" . date('F j, Y g:i A', strtotime($update['created_at'])) . "]\n";
            echo $update['update_text'] . "\n\n";
        }
    }
    
    echo str_repeat("=", 50) . "\n";
    echo "End of Report\n";
    echo "This document was generated from the Incident Reporting System\n";
    exit;
}

// Get view mode
$view = $_GET['view'] ?? 'list';
$incidents = [];

if ($view === 'list') {
    $stmt = $conn->query("SELECT * FROM incidents ORDER BY incident_date DESC");
    $incidents = $stmt->fetchAll(PDO::FETCH_ASSOC);
} elseif ($view === 'detail' && isset($_GET['id'])) {
    $stmt = $conn->prepare("SELECT * FROM incidents WHERE id = ?");
    $stmt->execute([$_GET['id']]);
    $incident = $stmt->fetch(PDO::FETCH_ASSOC);
    
    $stmt = $conn->prepare("SELECT * FROM incident_updates WHERE incident_id = ? ORDER BY created_at ASC");
    $stmt->execute([$_GET['id']]);
    $updates = $stmt->fetchAll(PDO::FETCH_ASSOC);
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Incident Reporter - Court-Ready Documentation</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            padding: 20px;
        }
        
        .container {
            max-width: 1200px;
            margin: 0 auto;
            background: white;
            border-radius: 15px;
            box-shadow: 0 20px 60px rgba(0,0,0,0.3);
            overflow: hidden;
        }
        
        header {
            background: linear-gradient(135deg, #1e3c72 0%, #2a5298 100%);
            color: white;
            padding: 30px;
            text-align: center;
        }
        
        header h1 {
            font-size: 2em;
            margin-bottom: 10px;
        }
        
        header p {
            opacity: 0.9;
            font-size: 1.1em;
        }
        
        .alert {
            padding: 15px;
            margin: 20px;
            background: #d4edda;
            border: 1px solid #c3e6cb;
            border-radius: 8px;
            color: #155724;
        }
        
        .nav-tabs {
            display: flex;
            background: #f8f9fa;
            border-bottom: 2px solid #dee2e6;
        }
        
        .nav-tab {
            flex: 1;
            padding: 15px;
            text-align: center;
            background: none;
            border: none;
            cursor: pointer;
            font-size: 1em;
            color: #495057;
            transition: all 0.3s;
        }
        
        .nav-tab:hover {
            background: #e9ecef;
        }
        
        .nav-tab.active {
            background: white;
            color: #2a5298;
            font-weight: bold;
            border-bottom: 3px solid #2a5298;
        }
        
        .content {
            padding: 30px;
        }
        
        .form-group {
            margin-bottom: 20px;
        }
        
        label {
            display: block;
            font-weight: bold;
            margin-bottom: 5px;
            color: #333;
        }
        
        input[type="text"],
        input[type="datetime-local"],
        select,
        textarea {
            width: 100%;
            padding: 12px;
            border: 2px solid #e1e8ed;
            border-radius: 8px;
            font-size: 1em;
            transition: border-color 0.3s;
        }
        
        input:focus,
        select:focus,
        textarea:focus {
            outline: none;
            border-color: #667eea;
        }
        
        textarea {
            min-height: 120px;
            resize: vertical;
            font-family: inherit;
        }
        
        .btn {
            padding: 12px 30px;
            border: none;
            border-radius: 8px;
            font-size: 1em;
            cursor: pointer;
            transition: all 0.3s;
            font-weight: bold;
        }
        
        .btn-primary {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
        }
        
        .btn-primary:hover {
            transform: translateY(-2px);
            box-shadow: 0 5px 15px rgba(102, 126, 234, 0.4);
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
        
        .incident-card {
            background: #f8f9fa;
            border-radius: 10px;
            padding: 20px;
            margin-bottom: 20px;
            border-left: 5px solid #667eea;
            transition: transform 0.2s;
        }
        
        .incident-card:hover {
            transform: translateX(5px);
            box-shadow: 0 5px 15px rgba(0,0,0,0.1);
        }
        
        .incident-header {
            display: flex;
            justify-content: space-between;
            align-items: start;
            margin-bottom: 15px;
        }
        
        .incident-type {
            display: inline-block;
            padding: 5px 15px;
            background: #667eea;
            color: white;
            border-radius: 20px;
            font-size: 0.9em;
            font-weight: bold;
        }
        
        .incident-date {
            color: #6c757d;
            font-size: 0.95em;
        }
        
        .incident-actions {
            display: flex;
            gap: 10px;
            margin-top: 15px;
        }
        
        .update-item {
            background: white;
            padding: 15px;
            border-radius: 8px;
            margin-bottom: 10px;
            border-left: 3px solid #28a745;
        }
        
        .update-date {
            color: #6c757d;
            font-size: 0.85em;
            margin-bottom: 8px;
        }
        
        .detail-section {
            margin-bottom: 30px;
        }
        
        .detail-section h3 {
            color: #2a5298;
            margin-bottom: 15px;
            padding-bottom: 10px;
            border-bottom: 2px solid #e9ecef;
        }
        
        .back-link {
            display: inline-block;
            margin-bottom: 20px;
            color: #667eea;
            text-decoration: none;
            font-weight: bold;
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
            padding: 60px 20px;
            color: #6c757d;
        }
        
        .empty-state h3 {
            margin-bottom: 10px;
        }
    </style>
</head>
<body>
    <div class="container">
        <header>
            <h1>🎯 Incident Reporter</h1>
            <p>Court-Ready Documentation | Timestamp Everything | Professional Exports</p>
        </header>
        
        <?php if (isset($_SESSION['message'])): ?>
            <div class="alert">
                <?php echo htmlspecialchars($_SESSION['message']); unset($_SESSION['message']); ?>
            </div>
        <?php endif; ?>
        
        <?php if ($view === 'list'): ?>
        <div class="nav-tabs">
            <button class="nav-tab active" onclick="showTab('list')">📋 All Incidents</button>
            <button class="nav-tab" onclick="showTab('new')">➕ Report New Incident</button>
        </div>
        
        <div class="content">
            <div id="list-tab" class="tab-content active">
                <h2>Incident Reports</h2>
                <p style="color: #6c757d; margin-bottom: 20px;">All incidents are timestamped and ready for legal documentation</p>
                
                <?php if (empty($incidents)): ?>
                    <div class="empty-state">
                        <h3>No Incidents Reported Yet</h3>
                        <p>Click "Report New Incident" to document your first incident</p>
                    </div>
                <?php else: ?>
                    <?php foreach ($incidents as $inc): ?>
                    <div class="incident-card">
                        <div class="incident-header">
                            <div>
                                <span class="incident-type"><?php echo htmlspecialchars($inc['incident_type']); ?></span>
                                <h3 style="margin-top: 10px;">Incident #<?php echo $inc['id']; ?></h3>
                            </div>
                            <div class="incident-date">
                                📅 <?php echo date('M j, Y g:i A', strtotime($inc['incident_date'])); ?>
                            </div>
                        </div>
                        
                        <p><strong>Location:</strong> <?php echo htmlspecialchars($inc['location']); ?></p>
                        <p style="margin-top: 10px;"><?php echo htmlspecialchars(substr($inc['description'], 0, 150)); ?>...</p>
                        
                        <div class="incident-actions">
                            <a href="?view=detail&id=<?php echo $inc['id']; ?>" class="btn btn-primary">View Details</a>
                            <a href="?export=<?php echo $inc['id']; ?>" class="btn btn-success">📄 Export Report</a>
                            <form method="POST" style="display: inline;" onsubmit="return confirm('Delete this incident?');">
                                <input type="hidden" name="action" value="delete_incident">
                                <input type="hidden" name="incident_id" value="<?php echo $inc['id']; ?>">
                                <button type="submit" class="btn btn-danger">Delete</button>
                            </form>
                        </div>
                    </div>
                    <?php endforeach; ?>
                <?php endif; ?>
            </div>
            
            <div id="new-tab" class="tab-content">
                <h2>Report New Incident</h2>
                <p style="color: #6c757d; margin-bottom: 20px;">Document everything with precise timestamps for court-ready evidence</p>
                
                <form method="POST">
                    <input type="hidden" name="action" value="create_incident">
                    
                    <div class="form-group">
                        <label>📅 Date & Time of Incident *</label>
                        <input type="datetime-local" name="incident_date" required>
                    </div>
                    
                    <div class="form-group">
                        <label>🏷️ Incident Type *</label>
                        <select name="incident_type" required>
                            <option value="">Select type...</option>
                            <option value="Harassment">Harassment</option>
                            <option value="Verbal Abuse">Verbal Abuse</option>
                            <option value="Threats">Threats</option>
                            <option value="Property Damage">Property Damage</option>
                            <option value="Workplace Misconduct">Workplace Misconduct</option>
                            <option value="Discrimination">Discrimination</option>
                            <option value="Other">Other</option>
                        </select>
                    </div>
                    
                    <div class="form-group">
                        <label>📍 Location *</label>
                        <input type="text" name="location" placeholder="Where did this occur?" required>
                    </div>
                    
                    <div class="form-group">
                        <label>👥 Witnesses</label>
                        <input type="text" name="witnesses" placeholder="Names of any witnesses (optional)">
                    </div>
                    
                    <div class="form-group">
                        <label>📝 Detailed Description *</label>
                        <textarea name="description" placeholder="Describe what happened in detail. Include quotes, actions, and context." required></textarea>
                    </div>
                    
                    <div class="form-group">
                        <label>⚠️ Immediate Impact</label>
                        <textarea name="immediate_impact" placeholder="How did this affect you immediately? (emotional, physical, professional, etc.)"></textarea>
                    </div>
                    
                    <div class="form-group">
                        <label>📎 Evidence Files (optional)</label>
                        <input type="text" name="evidence_files" placeholder="List file names of photos, videos, screenshots, etc.">
                    </div>
                    
                    <button type="submit" class="btn btn-primary">Submit Incident Report</button>
                </form>
            </div>
        </div>
        
        <?php elseif ($view === 'detail' && isset($incident)): ?>
        <div class="content">
            <a href="index.php" class="back-link">← Back to All Incidents</a>
            
            <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 30px;">
                <h2>Incident #<?php echo $incident['id']; ?> Details</h2>
                <a href="?export=<?php echo $incident['id']; ?>" class="btn btn-success">📄 Export Full Report</a>
            </div>
            
            <div class="detail-section">
                <h3>Incident Information</h3>
                <p><strong>Type:</strong> <span class="incident-type"><?php echo htmlspecialchars($incident['incident_type']); ?></span></p>
                <p><strong>Date/Time:</strong> <?php echo date('F j, Y g:i A', strtotime($incident['incident_date'])); ?></p>
                <p><strong>Location:</strong> <?php echo htmlspecialchars($incident['location']); ?></p>
                <p><strong>Witnesses:</strong> <?php echo htmlspecialchars($incident['witnesses']) ?: 'None listed'; ?></p>
                <p><strong>Reported:</strong> <?php echo date('F j, Y g:i A', strtotime($incident['created_at'])); ?></p>
            </div>
            
            <div class="detail-section">
                <h3>Description</h3>
                <p style="white-space: pre-wrap;"><?php echo htmlspecialchars($incident['description']); ?></p>
            </div>
            
            <?php if (!empty($incident['immediate_impact'])): ?>
            <div class="detail-section">
                <h3>Immediate Impact</h3>
                <p style="white-space: pre-wrap;"><?php echo htmlspecialchars($incident['immediate_impact']); ?></p>
            </div>
            <?php endif; ?>
            
            <?php if (!empty($incident['evidence_files'])): ?>
            <div class="detail-section">
                <h3>Evidence Files</h3>
                <p><?php echo htmlspecialchars($incident['evidence_files']); ?></p>
            </div>
            <?php endif; ?>
            
            <div class="detail-section">
                <h3>Updates & Follow-ups</h3>
                
                <?php if (empty($updates)): ?>
                    <p style="color: #6c757d;">No updates yet</p>
                <?php else: ?>
                    <?php foreach ($updates as $update): ?>
                    <div class="update-item">
                        <div class="update-date">
                            📅 <?php echo date('F j, Y g:i A', strtotime($update['created_at'])); ?>
                        </div>
                        <p style="white-space: pre-wrap;"><?php echo htmlspecialchars($update['update_text']); ?></p>
                    </div>
                    <?php endforeach; ?>
                <?php endif; ?>
                
                <form method="POST" style="margin-top: 20px;">
                    <input type="hidden" name="action" value="add_update">
                    <input type="hidden" name="incident_id" value="<?php echo $incident['id']; ?>">
                    <div class="form-group">
                        <label>Add Update</label>
                        <textarea name="update_text" placeholder="Document new developments, follow-up actions, or additional context..." required></textarea>
                    </div>
                    <button type="submit" class="btn btn-primary">Add Update</button>
                </form>
            </div>
        </div>
        <?php endif; ?>
    </div>
    
    <script>
        function showTab(tab) {
            document.querySelectorAll('.tab-content').forEach(t => t.classList.remove('active'));
            document.querySelectorAll('.nav-tab').forEach(t => t.classList.remove('active'));
            
            document.getElementById(tab + '-tab').classList.add('active');
            event.target.classList.add('active');
        }
    </script>
</body>
</html>
