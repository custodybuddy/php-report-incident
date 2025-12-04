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
                urgency_level VARCHAR(20) DEFAULT 'medium',
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
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
    }
    
    public function getConnection() {
        return $this->db;
    }
}

// index.php - Main Application
session_start();
$db = new Database();
$conn = $db->getConnection();

function validateIncident(array $data): array {
    $errors = [];

    $incidentDate = trim($data['incident_date'] ?? '');
    $incidentType = trim($data['incident_type'] ?? '');
    $description = trim($data['description'] ?? '');
    $urgency = $data['urgency_level'] ?? '';

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

    $allowedUrgency = ['low', 'medium', 'high'];
    if (!in_array($urgency, $allowedUrgency, true)) {
        $errors[] = 'Urgency level is invalid.';
    }

    return $errors;
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
            case 'create_incident':
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
                    'urgency_level' => $_POST['urgency_level'] ?? ''
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

                $stmt = $conn->prepare("
                    INSERT INTO incidents (incident_date, incident_type, location, communication_method,
                                         witnesses, children_present, description, direct_quotes,
                                         child_impact, your_response, evidence_list, legal_violations,
                                         pattern_notes, urgency_level)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
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
                    $incidentData['urgency_level']
                ]);

                $_SESSION['message'] = "✅ Incident #" . $conn->lastInsertId() . " documented successfully!";
                $_SESSION['message_type'] = "success";
                header('Location: index.php');
                exit;

            case 'add_update':
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
                
            case 'delete_incident':
                $stmt = $conn->prepare("DELETE FROM incidents WHERE id = ?");
                $stmt->execute([$_POST['incident_id']]);
                $_SESSION['message'] = "🗑️ Incident deleted";
                $_SESSION['message_type'] = "info";
                header('Location: index.php');
                exit;
        }
    }
}

// Export functionality
if (isset($_GET['export'])) {
    $id = $_GET['export'];
    $format = $_GET['format'] ?? 'txt';
    
    $stmt = $conn->prepare("SELECT * FROM incidents WHERE id = ?");
    $stmt->execute([$id]);
    $incident = $stmt->fetch(PDO::FETCH_ASSOC);
    
    $stmt = $conn->prepare("SELECT * FROM incident_updates WHERE incident_id = ? ORDER BY created_at ASC");
    $stmt->execute([$id]);
    $updates = $stmt->fetchAll(PDO::FETCH_ASSOC);
    
    if ($format === 'txt') {
        header('Content-Type: text/plain; charset=utf-8');
        header('Content-Disposition: attachment; filename="custody_incident_' . $id . '_' . date('Y-m-d') . '.txt"');
        
        echo "═══════════════════════════════════════════════════════════════\n";
        echo "           CO-PARENTING INCIDENT REPORT - OFFICIAL\n";
        echo "═══════════════════════════════════════════════════════════════\n\n";
        
        echo "REPORT INFORMATION\n";
        echo str_repeat("─", 63) . "\n";
        echo "Report ID:           #" . str_pad($incident['id'], 6, '0', STR_PAD_LEFT) . "\n";
        echo "Generated:           " . date('F j, Y \a\t g:i A T') . "\n";
        echo "Report Created:      " . date('F j, Y \a\t g:i A', strtotime($incident['created_at'])) . "\n";
        echo "Last Updated:        " . date('F j, Y \a\t g:i A', strtotime($incident['updated_at'])) . "\n";
        echo "Urgency Level:       " . strtoupper($incident['urgency_level']) . "\n\n";
        
        echo "INCIDENT DETAILS\n";
        echo str_repeat("─", 63) . "\n";
        echo "Date/Time:           " . date('F j, Y \a\t g:i A', strtotime($incident['incident_date'])) . "\n";
        echo "Incident Type:       " . $incident['incident_type'] . "\n";
        echo "Location:            " . $incident['location'] . "\n";
        echo "Communication Via:   " . ($incident['communication_method'] ?: 'N/A') . "\n";
        echo "Children Present:    " . ($incident['children_present'] ?: 'N/A') . "\n";
        echo "Witnesses:           " . ($incident['witnesses'] ?: 'None') . "\n\n";
        
        echo "DETAILED DESCRIPTION\n";
        echo str_repeat("─", 63) . "\n";
        echo wordwrap($incident['description'], 63) . "\n\n";
        
        if (!empty($incident['direct_quotes'])) {
            echo "DIRECT QUOTES / VERBATIM STATEMENTS\n";
            echo str_repeat("─", 63) . "\n";
            echo wordwrap($incident['direct_quotes'], 63) . "\n\n";
        }
        
        if (!empty($incident['child_impact'])) {
            echo "IMPACT ON CHILD(REN)\n";
            echo str_repeat("─", 63) . "\n";
            echo wordwrap($incident['child_impact'], 63) . "\n\n";
        }
        
        if (!empty($incident['your_response'])) {
            echo "YOUR RESPONSE\n";
            echo str_repeat("─", 63) . "\n";
            echo wordwrap($incident['your_response'], 63) . "\n\n";
        }
        
        if (!empty($incident['evidence_list'])) {
            echo "SUPPORTING EVIDENCE\n";
            echo str_repeat("─", 63) . "\n";
            echo wordwrap($incident['evidence_list'], 63) . "\n\n";
        }
        
        if (!empty($incident['legal_violations'])) {
            echo "POTENTIAL LEGAL VIOLATIONS / COURT ORDER BREACHES\n";
            echo str_repeat("─", 63) . "\n";
            echo wordwrap($incident['legal_violations'], 63) . "\n\n";
        }
        
        if (!empty($incident['pattern_notes'])) {
            echo "PATTERN ANALYSIS\n";
            echo str_repeat("─", 63) . "\n";
            echo wordwrap($incident['pattern_notes'], 63) . "\n\n";
        }
        
        if (!empty($updates)) {
            echo "FOLLOW-UP DOCUMENTATION\n";
            echo str_repeat("─", 63) . "\n";
            foreach ($updates as $i => $update) {
                echo "\n[Update #" . ($i + 1) . " - " . date('F j, Y \a\t g:i A', strtotime($update['created_at'])) . "]\n";
                echo "Type: " . ucfirst($update['update_type']) . "\n";
                echo wordwrap($update['update_text'], 63) . "\n";
            }
            echo "\n";
        }
        
        echo str_repeat("═", 63) . "\n";
        echo "END OF REPORT\n\n";
        echo "This document was generated by CustodyBuddy Incident Reporting System\n";
        echo "Document is timestamped and suitable for legal proceedings.\n";
        echo "Please consult with your attorney regarding use of this documentation.\n";
        echo str_repeat("═", 63) . "\n";
        
    } elseif ($format === 'timeline') {
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
    }
    exit;
}

// Get statistics
$stats = [
    'total' => $conn->query("SELECT COUNT(*) FROM incidents")->fetchColumn(),
    'high_urgency' => $conn->query("SELECT COUNT(*) FROM incidents WHERE urgency_level = 'high'")->fetchColumn(),
    'this_month' => $conn->query("SELECT COUNT(*) FROM incidents WHERE strftime('%Y-%m', incident_date) = strftime('%Y-%m', 'now')")->fetchColumn()
];

// Get view mode
$view = $_GET['view'] ?? 'dashboard';
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
        
        <?php if ($view === 'dashboard'): ?>
        <div class="nav-tabs">
            <button class="nav-tab active" onclick="showTab('dashboard')">📊 Dashboard</button>
            <button class="nav-tab" onclick="showTab('list')">📋 All Incidents</button>
            <button class="nav-tab" onclick="showTab('new')">➕ Report Incident</button>
            <button class="nav-tab" onclick="showTab('tips')">💡 Tips & Guide</button>
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
                
                <?php
                $incidents = $conn->query("SELECT * FROM incidents ORDER BY incident_date DESC")->fetchAll(PDO::FETCH_ASSOC);
                if (empty($incidents)): ?>
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
                
                <form method="POST">
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
        ?>
        
        <div class="content">
            <a href="index.php" class="back-link">← Back to Dashboard</a>
            
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
                <a href="?export=<?php echo $incident['id']; ?>&format=txt" class="btn btn-success">📄 Export Full Report</a>
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
                </div>
            </div>
            
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
            </div>
        </div>
        <?php } endif; ?>
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
