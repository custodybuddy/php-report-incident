<?php
// Cron-compatible follow-up reminder script
$dsn = 'sqlite:' . __DIR__ . '/custodybuddy.db';
$db = new PDO($dsn);
$db->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

// escalate overdue
$escalateStmt = $db->prepare("UPDATE incidents SET status = 'escalated', updated_at = CURRENT_TIMESTAMP WHERE status NOT IN ('resolved','escalated') AND follow_up_at IS NOT NULL AND datetime(follow_up_at) < datetime('now')");
$escalateStmt->execute();

// fetch due today or overdue
$dueStmt = $db->prepare("SELECT id, incident_type, follow_up_at, status FROM incidents WHERE follow_up_at IS NOT NULL AND status != 'resolved' AND datetime(follow_up_at) <= datetime('now','+1 day') ORDER BY follow_up_at ASC");
$dueStmt->execute();
$due = $dueStmt->fetchAll(PDO::FETCH_ASSOC);

if (empty($due)) {
    echo "No follow-up reminders due.\n";
    exit;
}

$messageLines = ["CustodyBuddy Follow-Up Reminders", str_repeat('=', 40)];
foreach ($due as $item) {
    $messageLines[] = sprintf('#%d %s - Due %s (%s)', $item['id'], $item['incident_type'], $item['follow_up_at'], strtoupper($item['status']));
}

$message = implode("\n", $messageLines);

// simple stdout log; replace with mail() configuration as needed
file_put_contents('php://stdout', $message . "\n");

// optional email hook if mail configured
if (function_exists('mail') && ini_get('sendmail_path')) {
    @mail('owner@example.com', 'CustodyBuddy follow-up reminders', $message);
}
