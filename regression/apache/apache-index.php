<?php
header('Content-Type: text/plain');
echo "CALCYBER_APACHE_CONTROL\n";
echo 'VERSION=' . PHP_VERSION . "\n";
echo 'SAPI=' . PHP_SAPI . "\n";
echo 'PID=' . getmypid() . "\n";
if (isset($_GET['inspect'])) {
    echo 'FILE_COUNT=' . count($_FILES) . "\n";
    echo 'PART_LIMIT=' . ini_get('max_multipart_body_parts') . "\n";
    echo 'PROGRESS_ENABLED=' . ini_get('session.upload_progress.enabled') . "\n";
    echo 'PROGRESS_FILE=' . (file_exists('/tmp/sess_calcyberapachefixture') ? 'PRESENT' : 'ABSENT') . "\n";
    foreach (array('alpha', 'beta', 'gamma') as $key) {
        echo 'FIELD_' . $key . '=' . (isset($_POST[$key]) && is_string($_POST[$key]) ? $_POST[$key] : 'ABSENT') . "\n";
    }
}
