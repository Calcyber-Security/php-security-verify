<?php
// The matched minimal builds deliberately omit the optional JSON extension.
header('Content-Type: text/plain');
echo "CALCYBER_LAB_MARKER=CALCYBER_ISOLATED_LAB_CONTROL\n";
echo "CALCYBER_LAB_VERSION=" . PHP_VERSION . "\n";
echo "CALCYBER_LAB_SAPI=" . PHP_SAPI . "\n";
echo "CALCYBER_LAB_FILE_COUNT=" . count($_FILES) . "\n";
echo "CALCYBER_LAB_MULTIPART_LIMIT=" . ini_get('max_multipart_body_parts') . "\n";
echo "CALCYBER_LAB_COOKIE=" . (isset($_COOKIE['PHPSESSID']) ? $_COOKIE['PHPSESSID'] : 'MISSING') . "\n";
echo "CALCYBER_LAB_PROGRESS=" . ini_get('session.upload_progress.enabled') . "\n";
echo "CALCYBER_LAB_SESSION_PROGRESS_FILE=" . (file_exists('/tmp/sess_calcyberfixture') ? 'PRESENT' : 'ABSENT') . "\n";
foreach ($_POST as $name => $value) {
    echo "CALCYBER_LAB_FIELD_" . $name . "=" . $value . "\n";
}
