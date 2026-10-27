<?php
header('Content-Type: text/plain');
register_shutdown_function(function () {
    file_put_contents('/tmp/calcyber-oom-shutdown', 'SHUTDOWN_REACHED');
    echo "CALCYBER_SHUTDOWN_REACHED\n";
});
echo 'CALCYBER_OOM_STARTED PID=' . getmypid() . "\n";
flush();
$allocation = str_repeat('A', 64 * 1024 * 1024);
echo "CALCYBER_OOM_NOT_REACHED\n";
