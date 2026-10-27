<?php
// One disposable child, PHP memory_limit=8M; never a network endpoint.
register_shutdown_function(function () {
    echo "CALCYBER_SHUTDOWN_REACHED\n";
});
echo "CALCYBER_OOM_STARTED\n";
flush();
$allocation = str_repeat('A', 64 * 1024 * 1024);
echo "CALCYBER_OOM_NOT_REACHED\n";
