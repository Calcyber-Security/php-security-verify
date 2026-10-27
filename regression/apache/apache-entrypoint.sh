#!/bin/sh
set -eu
mkdir -p /tmp/apache /tmp/www/limited /tmp/www/session
cp /input/index.php /tmp/www/index.php
cp /input/index.php /tmp/www/limited/index.php
cp /input/index.php /tmp/www/session/index.php
cp /input/oom.php /tmp/www/oom.php
cd /tmp/www
exec apache2 -f /input/httpd.conf -DFOREGROUND
