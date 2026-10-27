#!/bin/sh
set -eu
export DEBIAN_FRONTEND=noninteractive
printf '%s\n' 'deb https://archive.debian.org/debian bullseye main' > /etc/apt/sources.list
mkdir -p /tmp/archive-apt/partial
apt-get -o Dir::State::lists=/tmp/archive-apt -o Acquire::Check-Valid-Until=false update
apt-get -o Dir::State::lists=/tmp/archive-apt -o Acquire::Check-Valid-Until=false install -y --no-install-recommends apache2-dev $PHPIZE_DEPS
apt-get clean
command -v apxs
apxs -q HTTPD_VERSION
gcc --version | head -n 1
sha256sum /usr/src/php.tar.xz
