#!/bin/sh
set -eu
# Runs only in a separately resource-limited build container. No regression tests.
cd /work
mkdir -p /work/compiler-tmp
export TMPDIR=/work/compiler-tmp
unset MAKEFLAGS MFLAGS
tar -xJf /usr/src/php.tar.xz --strip-components=1
if [ "$LAB_VARIANT" = patched ]; then
    patch -p1 < /input/mitigation.patch
    patch -p1 < /input/version.patch
fi
./buildconf --force
./configure --disable-all --enable-cli --enable-cgi --enable-session --without-pear --prefix=/opt/lab-php
make -j1
make -j1 install
sha256sum /opt/lab-php/bin/php /opt/lab-php/bin/php-cgi
# Deliberately do not invoke PHP or tests here.
