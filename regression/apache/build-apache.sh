#!/bin/sh
set -eu
cd /work
mkdir -p /work/compiler-tmp /artifacts
export TMPDIR=/work/compiler-tmp
unset MAKEFLAGS MFLAGS
echo '924846abf93bc613815c55dd3f5809377813ac62a9ec4eb3778675b82a27b927  /usr/src/php.tar.xz' | sha256sum -c -
tar -xJf /usr/src/php.tar.xz --strip-components=1
if [ "$LAB_VARIANT" = patched ]; then
    patch -p1 < /input/mitigation.patch
    patch -p1 < /input/version.patch
fi
./buildconf --force
./configure --disable-all --enable-cli --enable-session --without-pear --with-apxs2=/usr/bin/apxs --prefix=/opt/lab-php
make -j1
cp libs/libphp7.so /artifacts/libphp7.so
cp sapi/cli/php /artifacts/php
cp config.nice /artifacts/config.nice
sha256sum /artifacts/libphp7.so /artifacts/php
