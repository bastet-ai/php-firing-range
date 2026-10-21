#!/bin/sh
# reconfigure php-src fuzzer build with ASan+UBSan instrumentation
cd /home/user/php-firing-range/research/src/php-src-83 || exit 1
export CC=clang CXX=clang++
export CFLAGS="-fsanitize=address,undefined,fuzzer-no-link -fno-omit-frame-pointer -fsanitize-recover=undefined"
export CXXFLAGS="-fsanitize=address,undefined,fuzzer-no-link -fno-omit-frame-pointer"
export LDFLAGS="-fsanitize=address,undefined"
exec ./configure --enable-fuzzer --disable-all --enable-session --enable-cli \
  --with-valgrind=no --without-pear --disable-cgi --prefix=/tmp/phpfuzz
