#!/bin/sh
# Register qemu-x86_64 binfmt (with F=fix-binary flag so it works in
# containers) on this aarch64 host. Needed by the *-x86 range lanes
# (wordpress-x86/wpdb-x86) since no native amd64 host exists here.
set -e
command -v qemu-x86_64-static >/dev/null || { echo "apt-get install -y qemu-user-static first"; exit 1; }
Q=$(command -v qemu-x86_64-static)
echo ':qemu-x86_64:M::\x7fELF\x02\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x02\x00\x3e\x00:\xff\xff\xff\xff\xff\xff\xff\x00\xff\xff\xff\xff\xff\xff\xff\xff\xfe\xff\xff\xff:/usr/bin/qemu-x86_64-static:F' > /proc/sys/fs/binfmt_misc/register 2>/dev/null || \
echo ':qemu-x86_64:M::\x7fELF\x02\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x02\x00\x3e\x00:\xff\xff\xff\xff\xff\xff\xff\x00\xff\xff\xff\xff\xff\xff\xff\xff\xfe\xff\xff\xff:/usr/bin/qemu-x86_64-static:F' > /proc/sys/fs/binfmt_misc/register
echo registered; docker run --rm --platform linux/amd64 debian:bookworm-slim uname -m
