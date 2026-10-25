<?php
// memread.php — run inside a SYS_PTRACE helper sharing the target's pid ns:
//   docker run --rm --cap-add SYS_PTRACE --pid=container:CT -v SCRIPTS:/sc:ro \
//     stealmybitcoin-smb-php-vuln:latest php /sc/memread.php <mode> <args...>
// modes:
//   pid                 print the php -S pid
//   maps                print /proc/PID/maps
//   read <hex> <len>    base64 of [addr, addr+len)
//   findphp             print pid of 'php -S 0.0.0.0:8080'
$mode = $argv[1] ?? '';
function findphp() {
    foreach (glob('/proc/[0-9]*/cmdline') as $f) {
        $c = @file_get_contents($f);
        if ($c !== false && strpos(str_replace("\0", ' ', $c), 'php -S 0.0.0.0:8080') !== false) {
            return basename(dirname($f));
        }
    }
    return '';
}
if ($mode === 'findphp' || $mode === 'pid') { echo findphp(); exit(0); }
$pid = findphp();
if (!$pid) { fwrite(STDERR, "no php -S pid\n"); exit(1); }
if ($mode === 'maps') { echo @file_get_contents("/proc/$pid/maps"); exit(0); }
if ($mode === 'read') {
    $addr = hexdec($argv[2]); $len = (int)$argv[3];
    $fh = @fopen("/proc/$pid/mem", 'rb');
    if (!$fh) { fwrite(STDERR, "open mem failed\n"); exit(1); }
    if (fseek($fh, $addr) === -1) { fwrite(STDERR, "seek failed\n"); exit(1); }
    echo base64_encode(fread($fh, $len));
    exit(0);
}
fwrite(STDERR, "unknown mode\n"); exit(1);
