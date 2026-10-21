<?php
// range lab sink + FULL fingerprint oracle (ours; mirrors jackalsyn webrootF
// semantics: session active + slow handler so progress polls land mid-upload).
//
// ?probe=base  -> legacy single-line BIAS
// ?probe=all   -> JSON fingerprint: arch, php version, SAPI, per-module load
//                 biases (the module hosting zend_call_function + libc +
//                 executable), heap range, allocator, and the module path
//                 basename list. This is what a real leak stage has to
//                 reconstruct before forging anything.
if (($_GET['probe'] ?? '') !== '') {
    $mode = $_GET['probe'];
    $maps = file('/proc/self/maps');
    $mods = [];
    $heap_lo = null; $heap_hi = null;
    foreach ($maps as $l) {
        $f = preg_split('/\s+/', trim($l));
        if (count($f) < 6) {
            // anonymous regions: [heap] or unnamed rw- segments (arena)
            if (($f[count($f) - 1] ?? '') === '[heap]') {
                [$lo, $hi] = array_map('hexdec', explode('-', $f[0]));
                if ($heap_lo === null || $lo < $heap_lo) $heap_lo = $lo;
                if ($heap_hi === null || $hi > $heap_hi) $heap_hi = $hi;
            }
            continue;
        }
        $path = $f[5];
        if ($path[0] !== '/') continue;
        [$lo] = explode('-', $f[0]);
        $b = hexdec($lo) - hexdec($f[2]);
        $base = basename($path);
        if (!isset($mods[$base]) || $b < $mods[$base]) $mods[$base] = $b;
    }
    $want = ['php', 'libphp'];   // module hosting zend_call_function
    $bias = null; $hitpath = '';
    foreach ($mods as $base => $b) {
        foreach ($want as $w) {
            if (str_starts_with($base, $w)) {
                if ($bias === null || $b < $bias) { $bias = $b; $hitpath = $base; }
                break;
            }
        }
    }
    if ($mode === 'base') {
        header('Content-Type: text/plain');
        echo $bias === null ? "NOBASE\n" : sprintf("BIAS %d 0x%x %s\n", $bias, $bias, $hitpath);
        exit;
    }
    // probe=all
    $u = php_uname();
    $out = [
        'arch' => php_uname('m'),
        'kernel' => php_uname('r'),
        'php_version' => PHP_VERSION,
        'php_sapi' => PHP_SAPI,
        'zend_call_function_module' => $hitpath ?: null,
        'bias' => $bias,
        'mods' => $mods,           // basename -> load bias of every mapped file
        'heap' => [$heap_lo, $heap_hi],
        'page_size' => 4096,
        'ptr_bits' => PHP_INT_SIZE * 8,
        'allocator' => (getenv('USE_ZEND_ALLOC') === '0') ? 'system-malloc' : 'zend-mm',
        'upload_progress' => [
            'enabled' => (bool) ini_get('session.upload_progress.enabled'),
            'min_freq' => ini_get('session.upload_progress.min_freq'),
            'freq' => ini_get('session.upload_progress.freq'),
        ],
    ];
    header('Content-Type: application/json');
    echo json_encode($out, JSON_PRETTY_PRINT), "\n";
    exit;
}
session_start();
$data = file_get_contents("php://input");
sleep(2);
echo "lab ok " . strlen($data) . "\n";
