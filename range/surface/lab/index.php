<?php
// range lab sink + bias oracle (ours; mirrors jackalsyn webrootF semantics:
// session active + slow handler so progress polls land mid-upload).
// Oracle leaks the PIE/DSO load bias of the module hosting zend_call_function.
if (($_GET['probe'] ?? '') === 'base') {
    $want = ['php', 'libphp'];   // candidates: static cli/fpm binary or libphp DSO
    $bias = null; $hitline = '';
    foreach (file('/proc/self/maps') as $l) {
        $f = preg_split('/\s+/', trim($l));
        $path = $f[count($f) - 1] ?? '';
        if ($path === '' || $path[0] !== '/') continue;
        $base = basename($path);
        $match = false;
        foreach ($want as $w) {
            if (str_starts_with($base, $w)) { $match = true; break; }
        }
        if (!$match) continue;
        [$lo] = explode('-', $f[0]);
        $b = hexdec($lo) - hexdec($f[2]);
        if ($bias === null || $b < $bias) { $bias = $b; $hitline = $path; }
    }
    header('Content-Type: text/plain');
    echo $bias === null ? "NOBASE\n" : sprintf("BIAS %d 0x%x %s\n", $bias, $bias, $hitline);
    exit;
}
session_start();
$data = file_get_contents("php://input");
sleep(2);
echo "lab ok " . strlen($data) . "\n";
