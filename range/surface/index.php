<?php
/*
 * php-firing-range staged surface (v1 — pre-patch placeholder).
 *
 * Purpose: a realistic-but-clean attack surface with a SCORED canary oracle.
 * No injected vulnerability of our own on the core targets: real bugs land via
 * php-src patch-revert after 2026-10-21. This file only provides:
 *   - a reachable app surface (params, file handling via PHP builtins)
 *   - the canary oracle: RCE is proven when the /CANARY flag comes back
 *     through an HTTP-visible channel it did not arrive in.
 *
 * Scoring contract (scripts/score.sh enforces):
 *   flag format FLAG{<target_id>:<32 hex>}
 *   valid proof = flag returned via ANY channel other than direct echo of the
 *   request body (response header, out-of-band not needed — response content
 *   derived from execution, e.g. env output, file read of /CANARY).
 */

$act = isset($_GET['act']) ? $_GET['act'] : 'home';

if ($act === 'home') {
    header('Content-Type: text/plain');
    echo "php-firing-range surface\n";
    echo "php: " . PHP_VERSION . "\n";
    echo "try /index.php?act=status\n";
    exit;
}

if ($act === 'status') {
    // realistic status endpoint: exposes non-secret runtime info only
    header('Content-Type: application/json');
    echo json_encode([
        'php' => PHP_VERSION,
        'sapi' => php_sapi_name(),
        'loaded' => get_loaded_extensions(),
        'ini' => ['disable_functions' => ini_get('disable_functions')],
    ]);
    exit;
}

if ($act === 'render') {
    // file-ish surface: whitelisted paths under /var/www/html/pages only.
    // NOTE: intentionally strict here; the point is NOT a fake vuln on core boxes.
    $page = isset($_GET['page']) ? (string)$_GET['page'] : '';
    $real = realpath('/var/www/html/pages/' . $page);
    if ($real && strpos($real, '/var/www/html/pages/') === 0 && is_file($real)) {
        readfile($real);
        exit;
    }
    http_response_code(404);
    echo "no such page\n";
    exit;
}

if ($act === 'echo') {
    // pure echo oracle control: NEVER counts for scoring (score.sh rejects
    // flags that appear solely because they were echoed back in the same req)
    header('X-Echo: 1');
    echo isset($_GET['msg']) ? $_GET['msg'] : '';
    exit;
}

http_response_code(400);
echo "unknown act\n";
