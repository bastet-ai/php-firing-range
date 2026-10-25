<?php
// q2_direct.php - run INSIDE the php container (docker exec, background):
// usage: php /tmp/q2_direct.php <mode>
//   stall <sid> <value>  stalled multipart at 127.0.0.1:8080 (direct, no
//                        nginx); sess file readable mid-flight
//   conc <n> <mb>        <n> parallel <mb>MB POSTs, prints wall ms
$mode = $argv[1] ?? '';
if ($mode === 'stall') {
    $sid = $argv[2]; $value = $argv[3];
    $bnd = 'Q2DIR';
    $head = "--$bnd\r\n"
        . "Content-Disposition: form-data; name=\"PHPSESSID\"\r\n\r\n$sid\r\n"
        . "--$bnd\r\n"
        . "Content-Disposition: form-data; name=\"PHP_SESSION_UPLOAD_PROGRESS\"\r\n\r\n$value\r\n"
        . "--$bnd\r\n"
        . "Content-Disposition: form-data; name=\"f\"; filename=\"a.txt\"\r\n"
        . "Content-Type: text/plain\r\n\r\n";
    $tail = "\r\n--$bnd--\r\n";
    $total = 131072;
    $body = $head . str_repeat('z', $total) . $tail;
    $ctx = stream_context_create();
    $s = stream_socket_client('127.0.0.1:8080', $errno, $err, 10, STREAM_CLIENT_CONNECT, $ctx);
    fwrite($s, "POST /ping.php HTTP/1.1\r\nHost: 127.0.0.1\r\n"
        . "Content-Type: multipart/form-data; boundary=$bnd\r\n"
        . "Content-Length: " . strlen($body) . "\r\nConnection: close\r\n\r\n");
    fwrite($s, $head);
    fwrite($s, str_repeat("z", 8192));
    sleep(4);                       // mid-flight stall (direct at php -S)
    fwrite($s, str_repeat('z', $total - 4096) . $tail);
    stream_get_contents($s);
    fclose($s);
    echo "stall-done\n";
} elseif ($mode === 'conc') {
    $n = (int)$argv[2]; $mb = (int)$argv[3];
    $body = str_repeat('m', $mb * 1048576);
    $t0 = microtime(true);
    $mh = [];
    for ($i = 0; $i < $n; $i++) {
        $fp = stream_socket_client('127.0.0.1:8080', $e, $es, 30);
        fwrite($fp, "POST /ping.php HTTP/1.1\r\nHost: 127.0.0.1\r\n"
            . "Content-Type: application/x-www-form-urlencoded\r\n"
            . "Content-Length: " . strlen($body) . "\r\nConnection: close\r\n\r\n" . $body);
        $mh[] = $fp;
    }
    foreach ($mh as $fp) { stream_get_contents($fp); fclose($fp); }
    printf("conc-done n=%d mb=%d wall_ms=%d\n", $n, $mb, (microtime(true) - $t0) * 1000);
}
