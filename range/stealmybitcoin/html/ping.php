<?php
// mirror of the CTF's /ping.php: message=ping -> pong. Starts a session so
// the serialized-session surface (the 618/619 decode path) is live, like any
// boring app page that calls session_start().
session_start();
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['message'])) {
    header('Content-Type: text/plain');
    echo $_POST['message'] === 'ping' ? 'pong' : 'nope';
    exit;
}
header('Content-Type: text/plain');
echo "POST ping here: /ping.php\nSend message=ping to receive pong.";
