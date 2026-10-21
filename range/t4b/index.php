<?php
// T4b range target: NO Serializable class in the app at all. Only an
// ordinary SPL child (the stock-shape that proved to route C: through
// zend_user_unserialize). If the var_hash UAF can be triggered through
// SESSION DECODE here, the bug class becomes pre-auth with zero gadget.
error_reporting(E_ALL);
ini_set('display_errors', 0);

class Probe extends ArrayObject {
    public function unserialize(string $d): void { parent::unserialize($d); }
    public function serialize(): string { return ''; }
}

session_start();
echo "ok " . ($_SESSION['n'] ?? 0) . "\n";
