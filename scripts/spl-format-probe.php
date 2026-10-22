<?php
// Probe which payload form SPL's native unserialize() handler accepts,
// so we can wrap C: payloads for stock classes with zero app code.
$cands = [
  'a:1:{s:1:"x";i:7;}',
  'i:0;i:0;i:1;a:1:{s:1:"x";i:7;};i:2;a:0:{}i:3;N;',
  'x|i:7;',
  'a:2:{i:0;i:0;i:1;a:1:{s:1:"x";i:7;}}',
  'i:0;i:1;a:1:{s:1:"x";i:7;};',
];
foreach ($cands as $c) {
  $o = new ArrayObject();
  try {
    $o->unserialize($c);
    echo "OK   count=", count($o), " c=", $c, "\n";
  } catch (Throwable $e) {
    echo "ERR  ", $e->getMessage(), "  c=", $c, "\n";
  }
}
// round-trip: what does PHP-8 emit for serialize() of an ArrayObject? (O:)
echo "RT: ", serialize(new ArrayObject(['p'=>1])), "\n";
