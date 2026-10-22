<?php
// T4a: the arbitrary-target sink. Zero user-defined classes, zero
// Serializable, zero gadget code. This is the shape of thousands of
// real apps: unserialize(user input) then echo/reflect the result.
// If stock PHP's built-in classes route C: through the vulnerable
// zend_user_unserialize, no app cooperation beyond this one line is
// needed. The vendor's own writeup demands an app Serializable class;
// stock-SPL would beat that bar entirely.
error_reporting(E_ALL);
ini_set('display_errors', 0);
echo @serialize(unserialize($_POST['cook'] ?? ''));
