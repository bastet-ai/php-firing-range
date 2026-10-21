<?php
// Vulnerable endpoint (vendor Calif MADBugs remote_app.php, verbatim except
// canary handling): CachedData::unserialize() one-statement gadget.
error_reporting(0);

class CachedData implements Serializable {
    public function serialize(): string { return ''; }
    public function unserialize(string $data): void {
        unserialize($data)->x = 0;
    }
}

echo serialize(@unserialize($_REQUEST['cook']));
