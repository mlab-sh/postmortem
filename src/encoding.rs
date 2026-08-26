//! Small encodings postmortem needs in more than one place.

/// Standard base64 (RFC 4648) of arbitrary bytes.
///
/// Hand-rolled rather than pulling a crate in for twenty lines — the same
/// reason the Windows backends avoid the `windows` crate.
pub fn base64(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 64] =
        b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let b = [
            chunk[0],
            *chunk.get(1).unwrap_or(&0),
            *chunk.get(2).unwrap_or(&0),
        ];
        let n = u32::from(b[0]) << 16 | u32::from(b[1]) << 8 | u32::from(b[2]);
        for i in 0..4 {
            if i <= chunk.len() {
                out.push(ALPHABET[(n >> (18 - i * 6)) as usize & 0x3F] as char);
            } else {
                out.push('=');
            }
        }
    }
    out
}

/// Base64 of a string encoded UTF-16LE — what PowerShell's `-EncodedCommand`
/// expects.
pub fn base64_utf16le(s: &str) -> String {
    let bytes: Vec<u8> = s.encode_utf16().flat_map(u16::to_le_bytes).collect();
    base64(&bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Checked against vectors computed independently, not against itself.
    #[test]
    fn base64_matches_known_vectors() {
        assert_eq!(base64(b""), "");
        assert_eq!(base64(b"f"), "Zg==");
        assert_eq!(base64(b"fo"), "Zm8=");
        assert_eq!(base64(b"foo"), "Zm9v");
        assert_eq!(base64(b"foob"), "Zm9vYg==");
        assert_eq!(base64(b"fooba"), "Zm9vYmE=");
        assert_eq!(base64(b"foobar"), "Zm9vYmFy");
        // The shape Basic auth uses.
        assert_eq!(base64(b"alice:s3cret"), "YWxpY2U6czNjcmV0");
        // Bytes above 0x7f must not be mangled.
        assert_eq!(base64(&[0xff, 0xfe, 0xfd]), "//79");
    }

    #[test]
    fn utf16le_matches_known_vectors() {
        assert_eq!(base64_utf16le(""), "");
        assert_eq!(base64_utf16le("a"), "YQA=");
        assert_eq!(base64_utf16le("abc"), "YQBiAGMA");
        assert_eq!(
            base64_utf16le("Get-AppxPackage"),
            "RwBlAHQALQBBAHAAcAB4AFAAYQBjAGsAYQBnAGUA"
        );
        assert_eq!(base64_utf16le("é€"), "6QCsIA==");
    }
}
