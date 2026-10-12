//! NVD CPE names for native libraries — the vuln route for ecosystems OSV
//! barely covers (ConanCenter) or not at all (vcpkg, conda's native packages).
//!
//! vuln.mlab.sh matches a `{"cpe": …}` coordinate against NVD's configurations.
//! The hard part is the name: a package name is not a CPE, and guessing one
//! from it is wrong often enough to matter (`benchmark` is a Tanium product in
//! NVD, `zlib` has three vendors). So the table below is curated, each entry
//! checked against vuln.mlab.sh, and a library missing from it is left
//! unassessed rather than matched by name.

/// `(aliases, CPEs)`: a library's package names across Conan, vcpkg and conda
/// (lowercase), and the NVD `vendor:product`s its advisories are filed under —
/// more than one where NVD splits them (curl / libcurl, two c-ares vendors).
/// Every CPE here returned advisories from vuln.mlab.sh; the 20 candidates
/// that returned none (opus, flac, libiconv, proj, lua, …) are left out.
const TABLE: &[(&[&str], &[&str])] = &[
    (&["openssl"], &["openssl:openssl"]),
    (&["zlib", "libzlib"], &["zlib:zlib"]),
    (&["sqlite3", "sqlite", "libsqlite"], &["sqlite:sqlite"]),
    (&["curl", "libcurl"], &["haxx:curl", "haxx:libcurl"]),
    (&["libpng"], &["libpng:libpng"]),
    (&["libxml2"], &["xmlsoft:libxml2"]),
    (&["libxslt"], &["xmlsoft:libxslt"]),
    (&["expat", "libexpat"], &["libexpat_project:libexpat"]),
    (&["bzip2"], &["bzip2_project:bzip2"]),
    (&["xz_utils", "xz", "liblzma"], &["tukaani:xz"]),
    (&["freetype", "libfreetype"], &["freetype:freetype"]),
    (&["libjpeg-turbo"], &["libjpeg-turbo:libjpeg-turbo"]),
    (&["libtiff"], &["libtiff:libtiff"]),
    (&["libwebp", "libwebp-base"], &["webmproject:libwebp"]),
    (&["pcre"], &["pcre:pcre"]),
    (&["pcre2"], &["pcre:pcre2"]),
    (&["libssh2"], &["libssh2:libssh2"]),
    (&["libssh"], &["libssh:libssh"]),
    (&["nghttp2", "libnghttp2"], &["nghttp2:nghttp2"]),
    (&["c-ares"], &["c-ares:c-ares", "c-ares_project:c-ares"]),
    (&["grpc", "libgrpc"], &["grpc:grpc"]),
    (&["boost"], &["boost:boost"]),
    (&["harfbuzz"], &["harfbuzz_project:harfbuzz"]),
    (&["fontconfig"], &["fontconfig_project:fontconfig"]),
    (&["libarchive"], &["libarchive:libarchive"]),
    (&["lz4", "lz4-c"], &["lz4_project:lz4"]),
    (&["zstd", "libzstd"], &["facebook:zstandard"]),
    (&["brotli"], &["google:brotli"]),
    (&["openjpeg"], &["uclouvain:openjpeg"]),
    (&["libgit2"], &["libgit2_project:libgit2"]),
    (&["libuv"], &["libuv:libuv"]),
    (&["libevent"], &["libevent_project:libevent"]),
    (&["mbedtls"], &["arm:mbed_tls"]),
    (&["wolfssl"], &["wolfssl:wolfssl"]),
    (&["libyaml", "yaml"], &["pyyaml:libyaml"]),
    (&["yaml-cpp"], &["yaml-cpp_project:yaml-cpp"]),
    (&["ffmpeg"], &["ffmpeg:ffmpeg"]),
    (&["opencv", "libopencv"], &["opencv:opencv"]),
    (&["sdl", "sdl2"], &["libsdl:simple_directmedia_layer"]),
    (&["libzip"], &["nih:libzip"]),
    (&["glib", "libglib"], &["gnome:glib"]),
    (&["cairo"], &["cairographics:cairo"]),
    (&["poppler"], &["freedesktop:poppler"]),
    (&["apr-util"], &["apache:apr-util"]),
    (&["mosquitto"], &["eclipse:mosquitto"]),
    (&["gnutls"], &["gnu:gnutls"]),
    (&["nettle"], &["nettle_project:nettle"]),
    (&["libgcrypt"], &["gnupg:libgcrypt"]),
    (&["krb5"], &["mit:kerberos_5"]),
    (&["openldap"], &["openldap:openldap"]),
    (&["libpq"], &["postgresql:postgresql"]),
    (&["hdf5"], &["hdfgroup:hdf5"]),
    (&["gdal", "libgdal"], &["osgeo:gdal"]),
    (&["tinyxml2"], &["tinyxml2_project:tinyxml2"]),
    (&["imagemagick"], &["imagemagick:imagemagick"]),
    (&["libraw"], &["libraw:libraw"]),
    (&["libsndfile"], &["libsndfile_project:libsndfile"]),
    (&["libvpx"], &["webmproject:libvpx"]),
    (&["icu"], &["icu-project:international_components_for_unicode", "unicode:international_components_for_unicode"]),
    // conda pins the interpreter itself as a package. Not `cpython`: conda
    // pins that metapackage next to `python`, and both would report the same.
    (&["python", "python3"], &["python:python"]),
    (&["jasper"], &["jasper_project:jasper"]),
    (&["giflib"], &["giflib_project:giflib"]),
];

/// The library's NVD `vendor:product`s; empty when it is not in the table.
fn products(name: &str) -> &'static [&'static str] {
    let name = name.to_ascii_lowercase();
    TABLE
        .iter()
        .find(|(aliases, _)| aliases.contains(&name.as_str()))
        .map_or(&[], |(_, cpes)| *cpes)
}

/// The version as NVD writes it, or `None` when it cannot match a range: a
/// Conan `cci.20210118` snapshot, vcpkg's unbuilt `baseline`. vcpkg's port
/// revision (`1.3.1#2`) is packaging, not upstream, and is dropped.
fn version(v: &str) -> Option<&str> {
    let v = v.split('#').next().unwrap_or(v);
    v.starts_with(|c: char| c.is_ascii_digit()).then_some(v)
}

/// The pseudo-ecosystems a package's CPE coordinates travel under in
/// [`crate::vuln`]'s `(ecosystem, name, version)` tuples: `CPE:vendor:product`,
/// one per CPE. Empty when the library is not curated or the version cannot
/// match a range.
pub fn coordinates(name: &str, ver: &str) -> Vec<String> {
    if version(ver).is_none() {
        return Vec::new();
    }
    products(name).iter().map(|vp| format!("CPE:{vp}")).collect()
}

/// The CPE 2.3 name sent for one of [`coordinates`], or `None` for any other ecosystem.
pub fn uri(eco: &str, ver: &str) -> Option<String> {
    let vp = eco.strip_prefix("CPE:")?;
    Some(format!("cpe:2.3:a:{vp}:{}:*:*:*:*:*:*:*", version(ver)?))
}

/// How a CPE-matched package's ecosystem reads in the report.
pub fn display_ecosystem(eco: &str) -> &str {
    if eco.starts_with("CPE:") { "CPE" } else { eco }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn aliases_map_to_their_curated_cpes() {
        assert_eq!(coordinates("sqlite3", "3.53.0"), ["CPE:sqlite:sqlite"]);
        assert_eq!(coordinates("libsqlite", "3.46.0"), ["CPE:sqlite:sqlite"]);
        // NVD files curl's advisories under two products: both are asked.
        assert_eq!(coordinates("LibCurl", "8.9.1"), ["CPE:haxx:curl", "CPE:haxx:libcurl"]);
        // Not curated: never guessed from the name.
        assert!(coordinates("benchmark", "1.9.5").is_empty());
        // No version a range can hold.
        assert!(coordinates("zlib", "baseline").is_empty());
        assert!(coordinates("openssl", "cci.20210118").is_empty());
        // An alias belongs to one library only.
        let mut seen = std::collections::HashSet::new();
        for (aliases, _) in TABLE {
            for a in *aliases {
                assert!(seen.insert(*a), "{a} is listed twice");
                assert_eq!(*a, a.to_ascii_lowercase());
            }
        }
    }

    #[test]
    fn uri_is_a_concrete_cpe_23_name() {
        assert_eq!(
            uri("CPE:openssl:openssl", "3.6.3").as_deref(),
            Some("cpe:2.3:a:openssl:openssl:3.6.3:*:*:*:*:*:*:*")
        );
        // vcpkg's port revision is not part of the upstream version.
        assert_eq!(
            uri("CPE:zlib:zlib", "1.3.1#2").as_deref(),
            Some("cpe:2.3:a:zlib:zlib:1.3.1:*:*:*:*:*:*:*")
        );
        assert_eq!(uri("ConanCenter", "1.0"), None);
    }
}
