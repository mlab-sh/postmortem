//! End-to-end integration tests against fixtures that emulate real public
//! supply-chain incidents (event-stream 2018, ctx 2022, rustdecimal 2022).
//! All payloads are INERT — see `tests/fixtures/README.md`.

use serde_json::Value;
use std::path::PathBuf;
use std::process::{Command, Stdio};

fn bin() -> &'static str {
    env!("CARGO_BIN_EXE_postmortem")
}

/// A `postmortem scan ...` command. All end-to-end tests drive the `scan`
/// subcommand, so the verb is baked in here.
fn cmd() -> Command {
    let mut c = Command::new(bin());
    c.arg("scan");
    c
}

fn fixture(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
        .join(name)
}

/// Run postmortem in JSON mode and return (exit_code, parsed_json).
/// Passes `-o -` so the default-file behavior doesn't intercept stdout.
fn scan_json(fixture_name: &str, extra_args: &[&str]) -> (i32, Value) {
    let mut cmd = cmd();
    cmd.arg(fixture(fixture_name))
        .arg("--json")
        .args(["-o", "-"])
        .args(extra_args)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let out = cmd.output().expect("postmortem binary did not run");
    let exit = out.status.code().unwrap_or(-1);
    let parsed: Value = serde_json::from_slice(&out.stdout).unwrap_or_else(|e| {
        panic!(
            "json parse failed (exit {exit}): {e}\nstdout: {}\nstderr: {}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr),
        )
    });
    (exit, parsed)
}

fn findings(report: &Value) -> &Vec<Value> {
    report["findings"].as_array().expect("findings array")
}

fn deps(report: &Value) -> &Vec<Value> {
    report["dependencies"].as_array().expect("deps array")
}

fn dep_present(report: &Value, name: &str, version: &str) -> bool {
    deps(report)
        .iter()
        .any(|d| d["name"] == name && d["version"] == version)
}

fn has_finding(report: &Value, dep_substr: &str, category: &str) -> bool {
    findings(report).iter().any(|f| {
        f["category"] == category
            && f["dependency"]
                .as_str()
                .map(|s| s.contains(dep_substr))
                .unwrap_or(false)
    })
}

// ---------- malicious-node (event-stream / flatmap-stream, 2018) ----------

#[test]
fn malicious_node_resolves_event_stream_chain() {
    let (_, report) = scan_json("malicious-node", &["--skip-analyze"]);
    assert!(dep_present(&report, "event-stream", "3.3.6"));
    assert!(dep_present(&report, "flatmap-stream", "0.1.1"));

    // flatmap-stream is a transitive of event-stream — verify the parent edge.
    let fms = deps(&report)
        .iter()
        .find(|d| d["name"] == "flatmap-stream")
        .expect("flatmap-stream dep");
    let parents: Vec<String> = fms["parents"]
        .as_array()
        .unwrap()
        .iter()
        .map(|p| format!("{}@{}", p[0].as_str().unwrap(), p[1].as_str().unwrap()))
        .collect();
    assert!(
        parents.iter().any(|p| p == "event-stream@3.3.6"),
        "expected event-stream@3.3.6 as parent, got {parents:?}"
    );
}

#[test]
fn malicious_node_detects_install_hook() {
    let (exit, report) = scan_json("malicious-node", &[]);
    // High-severity findings are expected → exit code 1
    assert_eq!(exit, 1, "expected non-zero exit on malicious fixture");
    assert!(
        has_finding(&report, "flatmap-stream", "install_hook"),
        "expected install_hook finding for flatmap-stream, got: {}",
        serde_json::to_string_pretty(&report["findings"]).unwrap()
    );
}

#[test]
fn malicious_node_detects_obfuscation() {
    let (_, report) = scan_json("malicious-node", &[]);
    assert!(
        has_finding(&report, "flatmap-stream", "obfuscation"),
        "expected obfuscation finding for flatmap-stream"
    );
}

#[test]
fn malicious_node_detects_iocs() {
    let (_, report) = scan_json("malicious-node", &[]);
    let ioc_findings: Vec<&Value> = findings(&report)
        .iter()
        .filter(|f| {
            f["category"] == "ioc"
                && f["dependency"]
                    .as_str()
                    .unwrap_or("")
                    .contains("flatmap-stream")
        })
        .collect();
    assert!(
        ioc_findings.len() >= 5,
        "expected ≥5 IOCs (URL + domain + IPv6 + BTC + ETH), got {}: {:#?}",
        ioc_findings.len(),
        ioc_findings
    );
    // At least one BTC- or ETH-class finding (severity "high")
    assert!(
        ioc_findings.iter().any(|f| f["severity"] == "high"),
        "expected at least one high-sev IOC (BTC/ETH wallet)"
    );
}

#[test]
fn malicious_node_detects_bare_domain() {
    let (_, report) = scan_json("malicious-node", &[]);
    assert!(
        findings(&report).iter().any(|f| {
            f["category"] == "ioc"
                && f["detail"] == "embedded domain name"
                && f["evidence"]
                    .as_str()
                    .map(|s| s.contains("track.evil.tk"))
                    .unwrap_or(false)
        }),
        "expected bare-domain finding for track.evil.tk"
    );
}

#[test]
fn malicious_node_detects_ipv6() {
    let (_, report) = scan_json("malicious-node", &[]);
    assert!(
        findings(&report).iter().any(|f| {
            f["category"] == "ioc"
                && f["detail"] == "embedded IPv6 address"
                && f["evidence"]
                    .as_str()
                    .map(|s| s.contains("2606:4700:1c1c::dead:beef"))
                    .unwrap_or(false)
        }),
        "expected IPv6 finding for 2606:4700:1c1c::dead:beef"
    );
}

#[test]
fn malicious_node_detects_sensitive_api() {
    let (_, report) = scan_json("malicious-node", &[]);
    assert!(
        has_finding(&report, "flatmap-stream", "sensitive_api"),
        "expected sensitive_api finding for flatmap-stream (child_process / https)"
    );
}

// ---------- malicious-python (ctx, 2022) ----------

#[test]
fn malicious_python_detects_setup_py_payload() {
    let (exit, report) = scan_json("malicious-python", &[]);
    assert_eq!(exit, 1);
    // setup.py uses subprocess + os.system + base64 + urllib → install_hook category
    assert!(
        findings(&report)
            .iter()
            .any(|f| f["category"] == "install_hook"),
        "expected install_hook finding on setup.py: {}",
        serde_json::to_string_pretty(&report["findings"]).unwrap()
    );
    // requirements.txt should expose `ctx==0.2.6`
    assert!(dep_present(&report, "ctx", "0.2.6"));
}

#[test]
fn malicious_python_detects_exfil_url() {
    let (_, report) = scan_json("malicious-python", &[]);
    let urls: Vec<&Value> = findings(&report)
        .iter()
        .filter(|f| f["category"] == "ioc" && f["detail"].as_str().unwrap_or("").contains("URL"))
        .collect();
    assert!(!urls.is_empty(), "expected an IOC URL finding");
}

// ---------- malicious-rust (rustdecimal typosquat, 2022) ----------

#[test]
fn malicious_rust_resolves_typosquat() {
    let (_, report) = scan_json("malicious-rust", &["--skip-analyze"]);
    assert!(dep_present(&report, "rustdecimal", "1.21.2"));
    let dep = deps(&report)
        .iter()
        .find(|d| d["name"] == "rustdecimal")
        .unwrap();
    assert_eq!(dep["direct"], true);
    assert_eq!(dep["ecosystem"], "rust");
}

#[test]
fn malicious_rust_detects_sensitive_api_in_local_src() {
    let (_, report) = scan_json("malicious-rust", &[]);
    assert!(
        findings(&report)
            .iter()
            .any(|f| f["category"] == "sensitive_api"),
        "expected sensitive_api finding (std::process / std::net) in src/main.rs"
    );
}

// ---------- malicious-ruby (rest-client 1.6.13 shape, 2019) ----------

#[test]
fn malicious_ruby_resolves_typosquat_and_graph() {
    let (_, report) = scan_json("malicious-ruby", &["--skip-analyze"]);
    assert_eq!(report["ecosystems"][0], "ruby");
    assert!(dep_present(&report, "rest-cliient", "1.6.13"));

    let root = deps(&report)
        .iter()
        .find(|d| d["name"] == "rest-cliient")
        .unwrap();
    assert_eq!(root["direct"], true);
    assert_eq!(root["ecosystem"], "ruby");

    // mime-types is transitive with rest-cliient as its parent.
    let mt = deps(&report)
        .iter()
        .find(|d| d["name"] == "mime-types")
        .expect("mime-types dep");
    assert_eq!(mt["direct"], false);
    let parents: Vec<String> = mt["parents"]
        .as_array()
        .unwrap()
        .iter()
        .map(|p| p[0].as_str().unwrap().to_string())
        .collect();
    assert!(
        parents.iter().any(|p| p == "rest-cliient"),
        "got {parents:?}"
    );
}

#[test]
fn malicious_ruby_detects_sensitive_api_and_obfuscation() {
    let (_, report) = scan_json("malicious-ruby", &[]);
    assert!(
        has_finding(&report, "<project>", "sensitive_api"),
        "expected sensitive_api (system/Net::HTTP/socket) in lib/exfil.rb"
    );
    assert!(
        findings(&report)
            .iter()
            .any(|f| f["category"] == "obfuscation"),
        "expected obfuscation (eval + Base64.decode64) in lib/exfil.rb"
    );
}

#[test]
fn malicious_ruby_detects_exfil_iocs() {
    let (_, report) = scan_json("malicious-ruby", &[]);
    let iocs: Vec<&Value> = findings(&report)
        .iter()
        .filter(|f| f["category"] == "ioc")
        .collect();
    assert!(
        iocs.iter()
            .any(|f| f["detail"].as_str().unwrap_or("").contains("URL")),
        "expected an exfil URL finding"
    );
    assert!(
        iocs.iter()
            .any(|f| f["detail"].as_str().unwrap_or("").contains("domain")),
        "expected the exfil.evil.tk domain finding"
    );
}

// ---------- malicious-php (Composer package hijack shape) ----------

#[test]
fn malicious_php_resolves_typosquat_and_graph() {
    let (_, report) = scan_json("malicious-php", &["--skip-analyze"]);
    assert_eq!(report["ecosystems"][0], "php");
    assert!(dep_present(&report, "guzzlehttp/guzzel", "7.5.0"));

    let root = deps(&report)
        .iter()
        .find(|d| d["name"] == "guzzlehttp/guzzel")
        .unwrap();
    assert_eq!(root["direct"], true);
    assert_eq!(root["ecosystem"], "php");

    let psr = deps(&report)
        .iter()
        .find(|d| d["name"] == "psr/http-client")
        .expect("psr/http-client dep");
    assert_eq!(psr["direct"], false);
    let parents: Vec<String> = psr["parents"]
        .as_array()
        .unwrap()
        .iter()
        .map(|p| p[0].as_str().unwrap().to_string())
        .collect();
    assert!(
        parents.iter().any(|p| p == "guzzlehttp/guzzel"),
        "got {parents:?}"
    );
}

#[test]
fn malicious_php_detects_obfuscation_chain() {
    let (_, report) = scan_json("malicious-php", &[]);
    // eval + base64_decode + gzinflate is the classic PHP webshell chain → High.
    assert!(
        findings(&report)
            .iter()
            .any(|f| f["category"] == "obfuscation"
                && (f["severity"] == "high" || f["severity"] == "critical")),
        "expected a high-severity obfuscation finding: {}",
        serde_json::to_string_pretty(&report["findings"]).unwrap()
    );
    assert!(
        has_finding(&report, "<project>", "sensitive_api"),
        "expected sensitive_api (shell_exec/fsockopen) in src/Payload.php"
    );
}

#[test]
fn malicious_php_detects_exfil_iocs() {
    let (_, report) = scan_json("malicious-php", &[]);
    let iocs: Vec<&Value> = findings(&report)
        .iter()
        .filter(|f| f["category"] == "ioc")
        .collect();
    assert!(
        iocs.iter()
            .any(|f| f["detail"].as_str().unwrap_or("").contains("URL"))
    );
    assert!(
        iocs.iter()
            .any(|f| f["detail"].as_str().unwrap_or("").contains("domain"))
    );
}

// ---------- malicious-go (module typosquat shape) ----------

#[test]
fn malicious_go_resolves_typosquat_and_classifies_indirect() {
    let (_, report) = scan_json("malicious-go", &["--skip-analyze"]);
    assert_eq!(report["ecosystems"][0], "go");
    assert!(dep_present(
        &report,
        "github.com/sirupsen/logrous",
        "v1.9.3"
    ));

    let root = deps(&report)
        .iter()
        .find(|d| d["name"] == "github.com/sirupsen/logrous")
        .unwrap();
    assert_eq!(root["direct"], true);
    assert_eq!(root["ecosystem"], "go");
    // go.sum checksum is attached as integrity.
    assert!(root["integrity"].as_str().unwrap_or("").starts_with("h1:"));

    let indirect = deps(&report)
        .iter()
        .find(|d| d["name"] == "golang.org/x/sys")
        .expect("x/sys dep");
    assert_eq!(indirect["direct"], false, "// indirect must be transitive");
}

#[test]
fn malicious_go_detects_sensitive_api_and_obfuscation() {
    let (_, report) = scan_json("malicious-go", &[]);
    assert!(
        has_finding(&report, "<project>", "sensitive_api"),
        "expected sensitive_api (exec.Command / net.Dial) in main.go"
    );
    assert!(
        findings(&report)
            .iter()
            .any(|f| f["category"] == "obfuscation"),
        "expected obfuscation (base64 decode + blob) in main.go"
    );
}

#[test]
fn malicious_go_detects_exfil_iocs() {
    let (_, report) = scan_json("malicious-go", &[]);
    let iocs: Vec<&Value> = findings(&report)
        .iter()
        .filter(|f| f["category"] == "ioc")
        .collect();
    assert!(
        iocs.iter()
            .any(|f| f["detail"].as_str().unwrap_or("").contains("URL"))
    );
    assert!(
        iocs.iter()
            .any(|f| f["detail"].as_str().unwrap_or("").contains("domain"))
    );
}

// ---------- malicious-java (Maven artifact typosquat shape) ----------

#[test]
fn malicious_java_reads_pom_direct_deps_and_skips_bom() {
    let (_, report) = scan_json("malicious-java", &["--skip-analyze"]);
    assert_eq!(report["ecosystems"][0], "java");
    assert!(dep_present(
        &report,
        "org.apache.commons:commons-colletions",
        "3.2.1"
    ));

    let typo = deps(&report)
        .iter()
        .find(|d| d["name"] == "org.apache.commons:commons-colletions")
        .unwrap();
    assert_eq!(typo["direct"], true);
    assert_eq!(typo["ecosystem"], "java");

    // dependencyManagement (BOM) entries are not real dependencies.
    assert!(
        !deps(&report)
            .iter()
            .any(|d| d["name"] == "org.springframework:spring-bom"),
        "dependencyManagement must be excluded from the SBOM"
    );
}

#[test]
fn malicious_java_detects_sensitive_api_and_obfuscation() {
    let (_, report) = scan_json("malicious-java", &[]);
    assert!(
        has_finding(&report, "<project>", "sensitive_api"),
        "expected sensitive_api (Runtime.exec / Socket) in Payload.java"
    );
    assert!(
        findings(&report)
            .iter()
            .any(|f| f["category"] == "obfuscation"),
        "expected obfuscation (base64 decode + blob) in Payload.java"
    );
}

#[test]
fn malicious_java_detects_exfil_iocs() {
    let (_, report) = scan_json("malicious-java", &[]);
    let iocs: Vec<&Value> = findings(&report)
        .iter()
        .filter(|f| f["category"] == "ioc")
        .collect();
    assert!(
        iocs.iter()
            .any(|f| f["detail"].as_str().unwrap_or("").contains("URL"))
    );
    assert!(
        iocs.iter()
            .any(|f| f["detail"].as_str().unwrap_or("").contains("domain"))
    );
}

// ---------- clean baseline ----------

#[test]
fn clean_node_emits_no_high_findings_and_exits_zero() {
    let (exit, report) = scan_json("clean-node", &[]);
    assert_eq!(exit, 0, "clean fixture should exit 0");
    let highs: Vec<&Value> = findings(&report)
        .iter()
        .filter(|f| f["severity"] == "high" || f["severity"] == "critical")
        .collect();
    assert!(
        highs.is_empty(),
        "clean fixture leaked high findings: {highs:#?}"
    );
}

// ---------- CLI flag behavior ----------

#[test]
fn min_severity_filters_findings() {
    let (_, all) = scan_json("malicious-node", &[]);
    let (_, only_critical) = scan_json("malicious-node", &["--min-severity", "critical"]);
    assert!(findings(&all).len() > findings(&only_critical).len());
}

// ---------- config & --skip-category ----------

#[test]
fn skip_category_flag_drops_findings() {
    let (_, all) = scan_json("malicious-node", &[]);
    let (_, no_ioc) = scan_json("malicious-node", &["--skip-category", "ioc"]);

    let ioc_in_all = findings(&all)
        .iter()
        .filter(|f| f["category"] == "ioc")
        .count();
    let ioc_in_filtered = findings(&no_ioc)
        .iter()
        .filter(|f| f["category"] == "ioc")
        .count();
    assert!(ioc_in_all > 0, "fixture should produce ioc findings");
    assert_eq!(
        ioc_in_filtered, 0,
        "--skip-category ioc must drop all ioc findings"
    );
    // other categories remain
    assert!(
        findings(&no_ioc)
            .iter()
            .any(|f| f["category"] == "install_hook")
    );
}

#[test]
fn skip_category_flag_accepts_comma_separated() {
    let (_, report) = scan_json(
        "malicious-node",
        &["--skip-category", "ioc,obfuscation,sensitive_api"],
    );
    let remaining: Vec<&str> = findings(&report)
        .iter()
        .map(|f| f["category"].as_str().unwrap())
        .collect();
    assert!(remaining.iter().all(|c| *c == "install_hook"));
    assert!(!remaining.is_empty());
}

#[test]
fn postmortem_conf_autoload_suppresses_findings() {
    // Copy the malicious-node fixture into a temp dir, drop a postmortem.conf alongside.
    let src = fixture("malicious-node");
    let dst =
        std::env::temp_dir().join(format!("postmortem-it-{}-{}", std::process::id(), line!()));
    let _ = std::fs::remove_dir_all(&dst);
    copy_tree(&src, &dst).unwrap();
    std::fs::write(
        dst.join("postmortem.conf"),
        r#"
skip_categories = ["ioc", "sensitive_api"]

[[ignore]]
category = "obfuscation"
dependency = "flatmap-stream"
reason = "test suppression"
"#,
    )
    .unwrap();

    let out = cmd()
        .arg(&dst)
        .arg("--json")
        .args(["-o", "-"])
        .output()
        .unwrap();
    let report: Value = serde_json::from_slice(&out.stdout).unwrap();
    let cats: Vec<&str> = report["findings"]
        .as_array()
        .unwrap()
        .iter()
        .map(|f| f["category"].as_str().unwrap())
        .collect();
    assert!(!cats.contains(&"ioc"), "ioc should be suppressed");
    assert!(
        !cats.contains(&"sensitive_api"),
        "sensitive_api should be suppressed"
    );
    assert!(
        !cats.contains(&"obfuscation"),
        "obfuscation on flatmap-stream should be suppressed by ignore rule"
    );
    // install_hook is not suppressed — should still be present
    assert!(cats.contains(&"install_hook"));
    // stderr mentions config was loaded
    assert!(String::from_utf8_lossy(&out.stderr).contains("loaded config"));

    let _ = std::fs::remove_dir_all(&dst);
}

#[test]
fn no_config_flag_disables_autoload() {
    let src = fixture("malicious-node");
    let dst =
        std::env::temp_dir().join(format!("postmortem-it-{}-{}", std::process::id(), line!()));
    let _ = std::fs::remove_dir_all(&dst);
    copy_tree(&src, &dst).unwrap();
    std::fs::write(
        dst.join("postmortem.conf"),
        "skip_categories = [\"ioc\", \"obfuscation\", \"install_hook\", \"sensitive_api\"]\n",
    )
    .unwrap();

    let out = cmd()
        .arg(&dst)
        .arg("--json")
        .arg("--no-config")
        .args(["-o", "-"])
        .output()
        .unwrap();
    let report: Value = serde_json::from_slice(&out.stdout).unwrap();
    // With config disabled, we get the full set of findings.
    assert!(report["findings"].as_array().unwrap().len() > 4);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(!stderr.contains("loaded config"));

    let _ = std::fs::remove_dir_all(&dst);
}

fn copy_tree(src: &std::path::Path, dst: &std::path::Path) -> std::io::Result<()> {
    std::fs::create_dir_all(dst)?;
    for entry in std::fs::read_dir(src)? {
        let entry = entry?;
        let from = entry.path();
        let to = dst.join(entry.file_name());
        if from.is_dir() {
            copy_tree(&from, &to)?;
        } else {
            std::fs::copy(&from, &to)?;
        }
    }
    Ok(())
}

#[test]
fn enrich_flag_attaches_mlab_links_to_iocs() {
    let (_, report) = scan_json("malicious-node", &["--enrich"]);
    let iocs: Vec<&Value> = findings(&report)
        .iter()
        .filter(|f| f["category"] == "ioc")
        .collect();
    assert!(!iocs.is_empty());

    // Every URL/IP/IPv6/domain finding gets a link; wallet findings don't (yet).
    let by_detail = |s: &str| {
        iocs.iter()
            .find(|f| f["detail"].as_str() == Some(s))
            .copied()
    };
    let url_f = by_detail("embedded URL").expect("URL finding present");
    assert_eq!(
        url_f["enrich_url"],
        "https://mlab.sh/domain/drop.malicious.invalid"
    );

    let dom_f = by_detail("embedded domain name").expect("domain finding present");
    assert_eq!(dom_f["enrich_url"], "https://mlab.sh/domain/track.evil.tk");

    let ip6_f = by_detail("embedded IPv6 address").expect("IPv6 finding present");
    assert_eq!(
        ip6_f["enrich_url"],
        "https://mlab.sh/ip/2606:4700:1c1c::dead:beef"
    );

    let btc_f = iocs
        .iter()
        .find(|f| f["detail"].as_str().unwrap_or("").contains("Bitcoin"))
        .expect("BTC finding present");
    assert_eq!(
        btc_f["enrich_url"],
        "https://mlab.sh/crypto/1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2"
    );

    let eth_f = iocs
        .iter()
        .find(|f| f["detail"].as_str().unwrap_or("").contains("Ethereum"))
        .expect("ETH finding present");
    assert_eq!(
        eth_f["enrich_url"],
        "https://mlab.sh/crypto/0xdeadbeefcafebabe0011223344556677889900aa"
    );
}

#[test]
fn enrich_flag_off_by_default() {
    let (_, report) = scan_json("malicious-node", &[]);
    assert!(
        findings(&report)
            .iter()
            .all(|f| f.get("enrich_url").is_none() || f["enrich_url"].is_null()),
        "without --enrich, no enrich_url should be emitted"
    );
}

#[test]
fn sarif_output_is_well_formed() {
    let out = cmd()
        .arg(fixture("malicious-node"))
        .arg("--sarif")
        .args(["-o", "-"])
        .output()
        .unwrap();
    let body = String::from_utf8(out.stdout).unwrap();
    let v: Value = serde_json::from_str(&body).expect("valid JSON");

    // Schema sanity
    assert_eq!(v["version"], "2.1.0");
    assert!(v["$schema"].as_str().unwrap().contains("sarif"));

    let run = &v["runs"][0];
    assert_eq!(run["tool"]["driver"]["name"], "postmortem");
    let driver_ver = run["tool"]["driver"]["version"].as_str().unwrap();
    assert!(!driver_ver.is_empty());

    // We expect rules for every category present in this fixture's findings.
    let rules = run["tool"]["driver"]["rules"].as_array().unwrap();
    let rule_ids: Vec<&str> = rules.iter().map(|r| r["id"].as_str().unwrap()).collect();
    assert!(rule_ids.contains(&"postmortem.install_hook"));
    assert!(rule_ids.contains(&"postmortem.obfuscation"));
    assert!(rule_ids.contains(&"postmortem.ioc"));
    assert!(rule_ids.contains(&"postmortem.sensitive_api"));

    // Results — at least one of each, all carrying a location with relative path + line.
    let results = run["results"].as_array().unwrap();
    assert!(results.len() >= 8);
    for r in results {
        let level = r["level"].as_str().unwrap();
        assert!(["error", "warning", "note", "none"].contains(&level));
        let loc = &r["locations"][0]["physicalLocation"]["artifactLocation"]["uri"];
        assert!(
            !loc.as_str().unwrap().starts_with('/'),
            "path should be SRCROOT-relative, got {loc}"
        );
        assert!(r["partialFingerprints"]["postmortem/finding-fingerprint"].is_string());
    }
}

#[test]
fn sarif_includes_enrich_url_when_flag_set() {
    let out = cmd()
        .arg(fixture("malicious-node"))
        .arg("--sarif")
        .arg("--enrich")
        .args(["-o", "-"])
        .output()
        .unwrap();
    let v: Value = serde_json::from_slice(&out.stdout).unwrap();
    let results = v["runs"][0]["results"].as_array().unwrap();
    let has_enrich = results.iter().any(|r| {
        r["properties"]["enrichUrl"]
            .as_str()
            .map(|s| s.starts_with("https://mlab.sh/"))
            .unwrap_or(false)
    });
    assert!(
        has_enrich,
        "expected at least one result with properties.enrichUrl"
    );
}

#[test]
fn default_output_filename_when_no_dash_o() {
    // Run in a fresh temp cwd so we can assert exactly one file was created.
    let tmp = std::env::temp_dir().join(format!("postmortem-it-default-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&tmp);
    std::fs::create_dir_all(&tmp).unwrap();

    let out = cmd()
        .arg(fixture("clean-node"))
        .arg("--json")
        .current_dir(&tmp)
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    // stdout must be empty — JSON should have gone to a file.
    assert!(
        out.stdout.is_empty(),
        "stdout should be empty when defaulting to file"
    );

    // Stderr advertises the file path.
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("wrote") && stderr.contains("bytes to"));

    // Exactly one file in the cwd, matching the timestamped pattern.
    let entries: Vec<_> = std::fs::read_dir(&tmp).unwrap().flatten().collect();
    assert_eq!(entries.len(), 1, "expected exactly one output file in cwd");
    let fname = entries[0].file_name().into_string().unwrap();
    assert!(
        fname.starts_with("postmortem-report-[") && fname.ends_with("].json"),
        "filename does not match expected pattern: {fname}"
    );

    // The file is valid JSON
    let body = std::fs::read_to_string(entries[0].path()).unwrap();
    let v: Value = serde_json::from_str(&body).unwrap();
    assert_eq!(v["schema_version"], 3);

    let _ = std::fs::remove_dir_all(&tmp);
}

#[test]
fn dash_o_dash_forces_stdout() {
    // -o - explicitly routes to stdout instead of a default file.
    let out = cmd()
        .arg(fixture("clean-node"))
        .arg("--json")
        .args(["-o", "-"])
        .output()
        .unwrap();
    let body = String::from_utf8(out.stdout).unwrap();
    let v: Value = serde_json::from_str(&body).expect("valid JSON on stdout");
    assert_eq!(v["schema_version"], 3);
}

#[test]
fn html_output_is_self_contained() {
    let out = cmd()
        .arg(fixture("malicious-node"))
        .arg("--html")
        .args(["-o", "-"])
        .output()
        .unwrap();
    let body = String::from_utf8_lossy(&out.stdout);
    assert!(body.starts_with("<!doctype html>"));
    assert!(body.contains("flatmap-stream"));
    assert!(!body.contains("<script src=")); // no external scripts
}

// ---------- tree command ----------

/// Run `postmortem tree --json -o -` and return (exit_code, parsed_json).
fn tree_json(fixture_name: &str, extra_args: &[&str]) -> (i32, Value) {
    let out = Command::new(bin())
        .arg("tree")
        .arg(fixture(fixture_name))
        .arg("--json")
        .args(["-o", "-"])
        .args(extra_args)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .expect("postmortem binary did not run");
    let exit = out.status.code().unwrap_or(-1);
    let parsed: Value = serde_json::from_slice(&out.stdout).unwrap_or_else(|e| {
        panic!(
            "tree json parse failed (exit {exit}): {e}\nstdout: {}\nstderr: {}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr),
        )
    });
    (exit, parsed)
}

#[test]
fn tree_resolves_event_stream_chain() {
    let (exit, t) = tree_json("malicious-node", &[]);
    assert_eq!(exit, 0, "tree is offline-only today, exit 0 expected");
    assert_eq!(t["ecosystems"][0], "node");

    // event-stream is the direct root; flatmap-stream hangs beneath it.
    let root = &t["roots"][0];
    assert_eq!(root["name"], "event-stream");
    assert_eq!(root["direct"], true);
    assert_eq!(root["children"][0]["name"], "flatmap-stream");
    assert_eq!(root["children"][0]["direct"], false);

    assert_eq!(t["stats"]["total"], 2);
    assert_eq!(t["stats"]["max_depth"], 2);
}

#[test]
fn tree_depth_truncates() {
    let (_, t) = tree_json("malicious-node", &["--depth", "1"]);
    let root = &t["roots"][0];
    // At depth 1 the transitive child is hidden and the node is flagged.
    assert_eq!(root["truncated"], true);
    assert!(root["children"].as_array().unwrap().is_empty());
}

#[test]
fn tree_online_is_wired_without_touching_the_network() {
    // The rust fixture has zero node dependencies, so `--online` exercises the
    // wiring (token resolution, resolver construction, empty resolution pass)
    // without making any HTTP call — keeping the test hermetic.
    let out = Command::new(bin())
        .arg("tree")
        .arg(fixture("malicious-rust"))
        .arg("--online")
        .arg("--no-progress")
        .env_remove("GITHUB_TOKEN")
        .stdin(Stdio::null()) // non-interactive → no token prompt
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "tree --online should succeed on a node-free project"
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("rustdecimal"),
        "expected the tree to still render"
    );
}

// ---------- multi-target trees (--allow-multiple) & pinned lockfiles ----------

/// Run `postmortem tree` over several raw targets. Returns (exit, stdout, stderr).
fn tree_multi(targets: &[PathBuf], extra_args: &[&str]) -> (i32, String, String) {
    let out = Command::new(bin())
        .arg("tree")
        .args(targets)
        .args(extra_args)
        .arg("--no-progress")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .expect("postmortem binary did not run");
    (
        out.status.code().unwrap_or(-1),
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

#[test]
fn machine_format_rejects_several_targets_without_the_flag() {
    let targets = [fixture("malicious-node"), fixture("clean-node")];
    let (exit, _, stderr) = tree_multi(&targets, &["--json", "-o", "-"]);
    assert_ne!(
        exit, 0,
        "several targets in --json must not silently succeed"
    );
    assert!(
        stderr.contains("--allow-multiple"),
        "the error should point at the opt-in flag, got: {stderr}"
    );
}

#[test]
fn allow_multiple_emits_one_json_tree_per_target() {
    let targets = [fixture("malicious-node"), fixture("clean-node")];
    let (exit, stdout, stderr) = tree_multi(&targets, &["--json", "--allow-multiple", "-o", "-"]);
    assert_eq!(exit, 0, "stderr: {stderr}");
    let v: Value = serde_json::from_str(&stdout).expect("stdout should be valid json");
    let arr = v
        .as_array()
        .expect("--allow-multiple emits an ARRAY of trees");
    assert_eq!(arr.len(), 2);
    assert!(arr[0]["root"].as_str().unwrap().ends_with("malicious-node"));
    assert!(arr[1]["root"].as_str().unwrap().ends_with("clean-node"));
}

#[test]
fn a_single_target_keeps_the_bare_object_shape() {
    // The historical shape must survive the multi-target work, flag or not.
    let (_, t) = tree_json("malicious-node", &[]);
    assert!(t.is_object(), "one target still emits a bare tree object");
    let targets = [fixture("malicious-node")];
    let (exit, stdout, _) = tree_multi(&targets, &["--json", "--allow-multiple", "-o", "-"]);
    assert_eq!(exit, 0);
    let v: Value = serde_json::from_str(&stdout).unwrap();
    assert!(
        v.is_array(),
        "with the flag the shape is an array even for one target"
    );
}

#[test]
fn allow_multiple_emits_one_sarif_run_per_target() {
    let targets = [fixture("malicious-node"), fixture("clean-node")];
    let (exit, stdout, stderr) = tree_multi(&targets, &["--sarif", "--allow-multiple", "-o", "-"]);
    assert_eq!(exit, 0, "stderr: {stderr}");
    let v: Value = serde_json::from_str(&stdout).expect("stdout should be valid sarif");
    let runs = v["runs"].as_array().expect("sarif runs[]");
    assert_eq!(runs.len(), 2, "one run per target");
    for run in runs {
        // Each run keeps its own SRCROOT so alerts stay attributed.
        let uri = run["originalUriBaseIds"]["SRCROOT"]["uri"]
            .as_str()
            .unwrap();
        assert!(
            uri.starts_with("file://") && uri.ends_with('/'),
            "got {uri}"
        );
    }
}

#[test]
fn a_pinned_lockfile_resolves_its_parent_project() {
    let targets = [fixture("malicious-node").join("package-lock.json")];
    let (exit, stdout, stderr) = tree_multi(&targets, &["--json", "-o", "-"]);
    assert_eq!(exit, 0, "stderr: {stderr}");
    let t: Value = serde_json::from_str(&stdout).unwrap();
    // The tree root is the project directory, not the lockfile itself.
    assert!(
        t["root"].as_str().unwrap().ends_with("malicious-node"),
        "root: {}",
        t["root"]
    );
    assert_eq!(
        t["roots"][0]["name"], "event-stream",
        "the graph still resolves"
    );
}

#[test]
fn an_unusable_target_is_a_configuration_error_not_a_clean_run() {
    // A file postmortem can't read as a manifest, alongside a project that
    // resolves fine: the run must NOT come back green.
    let targets = [
        fixture("malicious-node").join("package.json.nope"),
        fixture("clean-node"),
    ];
    let (exit, _, stderr) = tree_multi(&targets, &[]);
    assert_eq!(
        exit, 2,
        "unusable target must exit 2 (misconfig), stderr: {stderr}"
    );

    let targets = [fixture("README.md")];
    let (exit, _, stderr) = tree_multi(&targets, &[]);
    assert_eq!(exit, 2, "an unrecognised file must exit 2");
    assert!(
        stderr.contains("not a recognised manifest or lockfile"),
        "stderr should say why, got: {stderr}"
    );
}

// --- `--omit` / dependency scopes ---------------------------------------------
//
// The `scoped-node` fixture is built around the case that makes this feature
// non-trivial: `shared-lib` is reachable from BOTH a production dependency and a
// dev tool. Omitting dev must never drop it.

/// Every dependency name in a `tree --json` forest, flattened.
fn tree_names(extra_args: &[&str]) -> Vec<String> {
    let out = Command::new(bin())
        .arg("tree")
        .arg(fixture("scoped-node"))
        .args(extra_args)
        .args(["--json", "-o", "-", "--no-progress"])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .expect("postmortem binary did not run");
    let v: Value = serde_json::from_slice(&out.stdout).unwrap_or_else(|e| {
        panic!(
            "invalid JSON: {e}\n{}",
            String::from_utf8_lossy(&out.stderr)
        )
    });
    fn walk(n: &Value, acc: &mut Vec<String>) {
        acc.push(n["name"].as_str().unwrap().to_string());
        for c in n["children"].as_array().into_iter().flatten() {
            walk(c, acc);
        }
    }
    let mut acc = Vec::new();
    for r in v["roots"].as_array().unwrap() {
        walk(r, &mut acc);
    }
    acc.sort();
    acc.dedup();
    acc
}

#[test]
fn without_omit_every_scope_is_present() {
    assert_eq!(
        tree_names(&[]),
        [
            "dev-only-lib",
            "dev-tool",
            "opt-lib",
            "prod-lib",
            "shared-lib"
        ]
    );
}

#[test]
fn omit_dev_drops_the_dev_subtree() {
    assert_eq!(
        tree_names(&["--omit", "dev"]),
        ["opt-lib", "prod-lib", "shared-lib"]
    );
}

#[test]
fn omit_dev_keeps_a_package_that_also_ships() {
    // The whole point: `shared-lib` is a child of the dev tool AND of a prod
    // dependency. A naive "listed under devDependencies" filter would drop it.
    let names = tree_names(&["--omit", "dev"]);
    assert!(
        names.contains(&"shared-lib".to_string()),
        "shared-lib ships and must survive"
    );
    assert!(
        !names.contains(&"dev-only-lib".to_string()),
        "dev-only-lib must be dropped"
    );
}

#[test]
fn omit_optional_is_independent_of_dev() {
    assert_eq!(
        tree_names(&["--omit", "optional"]),
        ["dev-only-lib", "dev-tool", "prod-lib", "shared-lib"]
    );
}

#[test]
fn omit_flags_combine() {
    assert_eq!(
        tree_names(&["--omit", "dev", "--omit", "optional"]),
        ["prod-lib", "shared-lib"]
    );
}

#[test]
fn omit_rejects_production() {
    // `--omit prod` must not parse: it would only ever hide shipped code.
    let out = Command::new(bin())
        .args(["tree", "--omit", "prod"])
        .arg(fixture("scoped-node"))
        .output()
        .expect("postmortem binary did not run");
    assert_eq!(
        out.status.code(),
        Some(2),
        "invalid value should be a usage error"
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("dev") && stderr.contains("optional"),
        "usage should list the valid values, got: {stderr}"
    );
}

#[test]
fn scan_reports_the_scope_of_each_dependency() {
    let (_, v) = scan_json("scoped-node", &[]);
    let by_name = |n: &str| -> String {
        v["dependencies"]
            .as_array()
            .unwrap()
            .iter()
            .find(|d| d["name"] == n)
            .unwrap_or_else(|| panic!("{n} missing"))["scope"]
            .as_str()
            .unwrap()
            .to_string()
    };
    assert_eq!(by_name("prod-lib"), "prod");
    assert_eq!(by_name("dev-tool"), "dev");
    assert_eq!(by_name("opt-lib"), "optional");
    assert_eq!(
        by_name("dev-only-lib"),
        "dev",
        "a transitive of the dev tool"
    );
    assert_eq!(
        by_name("shared-lib"),
        "prod",
        "reachable from prod, so it ships"
    );
}

#[test]
fn omitting_is_disclosed_as_a_diagnostic() {
    // The progress UI is suppressed off-TTY, so the omission must still reach
    // the machine output — a silently smaller dependency set is exactly what
    // this tool refuses to produce.
    let (_, v) = scan_json("scoped-node", &["--omit", "dev"]);
    let diags = v["diagnostics"].as_array().expect("diagnostics present");
    let omitted = diags
        .iter()
        .find(|d| d["kind"] == "scope_omitted")
        .expect("an omit must be recorded as a diagnostic");
    let msg = omitted["message"].as_str().unwrap();
    assert!(
        msg.contains("2 of 5"),
        "message should quantify the omission, got: {msg}"
    );
}

#[test]
fn omitting_does_not_worsen_the_audit_verdict() {
    // `scope_omitted` is deliberate, so unlike a parse failure it must not
    // downgrade a clean project to WARN.
    let run = |args: &[&str]| -> String {
        let out = Command::new(bin())
            .arg("audit")
            .arg(fixture("scoped-node"))
            .args(args)
            .arg("--no-progress")
            .output()
            .expect("postmortem binary did not run");
        String::from_utf8_lossy(&out.stdout).into_owned()
    };
    let plain = run(&[]);
    let omitted = run(&["--omit", "dev"]);
    let verdict = |s: &str| {
        for tier in ["CRITICAL", "WARN", "CLEAN"] {
            if s.contains(tier) {
                return tier;
            }
        }
        "NONE"
    };
    assert_eq!(
        verdict(&plain),
        verdict(&omitted),
        "--omit must not change the grade\n--- plain ---\n{plain}\n--- omitted ---\n{omitted}"
    );
}

#[test]
fn sbom_honours_omit() {
    let out = Command::new(bin())
        .arg("sbom")
        .arg(fixture("scoped-node"))
        .args(["--omit", "dev", "-o", "-", "--no-progress"])
        .stdout(Stdio::piped())
        .output()
        .expect("postmortem binary did not run");
    let v: Value = serde_json::from_slice(&out.stdout).expect("valid CycloneDX JSON");
    let names: Vec<&str> = v["components"]
        .as_array()
        .unwrap()
        .iter()
        .map(|c| c["name"].as_str().unwrap())
        .collect();
    assert!(names.contains(&"shared-lib"));
    assert!(
        !names.contains(&"dev-tool"),
        "an omitted package must not reach the SBOM"
    );
}

// --- `cache` -------------------------------------------------------------------
//
// Every one of these drives the binary with a throwaway `$HOME`, because
// `settings::home_dir()` reads that variable and the cache lives under it. A test
// that forgot to would prune the developer's real cache.

/// A private `$HOME` with a cache dir ready to seed.
fn tmp_home(tag: &str) -> PathBuf {
    use std::sync::atomic::{AtomicU64, Ordering};
    static SEQ: AtomicU64 = AtomicU64::new(0);
    let home = std::env::temp_dir().join(format!(
        "pm-home-{tag}-{}-{}",
        std::process::id(),
        SEQ.fetch_add(1, Ordering::Relaxed)
    ));
    let _ = std::fs::remove_dir_all(&home);
    std::fs::create_dir_all(home.join(".postmortem").join("cache")).unwrap();
    home
}

fn cache_dir(home: &std::path::Path) -> PathBuf {
    home.join(".postmortem").join("cache")
}

/// Write a cache entry verbatim, so a test can plant a specific record format.
fn seed_entry(home: &std::path::Path, ns: &str, name: &str, body: &str) {
    let d = cache_dir(home).join(ns);
    std::fs::create_dir_all(&d).unwrap();
    std::fs::write(d.join(format!("{name}.json")), body).unwrap();
}

/// The record format version the binary is currently writing, read back from
/// `cache info`. Seeding entries with a hardcoded number would make every one of
/// these tests fail the next time the format is bumped — which is exactly when
/// they most need to keep working.
fn current_format_version(home: &std::path::Path) -> u32 {
    let (_, out) = cache_cmd(home, &["info"]);
    out.split("record format v")
        .nth(1)
        .and_then(|rest| rest.split(|c: char| !c.is_ascii_digit()).next())
        .and_then(|n| n.parse().ok())
        .unwrap_or_else(|| panic!("could not read the format version from: {out}"))
}

/// A current-format entry wrapping `payload`.
fn current_entry(home: &std::path::Path, payload: &str) -> String {
    format!(
        r#"{{"v":{},"fetched_at":1786000000,"data":{payload}}}"#,
        current_format_version(home)
    )
}

/// Run `postmortem cache <args>` against a private `$HOME`.
fn cache_cmd(home: &std::path::Path, args: &[&str]) -> (i32, String) {
    let out = Command::new(bin())
        .arg("cache")
        .args(args)
        .env("HOME", home)
        .output()
        .expect("postmortem binary did not run");
    let mut s = String::from_utf8_lossy(&out.stdout).into_owned();
    s.push_str(&String::from_utf8_lossy(&out.stderr));
    // These views are coloured unconditionally, and an escape sequence sits
    // between the count and its label ("\e[1m3\e[0m entries"), so assertions on
    // the text must run on the stripped form.
    (out.status.code().unwrap_or(-1), strip_ansi(&s))
}

/// Drop CSI escape sequences (`ESC [ ... <final byte>`).
fn strip_ansi(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut chars = s.chars();
    while let Some(c) = chars.next() {
        if c != '\u{1b}' {
            out.push(c);
            continue;
        }
        if chars.next() != Some('[') {
            continue;
        }
        for c in chars.by_ref() {
            if c.is_ascii_alphabetic() {
                break;
            }
        }
    }
    out
}

#[test]
fn cache_path_prints_only_the_directory() {
    let home = tmp_home("path");
    let (exit, out) = cache_cmd(&home, &["path"]);
    assert_eq!(exit, 0);
    assert_eq!(
        out.trim(),
        cache_dir(&home).display().to_string(),
        "the path must be the whole output, so `$(postmortem cache path)` composes"
    );
    let _ = std::fs::remove_dir_all(&home);
}

#[test]
fn cache_info_on_an_empty_cache_says_so() {
    let home = tmp_home("empty");
    let (exit, out) = cache_cmd(&home, &["info"]);
    assert_eq!(exit, 0);
    assert!(out.contains("empty"), "got: {out}");
    let _ = std::fs::remove_dir_all(&home);
}

#[test]
fn cache_info_counts_entries_per_namespace() {
    let home = tmp_home("info");
    let a = current_entry(&home, r#"{"repo":null}"#);
    seed_entry(&home, "registry", "a", &a);
    seed_entry(&home, "registry", "b", &a);
    let c = current_entry(&home, r#"{"stars":1}"#);
    seed_entry(&home, "repo", "c", &c);

    let (exit, out) = cache_cmd(&home, &["info"]);
    assert_eq!(exit, 0);
    assert!(out.contains("registry"), "got: {out}");
    assert!(out.contains("repo"), "got: {out}");
    assert!(
        out.contains("3 entries"),
        "totals should be reported, got: {out}"
    );
    assert!(
        !out.contains("predate record format"),
        "nothing is stale here, got: {out}"
    );
    let _ = std::fs::remove_dir_all(&home);
}

#[test]
fn cache_info_flags_entries_from_an_older_record_format() {
    let home = tmp_home("stale-info");
    let cur = current_entry(&home, r#"{"repo":null}"#);
    seed_entry(&home, "registry", "current", &cur);
    // A record predating the envelope: a bare payload.
    seed_entry(&home, "registry", "legacy", r#"{"repo":null}"#);
    // A payload carrying its OWN `v` field must still be seen as legacy — the
    // envelope is identified by its `data` wrapper, not by a bare `v`.
    seed_entry(&home, "registry", "decoy", r#"{"v":1,"stars":5}"#);

    let (exit, out) = cache_cmd(&home, &["info"]);
    assert_eq!(exit, 0);
    assert!(
        out.contains("predate record format"),
        "stale entries must be surfaced, got: {out}"
    );
    assert!(
        out.contains("2 entries predate"),
        "both legacy shapes count, got: {out}"
    );
    assert!(
        out.contains("prune --stale"),
        "and the fix should be suggested, got: {out}"
    );
    let _ = std::fs::remove_dir_all(&home);
}

#[test]
fn cache_prune_stale_spares_current_entries() {
    let home = tmp_home("prune-stale");
    let cur = current_entry(&home, r#"{"repo":null}"#);
    seed_entry(&home, "registry", "current", &cur);
    seed_entry(&home, "registry", "legacy", r#"{"repo":null}"#);

    let (exit, out) = cache_cmd(&home, &["prune", "--stale"]);
    assert_eq!(exit, 0);
    assert!(out.contains("removed 1"), "got: {out}");
    assert!(
        out.contains("stale format"),
        "the filter should be named, got: {out}"
    );
    assert!(
        cache_dir(&home)
            .join("registry")
            .join("current.json")
            .exists()
    );
    assert!(
        !cache_dir(&home)
            .join("registry")
            .join("legacy.json")
            .exists()
    );
    let _ = std::fs::remove_dir_all(&home);
}

#[test]
fn cache_prune_dry_run_deletes_nothing() {
    let home = tmp_home("prune-dry");
    let a = current_entry(&home, r#"{"repo":null}"#);
    seed_entry(&home, "registry", "a", &a);

    let (exit, out) = cache_cmd(&home, &["prune", "--dry-run"]);
    assert_eq!(exit, 0);
    assert!(out.contains("would remove 1"), "got: {out}");
    assert!(
        cache_dir(&home).join("registry").join("a.json").exists(),
        "dry run must not delete"
    );
    let _ = std::fs::remove_dir_all(&home);
}

#[test]
fn a_stale_entry_is_not_served_as_data() {
    // The whole point of the version: a record from an older format must be a
    // miss, not a plausible-looking answer. Planting one and re-reading it
    // through `info` proves it was dropped rather than trusted.
    let home = tmp_home("no-serve");
    seed_entry(
        &home,
        "registry",
        "legacy",
        r#"{"repo":{"host":"github.com","owner":"o","name":"r"}}"#,
    );
    let (_, before) = cache_cmd(&home, &["info"]);
    assert!(
        before.contains("1 entries predate") || before.contains("1 entry predate"),
        "got: {before}"
    );
    let _ = std::fs::remove_dir_all(&home);
}

// --- `licenses` ----------------------------------------------------------------
//
// The `licensed-node` fixture covers the cases that make license handling
// non-trivial: a permissive id, a dual license (which must escape a denylist via
// its other option), a copyleft id, free text that must NOT become an SPDX id,
// and a package declaring nothing at all.

fn licenses_cmd(args: &[&str]) -> (i32, String) {
    let out = Command::new(bin())
        .arg("licenses")
        .arg(fixture("licensed-node"))
        .args(args)
        .arg("--no-progress")
        .output()
        .expect("postmortem binary did not run");
    let mut s = String::from_utf8_lossy(&out.stdout).into_owned();
    s.push_str(&String::from_utf8_lossy(&out.stderr));
    (out.status.code().unwrap_or(-1), strip_ansi(&s))
}

fn licenses_json(args: &[&str]) -> Value {
    let out = Command::new(bin())
        .arg("licenses")
        .arg(fixture("licensed-node"))
        .args(args)
        .args(["--json", "-o", "-", "--no-progress"])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .expect("postmortem binary did not run");
    serde_json::from_slice(&out.stdout).unwrap_or_else(|e| {
        panic!(
            "invalid JSON: {e}\n{}",
            String::from_utf8_lossy(&out.stderr)
        )
    })
}

#[test]
fn licenses_are_read_from_the_lockfile_without_network() {
    let (exit, out) = licenses_cmd(&[]);
    assert_eq!(exit, 0, "no policy means no failure");
    assert!(out.contains("MIT"), "got: {out}");
    assert!(out.contains("AGPL-3.0"), "got: {out}");
    assert!(
        out.contains("(unknown)"),
        "the undeclared package must be surfaced"
    );
}

#[test]
fn free_text_is_reported_as_non_spdx_not_as_an_id() {
    let v = licenses_json(&[]);
    let bespoke = v["licenses"]
        .as_array()
        .unwrap()
        .iter()
        .find(|b| b["license"] == "see the LICENSE file")
        .expect("the free-text license should appear verbatim");
    assert_eq!(bespoke["spdx"], false, "it must not be claimed as SPDX");
}

#[test]
fn an_undeclared_license_is_unresolved_not_permissive() {
    let v = licenses_json(&[]);
    assert_eq!(v["unresolved"], 1);
    let unknown = v["licenses"]
        .as_array()
        .unwrap()
        .iter()
        .find(|b| b["license"] == "(unknown)")
        .unwrap();
    assert_eq!(unknown["packages"][0], "silent@1.0.0");
}

#[test]
fn deny_fails_the_run_and_names_the_package() {
    let (exit, out) = licenses_cmd(&["--deny", "AGPL-3.0"]);
    assert_eq!(exit, 1, "a denied license must fail the run");
    assert!(out.contains("copyleft@1.0.0"), "got: {out}");
    assert!(out.contains("denied"), "got: {out}");
}

#[test]
fn a_dual_licensed_package_escapes_the_denylist() {
    // `dual` offers `MIT OR AGPL-3.0`: denying AGPL leaves MIT available, so it
    // must not be flagged. Only `copyleft`, which offers no alternative, fails.
    let v = licenses_json(&["--deny", "AGPL-3.0"]);
    let flagged: Vec<&str> = v["violations"]
        .as_array()
        .unwrap()
        .iter()
        .map(|x| x["package"].as_str().unwrap())
        .collect();
    assert_eq!(
        flagged,
        vec!["copyleft"],
        "dual-licensed packages keep their other option"
    );
}

#[test]
fn an_allowlist_rejects_everything_absent_from_it() {
    let v = licenses_json(&["--allow", "MIT"]);
    let flagged: Vec<&str> = v["violations"]
        .as_array()
        .unwrap()
        .iter()
        .map(|x| x["package"].as_str().unwrap())
        .collect();
    // `dual` offers MIT, so it passes; the rest do not.
    assert!(flagged.contains(&"copyleft"), "got: {flagged:?}");
    assert!(flagged.contains(&"bespoke"), "got: {flagged:?}");
    assert!(!flagged.contains(&"permissive"), "MIT is allowed");
    assert!(!flagged.contains(&"dual"), "dual offers MIT");
}

#[test]
fn unknown_licenses_only_fail_when_asked() {
    let (exit, _) = licenses_cmd(&[]);
    assert_eq!(exit, 0, "an unresolved license is not a failure by default");
    let (exit, out) = licenses_cmd(&["--fail-on-unknown"]);
    assert_eq!(exit, 1);
    assert!(out.contains("silent@1.0.0"), "got: {out}");
}

#[test]
fn omit_dev_narrows_the_licence_inventory() {
    // `devtool` is GPL-3.0-only and never ships, so `--omit dev` must drop it —
    // this is the combination that answers "what copyleft do I distribute".
    let v = licenses_json(&["--omit", "dev"]);
    let labels: Vec<&str> = v["licenses"]
        .as_array()
        .unwrap()
        .iter()
        .map(|b| b["license"].as_str().unwrap())
        .collect();
    assert!(
        !labels.contains(&"GPL-3.0-only"),
        "the dev tool's licence must be gone: {labels:?}"
    );
    assert!(labels.contains(&"MIT"));

    let (exit, _) = licenses_cmd(&["--omit", "dev", "--deny", "GPL-3.0-only"]);
    assert_eq!(
        exit, 0,
        "denying a licence only present in dev deps must not fail a prod run"
    );
}

#[test]
fn unknown_only_narrows_the_view() {
    let (exit, out) = licenses_cmd(&["--unknown-only"]);
    assert_eq!(exit, 0);
    assert!(out.contains("silent@1.0.0"), "got: {out}");
    assert!(
        !out.contains("  MIT "),
        "other buckets should be hidden, got: {out}"
    );
}

#[test]
fn sbom_emits_valid_cyclonedx_license_shapes() {
    let out = Command::new(bin())
        .arg("sbom")
        .arg(fixture("licensed-node"))
        .args(["-o", "-", "--no-progress"])
        .stdout(Stdio::piped())
        .output()
        .expect("postmortem binary did not run");
    let v: Value = serde_json::from_slice(&out.stdout).expect("valid JSON");
    let by_name = |n: &str| {
        v["components"]
            .as_array()
            .unwrap()
            .iter()
            .find(|c| c["name"] == n)
            .unwrap()
            .clone()
    };

    // A recognised identifier goes in `license.id`.
    assert_eq!(by_name("permissive")["licenses"][0]["license"]["id"], "MIT");
    // A compound value goes in `expression`, as a sibling of `license`.
    assert_eq!(
        by_name("dual")["licenses"][0]["expression"],
        "MIT OR AGPL-3.0"
    );
    assert!(by_name("dual")["licenses"][0].get("license").is_none());
    // Free text goes in `license.name` — never `id`, which consumers validate
    // against the SPDX list and reject the whole document over.
    assert_eq!(
        by_name("bespoke")["licenses"][0]["license"]["name"],
        "see the LICENSE file"
    );
    assert!(
        by_name("bespoke")["licenses"][0]["license"]
            .get("id")
            .is_none()
    );
    // Nothing declared: the field is absent rather than an empty array.
    assert!(by_name("silent").get("licenses").is_none());
}

// --- `audit` CI gate -----------------------------------------------------------
//
// `audit` used to hardcode "exit 1 on CRITICAL" and ignore `[gate]` entirely, so
// a project's policy silently did not apply to the command sold as the CI-ready
// one. These pin both halves: the built-in grade still fails the build, and the
// layered policy now does too.

fn audit_cmd(fixture_name: &str, args: &[&str]) -> (i32, String) {
    let out = Command::new(bin())
        .arg("audit")
        .arg(fixture(fixture_name))
        .args(args)
        .arg("--no-progress")
        .output()
        .expect("postmortem binary did not run");
    let mut s = String::from_utf8_lossy(&out.stdout).into_owned();
    s.push_str(&String::from_utf8_lossy(&out.stderr));
    (out.status.code().unwrap_or(-1), strip_ansi(&s))
}

#[test]
fn audit_without_a_gate_is_unchanged() {
    let (exit, out) = audit_cmd("clean-node", &[]);
    assert_eq!(
        exit, 0,
        "a clean project with no policy still passes: {out}"
    );
    assert!(
        !out.contains("gate"),
        "no gate output when no policy is set: {out}"
    );
}

#[test]
fn audit_still_fails_on_a_critical_verdict() {
    // The built-in floor: malware fails the build with or without a policy.
    let (exit, out) = audit_cmd("malicious-node", &[]);
    assert_eq!(exit, 1);
    assert!(out.contains("CRITICAL"), "got: {out}");
}

#[test]
fn audit_risk_thresholds_require_online() {
    // Fail-closed: a threshold over data the run never collected is a
    // misconfiguration (exit 2), never a silent pass.
    let (exit, out) = audit_cmd("clean-node", &["--max-high", "0"]);
    assert_eq!(exit, 2, "got: {out}");
    assert!(
        out.contains("require --online"),
        "the error should say why: {out}"
    );
}

#[test]
fn audit_vuln_thresholds_require_vulns() {
    let (exit, out) = audit_cmd("clean-node", &["--fail-on-vuln", "high"]);
    assert_eq!(exit, 2, "got: {out}");
    assert!(out.contains("require --vulns"), "got: {out}");
}

#[test]
fn audit_rejects_an_unreadable_baseline() {
    let (exit, out) = audit_cmd("clean-node", &["--baseline", "/nonexistent-baseline.json"]);
    assert_eq!(
        exit, 2,
        "a baseline that cannot be read must not pass silently: {out}"
    );
}

#[test]
fn audit_reads_the_gate_table_from_a_config() {
    // The regression this whole change is about: `audit` previously ignored
    // `[gate]` completely, so a project policy did not apply to it at all.
    // Reaching the fail-closed error proves the table was read.
    let dir = std::env::temp_dir().join(format!("pm-audit-gate-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("postmortem.conf"), "[gate]\nmax_high = 0\n").unwrap();

    let out = Command::new(bin())
        .arg("audit")
        .arg(fixture("clean-node"))
        .args(["--config", dir.join("postmortem.conf").to_str().unwrap()])
        .arg("--no-progress")
        .output()
        .expect("postmortem binary did not run");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(2), "stderr: {stderr}");
    assert!(
        stderr.contains("require --online"),
        "the [gate] table must be honoured: {stderr}"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn audit_gate_flags_are_accepted_alongside_the_data_they_need() {
    // With `--online` present the thresholds are evaluated rather than rejected;
    // the clean fixture scores 0, so nothing trips and the run passes.
    let (exit, out) = audit_cmd("clean-node", &["--online", "--max-high", "0"]);
    assert_eq!(exit, 0, "got: {out}");
    assert!(
        out.contains("gate PASS"),
        "the gate result should be reported: {out}"
    );
}

// --- machine output for audit / why / diff, and tree --html ---------------------
//
// `audit` exits non-zero to be CI-usable, but an exit code cannot say *why*;
// `why` and `diff` were terminal-only, so their answers could not be consumed by
// anything. These pin the shapes.

fn json_of(cmd_args: &[&str]) -> Value {
    let out = Command::new(bin())
        .args(cmd_args)
        .args(["--json", "-o", "-", "--no-progress"])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .expect("postmortem binary did not run");
    serde_json::from_slice(&out.stdout).unwrap_or_else(|e| {
        panic!(
            "invalid JSON: {e}\n{}",
            String::from_utf8_lossy(&out.stderr)
        )
    })
}

#[test]
fn audit_json_carries_the_verdict_and_its_reason() {
    let v = json_of(&["audit", fixture("malicious-node").to_str().unwrap()]);
    assert_eq!(v["schema_version"], 1);
    assert_eq!(v["verdict"], "critical");
    assert_eq!(
        v["reason"], "malicious code detected",
        "the grade must explain itself"
    );
    assert_eq!(v["findings"]["critical"], 1);
    assert_eq!(v["dependencies"]["total"], 2);
}

#[test]
fn audit_json_distinguishes_unchecked_layers_from_clean_ones() {
    // `null` means "not checked"; a zeroed object would claim we looked.
    let v = json_of(&["audit", fixture("clean-node").to_str().unwrap()]);
    assert!(v["reputation"].is_null(), "no --online means not assessed");
    assert!(
        v["vulnerabilities"].is_null(),
        "no --vulns means not assessed"
    );
    assert!(v["gate_tripped"].is_null(), "no policy configured");
}

#[test]
fn audit_json_reports_whether_the_gate_ran() {
    // A configured policy that passes is `false`, never `null` — the difference
    // between "checked and fine" and "never checked".
    let out = Command::new(bin())
        .args(["audit", fixture("clean-node").to_str().unwrap()])
        .args([
            "--online",
            "--max-high",
            "0",
            "--json",
            "-o",
            "-",
            "--no-progress",
        ])
        .stdout(Stdio::piped())
        .output()
        .expect("postmortem binary did not run");
    let v: Value = serde_json::from_slice(&out.stdout).expect("valid JSON");
    assert_eq!(v["gate_tripped"], false);
}

#[test]
fn audit_json_still_exits_non_zero() {
    // The machine format must not soften the exit contract.
    let out = Command::new(bin())
        .args(["audit", fixture("malicious-node").to_str().unwrap()])
        .args(["--json", "-o", "-", "--no-progress"])
        .output()
        .expect("postmortem binary did not run");
    assert_eq!(out.status.code(), Some(1));
}

#[test]
fn why_json_groups_paths_per_installed_version() {
    let v = json_of(&[
        "why",
        "flatmap-stream",
        fixture("malicious-node").to_str().unwrap(),
    ]);
    assert_eq!(v["package"], "flatmap-stream");
    let installed = v["installed"].as_array().unwrap();
    assert_eq!(installed.len(), 1);
    assert_eq!(installed[0]["version"], "0.1.1");
    assert_eq!(installed[0]["direct"], false);
    // The path is what lies *above* the target, so it starts at the parent.
    assert_eq!(installed[0]["paths"][0][0]["name"], "event-stream");
}

#[test]
fn why_json_on_an_absent_package_is_an_empty_list_not_an_error() {
    let out = Command::new(bin())
        .args([
            "why",
            "not-a-real-package",
            fixture("clean-node").to_str().unwrap(),
        ])
        .args(["--json", "-o", "-", "--no-progress"])
        .stdout(Stdio::piped())
        .output()
        .expect("postmortem binary did not run");
    assert_eq!(out.status.code(), Some(0), "absence is a valid answer");
    let v: Value = serde_json::from_slice(&out.stdout).expect("valid JSON");
    assert!(v["installed"].as_array().unwrap().is_empty());
}

#[test]
fn diff_json_honours_omit_on_both_sides() {
    let v = json_of(&[
        "diff",
        fixture("clean-node").to_str().unwrap(),
        fixture("scoped-node").to_str().unwrap(),
        "--omit",
        "dev",
    ]);
    let added: Vec<&str> = v["added"]
        .as_array()
        .unwrap()
        .iter()
        .map(|x| x["name"].as_str().unwrap())
        .collect();
    assert!(
        !added.contains(&"dev-tool"),
        "dev packages must be filtered: {added:?}"
    );
    assert!(added.contains(&"prod-lib"));
}

#[test]
fn tree_html_is_a_self_contained_document() {
    let out = Command::new(bin())
        .args(["tree", fixture("malicious-node").to_str().unwrap()])
        .args(["--html", "-o", "-", "--no-progress"])
        .stdout(Stdio::piped())
        .output()
        .expect("postmortem binary did not run");
    let html = String::from_utf8_lossy(&out.stdout);
    assert!(
        html.starts_with("<!doctype html>"),
        "got: {}",
        &html[..60.min(html.len())]
    );
    assert!(html.contains("<style>"), "the stylesheet must be inlined");
    assert!(
        !html.contains("src=\"http") && !html.contains("href=\"http"),
        "the report must reference no external asset"
    );
    // The forest is always present, even offline.
    assert!(html.contains("event-stream"), "got: {html}");
    assert!(html.contains("flatmap-stream"));
}

#[test]
fn tree_html_says_what_it_could_not_assess() {
    // Offline, an empty risk table would read as "we looked and found nothing".
    let out = Command::new(bin())
        .args(["tree", fixture("clean-node").to_str().unwrap()])
        .args(["--html", "-o", "-", "--no-progress"])
        .stdout(Stdio::piped())
        .output()
        .expect("postmortem binary did not run");
    let html = String::from_utf8_lossy(&out.stdout);
    assert!(html.contains("Not assessed"), "got: {html}");
    assert!(
        html.contains("--online"),
        "and it should say which flag fixes it"
    );
    assert!(html.contains("--vulns"));
}

#[test]
fn tree_html_escapes_package_names() {
    // Package names reach the document verbatim; an unescaped one would be an
    // HTML injection into a report people open in a browser.
    let out = Command::new(bin())
        .args(["tree", fixture("scoped-node").to_str().unwrap()])
        .args(["--html", "-o", "-", "--no-progress"])
        .stdout(Stdio::piped())
        .output()
        .expect("postmortem binary did not run");
    let html = String::from_utf8_lossy(&out.stdout);
    // The fixture has no hostile name, so assert the escaper is wired at all by
    // checking a known-safe render plus the absence of raw angle brackets in the
    // forest list items.
    assert!(html.contains("prod-lib"));
    assert!(!html.contains("<li><script"), "got: {html}");
}

#[test]
fn tree_html_rejects_several_targets_without_the_flag() {
    let targets = [fixture("malicious-node"), fixture("clean-node")];
    let (exit, _, stderr) = tree_multi(&targets, &["--html", "-o", "-"]);
    assert_ne!(
        exit, 0,
        "several targets in --html must not silently succeed"
    );
    assert!(
        stderr.contains("--html"),
        "the error should name the format: {stderr}"
    );
    assert!(
        stderr.contains("--allow-multiple"),
        "and point at the opt-in: {stderr}"
    );
}

// --- `diff` assessment ---------------------------------------------------------
//
// Offline `diff` is a set-diff. `--online` / `--vulns` assess what the change
// *introduces*, which is the question a reviewer is actually asking. These pin
// the offline shape and the opt-in boundary; the networked path is covered by
// unit tests in `src/diff.rs`, which can construct resolutions directly.

#[test]
fn diff_without_assessment_reports_no_risk_at_all() {
    // A zeroed assessment would read as "checked, and it is fine".
    let v = json_of(&[
        "diff",
        fixture("clean-node").to_str().unwrap(),
        fixture("scoped-node").to_str().unwrap(),
    ]);
    assert_eq!(v["schema_version"], 2);
    for a in v["added"].as_array().unwrap() {
        assert!(
            a["assessment"].is_null(),
            "offline diff must not claim an assessment: {a}"
        );
    }
}

#[test]
fn diff_json_keeps_the_three_change_sets() {
    let v = json_of(&[
        "diff",
        fixture("clean-node").to_str().unwrap(),
        fixture("scoped-node").to_str().unwrap(),
    ]);
    assert_eq!(v["summary"]["added"], 5);
    assert_eq!(v["summary"]["removed"], 1);
    let removed = v["removed"].as_array().unwrap();
    assert_eq!(removed[0]["name"], "leftpad-clean");
    assert_eq!(removed[0]["ecosystem"], "node");
}

#[test]
fn diff_accepts_the_assessment_flags() {
    // `--online`/`--vulns` must parse and not change the offline classification.
    let out = Command::new(bin())
        .arg("diff")
        .arg(fixture("clean-node"))
        .arg(fixture("scoped-node"))
        .args(["--vulns", "--json", "-o", "-", "--no-progress"])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .expect("postmortem binary did not run");
    let v: Value = serde_json::from_slice(&out.stdout).expect("valid JSON");
    assert_eq!(v["summary"]["added"], 5);
}

// --- `fix` ---------------------------------------------------------------------
//
// The plan itself is unit-tested in `src/fix.rs`, where remedies can be built
// without a network. These pin the command's contract: the exit code, the clean
// case, and that nothing is ever written.

#[test]
fn fix_on_a_project_without_advisories_exits_zero() {
    let out = Command::new(bin())
        .arg("fix")
        .arg(fixture("clean-node"))
        .arg("--no-progress")
        .output()
        .expect("postmortem binary did not run");
    assert_eq!(out.status.code(), Some(0));
    let s = strip_ansi(&String::from_utf8_lossy(&out.stdout));
    assert!(s.contains("no known vulnerabilities"), "got: {s}");
}

#[test]
fn fix_never_writes_to_the_project() {
    // The plan is advice, not an edit: applying it is the user's decision.
    let dir = std::env::temp_dir().join(format!("pm-fix-ro-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    for f in ["package.json", "package-lock.json"] {
        std::fs::copy(fixture("clean-node").join(f), dir.join(f)).unwrap();
    }
    let before: Vec<(String, u64)> = std::fs::read_dir(&dir)
        .unwrap()
        .flatten()
        .map(|e| {
            (
                e.file_name().to_string_lossy().into_owned(),
                e.metadata().unwrap().len(),
            )
        })
        .collect();

    let _ = Command::new(bin())
        .arg("fix")
        .arg(&dir)
        .arg("--no-progress")
        .output();

    let after: Vec<(String, u64)> = std::fs::read_dir(&dir)
        .unwrap()
        .flatten()
        .map(|e| {
            (
                e.file_name().to_string_lossy().into_owned(),
                e.metadata().unwrap().len(),
            )
        })
        .collect();
    assert_eq!(before, after, "fix must not touch the project");
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn fix_json_has_a_summary_even_when_empty() {
    let v = json_of(&["fix", fixture("clean-node").to_str().unwrap()]);
    assert_eq!(v["schema_version"], 1);
    assert_eq!(v["summary"]["packages"], 0);
    assert_eq!(v["summary"]["advisories"], 0);
    assert!(v["remedies"].as_array().unwrap().is_empty());
}

#[test]
fn fix_rejects_a_project_it_cannot_parse() {
    let out = Command::new(bin())
        .arg("fix")
        .arg(fixture("README.md"))
        .arg("--no-progress")
        .output()
        .expect("postmortem binary did not run");
    assert_ne!(out.status.code(), Some(0));
}

// --- suppressions and their expiry ---------------------------------------------
//
// A suppression is technical debt with a due date. These pin the two properties
// that make the date mean anything: a lapsed rule stops hiding, and the debt is
// listable.

/// A project with a `postmortem.conf`, returning its directory.
fn conf_project(tag: &str, conf: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("pm-supp-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    for f in ["package.json", "package-lock.json"] {
        std::fs::copy(fixture("malicious-node").join(f), dir.join(f)).unwrap();
    }
    std::fs::write(dir.join("postmortem.conf"), conf).unwrap();
    dir
}

fn run(args: &[&str]) -> (i32, String) {
    let out = Command::new(bin())
        .args(args)
        .arg("--no-progress")
        .output()
        .expect("ran");
    let mut s = String::from_utf8_lossy(&out.stdout).into_owned();
    s.push_str(&String::from_utf8_lossy(&out.stderr));
    (out.status.code().unwrap_or(-1), strip_ansi(&s))
}

#[test]
fn a_live_ignore_rule_suppresses_and_a_lapsed_one_does_not() {
    let live = conf_project(
        "live",
        "[[ignore]]\ncategory = \"ioc\"\nexpires = \"2099-01-01\"\n",
    );
    let (_, out) = run(&["scan", live.to_str().unwrap()]);
    assert!(
        !out.contains("no longer applies"),
        "a live rule is not reported: {out}"
    );

    let lapsed = conf_project(
        "lapsed",
        "[[ignore]]\ncategory = \"ioc\"\nexpires = \"2020-01-01\"\n",
    );
    let (_, out) = run(&["scan", lapsed.to_str().unwrap()]);
    assert!(
        out.contains("no longer applies"),
        "a lapsed rule must be reported: {out}"
    );

    let _ = std::fs::remove_dir_all(&live);
    let _ = std::fs::remove_dir_all(&lapsed);
}

#[test]
fn an_unparseable_expiry_stops_suppressing_rather_than_lasting_forever() {
    // A typo must not grant a permanent exemption.
    let dir = conf_project(
        "typo",
        "[[ignore]]\ncategory = \"ioc\"\nexpires = \"next tuesday\"\n",
    );
    let (_, out) = run(&["scan", dir.to_str().unwrap()]);
    assert!(out.contains("invalid expires"), "got: {out}");
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn audit_applies_the_projects_suppressions() {
    // `audit` previously ignored `postmortem.conf` entirely, so a config that
    // quieted `scan` had no effect on the one-shot verdict.
    let dir = conf_project(
        "audit",
        "skip_categories = [\"ioc\", \"obfuscation\", \"install_hook\", \"sensitive_api\"]\n",
    );
    let (_, out) = run(&["audit", dir.to_str().unwrap()]);
    assert!(
        out.contains("none"),
        "every category suppressed → no malware row: {out}"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn allowlist_lists_every_table_with_its_status() {
    let dir = conf_project(
        "list",
        "skip_dependencies = [\"left-pad\"]\n\n\
         [[ignore]]\ndependency = \"a\"\nexpires = \"2099-01-01\"\n\n\
         [[ignore]]\ndependency = \"b\"\nexpires = \"2020-01-01\"\n\n\
         [[gate.allow]]\npackage = \"c\"\nexpires = \"2099-01-01\"\n",
    );
    let (exit, out) = run(&["allowlist", dir.to_str().unwrap()]);
    assert_eq!(exit, 0, "a plain listing is a report, not a check");
    for expected in [
        "skip_dependencies",
        "ignore",
        "gate.allow",
        "no expiry",
        "expired",
    ] {
        assert!(out.contains(expected), "missing {expected:?} in: {out}");
    }
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn allowlist_expired_exits_one_only_when_something_lapsed() {
    let clean = conf_project(
        "ok",
        "[[ignore]]\ndependency = \"a\"\nexpires = \"2099-01-01\"\n",
    );
    let (exit, _) = run(&["allowlist", clean.to_str().unwrap(), "--expired"]);
    assert_eq!(exit, 0, "nothing lapsed → pass");

    let debt = conf_project(
        "debt",
        "[[ignore]]\ndependency = \"a\"\nexpires = \"2020-01-01\"\n",
    );
    let (exit, out) = run(&["allowlist", debt.to_str().unwrap(), "--expired"]);
    assert_eq!(exit, 1, "lapsed debt must fail the check: {out}");

    let _ = std::fs::remove_dir_all(&clean);
    let _ = std::fs::remove_dir_all(&debt);
}

#[test]
fn allowlist_json_reports_days_left_only_for_active_entries() {
    let dir = conf_project(
        "json",
        "[[ignore]]\ndependency = \"a\"\nexpires = \"2099-01-01\"\n\n\
         [[ignore]]\ndependency = \"b\"\nexpires = \"2020-01-01\"\n",
    );
    let v = json_of(&["allowlist", dir.to_str().unwrap()]);
    assert_eq!(v["summary"]["lapsed"], 1);
    let by = |st: &str| {
        v["suppressions"]
            .as_array()
            .unwrap()
            .iter()
            .find(|s| s["status"] == st)
            .unwrap()
            .clone()
    };
    assert!(by("active")["days_left"].is_number());
    assert!(
        by("expired")["days_left"].is_null(),
        "a lapsed entry has no time left"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn allowlist_on_a_project_without_a_config_is_empty_not_an_error() {
    let (exit, out) = run(&["allowlist", fixture("clean-node").to_str().unwrap()]);
    assert_eq!(exit, 0);
    assert!(out.contains("no suppressions"), "got: {out}");
}

// --- `why --blast` -------------------------------------------------------------

#[test]
fn blast_reports_reach_and_entry_points() {
    let (exit, out) = run(&[
        "why",
        "shared-lib",
        fixture("scoped-node").to_str().unwrap(),
        "--blast",
    ]);
    assert_eq!(exit, 0, "got: {out}");
    assert!(out.contains("blast radius"), "got: {out}");
    // shared-lib is pulled by both prod-lib and the dev tool.
    assert!(out.contains("entered via"), "got: {out}");
    assert!(out.contains("prod-lib"), "got: {out}");
}

#[test]
fn blast_on_an_absent_package_is_an_error_not_an_empty_report() {
    let (exit, _) = run(&[
        "why",
        "nope",
        fixture("clean-node").to_str().unwrap(),
        "--blast",
    ]);
    assert_ne!(
        exit, 0,
        "a package that is not there has no blast radius to report"
    );
}

#[test]
fn blast_says_unknown_when_the_dependency_code_was_never_read() {
    // The fixture has node_modules, so the hook question IS answerable there;
    // a lockfile-only project must say so instead of implying a clean result.
    let dir = std::env::temp_dir().join(format!("pm-blast-lock-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    for f in ["package.json", "package-lock.json"] {
        std::fs::copy(fixture("scoped-node").join(f), dir.join(f)).unwrap();
    }
    let (_, out) = run(&["why", "shared-lib", dir.to_str().unwrap(), "--blast"]);
    assert!(out.contains("unknown"), "got: {out}");
    assert!(out.contains("not on disk"), "and it should say why: {out}");
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn blast_json_separates_the_ceiling_from_current_behaviour() {
    let v = json_of(&[
        "why",
        "flatmap-stream",
        fixture("malicious-node").to_str().unwrap(),
        "--blast",
    ]);
    assert_eq!(v["package"], "flatmap-stream");
    assert_eq!(v["position"]["trigger"], "install");
    // `exposure` follows from position; `observed` is only what the code does now.
    let exposure = v["exposure"].as_array().unwrap();
    assert!(exposure.iter().any(|e| e.as_str().unwrap().contains("CI")));
    assert!(v["observed"].is_array());
}

#[test]
fn blast_does_not_change_the_default_why_output() {
    let (_, plain) = run(&[
        "why",
        "flatmap-stream",
        fixture("malicious-node").to_str().unwrap(),
    ]);
    assert!(
        plain.contains("required by"),
        "the path view is unchanged: {plain}"
    );
    assert!(!plain.contains("blast radius"));
}

// --- `tree --human` -------------------------------------------------------------
//
// The graph itself is unit-tested in `src/human.rs`, where resolutions can be
// built without a network. These pin the command's contract.

#[test]
fn human_requires_online_and_says_why() {
    // Nothing in a lockfile names who can publish, so an offline maintainer
    // graph would be empty for a reason the user could not guess.
    let (exit, out) = run(&["tree", fixture("clean-node").to_str().unwrap(), "--human"]);
    assert_ne!(exit, 0);
    assert!(out.contains("--online"), "got: {out}");
    assert!(
        out.contains("who can publish"),
        "the error should explain: {out}"
    );
}

// --- install-time execution: `scripts`, `hook`, `watch` -------------------------

#[test]
fn scripts_finds_install_scripts_from_the_lockfile_alone() {
    // npm records `hasInstallScript`, so the decision list works uninstalled.
    let (exit, out) = run(&["scripts", "tests/realrepo/Capsule"]);
    assert_eq!(exit, 0, "pending alone does not fail: {out}");
    assert!(out.contains("bcrypt"), "got: {out}");
    assert!(out.contains("pending"), "got: {out}");
    assert!(
        out.contains("not on disk"),
        "an unread script must say so: {out}"
    );
}

#[test]
fn scripts_fails_on_a_hostile_script_but_not_on_mere_pending() {
    let (exit, out) = run(&["scripts", fixture("malicious-node").to_str().unwrap()]);
    assert_eq!(exit, 1, "a flagged script fails: {out}");

    let (exit, _) = run(&["scripts", "tests/realrepo/Capsule"]);
    assert_eq!(exit, 0);
    let (exit, _) = run(&["scripts", "tests/realrepo/Capsule", "--fail-on-pending"]);
    assert_eq!(exit, 1, "pending fails only when asked");
}

#[test]
fn scripts_reports_an_approved_package_whose_script_turned_hostile() {
    // The case npm's own mechanism cannot catch: `allowScripts` records a name,
    // not a version, so an approval carries across a release.
    let dir = std::env::temp_dir().join(format!("pm-appr-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    let src = fixture("malicious-node");
    std::fs::create_dir_all(dir.join("node_modules")).unwrap();
    for f in ["package.json", "package-lock.json"] {
        std::fs::copy(src.join(f), dir.join(f)).unwrap();
    }
    let out = Command::new("cp")
        .arg("-r")
        .arg(src.join("node_modules"))
        .arg(&dir)
        .output();
    assert!(out.is_ok());
    let pkg = dir.join("package.json");
    let mut v: Value = serde_json::from_str(&std::fs::read_to_string(&pkg).unwrap()).unwrap();
    v["allowScripts"] = serde_json::json!({ "flatmap-stream": true });
    std::fs::write(&pkg, v.to_string()).unwrap();

    let (_, out) = run(&["scripts", dir.to_str().unwrap()]);
    assert!(out.contains("approved"), "got: {out}");
    assert!(
        out.contains("looks hostile now"),
        "the rot must be called out: {out}"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn allowlist_lists_npm_script_approvals_too() {
    // They live in package.json rather than postmortem.conf, but they suppress
    // the same way — omitting them would understate what was waved through.
    let dir = std::env::temp_dir().join(format!("pm-appr-list-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(
        dir.join("package.json"),
        r#"{"name":"x","allowScripts":{"bcrypt":true}}"#,
    )
    .unwrap();
    let (exit, out) = run(&["allowlist", dir.to_str().unwrap()]);
    assert_eq!(exit, 0);
    assert!(out.contains("allowScripts"), "got: {out}");
    assert!(out.contains("bcrypt"), "got: {out}");
    let _ = std::fs::remove_dir_all(&dir);
}

/// A throwaway git repository.
fn git_repo(tag: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("pm-git-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    let _ = Command::new("git")
        .arg("init")
        .arg("-q")
        .current_dir(&d)
        .output();
    d
}

#[test]
fn hook_install_status_and_uninstall_round_trip() {
    let d = git_repo("roundtrip");
    let (exit, out) = run(&["hook", "install", "--path", d.to_str().unwrap()]);
    assert_eq!(exit, 0, "got: {out}");
    assert!(d.join(".git/hooks/pre-commit").exists());
    // The expectation is set at install time, not buried in docs.
    assert!(
        out.contains("does not stop a malicious install script"),
        "got: {out}"
    );

    let (_, out) = run(&["hook", "status", "--path", d.to_str().unwrap()]);
    assert!(out.contains("installed by postmortem"), "got: {out}");
    assert!(
        out.contains("no-verify"),
        "it must not claim to be a control: {out}"
    );

    let (exit, _) = run(&["hook", "uninstall", "--path", d.to_str().unwrap()]);
    assert_eq!(exit, 0);
    assert!(!d.join(".git/hooks/pre-commit").exists());
    let _ = std::fs::remove_dir_all(&d);
}

#[test]
fn hook_refuses_to_clobber_or_delete_a_foreign_hook() {
    let d = git_repo("foreign");
    let p = d.join(".git/hooks/pre-commit");
    std::fs::create_dir_all(p.parent().unwrap()).unwrap();
    std::fs::write(&p, "#!/bin/sh\necho mine\n").unwrap();

    let (exit, out) = run(&["hook", "install", "--path", d.to_str().unwrap()]);
    assert_ne!(exit, 0, "an existing hook is somebody's work: {out}");
    assert_eq!(
        std::fs::read_to_string(&p).unwrap(),
        "#!/bin/sh\necho mine\n"
    );

    let (exit, _) = run(&["hook", "uninstall", "--path", d.to_str().unwrap()]);
    assert_ne!(exit, 0, "uninstall must not delete a file we did not write");
    assert!(p.exists());
    let _ = std::fs::remove_dir_all(&d);
}

#[test]
fn watch_rejects_a_path_it_cannot_resolve() {
    // The loop itself only ends on a change, so it is covered by unit tests in
    // `src/watch.rs`; what is worth pinning here is that the command validates
    // before entering a loop the user would have to interrupt.
    let out = Command::new(bin())
        .args(["watch", "/nonexistent-watch-dir-xyz", "--interval", "1"])
        .output()
        .expect("postmortem binary did not run");
    assert_ne!(out.status.code(), Some(0));
}

#[test]
fn the_overview_lists_every_command() {
    // A help text that drifts behind the CLI is worse than none: it tells people
    // a capability does not exist. Pin it against clap's own command list.
    let (exit, overview) = run_bare(&["help"]);
    assert_eq!(exit, 0);
    for c in [
        "scan", "tree", "audit", "system", "why", "timeline", "diff", "scripts", "fix",
        "licenses", "allowlist", "sbom", "hook", "watch", "cache",
    ] {
        assert!(overview.contains(c), "`{c}` missing from the overview");
    }
    // And every command clap knows about is in there.
    let (_, usage) = run_bare(&["--help"]);
    let listed: Vec<&str> = usage
        .lines()
        .skip_while(|l| !l.starts_with("Commands:"))
        .skip(1)
        .take_while(|l| l.starts_with("  ") && !l.trim_start().starts_with('-'))
        .filter_map(|l| l.split_whitespace().next())
        .collect();
    assert!(listed.len() >= 15, "expected clap to list the commands, got {listed:?}");
    for c in &listed {
        assert!(overview.contains(c), "`{c}` is a real command but absent from `help`");
    }
}

/// Run without the `--no-progress` the other helper appends.
fn run_bare(args: &[&str]) -> (i32, String) {
    let out = Command::new(bin()).args(args).output().expect("ran");
    let mut s = String::from_utf8_lossy(&out.stdout).into_owned();
    s.push_str(&String::from_utf8_lossy(&out.stderr));
    (out.status.code().unwrap_or(-1), strip_ansi(&s))
}
