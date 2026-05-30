//! End-to-end integration tests against fixtures that emulate real public
//! supply-chain incidents (event-stream 2018, ctx 2022, rustdecimal 2022).
//! All payloads are INERT — see `tests/fixtures/README.md`.

use serde_json::Value;
use std::path::PathBuf;
use std::process::{Command, Stdio};

fn bin() -> &'static str {
    env!("CARGO_BIN_EXE_postmortem")
}

fn fixture(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
        .join(name)
}

/// Run postmortem in JSON mode and return (exit_code, parsed_json).
fn scan_json(fixture_name: &str, extra_args: &[&str]) -> (i32, Value) {
    let mut cmd = Command::new(bin());
    cmd.arg(fixture(fixture_name))
        .arg("--json")
        .args(extra_args)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let out = cmd.output().expect("postmortem binary did not run");
    let exit = out.status.code().unwrap_or(-1);
    let parsed: Value = serde_json::from_slice(&out.stdout)
        .unwrap_or_else(|e| panic!(
            "json parse failed (exit {exit}): {e}\nstdout: {}\nstderr: {}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr),
        ));
    (exit, parsed)
}

fn findings(report: &Value) -> &Vec<Value> {
    report["findings"].as_array().expect("findings array")
}

fn deps(report: &Value) -> &Vec<Value> {
    report["dependencies"].as_array().expect("deps array")
}

fn dep_present(report: &Value, name: &str, version: &str) -> bool {
    deps(report).iter().any(|d| d["name"] == name && d["version"] == version)
}

fn has_finding(report: &Value, dep_substr: &str, category: &str) -> bool {
    findings(report).iter().any(|f| {
        f["category"] == category
            && f["dependency"].as_str().map(|s| s.contains(dep_substr)).unwrap_or(false)
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
        .filter(|f| f["category"] == "ioc"
            && f["dependency"].as_str().unwrap_or("").contains("flatmap-stream"))
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
                && f["evidence"].as_str().map(|s| s.contains("track.evil.tk")).unwrap_or(false)
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
                && f["evidence"].as_str().map(|s| s.contains("2001:db8::dead:beef")).unwrap_or(false)
        }),
        "expected IPv6 finding for 2001:db8::dead:beef"
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
        findings(&report).iter().any(|f| f["category"] == "install_hook"),
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

// ---------- clean baseline ----------

#[test]
fn clean_node_emits_no_high_findings_and_exits_zero() {
    let (exit, report) = scan_json("clean-node", &[]);
    assert_eq!(exit, 0, "clean fixture should exit 0");
    let highs: Vec<&Value> = findings(&report)
        .iter()
        .filter(|f| f["severity"] == "high" || f["severity"] == "critical")
        .collect();
    assert!(highs.is_empty(), "clean fixture leaked high findings: {highs:#?}");
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

    let ioc_in_all = findings(&all).iter().filter(|f| f["category"] == "ioc").count();
    let ioc_in_filtered = findings(&no_ioc).iter().filter(|f| f["category"] == "ioc").count();
    assert!(ioc_in_all > 0, "fixture should produce ioc findings");
    assert_eq!(ioc_in_filtered, 0, "--skip-category ioc must drop all ioc findings");
    // other categories remain
    assert!(findings(&no_ioc).iter().any(|f| f["category"] == "install_hook"));
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
    let dst = std::env::temp_dir().join(format!(
        "postmortem-it-{}-{}",
        std::process::id(),
        line!()
    ));
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

    let out = Command::new(bin())
        .arg(&dst)
        .arg("--json")
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
    assert!(!cats.contains(&"sensitive_api"), "sensitive_api should be suppressed");
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
    let dst = std::env::temp_dir().join(format!(
        "postmortem-it-{}-{}",
        std::process::id(),
        line!()
    ));
    let _ = std::fs::remove_dir_all(&dst);
    copy_tree(&src, &dst).unwrap();
    std::fs::write(
        dst.join("postmortem.conf"),
        "skip_categories = [\"ioc\", \"obfuscation\", \"install_hook\", \"sensitive_api\"]\n",
    )
    .unwrap();

    let out = Command::new(bin())
        .arg(&dst)
        .arg("--json")
        .arg("--no-config")
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
    assert_eq!(url_f["enrich_url"], "https://mlab.sh/domain/drop.malicious.invalid");

    let dom_f = by_detail("embedded domain name").expect("domain finding present");
    assert_eq!(dom_f["enrich_url"], "https://mlab.sh/domain/track.evil.tk");

    let ip6_f = by_detail("embedded IPv6 address").expect("IPv6 finding present");
    assert_eq!(ip6_f["enrich_url"], "https://mlab.sh/ip/2001:db8::dead:beef");

    let btc_f = iocs
        .iter()
        .find(|f| f["detail"].as_str().unwrap_or("").contains("Bitcoin"))
        .expect("BTC finding present");
    assert_eq!(
        btc_f["enrich_url"], "https://mlab.sh/crypto/1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2"
    );

    let eth_f = iocs
        .iter()
        .find(|f| f["detail"].as_str().unwrap_or("").contains("Ethereum"))
        .expect("ETH finding present");
    assert_eq!(
        eth_f["enrich_url"], "https://mlab.sh/crypto/0xdeadbeefcafebabe0011223344556677889900aa"
    );
}

#[test]
fn enrich_flag_off_by_default() {
    let (_, report) = scan_json("malicious-node", &[]);
    assert!(
        findings(&report).iter().all(|f| f.get("enrich_url").is_none() || f["enrich_url"].is_null()),
        "without --enrich, no enrich_url should be emitted"
    );
}

#[test]
fn html_output_is_self_contained() {
    let out = Command::new(bin())
        .arg(fixture("malicious-node"))
        .arg("--html")
        .output()
        .unwrap();
    let body = String::from_utf8_lossy(&out.stdout);
    assert!(body.starts_with("<!doctype html>"));
    assert!(body.contains("flatmap-stream"));
    assert!(!body.contains("<script src=")); // no external scripts
}
