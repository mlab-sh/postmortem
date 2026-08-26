//! `postmortem ci <platform>` — print a ready-to-commit CI pipeline.
//!
//! postmortem ships a GitHub Action, but three other platforms need the same
//! two things — install the binary, run the gate — and differ only in how they
//! ingest the report. Rather than four hand-maintained YAML files in the repo
//! that drift the first time a release URL or a flag name changes, the templates
//! are generated here: one [`INSTALL`] snippet, one place to fix.
//!
//! The generated pipeline pins the release matching the binary that printed it,
//! so a template can never point at a version that does not exist.
//!
//! ## What differs per platform
//!
//! | Platform | Report format | Ingestion |
//! |---|---|---|
//! | GitHub | SARIF | Code Scanning (the Action does this) |
//! | Azure DevOps | SARIF | the `CodeAnalysisLogs` artifact, read by the SARIF SAST Scans Tab extension |
//! | Jenkins | SARIF | Warnings NG's `sarif` parser |
//! | GitLab | its own schema | `artifacts:reports:dependency_scanning` — GitLab does **not** read SARIF |
//!
//! ## The detail that makes these actually work
//!
//! A tripped gate exits non-zero, and on every one of these platforms the
//! default is to abandon the job at that point — including the step that
//! publishes the report. That is exactly backwards: the run you most need the
//! findings from is the one that failed. So each template forces the publish to
//! happen anyway (`artifacts.when: always`, `condition: succeededOrFailed()`,
//! `post { always { … } }`).

use std::fmt;

/// A CI platform postmortem can emit a pipeline for.
#[derive(Copy, Clone, Debug, PartialEq, Eq, clap::ValueEnum)]
pub enum Platform {
    Github,
    Gitlab,
    Azure,
    Jenkins,
}

impl Platform {
    /// The conventional filename for this platform's pipeline, used in the
    /// header comment so the output says where it belongs.
    pub fn filename(self) -> &'static str {
        match self {
            Platform::Github => ".github/workflows/postmortem.yml",
            Platform::Gitlab => ".gitlab-ci.yml",
            Platform::Azure => "azure-pipelines.yml",
            Platform::Jenkins => "Jenkinsfile",
        }
    }

    /// Comment syntax — Jenkinsfile is Groovy, the rest are YAML. They happen to
    /// agree on `#`, but stating it keeps the header generation honest if a
    /// platform is added that does not.
    fn comment(self) -> &'static str {
        match self {
            Platform::Jenkins => "//",
            _ => "#",
        }
    }
}

impl fmt::Display for Platform {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Platform::Github => "github",
            Platform::Gitlab => "gitlab",
            Platform::Azure => "azure",
            Platform::Jenkins => "jenkins",
        })
    }
}

/// The one install snippet, shared by every template.
///
/// `{version}` is the tag (`v2.2.0`) and `{num}` the bare number (`2.2.0`) —
/// the release assets use both. Kept identical to the GitHub Action's install
/// step; if the release layout changes, this and `action.yml` are the two places
/// to update, and the tests below assert they agree.
const INSTALL: &str = r#"set -euo pipefail
# On a Windows runner this script runs under Git Bash, where `uname -s` reports
# MINGW64_NT-… rather than anything containing "Windows".
case "$(uname -s)-$(uname -m)" in
  Linux-x86_64)   target=x86_64-unknown-linux-gnu ;;
  Linux-aarch64)  target=aarch64-unknown-linux-gnu ;;
  Darwin-x86_64)  target=x86_64-apple-darwin ;;
  Darwin-arm64)   target=aarch64-apple-darwin ;;
  MINGW*-x86_64|MSYS*-x86_64|CYGWIN*-x86_64) target=x86_64-pc-windows-msvc ;;
  *) echo "unsupported runner $(uname -s)-$(uname -m)" >&2; exit 1 ;;
esac
case "$target" in *windows*) ext=zip ;; *) ext=tar.gz ;; esac
url="https://github.com/mlab-sh/postmortem/releases/download/{version}/postmortem-{num}-${target}.${ext}"
if [ "$ext" = zip ]; then
  curl -fsSL "$url" -o pm.zip
  # unzip exits 1 on a warning while still extracting everything.
  unzip -q pm.zip || [ "$?" -le 1 ]
  rm -f pm.zip
else
  curl -fsSL "$url" | tar xz
fi
export PATH="$PWD/postmortem-{num}-${target}:$PATH"
postmortem --version"#;

/// The install snippet with the version substituted and every line indented by
/// `indent` spaces, ready to drop into a YAML block scalar.
fn install(version: &str, indent: usize) -> String {
    let num = version.trim_start_matches('v');
    let pad = " ".repeat(indent);
    INSTALL
        .replace("{version}", version)
        .replace("{num}", num)
        .lines()
        .map(|l| {
            if l.is_empty() {
                String::new()
            } else {
                format!("{pad}{l}")
            }
        })
        .collect::<Vec<_>>()
        .join("\n")
}

/// Render the pipeline for `platform`, pinning `version`.
pub fn render(platform: Platform, version: &str) -> String {
    let c = platform.comment();
    let header = format!(
        "{c} {} — generated by postmortem {}\n\
         {c} Write this to {}, then edit the gate thresholds to taste.\n\
         {c} Regenerate with: postmortem ci {}\n",
        platform.filename(),
        env!("CARGO_PKG_VERSION"),
        platform.filename(),
        platform,
    );
    let body = match platform {
        Platform::Github => github(version),
        Platform::Gitlab => gitlab(version),
        Platform::Azure => azure(version),
        Platform::Jenkins => jenkins(version),
    };
    format!("{header}\n{body}")
}

/// GitHub already has a composite action; this is the raw-shell equivalent for
/// anyone who would rather not depend on it.
fn github(version: &str) -> String {
    format!(
        r#"name: postmortem

on: [push, pull_request]

permissions:
  contents: read
  security-events: write   # required to upload SARIF

jobs:
  supply-chain:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      # The maintained path is the action itself:
      #   - uses: mlab-sh/postmortem@{version}
      #     with: {{ online: true, vulns: true, max-high: 0 }}
      # Everything below is the same thing in plain shell.

      - name: Install postmortem
        run: |
{install}
          # Export to later steps: each `run:` is its own shell, so without
          # this the gate step below would have to download the binary again.
          echo "$PWD/postmortem-{num}-${{target}}" >> "$GITHUB_PATH"

      - name: Gate
        env:
          GITHUB_TOKEN: ${{{{ secrets.GITHUB_TOKEN }}}}
        run: |
          postmortem tree . \
            --online --vulns \
            --max-high 0 --fail-on-vuln high \
            --sarif -o postmortem.sarif

      - name: Upload SARIF
        # Runs even when the gate failed — a failing run is the one whose
        # findings you most need to see.
        if: always()
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: postmortem.sarif
"#,
        version = version,
        num = version.trim_start_matches('v'),
        install = install(version, 10),
    )
}

/// GitLab: the only platform needing the native report format.
fn gitlab(version: &str) -> String {
    format!(
        r#"stages: [test]

postmortem:
  stage: test
  image: debian:stable-slim
  before_script:
    - apt-get update -qq && apt-get install -y -qq curl ca-certificates
  script:
    # One block scalar, not one list item per line: the shell `case` below has a
    # `*)` branch, and YAML reads a sequence item starting with `*` as an alias.
    - |
{install}
    # `audit --gitlab` does both jobs in one pass: it writes the report GitLab's
    # merge-request widget reads, and its exit code is the gate.
    - |
      postmortem audit . \
        --online --vulns \
        --max-high 0 --fail-on-vuln high \
        --gitlab -o gl-dependency-scanning-report.json
  artifacts:
    # `always` is load-bearing: the gate exits non-zero on a finding, and
    # without this GitLab would discard the very report explaining why.
    when: always
    reports:
      dependency_scanning: gl-dependency-scanning-report.json
    paths:
      - gl-dependency-scanning-report.json
    expire_in: 1 week
  variables:
    GIT_DEPTH: "1"
  # --online reads $GITHUB_TOKEN for the repo-reputation lookups; without one
  # you will hit the unauthenticated GitHub rate limit on any real dependency
  # set. Add GITHUB_TOKEN as a masked CI/CD variable in the project settings —
  # it is deliberately not declared here, so an empty default cannot shadow it.
  allow_failure: false
"#,
        install = install(version, 6),
    )
}

/// Azure DevOps: SARIF in an artifact named `CodeAnalysisLogs`, which is the
/// exact name the SARIF SAST Scans Tab extension looks for.
fn azure(version: &str) -> String {
    format!(
        r#"trigger: [main]
pr: [main]

pool:
  vmImage: ubuntu-latest

steps:
  - checkout: self

  - script: |
{install}
      postmortem tree . \
        --online --vulns \
        --max-high 0 --fail-on-vuln high \
        --sarif -o "$(Build.ArtifactStagingDirectory)/CodeAnalysisLogs/postmortem.sarif"
    displayName: postmortem gate
    env:
      # Define GITHUB_TOKEN as a secret pipeline variable; --online needs it to
      # stay under the GitHub API rate limit.
      GITHUB_TOKEN: $(GITHUB_TOKEN)

  - task: PublishBuildArtifacts@1
    displayName: Publish SARIF
    # Publish even on a failed gate, otherwise the findings die with the job.
    condition: succeededOrFailed()
    inputs:
      PathtoPublish: "$(Build.ArtifactStagingDirectory)/CodeAnalysisLogs"
      # This artifact name is not arbitrary: the "SARIF SAST Scans Tab"
      # marketplace extension renders whatever it finds under CodeAnalysisLogs.
      ArtifactName: CodeAnalysisLogs
"#,
        install = install(version, 6),
    )
}

/// Jenkins: Warnings NG parses SARIF directly, so the pipeline only has to
/// produce the file and hand it over.
fn jenkins(version: &str) -> String {
    format!(
        r#"// Requires the "Warnings Next Generation" plugin for the SARIF parser.
pipeline {{
  agent any

  environment {{
    // --online needs this to stay under the GitHub API rate limit.
    GITHUB_TOKEN = credentials('postmortem-github-token')
  }}

  stages {{
    stage('postmortem') {{
      steps {{
        sh '''
{install}
          postmortem tree . \\
            --online --vulns \\
            --max-high 0 --fail-on-vuln high \\
            --sarif -o postmortem.sarif
        '''
      }}
    }}
  }}

  post {{
    // `always`, so a tripped gate still publishes what tripped it.
    always {{
      recordIssues(tools: [sarif(pattern: 'postmortem.sarif')])
      archiveArtifacts artifacts: 'postmortem.sarif', allowEmptyArchive: true
    }}
  }}
}}
"#,
        install = install(version, 10),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    const ALL: [Platform; 4] = [
        Platform::Github,
        Platform::Gitlab,
        Platform::Azure,
        Platform::Jenkins,
    ];

    #[test]
    fn every_template_installs_the_pinned_version() {
        // The whole reason these are generated rather than committed: a template
        // that points at a release that does not exist is worse than none.
        for p in ALL {
            let out = render(p, "v9.9.9");
            assert!(
                out.contains("releases/download/v9.9.9/postmortem-9.9.9-"),
                "{p} does not pin the version"
            );
            assert!(
                !out.contains("{version}"),
                "{p} left a placeholder unfilled"
            );
            assert!(!out.contains("{num}"), "{p} left a placeholder unfilled");
        }
    }

    #[test]
    fn every_template_actually_runs_postmortem_with_a_gate() {
        for p in ALL {
            let out = render(p, "v1.0.0");
            assert!(out.contains("postmortem tree .") || out.contains("postmortem audit ."));
            assert!(out.contains("--max-high"), "{p} has no threshold");
            assert!(out.contains("--vulns"), "{p} does not scan for vulns");
        }
    }

    #[test]
    fn only_gitlab_uses_the_gitlab_format_and_it_never_uses_sarif() {
        // GitLab does not read SARIF. Emitting SARIF there would produce a green
        // pipeline with an empty security widget — the worst failure mode.
        let gl = render(Platform::Gitlab, "v1.0.0");
        assert!(gl.contains("--gitlab"));
        assert!(gl.contains("gl-dependency-scanning-report.json"));
        assert!(gl.contains("dependency_scanning:"));
        assert!(!gl.contains("--sarif"), "GitLab cannot consume SARIF");

        for p in [Platform::Github, Platform::Azure, Platform::Jenkins] {
            let out = render(p, "v1.0.0");
            assert!(out.contains("--sarif"), "{p} should use SARIF");
            assert!(
                !out.contains("--gitlab"),
                "{p} should not use the GitLab format"
            );
        }
    }

    #[test]
    fn the_report_is_published_even_when_the_gate_fails() {
        // Each platform's own spelling of "run this step anyway". Without it the
        // failing run — the one that matters — publishes nothing.
        assert!(render(Platform::Github, "v1.0.0").contains("if: always()"));
        assert!(render(Platform::Gitlab, "v1.0.0").contains("when: always"));
        assert!(render(Platform::Azure, "v1.0.0").contains("succeededOrFailed()"));
        assert!(render(Platform::Jenkins, "v1.0.0").contains("always {"));
    }

    #[test]
    fn azure_publishes_under_the_artifact_name_its_extension_expects() {
        // "CodeAnalysisLogs" is a fixed contract with the SARIF SAST Scans Tab
        // extension; any other name renders nothing.
        let az = render(Platform::Azure, "v1.0.0");
        assert!(az.contains("ArtifactName: CodeAnalysisLogs"));
    }

    #[test]
    fn jenkins_hands_the_sarif_to_the_warnings_ng_parser() {
        let j = render(Platform::Jenkins, "v1.0.0");
        assert!(j.contains("recordIssues(tools: [sarif(pattern: 'postmortem.sarif')])"));
    }

    #[test]
    fn the_header_says_where_the_file_goes_and_how_to_regenerate_it() {
        for p in ALL {
            let out = render(p, "v1.0.0");
            let first = out.lines().next().unwrap();
            assert!(
                first.starts_with(p.comment()),
                "{p} header is not a comment"
            );
            assert!(out.contains(p.filename()));
            assert!(out.contains(&format!("postmortem ci {p}")));
        }
    }

    #[test]
    fn the_install_snippet_is_indented_into_its_block_not_left_flush() {
        // A YAML block scalar with a flush-left line is a parse error, so this
        // is the difference between a template that works and one that does not.
        for (p, indent) in [
            (Platform::Github, "          "),
            (Platform::Azure, "      "),
            (Platform::Jenkins, "          "),
        ] {
            let out = render(p, "v1.0.0");
            assert!(
                out.contains(&format!("{indent}set -euo pipefail")),
                "{p} install block is not indented to {}",
                indent.len()
            );
        }
        assert!(render(Platform::Gitlab, "v1.0.0").contains("      set -euo pipefail"));
    }

    #[test]
    fn the_install_snippet_matches_the_github_action() {
        // These are the two copies of the release layout. If action.yml changes
        // its URL shape, this catches the drift rather than a user's failing CI.
        let action = include_str!("../action.yml");
        for target in [
            "x86_64-unknown-linux-gnu",
            "aarch64-unknown-linux-gnu",
            "x86_64-apple-darwin",
            "aarch64-apple-darwin",
            "x86_64-pc-windows-msvc",
        ] {
            assert!(action.contains(target), "action.yml lost target {target}");
            assert!(INSTALL.contains(target), "INSTALL lost target {target}");
        }
        assert!(
            action.contains("releases/download/${VERSION}/postmortem-${num}-${target}.${ext}"),
            "action.yml release URL changed — update INSTALL to match"
        );
        // Windows ships a zip; everything else a tarball. Both copies have to
        // know that, or a Windows runner downloads an archive that is not there.
        for copy in [action, INSTALL] {
            assert!(copy.contains("ext=zip"), "a copy lost the Windows archive form");
            assert!(copy.contains("ext=tar.gz"), "a copy lost the tarball form");
        }
    }

    #[test]
    fn the_templates_name_the_token_variable_the_code_actually_reads() {
        // `settings` falls back to $GITHUB_TOKEN. A template inventing its own
        // name would leave --online unauthenticated and rate-limited, with no
        // error to explain why the reputation data went missing.
        let settings = include_str!("settings.rs");
        assert!(settings.contains(r#"var("GITHUB_TOKEN")"#));
        for p in ALL {
            let out = render(p, "v1.0.0");
            assert!(out.contains("GITHUB_TOKEN"), "{p} never mentions the token");
            assert!(
                !out.contains("POSTMORTEM_GITHUB_TOKEN"),
                "{p} uses a variable name nothing reads"
            );
        }
    }

    #[test]
    fn the_github_template_installs_once_not_once_per_step() {
        // Each `run:` is a separate shell, so the binary is put on $GITHUB_PATH
        // rather than downloaded again in the gate step.
        let gh = render(Platform::Github, "v1.0.0");
        assert_eq!(gh.matches("releases/download").count(), 1);
        assert!(gh.contains(r#">> "$GITHUB_PATH""#));
    }

    #[test]
    fn yaml_templates_actually_parse() {
        // Not a structural approximation — a real parse. The first version of
        // the GitLab template emitted the install snippet as one sequence item
        // per line, which turned the shell `case`'s `*)` branch into a YAML
        // alias and made the whole pipeline unloadable. A "no tabs" check
        // passed it happily; only parsing catches that class of bug.
        for p in [Platform::Github, Platform::Gitlab, Platform::Azure] {
            let out = render(p, "v1.0.0");
            let parsed: Result<serde_yaml::Value, _> = serde_yaml::from_str(&out);
            assert!(parsed.is_ok(), "{p} is not valid YAML: {:?}", parsed.err());
            assert!(
                parsed.unwrap().is_mapping(),
                "{p} did not parse to a mapping"
            );
        }
    }

    #[test]
    fn the_gitlab_job_declares_the_report_where_gitlab_looks_for_it() {
        // Verified against the parsed document rather than a substring: the
        // path under artifacts.reports.dependency_scanning is the contract, and
        // a typo there yields a green pipeline with an empty widget.
        let doc: serde_yaml::Value =
            serde_yaml::from_str(&render(Platform::Gitlab, "v1.0.0")).unwrap();
        let job = &doc["postmortem"];
        assert_eq!(
            job["artifacts"]["reports"]["dependency_scanning"]
                .as_str()
                .unwrap(),
            "gl-dependency-scanning-report.json"
        );
        assert_eq!(job["artifacts"]["when"].as_str().unwrap(), "always");
        // And the script must actually write to that same path.
        let script = serde_yaml::to_string(&job["script"]).unwrap();
        assert!(script.contains("gl-dependency-scanning-report.json"));
    }

    #[test]
    fn azure_publishes_the_directory_the_scan_writes_to() {
        // Same class of contract: the SARIF is written under
        // CodeAnalysisLogs and the publish task must point at that directory.
        let doc: serde_yaml::Value =
            serde_yaml::from_str(&render(Platform::Azure, "v1.0.0")).unwrap();
        let steps = doc["steps"].as_sequence().unwrap();
        let script = serde_yaml::to_string(&steps[1]).unwrap();
        let publish = serde_yaml::to_string(&steps[2]).unwrap();
        assert!(script.contains("CodeAnalysisLogs/postmortem.sarif"));
        assert!(publish.contains("CodeAnalysisLogs"));
    }
}
