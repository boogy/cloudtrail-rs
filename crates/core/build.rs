//! Bakes version + commit provenance into the binary at compile time.
//!
//! Resolution order: CI-injected `CLOUDTRAIL_RS_VERSION`/`CLOUDTRAIL_RS_GIT_SHA`
//! (GitHub's checkout is shallow and tag-less, so `git describe` cannot be
//! trusted in CI), then local git, then the crate semver.
//!
//! No build timestamp is captured, so a commit builds reproducibly.

use std::process::Command;

/// Runs a git subcommand, returning trimmed stdout only on success.
fn git(args: &[&str]) -> Option<String> {
    let out = Command::new("git").args(args).output().ok()?;
    if !out.status.success() {
        return None;
    }
    let s = String::from_utf8(out.stdout).ok()?.trim().to_string();
    (!s.is_empty()).then_some(s)
}

/// Non-empty env var, or `None`.
fn env_opt(key: &str) -> Option<String> {
    std::env::var(key).ok().filter(|s| !s.is_empty())
}

fn main() {
    let version = env_opt("CLOUDTRAIL_RS_VERSION")
        .or_else(|| git(&["describe", "--tags", "--always", "--dirty"]))
        .unwrap_or_else(|| {
            format!(
                "v{}",
                std::env::var("CARGO_PKG_VERSION").unwrap_or_default()
            )
        });

    // Normalize to a 12-char short SHA — `github.sha` is the full 40 chars,
    // `git rev-parse --short=12` already 12.
    let sha: String = env_opt("CLOUDTRAIL_RS_GIT_SHA")
        .or_else(|| git(&["rev-parse", "--short=12", "HEAD"]))
        .unwrap_or_else(|| "unknown".to_string())
        .chars()
        .take(12)
        .collect();

    println!("cargo:rustc-env=CLOUDTRAIL_RS_BUILD_VERSION={version}");
    println!("cargo:rustc-env=CLOUDTRAIL_RS_BUILD_GIT_SHA={sha}");
    println!("cargo:rustc-env=CLOUDTRAIL_RS_BUILD_LONG={version} ({sha})");

    // `--git-path HEAD` resolves correctly inside a git worktree; the printed
    // path is relative to this crate dir, which is what cargo expects.
    println!("cargo:rerun-if-env-changed=CLOUDTRAIL_RS_VERSION");
    println!("cargo:rerun-if-env-changed=CLOUDTRAIL_RS_GIT_SHA");
    if let Some(head) = git(&["rev-parse", "--git-path", "HEAD"]) {
        println!("cargo:rerun-if-changed={head}");
    }
}
