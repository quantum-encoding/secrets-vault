//! Google Secret Manager backend via the `gcloud` CLI.
//!
//! No heavy SDK/HTTP deps — reuses the user's existing gcloud auth (and whatever
//! account/ADC they've configured). Secret VALUES transit gcloud's stdin/stdout,
//! never argv (so they never appear in `ps`). The acting identity needs
//! `roles/secretmanager.secretAccessor` (read) + `secretVersionAdder` (write) on
//! the target project; otherwise gcloud's permission error is surfaced verbatim.

use std::io::Write;
use std::process::{Command, Stdio};

pub struct GsmConfig {
    pub project: String,
    /// Override the active gcloud account (e.g. your user identity, not a SA).
    pub account: Option<String>,
    /// Impersonate a service account that holds the Secret Manager roles.
    pub impersonate: Option<String>,
}

impl GsmConfig {
    fn base(&self, verb: &[&str]) -> Vec<String> {
        let mut a: Vec<String> = vec!["secrets".into()];
        a.extend(verb.iter().map(|s| s.to_string()));
        a.push(format!("--project={}", self.project));
        a.push("--quiet".into());
        if let Some(ac) = &self.account {
            a.push(format!("--account={ac}"));
        }
        if let Some(im) = &self.impersonate {
            a.push(format!("--impersonate-service-account={im}"));
        }
        a
    }
}

/// Read the latest version of `name`. Returns the raw payload (no modification).
pub fn access(cfg: &GsmConfig, name: &str) -> Result<String, String> {
    let args = cfg.base(&["versions", "access", "latest", &format!("--secret={name}")]);
    let out = Command::new("gcloud")
        .args(&args)
        .output()
        .map_err(|e| format!("gcloud not runnable: {e}"))?;
    if out.status.success() {
        Ok(String::from_utf8_lossy(&out.stdout).into_owned())
    } else {
        Err(String::from_utf8_lossy(&out.stderr).trim().to_string())
    }
}

/// Add a new version of `name` (value via stdin). Creates the secret first if it
/// doesn't exist yet (idempotent — a create failure is ignored, the add reports
/// the real error).
pub fn add(cfg: &GsmConfig, name: &str, value: &str) -> Result<(), String> {
    // Idempotent create — ignore "already exists".
    let create = cfg.base(&["create", name, "--replication-policy=automatic"]);
    let _ = Command::new("gcloud")
        .args(&create)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();

    let args = cfg.base(&["versions", "add", name, "--data-file=-"]);
    let mut child = Command::new("gcloud")
        .args(&args)
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| format!("gcloud not runnable: {e}"))?;
    if let Some(mut stdin) = child.stdin.take() {
        stdin
            .write_all(value.as_bytes())
            .map_err(|e| format!("writing secret to gcloud stdin: {e}"))?;
    }
    let out = child
        .wait_with_output()
        .map_err(|e| format!("waiting on gcloud: {e}"))?;
    if out.status.success() {
        Ok(())
    } else {
        Err(String::from_utf8_lossy(&out.stderr).trim().to_string())
    }
}
