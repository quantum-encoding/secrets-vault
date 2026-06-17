//! Pluggable secret backends.
//!
//! The local biometric vault is the zero-config default. Any external secret
//! manager (AWS, Vault, 1Password, Doppler, …) is driven by a GENERIC templated
//! command: `{name}` in each arg is replaced with the secret name, read values
//! come back on the child's **stdout**, and write values are piped to the child's
//! **stdin** — so a secret value NEVER appears in `argv` (where `ps` would leak it).
//! This means a new vendor needs no Rust change: a `[backend]` block in
//! `.secrets.toml` with the right `read`/`write` command is enough.
//!
//! Google Secret Manager keeps its own dedicated path (`gsm.rs`) for backward
//! compatibility with existing `[gsm]` blocks.

use std::io::Write;
use std::process::{Command, Stdio};

use crate::gsm::GsmConfig;

/// Where a project's secret values come from.
pub enum Backend {
    /// Local AES-256-GCM vault — values keyed as `<project>/<name>` (handled by the
    /// in-process decrypt path, not here).
    Vault,
    /// Google Secret Manager via `gcloud` (the original verified backend).
    Gsm(GsmConfig),
    /// Any external manager via a templated CLI (the generic escape hatch).
    Command(CommandBackend),
}

/// A backend defined entirely by external commands. Read prints the value to
/// stdout; write consumes it from stdin. Both substitute `{name}`.
pub struct CommandBackend {
    /// Human label for log lines, e.g. "aws" or "1password".
    pub kind: String,
    /// Read template; `read[0]` is the program. Value expected on stdout.
    pub read: Vec<String>,
    /// Write template (program + args). Value is piped to the program's stdin.
    /// `None` ⇒ the backend is read-only (writes error out clearly).
    pub write: Option<Vec<String>>,
    /// Strip exactly one trailing '\n' from read output (most CLIs add one).
    /// Set false for secrets whose exact trailing bytes matter.
    pub strip_trailing_newline: bool,
}

fn subst(tmpl: &[String], name: &str) -> Vec<String> {
    tmpl.iter().map(|a| a.replace("{name}", name)).collect()
}

impl CommandBackend {
    /// Run the read command; return its stdout as the secret value.
    pub fn access(&self, name: &str) -> Result<String, String> {
        let argv = subst(&self.read, name);
        let (prog, args) = argv
            .split_first()
            .ok_or_else(|| "backend `read` command is empty".to_string())?;
        let out = Command::new(prog)
            .args(args)
            .output()
            .map_err(|e| format!("`{prog}` not runnable: {e}"))?;
        if out.status.success() {
            let mut v = String::from_utf8_lossy(&out.stdout).into_owned();
            if self.strip_trailing_newline {
                if let Some(s) = v.strip_suffix('\n') {
                    v = s.to_string();
                }
            }
            Ok(v)
        } else {
            Err(String::from_utf8_lossy(&out.stderr).trim().to_string())
        }
    }

    /// Run the write command, feeding `value` on stdin (never argv).
    pub fn add(&self, name: &str, value: &str) -> Result<(), String> {
        let tmpl = self.write.as_ref().ok_or_else(|| {
            format!("backend `{}` is read-only (no `write` command configured)", self.kind)
        })?;
        let argv = subst(tmpl, name);
        let (prog, args) = argv
            .split_first()
            .ok_or_else(|| "backend `write` command is empty".to_string())?;
        let mut child = Command::new(prog)
            .args(args)
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|e| format!("`{prog}` not runnable: {e}"))?;
        if let Some(mut stdin) = child.stdin.take() {
            stdin
                .write_all(value.as_bytes())
                .map_err(|e| format!("writing secret to `{prog}` stdin: {e}"))?;
            // stdin dropped here → EOF, so the child sees end-of-input.
        }
        let out = child
            .wait_with_output()
            .map_err(|e| format!("waiting on `{prog}`: {e}"))?;
        if out.status.success() {
            Ok(())
        } else {
            Err(String::from_utf8_lossy(&out.stderr).trim().to_string())
        }
    }
}

impl Backend {
    /// Short label for log lines.
    pub fn label(&self) -> String {
        match self {
            Backend::Vault => "local vault".into(),
            Backend::Gsm(cfg) => format!("Google Secret Manager ({})", cfg.project),
            Backend::Command(c) => c.kind.clone(),
        }
    }

    /// True for any non-local backend (values fetched via an external CLI).
    pub fn is_external(&self) -> bool {
        !matches!(self, Backend::Vault)
    }

    /// Fetch a value. Not valid for `Vault` (use the in-process decrypt path).
    /// External arms return the final value (trailing newline already handled).
    pub fn access(&self, name: &str) -> Result<String, String> {
        match self {
            Backend::Vault => Err("local vault values are read via the in-process decrypt path".into()),
            // Mirror the historical single-trailing-newline strip for GSM.
            Backend::Gsm(cfg) => crate::gsm::access(cfg, name)
                .map(|v| v.strip_suffix('\n').map(str::to_string).unwrap_or(v)),
            Backend::Command(c) => c.access(name),
        }
    }

    /// Write a value. Not valid for `Vault` (use the local vault writer).
    pub fn add(&self, name: &str, value: &str) -> Result<(), String> {
        match self {
            Backend::Vault => Err("local vault values are written via the in-process vault writer".into()),
            Backend::Gsm(cfg) => crate::gsm::add(cfg, name, value),
            Backend::Command(c) => c.add(name, value),
        }
    }
}

/// Parse a `[backend]` TOML table into a `Backend`. Recognized `kind`s:
/// - `"vault"` (or absent) → local vault.
/// - `"gsm"` → Google Secret Manager (`project` / `account` / `impersonate`).
/// - `"command"` → generic templated CLI (`read` required, `write` optional).
///
/// `account`/`impersonate` for gsm fall back to the same env vars as `[gsm]`.
pub fn from_table(t: &toml::Table) -> Result<Backend, String> {
    let kind = t.get("kind").and_then(|k| k.as_str()).unwrap_or("vault");
    match kind {
        "vault" => Ok(Backend::Vault),
        "gsm" => {
            let project = t
                .get("project")
                .and_then(|p| p.as_str())
                .ok_or_else(|| "[backend] kind=\"gsm\" needs `project`".to_string())?
                .to_string();
            Ok(Backend::Gsm(GsmConfig {
                project,
                account: t
                    .get("account")
                    .and_then(|a| a.as_str())
                    .map(String::from)
                    .or_else(|| std::env::var("SECRETS_GSM_ACCOUNT").ok()),
                impersonate: t
                    .get("impersonate")
                    .and_then(|a| a.as_str())
                    .map(String::from)
                    .or_else(|| std::env::var("SECRETS_GSM_IMPERSONATE").ok()),
            }))
        }
        "command" => {
            let read = string_array(t.get("read"))
                .ok_or_else(|| "[backend] kind=\"command\" needs `read = [...]`".to_string())?;
            if read.is_empty() {
                return Err("[backend] `read` must name a program".into());
            }
            let write = string_array(t.get("write"));
            let strip_trailing_newline = t
                .get("strip_trailing_newline")
                .and_then(|b| b.as_bool())
                .unwrap_or(true);
            Ok(Backend::Command(CommandBackend {
                kind: t.get("name").and_then(|n| n.as_str()).unwrap_or("command").to_string(),
                read,
                write,
                strip_trailing_newline,
            }))
        }
        other => Err(format!("unknown [backend] kind \"{other}\" (expected vault, gsm, or command)")),
    }
}

/// Coerce a TOML value into `Vec<String>` if it's an array of strings.
fn string_array(v: Option<&toml::Value>) -> Option<Vec<String>> {
    v.and_then(|a| a.as_array()).map(|arr| {
        arr.iter()
            .filter_map(|x| x.as_str().map(str::to_string))
            .collect()
    })
}
