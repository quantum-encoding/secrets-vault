//! Encrypted, biometric-gated metadata registry.
//!
//! Stores NO secret values — only the access-control map: which logical projects
//! exist (→ their GCP project id + key names), and which agent is granted which
//! project at what scope. Encrypted at rest (reuses the audited QVLT crypto via
//! `encrypt_blob`) and unlocked by the same biometric Keychain passphrase as the
//! vault. So a background agent can't even learn what other projects exist —
//! reading the map requires your fingerprint.
//!
//! NOTE on agent identity: `resolve_agent` walks the process ancestry, which a
//! same-user adversary can spoof (rename/re-parent). It is therefore a SOFT layer
//! — for accident-prevention, audit, and informed prompts — NOT a hard boundary.
//! The hard boundary is the Touch ID tap.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

use secrets_vault::{decrypt_blob, encrypt_blob};

#[derive(Default, Serialize, Deserialize)]
pub struct Registry {
    /// logical project name → metadata
    #[serde(default)]
    pub projects: BTreeMap<String, ProjectMeta>,
    /// agent id → (project name → grant)
    #[serde(default)]
    pub grants: BTreeMap<String, BTreeMap<String, Grant>>,
}

#[derive(Default, Serialize, Deserialize)]
pub struct ProjectMeta {
    pub gcp_project: String,
    #[serde(default)]
    pub keys: Vec<String>,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct Grant {
    pub scope: Scope,
}

#[derive(Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Scope {
    /// Persistent until explicitly revoked.
    Always,
    /// Valid until this Unix epoch second (a "session" grant).
    Session { expires: u64 },
}

pub fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

impl Registry {
    pub fn path(dir: &Path) -> PathBuf {
        dir.join("registry.enc")
    }

    /// Load + decrypt (or a fresh empty registry if none exists yet).
    pub fn load(dir: &Path, passphrase: &str) -> Result<Self, String> {
        match std::fs::read(Self::path(dir)) {
            Ok(data) => {
                let plain =
                    decrypt_blob(&data, passphrase).map_err(|e| format!("registry decrypt: {e}"))?;
                serde_json::from_slice(&plain).map_err(|e| format!("registry parse: {e}"))
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Registry::default()),
            Err(e) => Err(format!("reading registry: {e}")),
        }
    }

    /// Encrypt + write atomically-ish with 0700 dir / 0600 file.
    pub fn save(&self, dir: &Path, passphrase: &str) -> Result<(), String> {
        let json = serde_json::to_vec_pretty(self).map_err(|e| format!("serialize: {e}"))?;
        let enc = encrypt_blob(&json, passphrase).map_err(|e| format!("encrypt: {e}"))?;
        std::fs::create_dir_all(dir).ok();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700)).ok();
        }
        let path = Self::path(dir);
        std::fs::write(&path, &enc).map_err(|e| format!("writing registry: {e}"))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).ok();
        }
        Ok(())
    }

    /// The valid grant for (agent, project) at `now`, treating expired sessions
    /// as absent.
    pub fn grant_for(&self, agent: &str, project: &str, now: u64) -> Option<&Grant> {
        let g = self.grants.get(agent)?.get(project)?;
        match g.scope {
            Scope::Always => Some(g),
            Scope::Session { expires } if expires > now => Some(g),
            _ => None,
        }
    }

    pub fn set_grant(&mut self, agent: &str, project: &str, scope: Scope) {
        self.grants
            .entry(agent.to_string())
            .or_default()
            .insert(project.to_string(), Grant { scope });
    }

    pub fn revoke(&mut self, agent: &str, project: &str) -> bool {
        if let Some(m) = self.grants.get_mut(agent) {
            let removed = m.remove(project).is_some();
            if m.is_empty() {
                self.grants.remove(agent);
            }
            removed
        } else {
            false
        }
    }
}

// ── Agent resolution (process ancestry; SOFT) ──

/// Agent CLIs we recognize by process name anywhere in the ancestry chain.
pub const KNOWN_AGENTS: &[&str] = &[
    "claude", "grok", "codex", "cursor", "aider", "copilot", "gemini", "cody", "continue",
];

/// Resolve the agent driving us by walking the parent-process chain. Returns the
/// recognized agent id, or None when run by a plain shell / a human.
#[cfg(target_os = "macos")]
pub fn resolve_agent() -> Option<String> {
    let mut pid = std::process::id() as i32;
    for _ in 0..24 {
        let (ppid, comm) = proc_info(pid)?;
        let lc = comm.to_lowercase();
        if let Some(a) = KNOWN_AGENTS.iter().find(|a| lc.contains(**a)) {
            return Some((*a).to_string());
        }
        if ppid <= 1 {
            break;
        }
        pid = ppid;
    }
    None
}

#[cfg(target_os = "macos")]
fn proc_info(pid: i32) -> Option<(i32, String)> {
    let mut info: libc::proc_bsdinfo = unsafe { std::mem::zeroed() };
    let size = std::mem::size_of::<libc::proc_bsdinfo>() as libc::c_int;
    let n = unsafe {
        libc::proc_pidinfo(
            pid,
            libc::PROC_PIDTBSDINFO,
            0,
            &mut info as *mut _ as *mut libc::c_void,
            size,
        )
    };
    if n <= 0 {
        return None;
    }
    let cstr = |buf: &[libc::c_char]| -> String {
        buf.iter().take_while(|&&c| c != 0).map(|&c| c as u8 as char).collect()
    };
    let name = {
        let full = cstr(&info.pbi_name); // up to 32 chars
        if full.is_empty() {
            cstr(&info.pbi_comm) // 16-char fallback
        } else {
            full
        }
    };
    Some((info.pbi_ppid as i32, name))
}

#[cfg(not(target_os = "macos"))]
pub fn resolve_agent() -> Option<String> {
    None
}
