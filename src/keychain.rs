//! Biometric-gated Keychain storage for the vault master passphrase.
//!
//! The passphrase lives in a generic-password Keychain item in the team-prefixed
//! access group from `secrets.entitlements`, protected by a `SecAccessControl`
//! requiring biometry (`BiometryCurrentSet`). So only THIS signed binary can
//! reach it, and only after a Touch ID prompt — a background `evilpackage`
//! running `security find-generic-password` gets nothing. This replaces the
//! `SECRETS_PASSPHRASE`-in-env path (which every child process could inherit).
//!
//! macOS only; on other platforms the calls are no-ops that report unavailable.

#[cfg(target_os = "macos")]
mod imp {
    use core_foundation::base::{CFType, TCFType};
    use core_foundation::boolean::CFBoolean;
    use core_foundation::data::CFData;
    use core_foundation::dictionary::CFDictionary;
    use core_foundation::number::CFNumber;
    use core_foundation::string::CFString;
    use core_foundation_sys::base::CFTypeRef;
    use core_foundation_sys::data::CFDataRef;
    use core_foundation_sys::string::CFStringRef;
    use security_framework_sys::access_control::{
        kSecAccessControlBiometryCurrentSet, kSecAccessControlUserPresence,
        kSecAttrAccessibleWhenUnlockedThisDeviceOnly, SecAccessControlCreateWithFlags,
    };
    use security_framework_sys::base::{errSecItemNotFound, errSecSuccess};
    use security_framework_sys::item::{
        kSecAttrAccessControl, kSecAttrAccessGroup, kSecAttrAccount, kSecAttrService, kSecClass,
        kSecClassGenericPassword, kSecMatchLimit, kSecReturnAttributes, kSecReturnData,
        kSecUseAuthenticationContext, kSecUseDataProtectionKeychain, kSecValueData,
    };
    use security_framework_sys::keychain_item::{SecItemAdd, SecItemCopyMatching, SecItemDelete};
    use std::os::raw::{c_char, c_void};
    use std::ptr;

    const SERVICE: &str = "io.quantumencoding.secrets";
    const ACCOUNT: &str = "vault-master";
    /// The write-only inbox's age identity (AGENT_SECRET_LIFECYCLE.md). Same item
    /// family / access group as the master, distinct account → opened only at merge.
    const INBOX_ACCOUNT: &str = "inbox-identity";
    const ACCESS_GROUP: &str = "VLK8CVU5H3.io.quantumencoding.secrets";

    // Link LocalAuthentication so the LAContext class is registered at runtime
    // (used only by strict mode). The objc runtime symbols come from libobjc.
    #[link(name = "LocalAuthentication", kind = "framework")]
    #[link(name = "objc")]
    extern "C" {
        fn objc_getClass(name: *const c_char) -> *mut c_void;
        fn sel_registerName(name: *const c_char) -> *mut c_void;
        fn objc_msgSend();
    }

    // `kSecUseOperationPrompt` sets the custom reason line the OS Touch ID sheet
    // shows for a keychain read. security-framework-sys doesn't re-export it, but
    // it's a stable Security.framework CFString symbol — declare it directly.
    // Deprecated by Apple in favor of pre-evaluating an LAContext, but still honored
    // and works mode-independently (no context required), which is what we want so
    // the enriched prompt surfaces on BOTH strict and non-strict reads.
    #[link(name = "Security", kind = "framework")]
    extern "C" {
        static kSecUseOperationPrompt: CFStringRef;
    }

    /// Build an `LAContext` with `touchIDAuthenticationAllowableReuseDuration = reuse`.
    /// `0.0` forces a FRESH Touch ID tap with no grace (strict reads). A non-zero
    /// value lets back-to-back reads under the SAME context share one tap — used by
    /// `read_accounts` so `inbox merge` opens the identity + the vault master with a
    /// single prompt. Handed to `SecItemCopyMatching` via `kSecUseAuthenticationContext`.
    /// Raw objc runtime (no extra crate); `objc_msgSend` is transmuted to the exact
    /// typed signature per the documented calling convention.
    fn auth_context(reuse: f64) -> Option<CFType> {
        unsafe {
            let cls = objc_getClass(b"LAContext\0".as_ptr() as *const c_char);
            if cls.is_null() {
                return None;
            }
            let sel_new = sel_registerName(b"new\0".as_ptr() as *const c_char);
            let new_fn: extern "C" fn(*mut c_void, *mut c_void) -> *mut c_void =
                std::mem::transmute(objc_msgSend as *const ());
            let obj = new_fn(cls, sel_new);
            if obj.is_null() {
                return None;
            }
            let sel_set = sel_registerName(
                b"setTouchIDAuthenticationAllowableReuseDuration:\0".as_ptr() as *const c_char,
            );
            let set_fn: extern "C" fn(*mut c_void, *mut c_void, f64) =
                std::mem::transmute(objc_msgSend as *const ());
            set_fn(obj, sel_set, reuse);
            // `new` returned +1; wrap create-rule so CFType's Drop balances it.
            Some(CFType::wrap_under_create_rule(obj as CFTypeRef))
        }
    }

    /// Borrow an extern CFStringRef constant as a CFType (for dictionary keys/values).
    unsafe fn cfs(raw: CFStringRef) -> CFType {
        CFString::wrap_under_get_rule(raw).as_CFType()
    }

    /// The tuple identifying our item. Biometric SecAccessControl requires the
    /// data-protection keychain + a keychain-access-group entitlement (proven by
    /// elimination: without it, SecItemAdd → errSecMissingEntitlement -34018). The
    /// team-prefixed group is a profile-free entitlement, so Developer ID signing
    /// alone satisfies it — no provisioning profile needed.
    fn base_query(account: &str) -> Vec<(CFType, CFType)> {
        unsafe {
            vec![
                (cfs(kSecClass), cfs(kSecClassGenericPassword)),
                (cfs(kSecAttrService), CFString::new(SERVICE).as_CFType()),
                (cfs(kSecAttrAccount), CFString::new(account).as_CFType()),
                (cfs(kSecAttrAccessGroup), CFString::new(ACCESS_GROUP).as_CFType()),
                (cfs(kSecUseDataProtectionKeychain), CFBoolean::true_value().as_CFType()),
            ]
        }
    }

    fn delete_account(account: &str) -> Result<(), String> {
        let dict = CFDictionary::from_CFType_pairs(&base_query(account));
        let status = unsafe { SecItemDelete(dict.as_concrete_TypeRef()) };
        if status == errSecSuccess || status == errSecItemNotFound {
            Ok(())
        } else {
            Err(format!("SecItemDelete failed (OSStatus {status})"))
        }
    }

    /// Store a secret string under `account`. `strict` selects the ACL:
    /// - false → `UserPresence`: biometry OR watch OR device passcode; honors the
    ///   system Touch ID reuse grace (convenient: tap once, a burst of reads flow).
    /// - true  → `BiometryCurrentSet`: enrolled biometry ONLY (no watch/passcode
    ///   fallback) and self-invalidates if the fingerprint set changes.
    fn store_account(account: &str, secret: &str, strict: bool) -> Result<(), String> {
        let _ = delete_account(account); // replace any existing item

        let flags = if strict {
            kSecAccessControlBiometryCurrentSet
        } else {
            kSecAccessControlUserPresence
        };
        let ac = unsafe {
            let ac = SecAccessControlCreateWithFlags(
                ptr::null(),
                kSecAttrAccessibleWhenUnlockedThisDeviceOnly as CFTypeRef,
                flags,
                ptr::null_mut(),
            );
            if ac.is_null() {
                return Err("SecAccessControlCreateWithFlags returned null".into());
            }
            CFType::wrap_under_create_rule(ac as CFTypeRef)
        };

        let data = CFData::from_buffer(secret.as_bytes());
        let mut pairs = base_query(account);
        pairs.push((unsafe { cfs(kSecAttrAccessControl) }, ac));
        pairs.push((unsafe { cfs(kSecValueData) }, data.as_CFType()));

        let dict = CFDictionary::from_CFType_pairs(&pairs);
        let status = unsafe { SecItemAdd(dict.as_concrete_TypeRef(), ptr::null_mut()) };
        if status == errSecSuccess {
            Ok(())
        } else {
            Err(format!("SecItemAdd failed (OSStatus {status})"))
        }
    }

    /// Read one account's secret, attaching an optional shared auth context. The
    /// `_ctx` must outlive the call; pass it in so several reads can share one tap.
    fn read_account_with(
        account: &str,
        ctx: Option<&CFType>,
        prompt: Option<&str>,
    ) -> Result<Option<String>, String> {
        let mut pairs = base_query(account);
        pairs.push((unsafe { cfs(kSecReturnData) }, CFBoolean::true_value().as_CFType()));
        // kSecMatchLimit accepts a count CFNumber (the crate doesn't export the
        // kSecMatchLimitOne string constant).
        pairs.push((unsafe { cfs(kSecMatchLimit) }, CFNumber::from(1i64).as_CFType()));
        if let Some(ctx) = ctx {
            pairs.push((unsafe { cfs(kSecUseAuthenticationContext) }, ctx.clone()));
        }
        // Custom reason line on the OS Touch ID sheet — "read DATABASE_URL for
        // 'promeasure' (agent claude)…" instead of the generic system default.
        if let Some(prompt) = prompt.filter(|p| !p.is_empty()) {
            pairs.push((
                unsafe { cfs(kSecUseOperationPrompt) },
                CFString::new(prompt).as_CFType(),
            ));
        }

        let dict = CFDictionary::from_CFType_pairs(&pairs);
        let mut result: CFTypeRef = ptr::null();
        let status = unsafe { SecItemCopyMatching(dict.as_concrete_TypeRef(), &mut result) };

        if status == errSecItemNotFound {
            return Ok(None);
        }
        if status != errSecSuccess {
            return Err(format!("SecItemCopyMatching failed (OSStatus {status})"));
        }
        if result.is_null() {
            return Ok(None);
        }
        let data = unsafe { CFData::wrap_under_create_rule(result as CFDataRef) };
        String::from_utf8(data.bytes().to_vec())
            .map(Some)
            .map_err(|_| "keychain value is not valid UTF-8".into())
    }

    pub fn delete() -> Result<(), String> {
        delete_account(ACCOUNT)
    }

    /// Store the vault master passphrase (account `vault-master`).
    pub fn store(passphrase: &str, strict: bool) -> Result<(), String> {
        store_account(ACCOUNT, passphrase, strict)
    }

    /// Read the master passphrase, triggering the Touch ID prompt. Ok(None) = not
    /// unlocked. When `strict`, attach a zero-reuse `LAContext` so this read forces a
    /// fresh tap (no grace-window reuse).
    pub fn read(prompt: &str, strict: bool) -> Result<Option<String>, String> {
        let _ctx; // must outlive SecItemCopyMatching
        let ctx = if strict {
            match auth_context(0.0) {
                Some(c) => {
                    _ctx = c;
                    Some(&_ctx)
                }
                None => None,
            }
        } else {
            None
        };
        read_account_with(ACCOUNT, ctx, Some(prompt))
    }

    // ── Write-only inbox identity (AGENT_SECRET_LIFECYCLE.md) ──

    /// Store the inbox age identity (UserPresence — opened only at merge with a tap).
    /// Storing needs no tap; only reading does.
    pub fn store_inbox_identity(secret: &str) -> Result<(), String> {
        store_account(INBOX_ACCOUNT, secret, false)
    }

    /// Whether the inbox identity exists — WITHOUT triggering a Touch ID prompt
    /// (returns attributes only, not the protected data). Lets `inbox init` /
    /// `ensure_recipient` be idempotent and tap-free.
    pub fn inbox_identity_exists() -> bool {
        let mut pairs = base_query(INBOX_ACCOUNT);
        pairs.push((unsafe { cfs(kSecReturnAttributes) }, CFBoolean::true_value().as_CFType()));
        pairs.push((unsafe { cfs(kSecMatchLimit) }, CFNumber::from(1i64).as_CFType()));
        let dict = CFDictionary::from_CFType_pairs(&pairs);
        let mut result: CFTypeRef = ptr::null();
        let status = unsafe { SecItemCopyMatching(dict.as_concrete_TypeRef(), &mut result) };
        if !result.is_null() {
            // Balance the +1 from a successful attributes return.
            unsafe { CFType::wrap_under_create_rule(result) };
        }
        status == errSecSuccess
    }

    /// Read several accounts under ONE auth context, so a non-strict merge opens the
    /// inbox identity + the vault master with a single Touch ID tap (the reuse window
    /// carries the first auth to the rest). In `strict` mode the context is zero-reuse,
    /// so each item still demands a fresh tap (by design). Returns one entry per
    /// account, in order; `None` = that account isn't present.
    pub fn read_accounts(accounts: &[&str], strict: bool) -> Result<Vec<Option<String>>, String> {
        let _ctx; // must outlive every SecItemCopyMatching below
        let ctx = match auth_context(if strict { 0.0 } else { 15.0 }) {
            Some(c) => {
                _ctx = c;
                Some(&_ctx)
            }
            None => None,
        };
        let mut out = Vec::with_capacity(accounts.len());
        for account in accounts {
            out.push(read_account_with(account, ctx, None)?);
        }
        Ok(out)
    }
}

#[cfg(not(target_os = "macos"))]
mod imp {
    pub fn store(_passphrase: &str, _strict: bool) -> Result<(), String> {
        Err("biometric Keychain is macOS-only".into())
    }
    pub fn read(_prompt: &str, _strict: bool) -> Result<Option<String>, String> {
        Ok(None)
    }
    pub fn delete() -> Result<(), String> {
        Ok(())
    }
    pub fn store_inbox_identity(_secret: &str) -> Result<(), String> {
        Err("biometric Keychain is macOS-only".into())
    }
    pub fn inbox_identity_exists() -> bool {
        false
    }
    pub fn read_accounts(_accounts: &[&str], _strict: bool) -> Result<Vec<Option<String>>, String> {
        Ok(Vec::new())
    }
}

pub use imp::{
    delete, inbox_identity_exists, read, read_accounts, store, store_inbox_identity,
};
