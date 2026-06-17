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
        kSecClassGenericPassword, kSecMatchLimit, kSecReturnData, kSecUseAuthenticationContext,
        kSecUseDataProtectionKeychain, kSecValueData,
    };
    use security_framework_sys::keychain_item::{SecItemAdd, SecItemCopyMatching, SecItemDelete};
    use std::os::raw::{c_char, c_void};
    use std::ptr;

    const SERVICE: &str = "io.quantumencoding.secrets";
    const ACCOUNT: &str = "vault-master";
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

    /// Build an `LAContext` with `touchIDAuthenticationAllowableReuseDuration = 0`
    /// so the keychain read forces a FRESH Touch ID tap with no reuse grace. Handed
    /// to `SecItemCopyMatching` via `kSecUseAuthenticationContext`. Strict mode only.
    /// Raw objc runtime (no extra crate); `objc_msgSend` is transmuted to the exact
    /// typed signature per the documented calling convention.
    fn fresh_auth_context() -> Option<CFType> {
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
            set_fn(obj, sel_set, 0.0_f64);
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
    fn base_query() -> Vec<(CFType, CFType)> {
        unsafe {
            vec![
                (cfs(kSecClass), cfs(kSecClassGenericPassword)),
                (cfs(kSecAttrService), CFString::new(SERVICE).as_CFType()),
                (cfs(kSecAttrAccount), CFString::new(ACCOUNT).as_CFType()),
                (cfs(kSecAttrAccessGroup), CFString::new(ACCESS_GROUP).as_CFType()),
                (cfs(kSecUseDataProtectionKeychain), CFBoolean::true_value().as_CFType()),
            ]
        }
    }

    pub fn delete() -> Result<(), String> {
        let dict = CFDictionary::from_CFType_pairs(&base_query());
        let status = unsafe { SecItemDelete(dict.as_concrete_TypeRef()) };
        if status == errSecSuccess || status == errSecItemNotFound {
            Ok(())
        } else {
            Err(format!("SecItemDelete failed (OSStatus {status})"))
        }
    }

    /// Store the master passphrase. `strict` selects the access-control policy:
    /// - false → `UserPresence`: biometry OR watch OR device passcode; honors the
    ///   system Touch ID reuse grace (convenient: tap once, a burst of reads flow).
    /// - true  → `BiometryCurrentSet`: enrolled biometry ONLY (no watch/passcode
    ///   fallback) and self-invalidates if the fingerprint set changes. Paired with
    ///   the zero-reuse context in `read`, every access demands a fresh tap.
    pub fn store(passphrase: &str, strict: bool) -> Result<(), String> {
        let _ = delete(); // replace any existing item

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

        let data = CFData::from_buffer(passphrase.as_bytes());
        let mut pairs = base_query();
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

    /// Read the passphrase, triggering the Touch ID prompt. Ok(None) = not unlocked.
    /// When `strict`, attach a zero-reuse `LAContext` so this read forces a fresh
    /// tap (no grace-window reuse). Keep `_ctx` alive until after the call.
    pub fn read(_prompt: &str, strict: bool) -> Result<Option<String>, String> {
        let mut pairs = base_query();
        pairs.push((unsafe { cfs(kSecReturnData) }, CFBoolean::true_value().as_CFType()));
        // kSecMatchLimit accepts a count CFNumber (the crate doesn't export the
        // kSecMatchLimitOne string constant). Custom Touch ID prompt text needs
        // LAContext (phase-2 polish); the OS shows its default biometric prompt.
        pairs.push((unsafe { cfs(kSecMatchLimit) }, CFNumber::from(1i64).as_CFType()));

        let _ctx; // must outlive SecItemCopyMatching
        if strict {
            if let Some(ctx) = fresh_auth_context() {
                _ctx = ctx;
                pairs.push((unsafe { cfs(kSecUseAuthenticationContext) }, _ctx.clone()));
            }
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
}

pub use imp::{delete, read, store};
