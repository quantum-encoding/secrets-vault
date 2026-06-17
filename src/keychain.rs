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
        kSecAccessControlUserPresence, kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
        SecAccessControlCreateWithFlags,
    };
    use security_framework_sys::base::{errSecItemNotFound, errSecSuccess};
    use security_framework_sys::item::{
        kSecAttrAccessControl, kSecAttrAccessGroup, kSecAttrAccount, kSecAttrService, kSecClass,
        kSecClassGenericPassword, kSecMatchLimit, kSecReturnData, kSecUseDataProtectionKeychain,
        kSecValueData,
    };
    use security_framework_sys::keychain_item::{SecItemAdd, SecItemCopyMatching, SecItemDelete};
    use std::ptr;

    const SERVICE: &str = "io.quantumencoding.secrets";
    const ACCOUNT: &str = "vault-master";
    const ACCESS_GROUP: &str = "VLK8CVU5H3.io.quantumencoding.secrets";
    /// Distinct service for the transient GUI→headless passphrase bridge tickets.
    const TICKET_SERVICE: &str = "io.quantumencoding.secrets.ticket";

    // security-framework-sys 2.15 exports kSecAttrAccessControl but not the plain
    // kSecAttrAccessible key (needed for a NON-biometric item). The Security
    // framework is already linked via the crate, so declare the symbol ourselves.
    #[link(name = "Security", kind = "framework")]
    extern "C" {
        static kSecAttrAccessible: CFStringRef;
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

    pub fn store(passphrase: &str) -> Result<(), String> {
        let _ = delete(); // replace any existing item

        let ac = unsafe {
            let ac = SecAccessControlCreateWithFlags(
                ptr::null(),
                kSecAttrAccessibleWhenUnlockedThisDeviceOnly as CFTypeRef,
                kSecAccessControlUserPresence,
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
    pub fn read(_prompt: &str) -> Result<Option<String>, String> {
        let mut pairs = base_query();
        pairs.push((unsafe { cfs(kSecReturnData) }, CFBoolean::true_value().as_CFType()));
        // kSecMatchLimit accepts a count CFNumber (the crate doesn't export the
        // kSecMatchLimitOne string constant). Custom Touch ID prompt text needs
        // LAContext (phase-2 polish); the OS shows its default biometric prompt.
        pairs.push((unsafe { cfs(kSecMatchLimit) }, CFNumber::from(1i64).as_CFType()));

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

    // ── Transient "ticket" items: the GUI-session → headless passphrase bridge ──
    //
    // A second generic-password item in the SAME access group, but with NO
    // biometric ACL — just `WhenUnlockedThisDeviceOnly`. The OS still gates reads
    // to binaries in our access group (enforced by code signature), so a same-user
    // adversary can't read it, but OUR own headless process can — with no UI. The
    // GUI-session `_vend` helper (which already passed Touch ID) writes the master
    // passphrase into one of these; the waiting headless process reads it once and
    // deletes it. Lifetime = one exec; never touches disk.

    fn ticket_query(id: &str) -> Vec<(CFType, CFType)> {
        unsafe {
            vec![
                (cfs(kSecClass), cfs(kSecClassGenericPassword)),
                (cfs(kSecAttrService), CFString::new(TICKET_SERVICE).as_CFType()),
                (cfs(kSecAttrAccount), CFString::new(id).as_CFType()),
                (cfs(kSecAttrAccessGroup), CFString::new(ACCESS_GROUP).as_CFType()),
                (cfs(kSecUseDataProtectionKeychain), CFBoolean::true_value().as_CFType()),
            ]
        }
    }

    pub fn delete_ticket(id: &str) -> Result<(), String> {
        let dict = CFDictionary::from_CFType_pairs(&ticket_query(id));
        let status = unsafe { SecItemDelete(dict.as_concrete_TypeRef()) };
        if status == errSecSuccess || status == errSecItemNotFound {
            Ok(())
        } else {
            Err(format!("ticket SecItemDelete failed (OSStatus {status})"))
        }
    }

    /// Write the passphrase into a no-ACL ticket item (called from the GUI-session
    /// `_vend` helper after Touch ID). Readable only by our signed binary.
    pub fn store_ticket(id: &str, value: &str) -> Result<(), String> {
        let _ = delete_ticket(id);
        let data = CFData::from_buffer(value.as_bytes());
        let mut pairs = ticket_query(id);
        pairs.push((
            unsafe { cfs(kSecAttrAccessible) },
            unsafe { cfs(kSecAttrAccessibleWhenUnlockedThisDeviceOnly) },
        ));
        pairs.push((unsafe { cfs(kSecValueData) }, data.as_CFType()));
        let dict = CFDictionary::from_CFType_pairs(&pairs);
        let status = unsafe { SecItemAdd(dict.as_concrete_TypeRef(), ptr::null_mut()) };
        if status == errSecSuccess {
            Ok(())
        } else {
            Err(format!("ticket SecItemAdd failed (OSStatus {status})"))
        }
    }

    /// Read a ticket (no UI required — plain accessibility). Ok(None) = absent.
    pub fn read_ticket(id: &str) -> Result<Option<String>, String> {
        let mut pairs = ticket_query(id);
        pairs.push((unsafe { cfs(kSecReturnData) }, CFBoolean::true_value().as_CFType()));
        pairs.push((unsafe { cfs(kSecMatchLimit) }, CFNumber::from(1i64).as_CFType()));
        let dict = CFDictionary::from_CFType_pairs(&pairs);
        let mut result: CFTypeRef = ptr::null();
        let status = unsafe { SecItemCopyMatching(dict.as_concrete_TypeRef(), &mut result) };
        if status == errSecItemNotFound {
            return Ok(None);
        }
        if status != errSecSuccess {
            return Err(format!("ticket SecItemCopyMatching failed (OSStatus {status})"));
        }
        if result.is_null() {
            return Ok(None);
        }
        let data = unsafe { CFData::wrap_under_create_rule(result as CFDataRef) };
        String::from_utf8(data.bytes().to_vec())
            .map(Some)
            .map_err(|_| "ticket value is not valid UTF-8".into())
    }
}

#[cfg(not(target_os = "macos"))]
mod imp {
    pub fn store(_passphrase: &str) -> Result<(), String> {
        Err("biometric Keychain is macOS-only".into())
    }
    pub fn read(_prompt: &str) -> Result<Option<String>, String> {
        Ok(None)
    }
    pub fn delete() -> Result<(), String> {
        Ok(())
    }
    pub fn store_ticket(_id: &str, _value: &str) -> Result<(), String> {
        Err("biometric Keychain is macOS-only".into())
    }
    pub fn read_ticket(_id: &str) -> Result<Option<String>, String> {
        Ok(None)
    }
    pub fn delete_ticket(_id: &str) -> Result<(), String> {
        Ok(())
    }
}

pub use imp::{delete, delete_ticket, read, read_ticket, store, store_ticket};
