use super::{
    std_default, std_nist, Algorithm, ErrorCode, HashBuilder, LengthCalculationMethod,
    Normalization, PasswordStorageStandard, DEFAULT_USER_VERSION, INTERNAL_VERSION,
};
use crate::hash::HashFunction;
use crate::pass::XHMAC;
use crate::{deref_ptr, deref_ptr_mut, get_slice, get_slice_mut, get_string};
use std::ffi::CStr;

/// [C binding]
///
/// The C interface uses an enum named `libreauth_pass_xhmac` and the members has been renamed
/// as follows:
/// <table>
///     <thead>
///         <tr>
///             <th>Rust</th>
///             <th>C</th>
///         </tr>
///     </thead>
///     <tbody>
///         <tr>
///             <td>None</td>
///             <td>LIBREAUTH_PASS_XHMAC_NONE</td>
///         </tr>
///         <tr>
///             <td>Before</td>
///             <td>LIBREAUTH_PASS_XHMAC_BEFORE</td>
///         </tr>
///         <tr>
///             <td>After</td>
///             <td>LIBREAUTH_PASS_XHMAC_AFTER</td>
///         </tr>
///     </tbody>
/// </table>
#[repr(C)]
pub enum XHMACType {
    None = 0,
    Before = 1,
    After = 2,
}

/// [C binding] Password hasher configuration storage
///
/// The `struct libreauth_pass_cfg` contains the following fields:
///
/// - [min_len](./struct.HashBuilder.html#method.min_len)
/// - [max_len](./struct.HashBuilder.html#method.max_len)
/// - [salt_len](./struct.HashBuilder.html#method.salt_len)
/// - [algorithm](./enum.Algorithm.html#c-interface)
/// - [length_calculation](./enum.LengthCalculationMethod.html#c-interface)
/// - [normalization](./enum.Normalization.html#c-interface)
/// - [standard](./enum.PasswordStorageStandard.html#c-interface)
/// - [version](./struct.HashBuilder.html#method.version)
/// - [xhmac_type](./enum.XHMACType.html)
/// - [xhmac_alg](../hash/enum.HashFunction.html)
/// - `pepper` (*const u8): Key used for the XHMAC. NULL if no XHMAC is used.
/// - `pepper_len` (size_t): Length of the XHMAC key, in bytes.
#[repr(C)]
pub struct PassCfg {
    min_len: libc::size_t,
    max_len: libc::size_t,
    salt_len: libc::size_t,
    algorithm: Algorithm,
    length_calculation: LengthCalculationMethod,
    normalization: Normalization,
    standard: PasswordStorageStandard,
    version: libc::size_t,
    xhmac_type: XHMACType,
    xhmac_alg: HashFunction,
    pepper: *const u8,
    pepper_len: libc::size_t,
}

/// [C binding] Initialize a `struct libreauth_pass_cfg` with the default values.
///
/// # Parameter
///
/// `cfg`: pointer to a `struct libreauth_pass_cfg`
///
/// # Safety
///
/// This function is a C binding and is therefore unsafe. It is not meant to be used in Rust.
#[no_mangle]
pub unsafe extern "C" fn libreauth_pass_init(cfg: *mut PassCfg) -> ErrorCode {
    libreauth_pass_init_std(cfg, PasswordStorageStandard::NoStandard)
}

/// [C binding] Initialize a `struct libreauth_pass_cfg` with the default values for a given
/// standard.
///
/// # Parameters
///
/// - `cfg`: pointer to a `struct libreauth_pass_cfg`
/// - `std`: standard to use
///
/// # Safety
///
/// This function is a C binding and is therefore unsafe. It is not meant to be used in Rust.
#[no_mangle]
pub unsafe extern "C" fn libreauth_pass_init_std(
    cfg: *mut PassCfg,
    std: PasswordStorageStandard,
) -> ErrorCode {
    let c: &mut PassCfg = deref_ptr_mut!(cfg, ErrorCode::NullPtr);
    match std {
        PasswordStorageStandard::NoStandard => {
            c.min_len = std_default::DEFAULT_PASSWORD_MIN_LEN;
            c.max_len = std_default::DEFAULT_PASSWORD_MAX_LEN;
            c.salt_len = std_default::DEFAULT_SALT_LEN;
            c.algorithm = std_default::DEFAULT_ALGORITHM;
            c.length_calculation = std_default::DEFAULT_LENGTH_CALCULATION;
            c.normalization = std_default::DEFAULT_NORMALIZATION;
            c.standard = std;
            c.version = DEFAULT_USER_VERSION;
            c.xhmac_type = XHMACType::None;
            c.xhmac_alg = std_default::DEFAULT_XHMAC_ALGORITHM;
            c.pepper = std::ptr::null();
            c.pepper_len = 0;
        }
        PasswordStorageStandard::Nist80063b => {
            c.min_len = std_nist::DEFAULT_PASSWORD_MIN_LEN;
            c.max_len = std_nist::DEFAULT_PASSWORD_MAX_LEN;
            c.salt_len = std_nist::DEFAULT_SALT_LEN;
            c.algorithm = std_nist::DEFAULT_ALGORITHM;
            c.length_calculation = std_nist::DEFAULT_LENGTH_CALCULATION;
            c.normalization = std_nist::DEFAULT_NORMALIZATION;
            c.standard = std;
            c.version = DEFAULT_USER_VERSION;
            c.xhmac_type = XHMACType::None;
            c.xhmac_alg = std_nist::DEFAULT_XHMAC_ALGORITHM;
            c.pepper = std::ptr::null();
            c.pepper_len = 0;
        }
    };
    ErrorCode::Success
}

/// [C binding] Initialize a `struct libreauth_pass_cfg` from a PHC string.
///
/// # Parameters
///
/// - `cfg`: pointer to a `struct libreauth_pass_cfg`
/// - `phc`: string using LibreAuth's PHC notation
///
/// # Safety
///
/// This function is a C binding and is therefore unsafe. It is not meant to be used in Rust.
#[no_mangle]
pub unsafe extern "C" fn libreauth_pass_init_from_phc(
    cfg: *mut PassCfg,
    phc: *const libc::c_char,
) -> ErrorCode {
    let c: &mut PassCfg = deref_ptr_mut!(cfg, ErrorCode::NullPtr);
    let p = get_string!(phc);
    let checker = match HashBuilder::from_phc(p.as_str()) {
        Ok(ch) => ch,
        Err(e) => {
            return e;
        }
    };
    c.min_len = checker.min_len;
    c.max_len = checker.max_len;
    c.salt_len = checker.salt_len;
    c.algorithm = checker.algorithm;
    c.length_calculation = checker.length_calculation;
    c.normalization = checker.normalization;
    c.standard = PasswordStorageStandard::NoStandard;
    c.version = if checker.version >= INTERNAL_VERSION {
        checker.version - INTERNAL_VERSION
    } else {
        checker.version
    };
    c.xhmac_alg = checker.xhmax_alg;
    match checker.xhmac {
        XHMAC::Before(k) => {
            c.xhmac_type = XHMACType::Before;
            c.pepper = k.as_ptr();
            c.pepper_len = k.len();
        }
        XHMAC::After(k) => {
            c.xhmac_type = XHMACType::After;
            c.pepper = k.as_ptr();
            c.pepper_len = k.len();
        }
        XHMAC::None => {
            c.xhmac_type = XHMACType::None;
            c.pepper = std::ptr::null();
            c.pepper_len = 0;
        }
    };
    ErrorCode::Success
}

/// [C binding] Hash a password according to the given configuration and stores it in the supplied buffer.
///
/// # Parameters
///
/// - `cfg`: pointer to a `struct libreauth_pass_cfg`
/// - `pass`: password to hash
/// - `dest`: buffer that will hold the string representing the hash according LibreAuth's PHC notation
/// - `dest_len`: buffer's size, in bytes
///
/// # Safety
///
/// This function is a C binding and is therefore unsafe. It is not meant to be used in Rust.
#[no_mangle]
pub unsafe extern "C" fn libreauth_pass_hash(
    cfg: *const PassCfg,
    pass: *const libc::c_char,
    dest: *mut u8,
    dest_len: libc::size_t,
) -> ErrorCode {
    let c: &PassCfg = deref_ptr!(cfg, ErrorCode::NullPtr);
    let password = get_string!(pass);
    if dest.is_null() {
        return ErrorCode::NullPtr;
    }
    let buff = get_slice_mut!(dest, dest_len);
    let mut builder = HashBuilder::new();
    builder
        .min_len(c.min_len)
        .max_len(c.max_len)
        .salt_len(c.salt_len)
        .algorithm(c.algorithm)
        .length_calculation(c.length_calculation)
        .normalization(c.normalization)
        .version(c.version)
        .xhmac(c.xhmac_alg);
    let key = if c.pepper.is_null() {
        vec![]
    } else {
        match c.pepper_len {
            0 => return ErrorCode::InvalidKeyLen,
            l => get_slice!(c.pepper, l),
        }
    };
    if !key.is_empty() {
        match c.xhmac_type {
            XHMACType::Before => {
                builder.xhmac_before(&key);
            }
            XHMACType::After => {
                builder.xhmac_after(&key);
            }
            XHMACType::None => {}
        };
    }
    let hasher = match builder.finalize() {
        Ok(ch) => ch,
        Err(e) => {
            return e;
        }
    };
    match hasher.hash(&password) {
        Ok(h) => {
            let b = h.into_bytes();
            let len = b.len();
            if len >= dest_len {
                return ErrorCode::NotEnoughSpace;
            }
            buff[..len].clone_from_slice(&b[..len]);
            buff[len] = 0;
            ErrorCode::Success
        }
        Err(e) => e,
    }
}

/// [C binding] Check whether or not the supplied password is valid.
///
/// # Parameters
///
/// - `pass`: password to check
/// - `reference`: string representing a previously hashed password using LibreAuth's PHC notation
#[no_mangle]
pub extern "C" fn libreauth_pass_is_valid(
    pass: *const libc::c_char,
    reference: *const libc::c_char,
) -> i32 {
    libreauth_pass_is_valid_xhmac(pass, reference, std::ptr::null(), 0)
}

/// [C binding] Check whether or not the supplied password is valid using a XHMAC key.
///
/// # Parameters
///
/// - `pass`: password to check
/// - `reference`: string representing a previously hashed password using LibreAuth's PHC notation
/// - `key`: XHMAC key
/// - `key_len`: XHMAC key length, in bytes
#[no_mangle]
pub extern "C" fn libreauth_pass_is_valid_xhmac(
    pass: *const libc::c_char,
    reference: *const libc::c_char,
    key: *const u8,
    key_len: libc::size_t,
) -> i32 {
    let p = unsafe { get_string!(pass) };
    let r = unsafe { get_string!(reference) };
    let checker = if !key.is_null() {
        let k = unsafe { get_slice!(key, key_len) };
        HashBuilder::from_phc_xhmac(r.as_str(), &k)
    } else {
        HashBuilder::from_phc(r.as_str())
    };
    let checker = match checker {
        Ok(ch) => ch,
        Err(_) => {
            return 0;
        }
    };
    if checker.is_valid(&p) {
        1
    } else {
        0
    }
}
