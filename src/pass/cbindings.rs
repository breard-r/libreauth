use super::{
    std_default, std_nist, Algorithm, ErrorCode, HashBuilder, LengthCalculationMethod,
    Normalization, PasswordStorageStandard, DEFAULT_USER_VERSION, INTERNAL_VERSION,
};
use libc;
use std;
use std::ffi::CStr;

macro_rules! get_cfg {
    ($cfg: ident, $ret: expr) => {{
        match $cfg.is_null() {
            false => unsafe { &*$cfg },
            true => {
                return $ret;
            }
        }
    }};
}

macro_rules! get_cfg_mut {
    ($cfg: ident, $ret: expr) => {{
        match $cfg.is_null() {
            false => unsafe { &mut *$cfg },
            true => {
                return $ret;
            }
        }
    }};
}

/// [C binding] Password hasher configuration storage
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
}

/// [C binding] Initialize a `struct libreauth_pass_cfg` with the default values.
#[no_mangle]
pub extern "C" fn libreauth_pass_init(cfg: *mut PassCfg) -> ErrorCode {
    libreauth_pass_init_std(cfg, PasswordStorageStandard::NoStandard)
}

/// [C binding] Initialize a `struct libreauth_pass_cfg` with the default values for a given
/// standard.
#[no_mangle]
pub extern "C" fn libreauth_pass_init_std(
    cfg: *mut PassCfg,
    std: PasswordStorageStandard,
) -> ErrorCode {
    match cfg.is_null() {
        false => {
            let c: &mut PassCfg = unsafe { &mut *cfg };
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
                }
            };
            ErrorCode::Success
        }
        true => ErrorCode::NullPtr,
    }
}

/// [C binding] Initialize a `struct libreauth_pass_cfg` from a PHC string.
#[no_mangle]
pub extern "C" fn libreauth_pass_init_from_phc(
    cfg: *mut PassCfg,
    phc: *const libc::c_char,
) -> ErrorCode {
    let c: &mut PassCfg = get_cfg_mut!(cfg, ErrorCode::NullPtr);
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
    ErrorCode::Success
}

/// [C binding] Hash a password according to the given configuration and stores it in the supplied buffer.
#[no_mangle]
pub extern "C" fn libreauth_pass_hash(
    cfg: *const PassCfg,
    pass: *const libc::c_char,
    dest: *mut u8,
    dest_len: libc::size_t,
) -> ErrorCode {
    let c: &PassCfg = get_cfg!(cfg, ErrorCode::NullPtr);
    let password = get_string!(pass);
    if dest.is_null() {
        return ErrorCode::NullPtr;
    }
    let buff = unsafe { std::slice::from_raw_parts_mut(dest, dest_len) };
    let hasher = match HashBuilder::new()
        .min_len(c.min_len)
        .max_len(c.max_len)
        .salt_len(c.salt_len)
        .algorithm(c.algorithm)
        .length_calculation(c.length_calculation)
        .normalization(c.normalization)
        .version(c.version)
        .finalize()
    {
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
            for i in 0..len {
                buff[i] = b[i];
            }
            buff[len] = 0;
            ErrorCode::Success
        }
        Err(e) => e,
    }
}

/// [C binding] Check whether or not the supplied password is valid.
#[no_mangle]
pub extern "C" fn libreauth_pass_is_valid(
    pass: *const libc::c_char,
    reference: *const libc::c_char,
) -> i32 {
    let p = get_string!(pass);
    let r = get_string!(reference);
    let checker = match HashBuilder::from_phc(r.as_str()) {
        Ok(ch) => ch,
        Err(_) => {
            return 0;
        }
    };
    match checker.is_valid(&p) {
        true => 1,
        false => 0,
    }
}
