use super::HOTPBuilder;
use super::TOTPBuilder;
use crate::oath::{ErrorCode, HashFunction};
use libc;
use std;
use std::ffi::CStr;
use time;

macro_rules! otp_init {
    ($cfg_type: ty, $cfg: ident, $($field: ident, $value: expr), *) => {
        match $cfg.is_null() {
            false => {
                let c: &mut $cfg_type = unsafe { &mut *$cfg };
                c.key = std::ptr::null();
                c.key_len = 0;
                c.output_len = crate::oath::DEFAULT_OTP_OUT_LEN;
                c.output_base = std::ptr::null();
                c.hash_function = crate::oath::DEFAULT_OTP_HASH;
                $(
                    c.$field = $value;
                )*
                Ok(c)
            }
            true => Err(ErrorCode::NullPtr),
        }
    }
}

macro_rules! get_value_or_errno {
    ($val: expr) => {{
        match $val {
            Ok(v) => v,
            Err(errno) => return errno,
        }
    }};
}

macro_rules! get_value_or_false {
    ($val: expr) => {{
        match $val {
            Ok(v) => v,
            Err(_) => return 0,
        }
    }};
}

/// [C binding] HOTP configuration storage
#[repr(C)]
pub struct HOTPcfg {
    key: *const u8,
    key_len: libc::size_t,
    counter: u64,
    output_len: libc::size_t,
    output_base: *const libc::c_char,
    hash_function: HashFunction,
}

/// [C binding] TOTP configuration storage
#[repr(C)]
pub struct TOTPcfg {
    key: *const u8,
    key_len: libc::size_t,
    timestamp: i64,
    positive_tolerance: u64,
    negative_tolerance: u64,
    period: u32,
    initial_time: u64,
    output_len: libc::size_t,
    output_base: *const libc::c_char,
    hash_function: HashFunction,
}

pub fn write_code(code: &Vec<u8>, dest: &mut [u8]) {
    let len = code.len();
    for i in 0..len {
        dest[i] = code[i];
    }
    dest[len] = 0;
}

pub fn get_cfg<T>(cfg: *const T) -> Result<&'static T, ErrorCode> {
    if cfg.is_null() {
        return Err(ErrorCode::NullPtr);
    }
    let cfg: &T = unsafe { &*cfg };
    Ok(cfg)
}

pub fn get_code(code: *const u8, code_len: usize) -> Result<String, ErrorCode> {
    if code.is_null() {
        return Err(ErrorCode::NullPtr);
    }
    let code = unsafe { std::slice::from_raw_parts(code, code_len).to_owned() };
    match String::from_utf8(code) {
        Ok(code) => Ok(code),
        Err(_) => Err(ErrorCode::InvalidUTF8),
    }
}

pub fn get_mut_code(code: *mut u8, code_len: usize) -> Result<&'static mut [u8], ErrorCode> {
    if code.is_null() {
        return Err(ErrorCode::NullPtr);
    }
    Ok(unsafe { std::slice::from_raw_parts_mut(code, code_len + 1) })
}

pub fn get_output_base(output_base: *const libc::c_char) -> Result<String, ErrorCode> {
    if output_base.is_null() {
        return Ok(crate::oath::DEFAULT_OTP_OUT_BASE.to_string());
    }
    let raw_str = unsafe { CStr::from_ptr(output_base).to_bytes().to_vec() };
    let output_base = String::from_utf8(raw_str).map_err(|_| ErrorCode::InvalidUTF8)?;
    match output_base.len() {
        0 | 1 => Err(ErrorCode::InvalidBaseLen),
        _ => Ok(output_base),
    }
}

pub fn get_key(key: *const u8, key_len: usize) -> Result<Vec<u8>, ErrorCode> {
    match key.is_null() {
        false => match key_len {
            0 => Err(ErrorCode::InvalidKeyLen),
            l => Ok(unsafe { std::slice::from_raw_parts(key, l).to_owned() }),
        },
        true => Err(ErrorCode::NullPtr),
    }
}

/// [C binding] Initialize a `struct libreauth_hotp_cfg` with the default values.
///
/// ## Examples
/// ```c
/// struct libreauth_hotp_cfg cfg;
/// const char key[] = "12345678901234567890";
///
/// uint32_t ret = libreauth_hotp_init(&cfg);
/// if (ret != LIBREAUTH_OATH_SUCCESS) {
///     // Handle the error.
/// }
/// cfg.key = key;
/// cfg.key_len = strlen(key);
/// ```
#[no_mangle]
pub extern "C" fn libreauth_hotp_init(cfg: *mut HOTPcfg) -> ErrorCode {
    let res: Result<&mut HOTPcfg, ErrorCode> = otp_init!(HOTPcfg, cfg, counter, 0);
    match res {
        Ok(_) => ErrorCode::Success,
        Err(errno) => errno,
    }
}

/// [C binding] Generate an HOTP code according to the given configuration and stores it in the supplied buffer.
///
/// ## Examples
/// ```c
/// struct libreauth_hotp_cfg cfg;
/// const char key[] = "12345678901234567890";
/// char code[DEFAULT_BUFF_LEN + 1];
///
/// uint32_t ret = libreauth_hotp_init(&cfg);
/// if (ret != LIBREAUTH_OATH_SUCCESS) {
///     // Handle the error.
/// }
/// cfg.key = key;
/// cfg.key_len = strlen(key);
///
/// ret = libreauth_hotp_generate(&cfg, code);
/// if (ret != LIBREAUTH_OATH_SUCCESS) {
///     // Handle the error.
/// }
///
/// printf("HOTP code: %s\n", code);
/// ```
#[no_mangle]
pub extern "C" fn libreauth_hotp_generate(cfg: *const HOTPcfg, code: *mut u8) -> ErrorCode {
    let cfg = get_value_or_errno!(get_cfg(cfg));
    let code = get_value_or_errno!(get_mut_code(code, cfg.output_len as usize));
    let output_base = get_value_or_errno!(get_output_base(cfg.output_base));
    let key = get_value_or_errno!(get_key(cfg.key, cfg.key_len as usize));
    match HOTPBuilder::new()
        .key(&key)
        .output_len(cfg.output_len as usize)
        .output_base(&output_base)
        .hash_function(cfg.hash_function)
        .counter(cfg.counter)
        .finalize()
        {
            Ok(hotp) => {
                let ref_code = hotp.generate().into_bytes();
                write_code(&ref_code, code);
                ErrorCode::Success
            }
            Err(errno) => errno,
        }
}

/// [C binding] Check whether or not the supplied HOTP code is valid.
///
/// ## Examples
/// ```c
/// struct libreauth_hotp_cfg cfg;
/// const char key[] = "12345678901234567890";
///
/// uint32_t ret = libreauth_hotp_init(&cfg);
/// if (ret != LIBREAUTH_OATH_SUCCESS) {
///     // Handle the error.
/// }
/// cfg.key = key;
/// cfg.key_len = strlen(key);
///
/// if (libreauth_hotp_is_valid(&cfg, "755224")) {
///     printf("Valid HOTP code\n");
/// } else {
///     printf("Invalid HOTP code\n");
/// }
/// ```
#[no_mangle]
pub extern "C" fn libreauth_hotp_is_valid(cfg: *const HOTPcfg, code: *const u8) -> i32 {
    let cfg = get_value_or_false!(get_cfg(cfg));
    let code = get_value_or_false!(get_code(code, cfg.output_len as usize));
    let output_base = get_value_or_false!(get_output_base(cfg.output_base));
    let key = get_value_or_false!(get_key(cfg.key, cfg.key_len as usize));
    match HOTPBuilder::new()
        .key(&key)
        .output_len(cfg.output_len as usize)
        .output_base(&output_base)
        .hash_function(cfg.hash_function)
        .counter(cfg.counter)
        .finalize()
        {
            Ok(hotp) => match hotp.is_valid(&code) {
                true => 1,
                false => 0,
            },
            Err(_) => 0,
        }
}

#[no_mangle]
pub extern "C" fn libreauth_hotp_get_uri(
    cfg: *const HOTPcfg,
    issuer: *const libc::c_char,
    account_name: *const libc::c_char,
    uri_buff: *mut u8,
    uri_buff_len: libc::size_t,
    ) -> ErrorCode {
    let cfg = get_value_or_errno!(get_cfg(cfg));
    let issuer = get_string!(issuer);
    let acc_name = get_string!(account_name);
    let buff = get_value_or_errno!(get_mut_code(uri_buff, uri_buff_len));
    let output_base = get_value_or_errno!(get_output_base(cfg.output_base));
    let key = get_value_or_errno!(get_key(cfg.key, cfg.key_len as usize));
    match HOTPBuilder::new()
        .key(&key)
        .output_len(cfg.output_len as usize)
        .output_base(&output_base)
        .hash_function(cfg.hash_function)
        .counter(cfg.counter)
        .finalize()
        {
            Ok(hotp) => {
                let b = hotp
                    .key_uri_format(&issuer, &acc_name)
                    .finalize()
                    .into_bytes();
                let len = b.len();
                if len >= uri_buff_len {
                    return ErrorCode::NotEnoughSpace;
                }
                for i in 0..len {
                    buff[i] = b[i];
                }
                buff[len] = 0;
                ErrorCode::Success
            }
            Err(errno) => errno,
        }
}

/// [C binding] Initialize a `struct libreauth_totp_cfg` with the default values.
///
/// ## Examples
/// ```c
/// struct libreauth_totp_cfg cfg;
/// const char key[] = "12345678901234567890";
///
/// uint32_t ret = libreauth_totp_init(&cfg);
/// if (ret != LIBREAUTH_OATH_SUCCESS) {
///     // Handle the error.
/// }
/// cfg.key = key;
/// cfg.key_len = strlen(key);
/// ```
#[no_mangle]
pub extern "C" fn libreauth_totp_init(cfg: *mut TOTPcfg) -> ErrorCode {
    let res: Result<&mut TOTPcfg, ErrorCode> = otp_init!(
        TOTPcfg,
        cfg,
        timestamp,
        time::PrimitiveDateTime::now().timestamp(),
        positive_tolerance,
        0,
        negative_tolerance,
        0,
        period,
        30,
        initial_time,
        0
    );
    match res {
        Ok(_) => ErrorCode::Success,
        Err(errno) => errno,
    }
}

/// [C binding] Generate a TOTP code according to the given configuration and stores it in the supplied buffer.
///
/// ## Examples
/// ```c
/// struct libreauth_totp_cfg cfg;
/// const char key[] = "12345678901234567890";
/// char code[DEFAULT_BUFF_LEN + 1] = {0};
///
/// uint32_t ret = libreauth_totp_init(&cfg);
/// if (ret != LIBREAUTH_OATH_SUCCESS) {
///     // Handle the error.
/// }
/// cfg.key = key;
/// cfg.key_len = strlen(key);
///
/// ret = libreauth_totp_generate(&cfg, code);
/// if (ret != LIBREAUTH_OATH_SUCCESS) {
///     // Handle the error.
/// }
///
/// printf("TOTP code: %s\n", code);
/// ```
#[no_mangle]
pub extern "C" fn libreauth_totp_generate(cfg: *const TOTPcfg, code: *mut u8) -> ErrorCode {
    let cfg = get_value_or_errno!(get_cfg(cfg));
    let code = get_value_or_errno!(get_mut_code(code, cfg.output_len as usize));
    let output_base = get_value_or_errno!(get_output_base(cfg.output_base));
    let key = get_value_or_errno!(get_key(cfg.key, cfg.key_len as usize));
    match TOTPBuilder::new()
        .key(&key)
        .output_len(cfg.output_len as usize)
        .output_base(&output_base)
        .hash_function(cfg.hash_function)
        .timestamp(cfg.timestamp)
        .period(cfg.period)
        .initial_time(cfg.initial_time)
        .finalize()
        {
            Ok(hotp) => {
                let ref_code = hotp.generate().into_bytes();
                write_code(&ref_code, code);
                ErrorCode::Success
            }
            Err(errno) => errno,
        }
}

/// [C binding] Initialize a `struct libreauth_totp_cfg` with the default values.
///
/// ## Examples
/// ```c
/// struct libreauth_totp_cfg cfg;
/// const char key[] = "12345678901234567890";
///
/// uint32_t ret = libreauth_totp_init(&cfg);
/// if (ret != LIBREAUTH_OATH_SUCCESS) {
///     // Handle the error.
/// }
/// cfg.key = key;
/// cfg.key_len = strlen(key);
///
/// if (libreauth_totp_is_valid(&cfg, "4755224")) {
///     printf("Valid TOTP code\n");
/// } else {
///     printf("Invalid TOTP code\n");
/// }
/// ```
#[no_mangle]
pub extern "C" fn libreauth_totp_is_valid(cfg: *const TOTPcfg, code: *const u8) -> i32 {
    let cfg = get_value_or_false!(get_cfg(cfg));
    let code = get_value_or_false!(get_code(code, cfg.output_len as usize));
    let output_base = get_value_or_false!(get_output_base(cfg.output_base));
    let key = get_value_or_false!(get_key(cfg.key, cfg.key_len as usize));
    match TOTPBuilder::new()
        .key(&key)
        .output_len(cfg.output_len as usize)
        .output_base(&output_base)
        .hash_function(cfg.hash_function)
        .timestamp(cfg.timestamp)
        .period(cfg.period)
        .initial_time(cfg.initial_time)
        .positive_tolerance(cfg.positive_tolerance)
        .negative_tolerance(cfg.negative_tolerance)
        .finalize()
        {
            Ok(totp) => match totp.is_valid(&code) {
                true => 1,
                false => 0,
            },
            Err(_) => 0,
        }
}

#[no_mangle]
pub extern "C" fn libreauth_totp_get_uri(
    cfg: *const TOTPcfg,
    issuer: *const libc::c_char,
    account_name: *const libc::c_char,
    uri_buff: *mut u8,
    uri_buff_len: libc::size_t,
    ) -> ErrorCode {
    let cfg = get_value_or_errno!(get_cfg(cfg));
    let issuer = get_string!(issuer);
    let acc_name = get_string!(account_name);
    let buff = get_value_or_errno!(get_mut_code(uri_buff, uri_buff_len));
    let output_base = get_value_or_errno!(get_output_base(cfg.output_base));
    let key = get_value_or_errno!(get_key(cfg.key, cfg.key_len as usize));
    match TOTPBuilder::new()
        .key(&key)
        .output_len(cfg.output_len as usize)
        .output_base(&output_base)
        .hash_function(cfg.hash_function)
        .timestamp(cfg.timestamp)
        .period(cfg.period)
        .initial_time(cfg.initial_time)
        .positive_tolerance(cfg.positive_tolerance)
        .negative_tolerance(cfg.negative_tolerance)
        .finalize()
        {
            Ok(totp) => {
                let b = totp
                    .key_uri_format(&issuer, &acc_name)
                    .finalize()
                    .into_bytes();
                let len = b.len();
                if len >= uri_buff_len {
                    return ErrorCode::NotEnoughSpace;
                }
                for i in 0..len {
                    buff[i] = b[i];
                }
                buff[len] = 0;
                ErrorCode::Success
            }
            Err(errno) => errno,
        }
}

