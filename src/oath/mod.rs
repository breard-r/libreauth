//! HOTP and TOTP authentication module.
//!
//! ## Examples
//!
//! ```rust
//! let key_ascii = "12345678901234567890".to_owned();
//! let mut hotp = libreauth::oath::HOTPBuilder::new()
//!     .ascii_key(&key_ascii)
//!     .finalize()
//!     .unwrap();
//!
//! let code = hotp.generate();
//! assert_eq!(code, "755224");
//! assert!(hotp.is_valid(&"755224".to_owned()));
//!
//! let code = hotp.increment_counter().generate();
//! assert_eq!(code, "287082");
//! assert!(hotp.is_valid(&"287082".to_owned()));
//! ```
//!
//! ```rust
//! let key_base32 = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ".to_owned();
//! let mut totp = libreauth::oath::TOTPBuilder::new()
//!     .base32_key(&key_base32)
//!     .finalize()
//!     .unwrap();
//!
//! let code = totp.generate();
//! println!("TOTP code: {}", code);
//!
//! assert!(totp.is_valid(&code));
//! ```

use std::fmt;

const DEFAULT_KEY_URI_PARAM_POLICY: ParametersVisibility = ParametersVisibility::ShowNonDefault;
const DEFAULT_OTP_HASH: HashFunction = HashFunction::Sha1;
const DEFAULT_OTP_OUT_BASE: &str = "0123456789";
const DEFAULT_OTP_OUT_LEN: usize = 6;
const DEFAULT_TOTP_PERIOD: u32 = 30;
const DEFAULT_TOTP_T0: u64 = 0;

/// Hash functions used for the code's computation.
///
/// ## C interface
/// The C interface uses an enum of type `libreauth_oath_hash_function` and
/// the members has been renamed as follows:
/// <table>
///     <thead>
///         <tr>
///             <th>Rust</th>
///             <th>C</th>
///         </tr>
///     </thead>
///     <tbody>
///         <tr>
///             <td>Sha1</td>
///             <td>LIBREAUTH_OATH_SHA_1</td>
///         </tr>
///         <tr>
///             <td>Sha256</td>
///             <td>LIBREAUTH_OATH_SHA_256</td>
///         </tr>
///         <tr>
///             <td>Sha512</td>
///             <td>LIBREAUTH_OATH_SHA_512</td>
///         </tr>
///     </tbody>
/// </table>
#[repr(C)]
#[derive(Clone, Copy, Eq, PartialEq)]
pub enum HashFunction {
    Sha1 = 1,
    Sha224 = 2,
    Sha256 = 3,
    Sha384 = 4,
    Sha512 = 5,
    Sha512Trunc224 = 6,
    Sha512Trunc256 = 7,
    Sha3_224 = 8,
    Sha3_256 = 9,
    Sha3_384 = 10,
    Sha3_512 = 11,
    Keccak224 = 12,
    Keccak256 = 13,
    Keccak384 = 14,
    Keccak512 = 15,
}

impl fmt::Display for HashFunction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            HashFunction::Sha1 => "SHA1",
            HashFunction::Sha224 => "SHA224",
            HashFunction::Sha256 => "SHA256",
            HashFunction::Sha384 => "SHA384",
            HashFunction::Sha512 => "SHA512",
            HashFunction::Sha512Trunc224 => "SHA512-224",
            HashFunction::Sha512Trunc256 => "SHA512-256",
            HashFunction::Sha3_224 => "SHA3-224",
            HashFunction::Sha3_256 => "SHA3-256",
            HashFunction::Sha3_384 => "SHA3-384",
            HashFunction::Sha3_512 => "SHA3-512",
            HashFunction::Keccak224 => "Keccak224",
            HashFunction::Keccak256 => "Keccak256",
            HashFunction::Keccak384 => "Keccak384",
            HashFunction::Keccak512 => "Keccak512",
        };
        write!(f, "{}", s)
    }
}

/// Error codes used both in the rust and C interfaces.
///
/// ## C interface
/// The C interface uses an enum of type `libreauth_oath_errno` and the
/// members has been renamed as follows:
/// <table>
///     <thead>
///         <tr>
///             <th>Rust</th>
///             <th>C</th>
///         </tr>
///     </thead>
///     <tbody>
///         <tr>
///             <td>Success</td>
///             <td>LIBREAUTH_OATH_SUCCESS</td>
///         </tr>
///         <tr>
///             <td>NullPtr</td>
///             <td>LIBREAUTH_OATH_NULL_PTR</td>
///         </tr>
///         <tr>
///             <td>NotEnoughSpace</td>
///             <td>LIBREAUTH_OATH_NOT_ENOUGH_SPACE</td>
///         </tr>
///         <tr>
///             <td>InvalidBaseLen</td>
///             <td>LIBREAUTH_OATH_INVALID_BASE_LEN</td>
///         </tr>
///         <tr>
///             <td>InvalidKeyLen</td>
///             <td>LIBREAUTH_OATH_INVALID_KEY_LEN</td>
///         </tr>
///         <tr>
///             <td>CodeTooSmall</td>
///             <td>LIBREAUTH_OATH_CODE_TOO_SMALL</td>
///         </tr>
///         <tr>
///             <td>CodeTooBig</td>
///             <td>LIBREAUTH_OATH_CODE_TOO_BIG</td>
///         </tr>
///         <tr>
///             <td>InvalidKey</td>
///             <td>LIBREAUTH_OATH_INVALID_KEY</td>
///         </tr>
///         <tr>
///             <td>InvalidPeriod</td>
///             <td>LIBREAUTH_OATH_INVALID_PERIOD</td>
///         </tr>
///         <tr>
///             <td>InvalidUTF8</td>
///             <td>LIBREAUTH_OATH_INVALID_UTF8</td>
///         </tr>
///     </tbody>
/// </table>
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub enum ErrorCode {
    Success = 0,

    NullPtr = 1,
    NotEnoughSpace = 2,

    InvalidBaseLen = 10,
    InvalidKeyLen = 11,
    CodeTooSmall = 12,
    CodeTooBig = 13,

    InvalidKey = 20,
    InvalidPeriod = 21,

    InvalidUTF8 = 30,
}

macro_rules! builder_common {
    ($t:ty) => {
        /// Sets the shared secret.
        pub fn key(&mut self, key: &[u8]) -> &mut $t {
            self.key = Some(key.to_owned());
            self
        }

        /// Sets the shared secret. This secret is passed as an ASCII string.
        pub fn ascii_key(&mut self, key: &str) -> &mut $t {
            self.key = Some(key.as_bytes().to_vec());
            self
        }

        /// Sets the shared secret. This secret is passed as an hexadecimal encoded string.
        pub fn hex_key(&mut self, key: &str) -> &mut $t {
            match hex::decode(key) {
                Ok(k) => { self.key = Some(k); }
                Err(_) => { self.runtime_error = Some(ErrorCode::InvalidKey); }
            }
            self
        }

        /// Sets the shared secret. This secret is passed as a base32 encoded string.
        pub fn base32_key(&mut self, key: &str) -> &mut $t {
            match base32::decode(base32::Alphabet::RFC4648 { padding: false }, &key) {
                Some(k) => { self.key = Some(k); }
                None => { self.runtime_error = Some(ErrorCode::InvalidKey); }
            }
            self
        }

        /// Sets the shared secret. This secret is passed as a base64 encoded string.
        pub fn base64_key(&mut self, key: &str) -> &mut $t {
            match base64::decode(key) {
                Ok(k) => { self.key = Some(k); }
                Err(_) => { self.runtime_error = Some(ErrorCode::InvalidKey); }
            }
            self
        }

        fn code_length(&self) -> usize {
            let base_len = self.output_base.len();
            let mut nb_bits = base_len;
            for _ in 1..self.output_len {
                nb_bits = match nb_bits.checked_mul(base_len) {
                    Some(nb_bits) => nb_bits,
                    None => return ::std::usize::MAX,
                };
            }
            nb_bits
        }

        /// Sets the number of characters for the code. The minimum and maximum values depends the base. Default is 6.
        pub fn output_len(&mut self, output_len: usize) -> &mut $t {
            self.output_len = output_len;
            self
        }

        /// Sets the base used to represents the output code. Default is "0123456789".
        pub fn output_base(&mut self, base: &str) -> &mut $t {
            self.output_base = base.to_string();
            self
        }

        /// Sets the hash function. Default is Sha1.
        pub fn hash_function(&mut self, hash_function: HashFunction) -> &mut $t {
            self.hash_function = hash_function;
            self
        }
    }
}

#[cfg(feature = "cbindings")]
mod c {
    use super::ErrorCode;
    use std::{self, ffi::CStr};

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
}

#[cfg(feature = "cbindings")]
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

#[cfg(feature = "cbindings")]
macro_rules! get_value_or_errno {
    ($val: expr) => {{
        match $val {
            Ok(v) => v,
            Err(errno) => return errno,
        }
    }};
}

#[cfg(feature = "cbindings")]
macro_rules! get_value_or_false {
    ($val: expr) => {{
        match $val {
            Ok(v) => v,
            Err(_) => return 0,
        }
    }};
}

mod key_uri;
pub use self::key_uri::{KeyUriBuilder, ParametersVisibility};

mod hotp;
#[cfg(feature = "cbindings")]
pub use self::hotp::cbindings::libreauth_hotp_generate;
#[cfg(feature = "cbindings")]
pub use self::hotp::cbindings::libreauth_hotp_init;
#[cfg(feature = "cbindings")]
pub use self::hotp::cbindings::libreauth_hotp_is_valid;
#[cfg(feature = "cbindings")]
pub use self::hotp::cbindings::HOTPcfg;
pub use self::hotp::HOTPBuilder;
pub use self::hotp::HOTP;

mod totp;
#[cfg(feature = "cbindings")]
pub use self::totp::cbindings::libreauth_totp_generate;
#[cfg(feature = "cbindings")]
pub use self::totp::cbindings::libreauth_totp_init;
#[cfg(feature = "cbindings")]
pub use self::totp::cbindings::libreauth_totp_is_valid;
#[cfg(feature = "cbindings")]
pub use self::totp::cbindings::TOTPcfg;
pub use self::totp::TOTPBuilder;
pub use self::totp::TOTP;
