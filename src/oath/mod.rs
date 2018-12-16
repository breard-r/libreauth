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
#[derive(Clone, Copy)]
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
///             <td>CfgNullPtr</td>
///             <td>LIBREAUTH_OATH_CFG_NULL_PTR</td>
///         </tr>
///         <tr>
///             <td>CodeNullPtr</td>
///             <td>LIBREAUTH_OATH_CODE_NULL_PTR</td>
///         </tr>
///         <tr>
///             <td>KeyNullPtr</td>
///             <td>LIBREAUTH_OATH_KEY_NULL_PTR</td>
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
///             <td>CodeInvalidUTF8</td>
///             <td>LIBREAUTH_OATH_CODE_INVALID_UTF8</td>
///         </tr>
///     </tbody>
/// </table>
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub enum ErrorCode {
    Success = 0,

    CfgNullPtr = 1,
    CodeNullPtr = 2,
    KeyNullPtr = 3,

    InvalidBaseLen = 10,
    InvalidKeyLen = 11,
    CodeTooSmall = 12,
    CodeTooBig = 13,

    InvalidKey = 20,
    InvalidPeriod = 21,

    CodeInvalidUTF8 = 30,
}

#[derive(Eq, PartialEq)]
enum UriType {
    TOTP,
    HOTP,
}

/// Creates the Key Uri Format according to the [Google authenticator
/// specification](https://github.com/google/google-authenticator/wiki/Key-Uri-Format) by calling
/// `key_uri_format()` on [`HOTP`] or [`TOTP`]. This value can be used to generete QR
/// codes which allow easy scanning by the end user.
///
/// **WARNING**: The finalized value contains the secret key of the authentication process and
/// should only be displayed to the corresponding user!
///
/// ## Example
///
/// ```
/// let key_ascii = "12345678901234567890".to_owned();
/// let mut totp = libreauth::oath::TOTPBuilder::new()
///     .ascii_key(&key_ascii)
///     .finalize()
///     .unwrap();
///
/// let uri = totp
///     .key_uri_format("Provider1", "alice@gmail.com")
///     .finalize()
///
/// assert_eq!(
///     uri,
///     "otpauth://totp/Provider1:alice@gmail.com?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&issuer=Provider1&algorithm=SHA1&digits=6&period=30"
/// );
/// ```
pub struct KeyUriBuilder<'a> {
    uri_type: UriType,
    key: &'a Vec<u8>,
    issuer: &'a str,
    issuer_param: bool, // add issuer to parameters?
    account_name: &'a str,
    label: Option<&'a str>,
    parameters: Option<&'a str>,
    algo: Option<HashFunction>,
    digits: Option<usize>,
    counter: Option<u64>,
    period: Option<u32>,
}

impl<'a> KeyUriBuilder<'a> {
    /// Do not append the issuer to the parameters section.
    pub fn disable_issuer(&mut self) {
        self.issuer_param = false;
    }
    /// Do not append the hash function to the parameters section.
    pub fn disable_hash_function(&mut self) {
        self.algo = None;
    }
    /// Do not append digits to the parameters section.
    pub fn disable_digits(&mut self) {
        self.digits = None;
    }
    /// Do not append the period to the parameters section.
    pub fn disable_period(&mut self) {
        self.period = None;
    }
    /// Completely overwrite the default `{issuer}:{account_name}` label with a custom one.
    ///
    /// ## Example
    ///
    /// ```
    /// let key_ascii = "12345678901234567890".to_owned();
    /// let mut totp = libreauth::oath::TOTPBuilder::new()
    ///     .ascii_key(&key_ascii)
    ///     .finalize()
    ///     .unwrap();
    ///
    /// let uri = totp
    ///     .key_uri_format("Provider1", "alice@gmail.com")
    ///     .overwrite_label("Provider1Label")
    ///     .finalize()
    ///
    /// assert_eq!(
    ///     uri,
    ///     "otpauth://totp/Provider1Label?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&issuer=Provider1&algorithm=SHA1&digits=6&period=30"
    /// );
    /// ```
    pub fn overwrite_label(&mut self, label: &'a str) {
        self.label = Some(label);
    }
    /// Completely overwrite the default parameters section with a custom one.
    ///
    /// ## Example
    ///
    /// ```
    /// let key_ascii = "12345678901234567890".to_owned();
    /// let mut totp = libreauth::oath::TOTPBuilder::new()
    ///     .ascii_key(&key_ascii)
    ///     .finalize()
    ///     .unwrap();
    ///
    /// let uri = totp
    ///     .key_uri_format("Provider1", "alice@gmail.com")
    ///     .overwrite_parameters("Provider1Parameters")
    ///     .finalize()
    ///
    /// assert_eq!(
    ///     uri,
    ///     "otpauth://totp/Provider1:alice@gmail.com?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&Provider1Parameters"
    /// );
    /// ```
    pub fn overwrite_parameters(&mut self, parameters: &'a str) {
        self.parameters = Some(parameters);
    }
    /// Generate the final format.
    pub fn finalize(&self) -> String {
        let secret_final = base32::encode(
            base32::Alphabet::RFC4648 { padding: false },
            self.key.as_slice(),
        );

        use self::UriType::*;
        let uri_type_final = match self.uri_type {
            TOTP => "totp".to_string(),
            HOTP => "hotp".to_string(),
        };

        // Create the label according to the recommendations,
        // unless a custom label was set (overwritten).
        let label_final = match self.label {
            Some(label) => label.to_string(), // Custom label
            None => format!("{}:{}", self.issuer, self.account_name),
        };

        // Create the parameters structure according to the specification,
        // unless custom parameters were set (overwritten).
        let parameters_final = match self.parameters {
            Some(parameters) => parameters.to_string(), // Custom parameters
            None => {
                // STRONGLY RECOMMENDED: The issuer parameter is a string value indicating the
                // provider or service this account is associated with. If the issuer parameter
                // is absent, issuer information may be taken from the issuer prefix of the label.
                // If both issuer parameter and issuer label prefix are present, they should be equal.
                let mut issuer_final = String::new();
                if self.issuer_param {
                    issuer_final = format!("issuer={}", self.issuer);
                }

                // OPTIONAL: The algorithm may have the values: SHA1 (Default), SHA256, SHA512.
                let mut algo_final = String::new();
                if let Some(algo) = self.algo {
                    algo_final = match algo {
                        Sha1 => "&algorithm=SHA1".to_string(),
                        Sha256 => "&algorithm=SHA256".to_string(),
                        Sha512 => "&algorithm=SHA512".to_string(),
                        _ => "".to_string(),
                    };
                }

                // OPTIONAL: The digits parameter may have the values 6 or 8, and determines how
                // long of a one-time passcode to display to the user. The default is 6.
                let mut digits_final = String::new();
                if let Some(digits) = self.digits {
                    digits_final = format!("&digits={}", digits);
                }

                // REQUIRED if type is hotp: The counter parameter is required when provisioning
                // a key for use with HOTP. It will set the initial counter value.
                let mut counter_final = String::new();
                if self.uri_type == HOTP {
                    // Unwraping here is safe, since the counter is required for HOTP.
                    // Panicing would indicate a bug in `HOTP.key_uri_format()`.
                    counter_final = format!("&counter={}", self.counter.unwrap());
                }

                // OPTIONAL only if type is totp: The period parameter defines a period that a
                // TOTP code will be valid for, in seconds. The default value is 30.
                let mut period_final = String::new();
                if let Some(period) = self.period {
                    period_final = format!("&period={}", period);
                }

                format!(
                    "{issuer}{algo}{digits}{counter}{period}",
                    issuer = issuer_final,
                    algo = algo_final,
                    digits = digits_final,
                    counter = counter_final,
                    period = period_final,
                )
            }
        };

        url_encode(
            &format!(
                "otpauth://{uri_type}/{label}?secret={secret}&{params}",
                uri_type = uri_type_final,
                label = label_final,
                secret = secret_final,
                params = parameters_final,
            )
        ).to_string()
    }
}

/// The source code within this function was taken from the
/// [rust_urlencoding](https://github.com/bt/rust_urlencoding) library.
///
/// Copyright (c) 2016 Bertram Truong
///
/// Permission is hereby granted, free of charge, to any person obtaining a copy
/// of this software and associated documentation files (the "Software"), to deal
/// in the Software without restriction, including without limitation the rights
/// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
/// copies of the Software, and to permit persons to whom the Software is
/// furnished to do so, subject to the following conditions:
///
/// The above copyright notice and this permission notice shall be included in
/// all copies or substantial portions of the Software.
///
/// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
/// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
/// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
/// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
/// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
/// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
/// THE SOFTWARE.
fn url_encode(data: &str) -> String {
    let mut escaped = String::new();
    for b in data.as_bytes().iter() {
        match *b as char {
            // Accepted characters
            'A'...'Z' | 'a'...'z' | '0'...'9' | '-' | '_' | '.' | '~' => escaped.push(*b as char),

            // Everything else is percent-encoded
            b => escaped.push_str(format!("%{:02X}", b as u32).as_str()),
        };
    }
    return escaped;
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

        /// Sets the base used to represents the output code. Default is "0123456789".to_owned().into_bytes().
        pub fn output_base(&mut self, base: &[u8]) -> &mut $t {
            self.output_base = base.to_owned();
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
    use std;

    pub fn write_code(code: &Vec<u8>, dest: &mut [u8]) {
        let len = code.len();
        for i in 0..len {
            dest[i] = code[i];
        }
        dest[len] = 0;
    }

    pub fn get_cfg<T>(cfg: *const T) -> Result<&'static T, ErrorCode> {
        if cfg.is_null() {
            return Err(ErrorCode::CfgNullPtr);
        }
        let cfg: &T = unsafe { &*cfg };
        Ok(cfg)
    }

    pub fn get_code(code: *const u8, code_len: usize) -> Result<String, ErrorCode> {
        if code.is_null() {
            return Err(ErrorCode::CodeNullPtr);
        }
        let code = unsafe { std::slice::from_raw_parts(code, code_len).to_owned() };
        match String::from_utf8(code) {
            Ok(code) => Ok(code),
            Err(_) => Err(ErrorCode::CodeInvalidUTF8),
        }
    }

    pub fn get_mut_code(code: *mut u8, code_len: usize) -> Result<&'static mut [u8], ErrorCode> {
        if code.is_null() {
            return Err(ErrorCode::CodeNullPtr);
        }
        Ok(unsafe { std::slice::from_raw_parts_mut(code, code_len + 1) })
    }

    pub fn get_output_base(
        output_base: *const u8,
        output_base_len: usize,
    ) -> Result<Vec<u8>, ErrorCode> {
        match output_base.is_null() {
            false => match output_base_len {
                0 | 1 => Err(ErrorCode::InvalidBaseLen),
                l => Ok(unsafe { std::slice::from_raw_parts(output_base, l).to_owned() }),
            },
            true => Ok("0123456789".to_owned().into_bytes()),
        }
    }

    pub fn get_key(key: *const u8, key_len: usize) -> Result<Vec<u8>, ErrorCode> {
        match key.is_null() {
            false => match key_len {
                0 => Err(ErrorCode::InvalidKeyLen),
                l => Ok(unsafe { std::slice::from_raw_parts(key, l).to_owned() }),
            },
            true => Err(ErrorCode::KeyNullPtr),
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
                c.output_len = 6;
                c.output_base = std::ptr::null();
                c.output_base_len = 0;
                c.hash_function = HashFunction::Sha1;
                $(
                    c.$field = $value;
                )*
                Ok(c)
            }
            true => Err(ErrorCode::CfgNullPtr),
        }
    }
}

#[cfg(feature = "cbindings")]
macro_rules! get_value_or_errno {
    ($val:expr) => {{
        match $val {
            Ok(v) => v,
            Err(errno) => return errno,
        }
    }};
}

#[cfg(feature = "cbindings")]
macro_rules! get_value_or_false {
    ($val:expr) => {{
        match $val {
            Ok(v) => v,
            Err(_) => return 0,
        }
    }};
}

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
