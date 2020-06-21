//! Implementation of standards which are part of the [OATH Reference
//! Architecture](https://openauthentication.org/specifications-technical-resources/).
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

use crate::hash::HashFunction;

#[cfg(feature = "oath-uri")]
const DEFAULT_KEY_URI_PARAM_POLICY: ParametersVisibility = ParametersVisibility::ShowNonDefault;
const DEFAULT_OTP_HASH: HashFunction = HashFunction::Sha1;
const DEFAULT_OTP_OUT_BASE: &str = "0123456789";
const DEFAULT_OTP_OUT_LEN: usize = 6;
const DEFAULT_TOTP_PERIOD: u32 = 30;
const DEFAULT_TOTP_T0: u64 = 0;
const DEFAULT_LOOK_AHEAD: u64 = 0;

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
                Ok(k) => {
                    self.key = Some(k);
                }
                Err(_) => {
                    self.runtime_error = Some(ErrorCode::InvalidKey);
                }
            }
            self
        }

        /// Sets the shared secret. This secret is passed as a base32 encoded string.
        pub fn base32_key(&mut self, key: &str) -> &mut $t {
            match base32::decode(base32::Alphabet::RFC4648 { padding: false }, &key) {
                Some(k) => {
                    self.key = Some(k);
                }
                None => {
                    self.runtime_error = Some(ErrorCode::InvalidKey);
                }
            }
            self
        }

        /// Sets the shared secret. This secret is passed as a base64 encoded string.
        pub fn base64_key(&mut self, key: &str) -> &mut $t {
            match base64::decode(key) {
                Ok(k) => {
                    self.key = Some(k);
                }
                Err(_) => {
                    self.runtime_error = Some(ErrorCode::InvalidKey);
                }
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
    };
}

#[cfg(feature = "oath-uri")]
mod key_uri;
#[cfg(feature = "oath-uri")]
pub use self::key_uri::{KeyUriBuilder, ParametersVisibility};

mod hotp;
pub use self::hotp::HOTPBuilder;
pub use self::hotp::HOTP;

mod totp;
pub use self::totp::TOTPBuilder;
pub use self::totp::TOTP;

#[cfg(feature = "cbindings")]
mod cbindings;
#[cfg(feature = "cbindings")]
pub use self::cbindings::libreauth_hotp_generate;
#[cfg(all(feature = "cbindings", feature = "oath-uri"))]
pub use self::cbindings::libreauth_hotp_get_uri;
#[cfg(feature = "cbindings")]
pub use self::cbindings::libreauth_hotp_init;
#[cfg(feature = "cbindings")]
pub use self::cbindings::libreauth_hotp_is_valid;
#[cfg(feature = "cbindings")]
pub use self::cbindings::HOTPcfg;

#[cfg(feature = "cbindings")]
pub use self::cbindings::libreauth_totp_generate;
#[cfg(all(feature = "cbindings", feature = "oath-uri"))]
pub use self::cbindings::libreauth_totp_get_uri;
#[cfg(feature = "cbindings")]
pub use self::cbindings::libreauth_totp_init;
#[cfg(feature = "cbindings")]
pub use self::cbindings::libreauth_totp_is_valid;
#[cfg(feature = "cbindings")]
pub use self::cbindings::TOTPcfg;
