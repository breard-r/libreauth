/*
 * Copyright Rodolphe Breard (2015-2018)
 * Author: Rodolphe Breard (2015-2018)
 *
 * This software is a computer library whose purpose is to offer a
 * collection of tools for user authentication.
 *
 * This software is governed by the CeCILL  license under French law and
 * abiding by the rules of distribution of free software.  You can  use,
 * modify and/ or redistribute the software under the terms of the CeCILL
 * license as circulated by CEA, CNRS and INRIA at the following URL
 * "http://www.cecill.info".
 *
 * As a counterpart to the access to the source code and  rights to copy,
 * modify and redistribute granted by the license, users are provided only
 * with a limited warranty  and the software's author,  the holder of the
 * economic rights,  and the successive licensors  have only  limited
 * liability.
 *
 * In this respect, the user's attention is drawn to the risks associated
 * with loading,  using,  modifying and/or developing or reproducing the
 * software by the user in light of its specific status of free software,
 * that may mean  that it is complicated to manipulate,  and  that  also
 * therefore means  that it is reserved for developers  and  experienced
 * professionals having in-depth computer knowledge. Users are therefore
 * encouraged to load and test the software's suitability as regards their
 * requirements in conditions enabling the security of their systems and/or
 * data to be ensured and,  more generally, to use and operate it in the
 * same conditions as regards security.
 *
 * The fact that you are presently reading this means that you have had
 * knowledge of the CeCILL license and that you accept its terms.
 */

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
