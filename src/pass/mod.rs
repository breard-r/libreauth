/*
 * Copyright Rodolphe Breard (2016-2017)
 * Author: Rodolphe Breard (2016-2017)
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

//! Password authentication module.
//!
//! It allows you to:
//!
//! - generate a fingerprint of the password that could be stored;
//! - check a password against the stored fingerprint.
//!
//!
//! ## Standards
//!
//! By default, LibreAuth has security in mind and therefore provides a decent level of security.
//!
//! Sometimes, you may be required to use some approved items in order to comply with various standards. If you are in such a situation, LibreAuth can adapt to some well-known standards. Keep in mind that LibreAuth does only a part of the job, you may be required to implement additional components in order to comply with the minimal requirements of the selected standard.
//!
//! ## Storage format
//!
//! The password fingerprint is stored in the [PHC] format which is very close to the modular crypt format (cf. [[1]] and [[2]]).
//!
//! ## Supported identifiers and parameters
//!
//! <style>
//! .vcentered_table th, .vcentered_table td {vertical-align: middle;}
//! .vcentered_table > thead > tr > th {text-align: center;}
//! .vcentered_table > tbody > tr > td:last-child {text-align: center;}
//! .hash {text-align: center; vertical-align: middle;}
//! .legend {font-style: italic; font-size: smaller; color: gray;}
//! </style>
//! <table class="vcentered_table">
//!     <thead>
//!         <tr>
//!             <th>Algorithm</th>
//!             <th>Parameter name</th>
//!             <th>Parameter type</th>
//!             <th>Parameter description</th>
//!             <th>Default value</th>
//!         </tr>
//!     </thead>
//!     <tbody>
//!         <tr>
//!             <td rowspan="5" class="hash">argon2<br /><span class="legend">default</span></td>
//!             <td>passes</td>
//!             <td>integer</td>
//!             <td>The number of block matrix iterations to perform.</td>
//!             <td>3</td>
//!         </tr>
//!         <tr>
//!             <td>mem</td>
//!             <td>integer</td>
//!             <td>Memmory cost (2^mem kibbibytes).</td>
//!             <td>12 (4096 KiB)</td>
//!         </tr>
//!         <tr>
//!             <td>lanes</td>
//!             <td>integer</td>
//!             <td>The degree of parallelism by which memory is filled during hash computation.</td>
//!             <td>4</td>
//!         </tr>
//!         <tr>
//!             <td>len</td>
//!             <td>integer</td>
//!             <td>Output length, in bytes.</td>
//!             <td>32</td>
//!         </tr>
//!         <tr>
//!             <td>norm</td>
//!             <td>string: nfd | nfkd | nfc | nfkc | none</td>
//!             <td>Unicode normalization.</td>
//!             <td>nfkc</td>
//!         </tr>
//!         <tr>
//!             <td rowspan="3" class="hash">pbkdf2<br /><span class="legend">NIST SP 800-63B</span></td>
//!             <td>iter</td>
//!             <td>integer</td>
//!             <td>Number of iterations.</td>
//!             <td>45000</td>
//!         </tr>
//!         <tr>
//!             <td>hash</td>
//!             <td>string: sha1 | sha224 | sha256 | sha384 | sha512 | sha512t224 | sha512t256</td>
//!             <td>The hash function.</td>
//!             <td>sha256</td>
//!         </tr>
//!         <tr>
//!             <td>norm</td>
//!             <td>string: nfd | nfkd | nfc | nfkc | none</td>
//!             <td>Unicode normalization.</td>
//!             <td>nfkc</td>
//!         </tr>
//!     </tbody>
//! </table>
//!
//! ## Examples
//! ```rust
//! let password = "correct horse battery staple".to_string().into_bytes();
//! let stored_password = libreauth::pass::password_hash(&password).unwrap().into_bytes();
//! assert!(! libreauth::pass::is_valid(&"bad password".to_string().into_bytes(), &stored_password));
//! assert!(libreauth::pass::is_valid(&password, &stored_password));
//! ```
//!
//! [PHC]: https://github.com/P-H-C/phc-string-format/blob/master/phc-sf-spec.md
//! [1]: https://en.wikipedia.org/wiki/Crypt_(C)#Key_Derivation_Functions_Supported_by_crypt
//! [2]: https://pythonhosted.org/passlib/modular_crypt_format.html

use sha2::Sha512;
use hmac::{Hmac, Mac};
use key::KeyBuilder;

/// The minimal accepted length for passwords.
///
/// ## C interface
/// The C interface refers at this constant as `LIBREAUTH_PASSWORD_MIN_LEN`.
pub const PASSWORD_MIN_LEN: usize = 8;
/// The maximal accepted length for passwords.
///
/// A basic security advice is to use long password, therefore is may appear that limiting the
/// maximal length is a bad idea. However, authorizing arbitrary size password leads to a DOS
/// vulnerability: an attacker would submit excessively long passwords that would take ages to
/// compute, exhausting the resources. Such vulnerabilities has already been reported, like
/// CVE-2014-9016, CVE-2014-9034, CVE-2014-9218, and so on.
///
/// ## C interface
/// The C interface refers at this constant as `LIBREAUTH_PASSWORD_MAX_LEN`.
pub const PASSWORD_MAX_LEN: usize = 128;

/// Error codes used both in the rust and C interfaces.
///
/// ## C interface
/// The C interface uses an enum of type `libreauth_pass_errno` and the members has been renamed
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
///             <td>Success</td>
///             <td>LIBREAUTH_PASS_SUCCESS</td>
///         </tr>
///         <tr>
///             <td>PasswordTooShort</td>
///             <td>LIBREAUTH_PASS_PASSWORD_TOO_SHORT</td>
///         </tr>
///         <tr>
///             <td>PasswordTooLong</td>
///             <td>LIBREAUTH_PASS_PASSWORD_TOO_LONG</td>
///         </tr>
///         <tr>
///             <td>InvalidPasswordFormat</td>
///             <td>LIBREAUTH_PASS_INVALID_PASSWORD_FORMAT</td>
///         </tr>
///         <tr>
///             <td>NotEnoughSpace</td>
///             <td>LIBREAUTH_PASS_NOT_ENOUGH_SPACE</td>
///         </tr>
///     </tbody>
/// </table>
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub enum ErrorCode {
    /// Used in C-bindings to indicate the absence of errors.
    Success = 0,
    /// The password is shorter than [PASSWORD_MIN_LEN][1].
    /// [1]: constant.PASSWORD_MIN_LEN.html
    PasswordTooShort = 1,
    /// The password is longer than [PASSWORD_MAX_LEN][1].
    /// [1]: constant.PASSWORD_MAX_LEN.html
    PasswordTooLong = 2,
    /// The input does not respect the [storage format][1].
    /// [1]: index.html#storage-format
    InvalidPasswordFormat = 10,
    /// Used in C-bindings to indicate the storage does not have enough space to store the data.
    NotEnoughSpace = 20,
}

/// Defines whether or not LibreAuth should comply with recommendations from a specific standard.
///
/// ## C interface
/// The C interface uses an enum of type `libreauth_pass_standard` and the members has been renamed
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
///             <td>NoStandard</td>
///             <td>LIBREAUTH_PASS_NOSTANDARD</td>
///         </tr>
///         <tr>
///             <td>Nist80063b</td>
///             <td>LIBREAUTH_PASS_NIST80063B</td>
///         </tr>
///     </tbody>
/// </table>
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub enum PasswordStorageStandard {
    /// Default mode of operation, safe.
    NoStandard = 0,
    /// Comply with the [NIST Special Publication 800-63B](https://pages.nist.gov/800-63-3/sp800-63b.html).
    Nist80063b = 1,
}

mod hash;
mod phc;

/// Hash a password and returns its string representation so it can be stored.
///
/// The algorithm is automatically chosen by LibreAuth depending on the current state of
/// cryptography. This is why you should keep this crate up-to-date.
///
/// ## Examples
/// ```rust
/// let password = "1234567890".to_string().into_bytes();
/// let stored_password = libreauth::pass::password_hash(&password).unwrap();
/// ```
pub fn password_hash(password: &Vec<u8>) -> Result<String, ErrorCode> {
    password_hash_standard(password, PasswordStorageStandard::NoStandard)
}

/// Hash a password and returns its string representation so it can be stored.
///
/// The algorithm is chosen by LibreAuth in accordance the recommendations of the specified standard.
///
/// ## Examples
/// ```rust
/// let password = "1234567890".to_string().into_bytes();
/// let stored_password = libreauth::pass::password_hash_standard(&password, libreauth::pass::PasswordStorageStandard::Nist80063b).unwrap();
/// ```
pub fn password_hash_standard(
    password: &Vec<u8>,
    standard: PasswordStorageStandard,
) -> Result<String, ErrorCode> {
    match hash::PasswordHasher::new(standard).hash(password) {
        Ok(s) => Ok(s.to_string().unwrap()),
        Err(e) => Err(e),
    }
}

/// Check whether or not a s supplied password matches the stored hash.
///
/// ## Examples
/// ```rust
/// let password = "correct horse battery staple".to_string().into_bytes();
/// let stored_password = libreauth::pass::password_hash(&password).unwrap().into_bytes();
/// assert!(! libreauth::pass::is_valid(&"bad password".to_string().into_bytes(), &stored_password));
/// assert!(libreauth::pass::is_valid(&password, &stored_password));
/// ```
///
/// ```rust
/// let stored_reference = "$pbkdf2$hash=sha256,iter=21000$RSF4Aw$pgenLCySNXpFaLmYxfcI+AHwsf+66iBTV+COTTJYMMk".to_string().into_bytes();
/// assert!(! libreauth::pass::is_valid(&"bad password".to_string().into_bytes(), &stored_reference));
/// assert!(libreauth::pass::is_valid(&"password123".to_string().into_bytes(), &stored_reference));
/// ```
pub fn is_valid(password: &Vec<u8>, stored_hash: &Vec<u8>) -> bool {
    match phc::PHCData::from_bytes(stored_hash) {
        Ok(sh) => match hash::PasswordHasher::new_from_phc(&sh) {
            Ok(hasher) => match hasher.hash(password) {
                Ok(hashed_pass) => {
                    let salt = KeyBuilder::new().size(32).as_vec();

                    let sh_value = match sh.hash {
                        Some(v) => v,
                        None => {
                            return false;
                        }
                    };
                    let mut ref_hmac = match Hmac::<Sha512>::new_varkey(&salt) {
                        Ok(h) => h,
                        Err(_) => {
                            return false;
                        }
                    };
                    ref_hmac.input(sh_value.as_slice());

                    let mut pass_hmac = match Hmac::<Sha512>::new_varkey(&salt) {
                        Ok(h) => h,
                        Err(_) => {
                            return false;
                        }
                    };
                    pass_hmac.input(hashed_pass.hash.unwrap().as_slice());

                    ref_hmac.result().code() == pass_hmac.result().code()
                }
                Err(_) => false,
            },
            Err(_) => false,
        },
        Err(_) => false,
    }
}

#[cfg(feature = "cbindings")]
mod cbindings {
    use super::*;
    use libc;
    use std;

    /// [C binding] Hash a password and returns its string representation so it can be stored.
    ///
    /// ## Examples
    /// ```c
    /// const char password[] = "correct horse battery staple";
    /// uint8_t derived_password[LIBREAUTH_PASS_STORAGE_LEN];
    ///
    /// libreauth_pass_errno ret = libreauth_password_hash(password, derived_password, LIBREAUTH_PASS_STORAGE_LEN);
    /// if (ret == LIBREAUTH_PASS_SUCCESS) {
    ///     // Store derived_password.
    /// } else {
    ///     // Handle the error.
    /// }
    /// ```
    #[no_mangle]
    pub extern "C" fn libreauth_password_hash(
        password: *const libc::c_char,
        storage: *mut libc::uint8_t,
        storage_len: libc::size_t,
    ) -> ErrorCode {
        libreauth_password_hash_standard(
            password,
            storage,
            storage_len,
            PasswordStorageStandard::NoStandard,
        )
    }

    /// [C binding] Hash a password and returns its string representation so it can be stored.
    ///
    /// ## Examples
    /// ```c
    /// const char password[] = "correct horse battery staple";
    /// uint8_t derived_password[LIBREAUTH_PASS_STORAGE_LEN];
    ///
    /// libreauth_pass_errno ret = libreauth_password_hash_standard(password, derived_password, LIBREAUTH_PASS_STORAGE_LEN, LIBREAUTH_PASS_NIST80063B);
    /// if (ret == LIBREAUTH_PASS_SUCCESS) {
    ///     // Store derived_password.
    /// } else {
    ///     // Handle the error.
    /// }
    /// ```
    #[no_mangle]
    pub extern "C" fn libreauth_password_hash_standard(
        password: *const libc::c_char,
        storage: *mut libc::uint8_t,
        storage_len: libc::size_t,
        standard: PasswordStorageStandard,
    ) -> ErrorCode {
        let r_storage = unsafe {
            assert!(!storage.is_null());
            std::slice::from_raw_parts_mut(storage, storage_len as usize)
        };
        let c_password = unsafe {
            assert!(!password.is_null());
            std::ffi::CStr::from_ptr(password)
        };
        let r_password = c_password.to_bytes().to_vec();
        let r_derived_password = match password_hash_standard(&r_password, standard) {
            Ok(some) => some,
            Err(errno) => return errno,
        };
        let out_len = r_derived_password.len();
        let pass_b = r_derived_password.into_bytes();
        if out_len >= storage_len as usize {
            return ErrorCode::NotEnoughSpace;
        }
        for i in 0..out_len {
            r_storage[i] = pass_b[i];
        }
        r_storage[out_len] = 0;
        ErrorCode::Success
    }

    /// [C binding] Check whether or not the password is valid.
    ///
    /// ## Examples
    /// ```c
    /// const char password[] = "correct horse battery staple",
    ///       invalid_pass[] = "123456";
    /// uint8_t storage[LIBREAUTH_PASS_STORAGE_LEN];
    ///
    /// libreauth_pass_errno ret = libreauth_password_password_hash(password, storage, LIBREAUTH_PASS_STORAGE_LEN);
    /// assert(ret == LIBREAUTH_PASS_SUCCESS);
    /// assert(libreauth_password_is_valid(password, storage));
    /// assert(!libreauth_password_is_valid(invalid_pass, storage));
    /// ```
    #[no_mangle]
    pub extern "C" fn libreauth_password_is_valid(
        password: *const libc::c_char,
        reference: *const libc::c_char,
    ) -> libc::int32_t {
        let c_password = unsafe {
            assert!(!password.is_null());
            std::ffi::CStr::from_ptr(password)
        };
        let r_password = c_password.to_bytes().to_vec();
        let c_reference = unsafe {
            assert!(!reference.is_null());
            std::ffi::CStr::from_ptr(reference)
        };
        let r_reference = c_reference.to_bytes().to_vec();
        is_valid(&r_password, &r_reference) as libc::int32_t
    }
}

#[cfg(feature = "cbindings")]
pub use self::cbindings::libreauth_password_hash_standard;
#[cfg(feature = "cbindings")]
pub use self::cbindings::libreauth_password_hash;
#[cfg(feature = "cbindings")]
pub use self::cbindings::libreauth_password_is_valid;

#[cfg(test)]
mod tests {
    use super::*;

    /// This test does not guaranty the random is cryptographically safe. It only test whether or not it is not absolutely inefficient.
    /// We generate 512 random 6 bytes salts. If there is any duplicate, the test fails.
    #[test]
    fn test_salt_gen() {
        let mut vec = Vec::new();
        for _ in 0..512 {
            let s = KeyBuilder::new().size(6).as_vec();
            vec.push(s);
        }
        let l = vec.len();
        vec.dedup();
        assert_eq!(l, vec.len());
    }

    #[test]
    fn test_default_hash() {
        let password = "correct horse battery staple".to_string().into_bytes();
        let h = password_hash(&password).unwrap().into_bytes();
        assert!(!is_valid(&"bad password".to_string().into_bytes(), &h));
        assert!(is_valid(&password, &h));
    }

    #[test]
    fn test_default_normalization() {
        let pass1 = vec![
            0x75, 0x6e, 0x69, 0x63, 0x6f, 0x64, 0x65, 0xe2, 0x84, 0xab, 0xe2, 0x84, 0xa6, 0x31,
            0x32,
        ];
        let pass2 = vec![
            0x75, 0x6e, 0x69, 0x63, 0x6f, 0x64, 0x65, 0xe2, 0x84, 0xab, 0xe2, 0x84, 0xa6, 0x31,
            0x31,
        ];
        let pass3 = vec![
            0x75, 0x6e, 0x69, 0x63, 0x6f, 0x64, 0x65, 0xc3, 0x85, 0xce, 0xa9, 0x31, 0x32
        ];
        let h = password_hash(&pass1).unwrap().into_bytes();
        assert!(!is_valid(&pass2, &h));
        assert!(is_valid(&pass3, &h));
    }

    #[test]
    fn test_std_nist_normalization() {
        let pass1 = vec![
            0x75, 0x6e, 0x69, 0x63, 0x6f, 0x64, 0x65, 0xe2, 0x84, 0xab, 0xe2, 0x84, 0xa6, 0x31,
            0x32,
        ];
        let pass2 = vec![
            0x75, 0x6e, 0x69, 0x63, 0x6f, 0x64, 0x65, 0xe2, 0x84, 0xab, 0xe2, 0x84, 0xa6, 0x31,
            0x31,
        ];
        let pass3 = vec![
            0x75, 0x6e, 0x69, 0x63, 0x6f, 0x64, 0x65, 0xc3, 0x85, 0xce, 0xa9, 0x31, 0x32
        ];
        let h = password_hash_standard(&pass1, PasswordStorageStandard::Nist80063b)
            .unwrap()
            .into_bytes();
        assert!(!is_valid(&pass2, &h));
        assert!(is_valid(&pass3, &h));
    }
}
