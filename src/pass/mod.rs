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
//! ## Storage format
//!
//! The password fingerprint is stored in the [PHC] format which is very close to the modular crypt format (cf. [[1]] and [[2]]).
//!
//! ## Supported identifiers and parameters
//!
//! <style>
//! .vcentered_table th, .vcentered_table td {vertical-align: middle;}
//! .vcentered_table > thead > tr > th {text-align: center;}
//! </style>
//! <table class="vcentered_table">
//!     <thead>
//!         <tr>
//!             <th>Algorithm</th>
//!             <th>Parameter name</th>
//!             <th>Parameter type</th>
//!             <th>Parameter description</th>
//!         </tr>
//!     </thead>
//!     <tbody>
//!         <tr>
//!             <td style="vertical-align: middle;">pbkdf2-sha512</td>
//!             <td>i</td>
//!             <td>integer<br>Default: 21000</td>
//!             <td>Number of iterations.</td>
//!         </tr>
//!         <tr>
//!             <td style="vertical-align: middle;">pbkdf2-sha256</td>
//!             <td>i</td>
//!             <td>integer<br>Default: 21000</td>
//!             <td>Number of iterations.</td>
//!         </tr>
//!         <tr>
//!             <td rowspan="2" style="vertical-align: middle;">pbkdf2</td>
//!             <td>i</td>
//!             <td>integer<br>Default: 21000</td>
//!             <td>Number of iterations.</td>
//!         </tr>
//!         <tr>
//!             <td>h</td>
//!             <td>string: sha1|sha256|sha512<br>Default: sha1</td>
//!             <td>The hash function.</td>
//!         </tr>
//!     </tbody>
//! </table>
//!
//! ## Examples
//! ```rust
//! let password = "correct horse battery staple";
//! let derived_password = libreauth::pass::derive_password(password).unwrap();
//! assert!(! libreauth::pass::is_valid("bad password", &derived_password));
//! assert!(libreauth::pass::is_valid(&password, &derived_password));
//! ```
//!
//! [PHC]: https://github.com/P-H-C/phc-string-format/blob/master/phc-sf-spec.md
//! [1]: https://en.wikipedia.org/wiki/Crypt_(C)#Key_Derivation_Functions_Supported_by_crypt
//! [2]: https://pythonhosted.org/passlib/modular_crypt_format.html

use rand::{Rng,thread_rng};
use crypto::mac::Mac;
use crypto::hmac::Hmac;
use crypto::sha2::Sha512;


/// The minimal accepted length for passwords.
///
/// This value is set at a quite low level so LibreAuth can be used is some scenarios where it is
/// ok to use such weak passwords. If the password is the main if not only authentication factor,
/// you should enforce a more robust policy beforehand.
///
/// ## C interface
/// The C interface refers at this constant as `LIBREAUTH_PASS_PASSWORD_MIN_LEN`.
pub const PASSWORD_MIN_LEN: usize = 4;
/// The maximal accepted length for passwords.
///
/// A basic security advice is to use long password, therefore is may appear that limiting the
/// maximal length is a bad idea. However, authorizing arbitrary size password leads to a DOS
/// vulnerability: an attacker would submit excessively long passwords that would take ages to
/// compute, exhausting the resources. Such vulnerabilities has already been reported, like
/// CVE-2014-9016, CVE-2014-9034, CVE-2014-9218, and so on.
///
/// ## C interface
/// The C interface refers at this constant as `LIBREAUTH_PASS_PASSWORD_MAX_LEN`.
pub const PASSWORD_MAX_LEN: usize = 128;


/// Error codes used both in the rust and C interfaces.
///
/// ## C interface
/// The C interface uses an enum of type `libreauth_pass_errno` and the members has been renamed
/// as follows:
/// <style>
/// .vcentered_table th, .vcentered_table td {vertical-align: middle;}
/// .vcentered_table > thead > tr > th {text-align: center;}
/// </style>
/// <table class="vcentered_table">
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
    /// The input does not respect the [modular crypt format][1].
    /// [1]: index.html#modular-crypt-format
    InvalidPasswordFormat = 10,
    /// Used in C-bindings to indicate the storage does not have enough space to store the data.
    NotEnoughSpace = 20,
}

mod derivation;
mod phc;

fn generate_salt(nb_bytes: usize) -> Vec<u8> {
    let mut salt: Vec<u8> = vec![0; nb_bytes];
    thread_rng().fill_bytes(&mut salt);
    salt
}

/// Derivate a password so it can be stored.
///
/// The algorithm is automatically chosen by LibreAuth depending on the current state of
/// cryptography. This is why you should keep this crate up-to-date.
///
/// ## Examples
/// ```rust
/// let password = "1234567890";
/// let stored_password = libreauth::pass::derive_password(password).unwrap();
/// ```
pub fn derive_password(password: &str) -> Result<String, ErrorCode> {
    match derivation::PasswordDerivationFunctionBuilder::new().finalize() {
        Ok(some) => some.derive(password),
        Err(err) => Err(err),
    }
}

/// Check whether or not the password is valid.
///
/// ## Examples
/// ```rust
/// let password = "correct horse battery staple";
/// let stored_password = libreauth::pass::derive_password(password).unwrap();
/// assert!(! libreauth::pass::is_valid("bad password", &stored_password));
/// assert!(libreauth::pass::is_valid(&password, &stored_password));
/// ```
///
/// ```rust
/// let stored_reference = "$pbkdf2-sha256$i=21000$RSF4Aw$pgenLCySNXpFaLmYxfcI+AHwsf+66iBTV+COTTJYMMk";
/// assert!(! libreauth::pass::is_valid("bad password", stored_reference));
/// assert!(libreauth::pass::is_valid("password123", stored_reference));
/// ```
pub fn is_valid(password: &str, reference: &str) -> bool {
    match derivation::PasswordDerivationFunctionBuilder::new().set_reference_hash(reference).finalize() {
        Ok(algo) => match algo.derive(password) {
            Ok(derived_pass) => {
                let salt = generate_salt(32);

                let mut ref_hmac = Hmac::new(Sha512::new(), &salt);
                ref_hmac.input(&reference.split("$").collect::<Vec<&str>>().last().unwrap().as_bytes());

                let mut pass_hmac = Hmac::new(Sha512::new(), &salt);
                pass_hmac.input(&derived_pass.split("$").collect::<Vec<&str>>().last().unwrap().as_bytes());

                ref_hmac.result() == pass_hmac.result()
            },
            Err(_) => false,
        },
        Err(_) => false,
    }
}

#[cfg(feature = "cbindings")]
mod cbindings {
    use super::{ErrorCode,derive_password,is_valid};
    use libc;
    use std;

    /// [C binding] Derivate a password so it can be stored.
    ///
    /// ## Examples
    /// ```c
    /// const char password[] = "correct horse battery staple";
    /// uint8_t derived_password[LIBREAUTH_PASS_STORAGE_LEN];
    ///
    /// libreauth_pass_errno ret = libreauth_pass_derive_password(password, derived_password, LIBREAUTH_PASS_STORAGE_LEN);
    /// if (ret == LIBREAUTH_PASS_SUCCESS) {
    ///     // Store derived_password.
    /// } else {
    ///     // Handle the error.
    /// }
    /// ```
    #[no_mangle]
    pub extern fn libreauth_pass_derive_password(password: *const libc::c_char, storage: *mut libc::uint8_t, storage_len: libc::size_t) -> ErrorCode {
        let mut r_storage = unsafe {
            assert!(!storage.is_null());
            std::slice::from_raw_parts_mut(storage, storage_len as usize)
        };
        let c_password = unsafe {
            assert!(!password.is_null());
            std::ffi::CStr::from_ptr(password)
        };
        let r_password = c_password.to_str().unwrap();
        let r_derived_password = match derive_password(r_password){
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
        };
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
    /// libreauth_pass_errno ret = libreauth_pass_derive_password(password, storage, LIBREAUTH_PASS_STORAGE_LEN);
    /// assert(ret == LIBREAUTH_PASS_SUCCESS);
    /// assert(libreauth_pass_is_valid(password, storage));
    /// assert(!libreauth_pass_is_valid(invalid_pass, storage));
    /// ```
    #[no_mangle]
    pub extern fn libreauth_pass_is_valid(password: *const libc::c_char, reference: *const libc::c_char) -> libc::int32_t {
        let c_password = unsafe {
            assert!(!password.is_null());
            std::ffi::CStr::from_ptr(password)
        };
        let r_password = c_password.to_str().unwrap();
        let c_reference = unsafe {
            assert!(!reference.is_null());
            std::ffi::CStr::from_ptr(reference)
        };
        let r_reference = c_reference.to_str().unwrap();
        is_valid(r_password, r_reference) as libc::int32_t
    }
}

#[cfg(feature = "cbindings")]
pub use self::cbindings::libreauth_pass_derive_password;
#[cfg(feature = "cbindings")]
pub use self::cbindings::libreauth_pass_is_valid;

#[cfg(test)]
mod tests {
    use super::{derive_password,is_valid};
    use super::derivation::PasswordDerivationFunctionBuilder;

    #[test]
    fn test_default_derivation() {
        let password = "123456";
        let stored_password = derive_password(password).unwrap();
        assert!(stored_password.starts_with("$pbkdf2-sha512$"));
    }

    #[test]
    fn test_random_salt() {
        let password = "derp";
        let stored_password_1 = derive_password(password).unwrap();
        let stored_password_2 = derive_password(password).unwrap();
        assert!(stored_password_1 != stored_password_2);
    }

    #[test]
    #[should_panic]
    fn test_empty_password_deriv() {
        derive_password("").unwrap();
    }

    #[test]
    #[should_panic]
    fn test_short_password_deriv() {
        derive_password("abc").unwrap();
    }

    #[test]
    fn test_empty_password_validation() {
        let stored_password = "$pbkdf2$0$RSF4Aw$La3iARLBBcBSD4vAi6wqO+DCQaU";
        assert!(! is_valid("", stored_password));
    }

    #[test]
    fn test_short_password_validation() {
        let stored_password = "$pbkdf2$0$RSF4Aw$zgNbu4BBTePeAdxUqe4gSyetGuU";
        assert!(! is_valid("abc", stored_password));
    }

    #[test]
    fn test_utf8_passwords() {
        let password_list = [
            "è_é ÖÀ",
            "пароль",
            "密码",
            "密碼",
            "كلمه السر",
            "ль\n\n\n密à\r\n$",
            "😁😊😣😺✅✨❕➡🚀🚧Ⓜ🇪🇸⏳🌎",
        ];
        for password in password_list.iter() {
            let stored_password = derive_password(password).unwrap();
            assert!(! is_valid("bad password", &stored_password));
            assert!(is_valid(&password, &stored_password));
        }
    }

    #[test]
    fn test_password_with_null_byte() {
        let password_list = [
            // (password, invalid_password),
            ("123456\x00789", "123456"),
            ("a\x00cd", "a"),
        ];
        for pass in password_list.iter() {
            let stored_password = derive_password(pass.0).unwrap();
            assert!(! is_valid(pass.1, &stored_password));
            assert!(is_valid(pass.0, &stored_password));
        }
    }

    #[test]
    fn test_format_with_salt() {
        let list = [
            // (password, storage, expected_output),
            ("password123", "$pbkdf2$i=1000,h=sha1$RSF4Aw", "$pbkdf2$i=1000$RSF4Aw$xvdfA4H7QJQ1w/4jGcjBEIjCvsc"),
            ("password123", "$pbkdf2$i=1000$RSF4Aw", "$pbkdf2$i=1000$RSF4Aw$xvdfA4H7QJQ1w/4jGcjBEIjCvsc"),
            ("password123", "$pbkdf2$$RSF4Aw", "$pbkdf2$i=21000$RSF4Aw$LwCbGeQoBZIraYoDZ8Oe/PxdJHc"),
            ("password123", "$pbkdf2-sha256$$RSF4Aw", "$pbkdf2-sha256$i=21000$RSF4Aw$pgenLCySNXpFaLmYxfcI+AHwsf+66iBTV+COTTJYMMk"),
            ("password123", "$pbkdf2$h=sha256$RSF4Aw", "$pbkdf2-sha256$i=21000$RSF4Aw$pgenLCySNXpFaLmYxfcI+AHwsf+66iBTV+COTTJYMMk"),
        ];
        for p in list.iter() {
            let deriv = PasswordDerivationFunctionBuilder::new()
                .set_reference_hash(p.1)
                .finalize()
                .unwrap()
                .derive(p.0)
                .unwrap();
            assert_eq!(p.2, deriv);
            assert!(! is_valid(p.0, p.1));
            assert!(is_valid(p.0, p.2));
        }
    }

    #[test]
    fn test_format_without_salt() {
        let list = [
            // (password, storage, expected_output_start),
            ("password123", "$pbkdf2$i=1000,h=sha1", "$pbkdf2$i=1000$"),
            ("password123", "$pbkdf2$i=1000,h=sha512", "$pbkdf2-sha512$i=1000$"),
            ("password123", "$pbkdf2-sha512", "$pbkdf2-sha512$i=21000$"),
        ];
        for p in list.iter() {
            let deriv: String = PasswordDerivationFunctionBuilder::new()
                .set_reference_hash(p.1)
                .finalize()
                .unwrap()
                .derive(p.0)
                .unwrap();
            assert!(deriv.starts_with(p.2));
        }
    }

    #[test]
    fn test_algos() {
        let password_list = [
            // (password, stored_hash),

            // pbkdf2
            ("password123", "$pbkdf2$i=1000$RSF4Aw$xvdfA4H7QJQ1w/4jGcjBEIjCvsc"),
            ("correct horse battery staple", "$pbkdf2$i=1000$RSF4Aw$xTnszJuU6xIkG39ha+NLAEh0L3w"),
            ("password123", "$pbkdf2$i=12345$RSF4Aw$peMYK10lIlWHNc2tlx3FyniUAec"),
            ("correct horse battery staple", "$pbkdf2$i=12345$RSF4Aw$+jgSn2gNV+F6RvzFo1hFCzgMTo0"),
            ("password123", "$pbkdf2$i=21000$RSF4Aw$LwCbGeQoBZIraYoDZ8Oe/PxdJHc"),
            ("correct horse battery staple", "$pbkdf2$i=21000$RSF4Aw$XPDp/vtRagureD7No7mRnBMBOps"),
            // pbkdf2-sha256
            ("password123", "$pbkdf2-sha256$i=1000$RSF4Aw$yY82x+kyEjBAfH9nhcKpOGmHCdFtH7YWTEPIP4t5V7U"),
            ("correct horse battery staple", "$pbkdf2-sha256$i=1000$RSF4Aw$fG/oZ6fBkkxuzqGnknc6rbj7bMwdIgZh91WKb6QfFbw"),
            ("password123", "$pbkdf2-sha256$i=12345$RSF4Aw$mV/c0MvAqHu8HzeRX1arlTy4hD4zaxV+RUDZv7zQ6bg"),
            ("correct horse battery staple", "$pbkdf2-sha256$i=12345$RSF4Aw$9C3iX18uvqcU9z6Z/7Ar0cJ0flk5eVviYyGAkPc8xc4"),
            ("password123", "$pbkdf2-sha256$i=21000$RSF4Aw$pgenLCySNXpFaLmYxfcI+AHwsf+66iBTV+COTTJYMMk"),
            ("correct horse battery staple", "$pbkdf2-sha256$i=21000$RSF4Aw$KuyNYVkNyeDRKEIdNFpj7qCSPKUTbN6ta/n9Pw+KBEc"),
            // pbkdf2 h=sha256
            ("password123", "$pbkdf2$i=1000,h=sha256$RSF4Aw$yY82x+kyEjBAfH9nhcKpOGmHCdFtH7YWTEPIP4t5V7U"),
            ("correct horse battery staple", "$pbkdf2$i=1000,h=sha256$RSF4Aw$fG/oZ6fBkkxuzqGnknc6rbj7bMwdIgZh91WKb6QfFbw"),
            ("password123", "$pbkdf2$h=sha256,i=12345$RSF4Aw$mV/c0MvAqHu8HzeRX1arlTy4hD4zaxV+RUDZv7zQ6bg"),
            ("correct horse battery staple", "$pbkdf2$h=sha256,i=12345$RSF4Aw$9C3iX18uvqcU9z6Z/7Ar0cJ0flk5eVviYyGAkPc8xc4"),
            ("password123", "$pbkdf2$i=21000,h=sha256$RSF4Aw$pgenLCySNXpFaLmYxfcI+AHwsf+66iBTV+COTTJYMMk"),
            ("correct horse battery staple", "$pbkdf2$i=21000,h=sha256$RSF4Aw$KuyNYVkNyeDRKEIdNFpj7qCSPKUTbN6ta/n9Pw+KBEc"),
            // pbkdf2-sha512
            ("password123", "$pbkdf2-sha512$i=1000$RSF4Aw$tH1SBLzs8BoxFS0IctA/Jw06jrK7MFhk0Ji+KBvCQ7JBLw7QE8x4F2DmTd6nBcwQTDcRHZnr3bNiMv5JTyTAug"),
            ("correct horse battery staple", "$pbkdf2-sha512$i=1000$RSF4Aw$U/19XPe7nKM/iZE1ZCQx/miEX67rG2cxA+n873HlN4Urqt0NBYT6u6o+GMaZvAhKpwfFqP8SXlFUlCeEcZAHgw"),
            ("password123", "$pbkdf2-sha512$i=12345$RSF4Aw$vKxujfEvw74w8Oud86V2zXnrrF+as5tAKqRHGc/bFlA+bKZEEWgen4iqE5bBOpJ2c6m9mR5iUhcdx4Fv1H2yfA"),
            ("correct horse battery staple", "$pbkdf2-sha512$i=12345$RSF4Aw$w4gfA+r/YvQvDtuAmnGZB4N03fg/jz2mOJer8ZA2k1mrh/+cPEYhrb1EUfp4guBXLT3GJe3oTMHMg0F5xn4IZg"),
            ("password123", "$pbkdf2-sha512$i=21000$RSF4Aw$xThRbOE1DPfUjMa1kRn6HZT6ufG5KixgPCt4+P0YALmdmkRH3fwcXCl721PP359zbYMYVOgkr3yt+XohRLk/aw"),
            ("correct horse battery staple", "$pbkdf2-sha512$i=21000$RSF4Aw$L2bmVIwbQ693Tbcm9upA0ZrtIf/bWSsqgwsLAb1Z2X2htwgEcPJdFzTxMxpxsiFqBiluLnuCbVtXulrhA8ZBSg"),
            // pbkdf2 h=sha512
            ("password123", "$pbkdf2$i=1000,h=sha512$RSF4Aw$tH1SBLzs8BoxFS0IctA/Jw06jrK7MFhk0Ji+KBvCQ7JBLw7QE8x4F2DmTd6nBcwQTDcRHZnr3bNiMv5JTyTAug"),
            ("correct horse battery staple", "$pbkdf2$i=1000,h=sha512$RSF4Aw$U/19XPe7nKM/iZE1ZCQx/miEX67rG2cxA+n873HlN4Urqt0NBYT6u6o+GMaZvAhKpwfFqP8SXlFUlCeEcZAHgw"),
            ("password123", "$pbkdf2$i=12345,h=sha512$RSF4Aw$vKxujfEvw74w8Oud86V2zXnrrF+as5tAKqRHGc/bFlA+bKZEEWgen4iqE5bBOpJ2c6m9mR5iUhcdx4Fv1H2yfA"),
            ("correct horse battery staple", "$pbkdf2$i=12345,h=sha512$RSF4Aw$w4gfA+r/YvQvDtuAmnGZB4N03fg/jz2mOJer8ZA2k1mrh/+cPEYhrb1EUfp4guBXLT3GJe3oTMHMg0F5xn4IZg"),
            ("password123", "$pbkdf2$h=sha512,i=21000$RSF4Aw$xThRbOE1DPfUjMa1kRn6HZT6ufG5KixgPCt4+P0YALmdmkRH3fwcXCl721PP359zbYMYVOgkr3yt+XohRLk/aw"),
            ("correct horse battery staple", "$pbkdf2$h=sha512,i=21000$RSF4Aw$L2bmVIwbQ693Tbcm9upA0ZrtIf/bWSsqgwsLAb1Z2X2htwgEcPJdFzTxMxpxsiFqBiluLnuCbVtXulrhA8ZBSg"),
        ];
        for p in password_list.iter() {
            let deriv = PasswordDerivationFunctionBuilder::new()
                .set_reference_hash(p.1)
                .finalize()
                .unwrap()
                .derive(p.0)
                .unwrap();
            assert_eq!(p.1.split("$").collect::<Vec<&str>>().last().unwrap(), deriv.split("$").collect::<Vec<&str>>().last().unwrap());
            assert!(! is_valid("bad password", p.1));
            assert!(is_valid(p.0, p.1));
        }
    }
}
