/*
 * Copyright Rodolphe Breard (2016)
 * Author: Rodolphe Breard (2016)
 *
 * This software is a computer program whose purpose is to [describe
 * functionalities and technical features of your software].
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


use rand::{Rng,thread_rng};
use crypto::mac::Mac;
use crypto::hmac::Hmac;
use crypto::sha2::Sha512;


pub const PASSWORD_MIN_LEN: usize = 4;
pub const PASSWORD_MAX_LEN: usize = 128;


#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub enum ErrorCode {
    PasswordTooShort = 1,
    PasswordTooLong = 2,
    InvalidPasswordFormat = 10,
    NotEnoughSpace = 20,
}

mod derivation;

fn generate_salt(nb_bytes: usize) -> Vec<u8> {
    let mut salt: Vec<u8> = vec![0; nb_bytes];
    thread_rng().fill_bytes(&mut salt);
    salt
}

/// Derivate a password so it can be stored.
///
/// # Examples
/// ```
/// let password = "1234567890";
/// let stored_password = libreauth::pass::derive_password(password).unwrap();
/// ```
pub fn derive_password(password: &str) -> Result<String, ErrorCode> {
    derivation::ALGORITHMS[0].derive(password)
}

/// Check whether or not the password is valid.
///
/// # Examples
/// ```
/// let password = "correct horse battery staple";
/// let stored_password = libreauth::pass::derive_password(password).unwrap();
/// assert!(! libreauth::pass::is_valid("bad password", &stored_password));
/// assert!(libreauth::pass::is_valid(&password, &stored_password));
/// ```
///
/// ```
/// let stored_reference = "$pbkdf2-sha256$0$45217803$a607a72c2c92357a4568b998c5f708f801f0b1ffbaea205357e08e4d325830c9$";
/// assert!(! libreauth::pass::is_valid("bad password", stored_reference));
/// assert!(libreauth::pass::is_valid("password123", stored_reference));
/// ```
pub fn is_valid(password: &str, reference: &str) -> bool {
    for alg in derivation::ALGORITHMS.iter() {
        if alg.check_type(reference) {
            let salt = generate_salt(32);

            let mut ref_hmac = Hmac::new(Sha512::new(), &salt);
            ref_hmac.input(&reference.as_bytes());

            let ref_salt = match derivation::get_salt(reference) {
                Ok(some) => some,
                Err(_) => return false,
            };
            let derived_pass = match alg.derive_with_salt(password, &ref_salt) {
                Ok(some) => some,
                Err(_) => return false,
            };
            let mut pass_hmac = Hmac::new(Sha512::new(), &salt);
            pass_hmac.input(&derived_pass.into_bytes());

            return ref_hmac.result() == pass_hmac.result();
        }
    }
    false
}

#[cfg(feature = "cbindings")]
mod cbindings {
    use super::{ErrorCode,derive_password,is_valid};
    use libc;
    use std;

    #[no_mangle]
    pub extern fn libreauth_pass_derive_password(password: *const libc::c_char, storage: *mut libc::uint8_t, storage_len: libc::size_t) -> libc::int32_t {
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
            Err(errno) => return errno as libc::int32_t,
        };
        let out_len = r_derived_password.len();
        let pass_b = r_derived_password.into_bytes();
        if out_len >= storage_len as usize {
            return ErrorCode::NotEnoughSpace as libc::int32_t;
        }
        for i in 0..out_len {
            r_storage[i] = pass_b[i];
        };
        r_storage[out_len] = 0;
        0
    }

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
        let stored_password = "$pbkdf2$0$45217803$2dade20112c105c0520f8bc08bac2a3be0c241a5$";
        assert!(! is_valid("", stored_password));
    }

    #[test]
    fn test_short_password_validation() {
        let stored_password = "$pbkdf2$0$45217803$ce035bbb80414de3de01dc54a9ee204b27ad1ae5$";
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
}
