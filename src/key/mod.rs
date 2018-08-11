/*
 * Copyright Rodolphe Breard (2018)
 * Author: Rodolphe Breard (2018)
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

//! Key generation module
//!
//! ## Cryptographic security
//!
//! Many random generators are available, but not all of them are
//! cryptographically secure. That is a problem because if a secret key may
//! be predictable, the security of your system crumbles into pieces. This
//! key generation module is a wrapper upon `rand::OsRng` which, as its name
//! stands, is a rust wrapper around the operating system's RNG. If the OS's
//! entropy source is not available, it fails instead of falling back to a
//! less secure source.
//!
//! You may read more about cryptographic security in [rand's documentation](https://doc.rust-lang.org/rand/rand/index.html#cryptographic-security).
//!
//! ## Examples
//!
//! Generate a random key and display it in several forms.
//!
//! ```rust
//! let key = libreauth::key::KeyBuilder::new().generate();
//! println!("Key: Vec<u8>: {:?}", key.as_vec());
//! println!("Key: hex String: {}", key.as_hex());
//! println!("Key: base 32 String: {}", key.as_base32());
//! println!("Key: base 64 String: {}", key.as_base64());
//! assert!(key.as_vec() == key.as_vec());
//! assert!(key.as_hex() == key.as_hex());
//! assert!(key.as_base32() == key.as_base32());
//! assert!(key.as_base64() == key.as_base64());
//! ```
//!
//! Generate two random key and test if they are different.
//!
//! ```rust
//! let k1 = libreauth::key::KeyBuilder::new().generate().as_vec();
//! let k2 = libreauth::key::KeyBuilder::new().generate().as_vec();
//! assert!(k1 != k2);
//! ```

use base32;
use base64;
use hex;
use rand::rngs::OsRng;
use rand::RngCore;

/// Random key builder.
pub struct KeyBuilder {
    size: usize,
    key: Option<Vec<u8>>,
}

impl KeyBuilder {
    /// Create a new random key builder.
    pub fn new() -> KeyBuilder {
        KeyBuilder {
            size: 21,
            key: None,
        }
    }

    /// Set the key size (in bytes).
    pub fn size(mut self, size: usize) -> Self {
        match size != self.size {
            true => {
                self.size = size;
                self.generate()
            }
            false => self,
        }
    }

    /// Generate a random key.
    pub fn generate(mut self) -> Self {
        if self.size == 0 {
            panic!();
        }
        let mut key: Vec<u8> = vec![0; self.size];
        OsRng::new().unwrap().fill_bytes(&mut key.as_mut_slice());
        self.key = Some(key);
        self
    }

    /// Return the current key as a Vec<u8>.
    pub fn as_vec(&self) -> Vec<u8> {
        self.key.clone().unwrap()
    }

    /// Return the current key as an hexadecimal string.
    pub fn as_hex(&self) -> String {
        hex::encode(self.key.clone().unwrap())
    }

    /// Return the current key as a base 32 encoded string.
    pub fn as_base32(&self) -> String {
        base32::encode(
            base32::Alphabet::RFC4648 { padding: false },
            self.key.clone().unwrap().as_slice(),
        )
    }

    /// Return the current key as a base 64 encoded string.
    pub fn as_base64(&self) -> String {
        base64::encode(self.key.clone().unwrap().as_slice())
    }
}

#[cfg(feature = "cbindings")]
pub use self::cbindings::libreauth_keygen;

#[cfg(feature = "cbindings")]
mod cbindings {
    use super::KeyBuilder;
    use libc;
    use std;

    /// [C binding] Generate a random key.
    ///
    /// ## Examples
    /// ```c
    /// char key[DEFAULT_KEY_SIZE + 1] = {0};
    /// int32_t ret = libreauth_keygen(key, DEFAULT_KEY_SIZE);
    /// if (ret != EXIT_SUCCESS) {
    ///     // Handle the error.
    /// }
    /// ```
    #[no_mangle]
    pub extern "C" fn libreauth_keygen(
        buff: *mut libc::uint8_t,
        buff_len: libc::size_t,
    ) -> libc::int32_t {
        let key_size = buff_len as usize;
        if key_size == 0 || buff.is_null() {
            return 1;
        };
        let key = unsafe { std::slice::from_raw_parts_mut(buff, key_size + 1) };
        let out = KeyBuilder::new().size(key_size).generate().as_vec();
        let len = out.len();
        for i in 0..len {
            key[i] = out[i];
        }
        key[len] = 0;
        0
    }
}

#[cfg(test)]
mod tests {
    use super::KeyBuilder;

    #[test]
    fn test_uniqueness() {
        let k1 = KeyBuilder::new().generate().as_vec();
        let k2 = KeyBuilder::new().generate().as_vec();
        assert!(k1 != k2);
    }

    #[test]
    fn test_equality() {
        let key = KeyBuilder::new().generate();
        assert!(key.as_vec() == key.as_vec());
    }

    #[test]
    fn test_size_change() {
        let mut key = KeyBuilder::new().generate();
        let k1 = key.as_vec();
        key = key.size(42);
        let k2 = key.as_vec();
        assert!(k1 != k2);
    }

    #[test]
    fn test_size_unchanged() {
        let mut key = KeyBuilder::new().generate();
        let k1 = key.as_vec();
        key = key.size(21);
        let k2 = key.as_vec();
        assert!(k1 == k2);
    }

    #[test]
    fn test_default_len() {
        let key = KeyBuilder::new().generate().as_vec();
        assert!(key.len() == 21);
    }

    #[test]
    fn test_given_len() {
        let lst: Vec<usize> = vec![1, 12, 21, 42, 128, 256];
        for i in lst {
            let key = KeyBuilder::new().size(i).generate().as_vec();
            assert!(key.len() == i);
        }
    }

    #[test]
    #[should_panic]
    fn test_null_len() {
        KeyBuilder::new().size(0);
    }
}
