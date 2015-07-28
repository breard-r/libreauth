//
// Copyright (c) 2015 Rodolphe Breard
// 
// Permission to use, copy, modify, and/or distribute this software for any
// purpose with or without fee is hereby granted, provided that the above
// copyright notice and this permission notice appear in all copies.
// 
// THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
// WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
// MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
// ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
// WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
// ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
// OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
//

#[derive(Clone, Copy)]
pub enum HashFunction {
    Sha1,
    Sha256,
    Sha512,
}

macro_rules! builder_common {
    ($t:ty) => {
        /// Sets the shared secret.
        pub fn key(&mut self, key: &Vec<u8>) -> &mut $t {
            self.key = Some(key.clone());
            self
        }

        /// Sets the shared secret. This secret is passed as an ASCII string.
        pub fn ascii_key(&mut self, key: &String) -> &mut $t {
            self.key = Some(key.clone().into_bytes());
            self
        }

        /// Sets the shared secret. This secret is passed as an hexadecimal encoded string.
        pub fn hex_key(&mut self, key: &String) -> &mut $t {
            match key.from_hex() {
                Ok(k) => { self.key = Some(k); }
                Err(_) => { self.runtime_error = Some("Invalid key."); }
            }
            self
        }

        /// Sets the shared secret. This secret is passed as a base32 encoded string.
        pub fn base32_key(&mut self, key: &String) -> &mut $t {
            match base32::decode(base32::Alphabet::RFC4648 { padding: false }, &key) {
                Some(k) => { self.key = Some(k); }
                None => { self.runtime_error = Some("Invalid key."); }
            }
            self
        }

        /// Sets the number of digits for the code. The minimum is 6. Default is 6.
        pub fn nb_digits(&mut self, nb_digits: u8) -> &mut $t {
            if nb_digits < 6 {
                self.runtime_error = Some("There must be at least 6 digits.");
            } else {
                self.nb_digits = nb_digits;
            }
            self
        }

        /// Sets the hash function. Default is Sha1.
        pub fn hash_function(&mut self, hash_function: HashFunction) -> &mut $t {
            self.hash_function = hash_function;
            self
        }
    }
}

pub mod hotp;
pub mod totp;

pub type HOTPBuilder = hotp::HOTPBuilder;
pub type TOTPBuilder = totp::TOTPBuilder;
