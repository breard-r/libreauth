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

use rustc_serialize::hex::FromHex;
use crypto::sha2::{Sha256, Sha512};
use crypto::mac::{Mac, MacResult};
use crypto::digest::Digest;
use crypto::hmac::Hmac;
use crypto::sha1::Sha1;
use super::HashFunction;
use base32;


pub struct HOTP {
    key: Vec<u8>,
    counter: u64,
    nb_digits: u8,
    hash_function: HashFunction,
}

impl HOTP {
    fn compute_hmac<H: Digest>(&self, digest: H, msg: &Vec<u8>) -> MacResult {
        let mut hmac = Hmac::new(digest, &self.key);
        hmac.input(msg);
        hmac.result()
    }

    fn reduce_result(&self, hs: &[u8]) -> u32 {
        let offset = (hs[hs.len() - 1] & 0xf) as usize;
        let hash = hs[offset..offset+4].to_vec();
        let snum: u32 = ((hash[0] as u32 & 0x7f) << 24)
            | ((hash[1] as u32 & 0xff) << 16)
            | ((hash[2] as u32 & 0xff) <<  8)
            | (hash[3] as u32 & 0xff);

        let base: u32 = 10;
        snum % base.pow(self.nb_digits as u32)
    }

    /// Generate the HOTP value.
    ///
    /// # Examples
    /// ```
    /// let key_ascii = "12345678901234567890".to_string();
    /// let mut hotp = r2fa::otp::HOTPBuilder::new()
    ///     .ascii_key(&key_ascii)
    ///     .finalize()
    ///     .unwrap();
    ///
    /// let code = hotp.generate();
    /// assert_eq!(code, "755224");
    /// let code = hotp.increment_counter().generate();
    /// assert_eq!(code, "287082");
    /// ```
    pub fn generate(&self) -> String {
        let msg = vec![
            ((self.counter >> 56) & 0xff) as u8,
            ((self.counter >> 48) & 0xff) as u8,
            ((self.counter >> 40) & 0xff) as u8,
            ((self.counter >> 32) & 0xff) as u8,
            ((self.counter >> 24) & 0xff) as u8,
            ((self.counter >> 16) & 0xff) as u8,
            ((self.counter >> 8) & 0xff) as u8,
            (self.counter & 0xff) as u8,
        ];
        let result = match self.hash_function {
            HashFunction::Sha1 => self.compute_hmac(Sha1::new(), &msg),
            HashFunction::Sha256 => self.compute_hmac(Sha256::new(), &msg),
            HashFunction::Sha512 => self.compute_hmac(Sha512::new(), &msg),
        };
        let hs = result.code();
        let nb = self.reduce_result(&hs);
        format!("{:01$}", nb, self.nb_digits as usize)
    }

    /// Increments the internal counter.
    pub fn increment_counter(&mut self) -> &mut HOTP {
        self.counter += 1;
        self
    }

    /// Checks if the given code is valid. This implementation uses the [double HMAC verification](https://www.nccgroup.trust/us/about-us/newsroom-and-events/blog/2011/february/double-hmac-verification/) in order to prevent a timing side channel attack.
    ///
    /// # Examples
    /// ```
    /// let key_ascii = "12345678901234567890".to_string();
    /// let user_code = "755224".to_string();
    /// let valid = r2fa::otp::HOTPBuilder::new()
    ///     .ascii_key(&key_ascii)
    ///     .finalize()
    ///     .unwrap()
    ///     .is_valid(&user_code);
    /// assert_eq!(valid, true);
    /// ```
    pub fn is_valid(&self, code: &String) -> bool {
        if code.len() != self.nb_digits as usize {
            return false
        }
        let ref_code = self.generate().into_bytes();
        let code = code.clone().into_bytes();
        let (code, ref_code) = match self.hash_function {
            HashFunction::Sha1 => (self.compute_hmac(Sha1::new(), &code), self.compute_hmac(Sha1::new(), &ref_code)),
            HashFunction::Sha256 => (self.compute_hmac(Sha256::new(), &code), self.compute_hmac(Sha256::new(), &ref_code)),
            HashFunction::Sha512 => (self.compute_hmac(Sha512::new(), &code), self.compute_hmac(Sha512::new(), &ref_code)),
        };
        code == ref_code
    }
}

/// # Examples
///
/// The following examples uses the same shared secret passed in various forms.
///
///```
/// let key = vec![49, 50, 51, 52, 53, 54, 55, 56, 57, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 48];
/// let mut hotp = r2fa::otp::HOTPBuilder::new()
///     .key(&key)
///     .finalize()
///     .unwrap();
///```
///
///```
/// let key_ascii = "12345678901234567890".to_string();
/// let mut hotp = r2fa::otp::HOTPBuilder::new()
///     .ascii_key(&key_ascii)
///     .counter(42)
///     .finalize()
///     .unwrap();
///```
///
///```
/// let key_hex = "3132333435363738393031323334353637383930".to_string();
/// let mut hotp = r2fa::otp::HOTPBuilder::new()
///     .hex_key(&key_hex)
///     .counter(69)
///     .nb_digits(8)
///     .finalize();
///```
///
///```
/// let key_base32 = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ".to_string();
/// let mut hotp = r2fa::otp::HOTPBuilder::new()
///     .base32_key(&key_base32)
///     .nb_digits(8)
///     .hash_function(r2fa::otp::HashFunction::Sha256)
///     .finalize();
///```
pub struct HOTPBuilder {
    key: Option<Vec<u8>>,
    counter: u64,
    nb_digits: u8,
    hash_function: HashFunction,
    runtime_error: Option<&'static str>,
}

impl HOTPBuilder {
    /// Generates the base configuration for HOTP code generation.
    pub fn new() -> HOTPBuilder {
        HOTPBuilder {
            key: None,
            counter: 0,
            nb_digits: 6,
            hash_function: HashFunction::Sha1,
            runtime_error: None,
        }
    }

    builder_common!(HOTPBuilder);

    /// Sets the counter. Default is 0.
    pub fn counter(&mut self, counter: u64) -> &mut HOTPBuilder {
        self.counter = counter;
        self
    }

    /// Returns the finalized HOTP object.
    pub fn finalize(&self) -> Result<HOTP, &'static str> {
        match self.runtime_error {
            Some(e) => return Err(e),
            None => (),
        }
        match self.key {
            Some(ref k) => Ok(HOTP {
                key: k.clone(),
                counter: self.counter,
                nb_digits: self.nb_digits,
                hash_function: self.hash_function,
            }),
            None => Err("No key provided."),
        }

    }
}


#[cfg(test)]
mod tests {
    use super::HOTPBuilder;
    use otp::HashFunction;

    #[test]
    fn test_hotp_key_simple() {
        let key = vec![49, 50, 51, 52, 53, 54, 55, 56, 57, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 48];

        let hotp = HOTPBuilder::new()
            .key(&key)
            .finalize()
            .unwrap();

        assert_eq!(hotp.key, key);
        assert_eq!(hotp.counter, 0);
        assert_eq!(hotp.nb_digits, 6);
        match hotp.hash_function {
            HashFunction::Sha1 => assert!(true),
            _ => assert!(false),
        }

        let code = hotp.generate();
        assert_eq!(code.len(), 6);
        assert_eq!(code, "755224");
    }

    #[test]
    fn test_hotp_key_full() {
        let key = vec![49, 50, 51, 52, 53, 54, 55, 56, 57, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 48];

        let hotp = HOTPBuilder::new()
            .key(&key)
            .counter(5)
            .nb_digits(8)
            .hash_function(HashFunction::Sha256)
            .finalize()
            .unwrap();

        assert_eq!(hotp.key, key);
        assert_eq!(hotp.counter, 5);
        assert_eq!(hotp.nb_digits, 8);
        match hotp.hash_function {
            HashFunction::Sha256 => assert!(true),
            _ => assert!(false),
        }

        let code = hotp.generate();
        assert_eq!(code.len(), 8);
        assert_eq!(code, "89697997");
    }

    #[test]
    fn test_hotp_asciikey_simple() {
        let key_ascii = "12345678901234567890".to_string();
        let key = vec![49, 50, 51, 52, 53, 54, 55, 56, 57, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 48];

        let hotp = HOTPBuilder::new()
            .ascii_key(&key_ascii)
            .finalize()
            .unwrap();

        assert_eq!(hotp.key, key);
        assert_eq!(hotp.counter, 0);
        assert_eq!(hotp.nb_digits, 6);
        match hotp.hash_function {
            HashFunction::Sha1 => assert!(true),
            _ => assert!(false),
        }

        let code = hotp.generate();
        assert_eq!(code.len(), 6);
        assert_eq!(code, "755224");
    }

    #[test]
    fn test_hotp_asciikey_full() {
        let key_ascii = "12345678901234567890".to_string();
        let key = vec![49, 50, 51, 52, 53, 54, 55, 56, 57, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 48];

        let hotp = HOTPBuilder::new()
            .ascii_key(&key_ascii)
            .counter(5)
            .nb_digits(8)
            .hash_function(HashFunction::Sha256)
            .finalize()
            .unwrap();

        assert_eq!(hotp.key, key);
        assert_eq!(hotp.counter, 5);
        assert_eq!(hotp.nb_digits, 8);
        match hotp.hash_function {
            HashFunction::Sha256 => assert!(true),
            _ => assert!(false),
        }

        let code = hotp.generate();
        assert_eq!(code.len(), 8);
        assert_eq!(code, "89697997");
    }

    #[test]
    fn test_hotp_hexkey_simple() {
        let key_hex = "3132333435363738393031323334353637383930".to_string();
        let key = vec![49, 50, 51, 52, 53, 54, 55, 56, 57, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 48];

        let hotp = HOTPBuilder::new()
            .hex_key(&key_hex)
            .finalize()
            .unwrap();

        assert_eq!(hotp.key, key);
        assert_eq!(hotp.counter, 0);
        assert_eq!(hotp.nb_digits, 6);
        match hotp.hash_function {
            HashFunction::Sha1 => assert!(true),
            _ => assert!(false),
        }

        let code = hotp.generate();
        assert_eq!(code.len(), 6);
        assert_eq!(code, "755224");
    }

    #[test]
    fn test_hotp_hexkey_full() {
        let key_hex = "3132333435363738393031323334353637383930".to_string();
        let key = vec![49, 50, 51, 52, 53, 54, 55, 56, 57, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 48];

        let hotp = HOTPBuilder::new()
            .hex_key(&key_hex)
            .counter(5)
            .nb_digits(8)
            .hash_function(HashFunction::Sha512)
            .finalize()
            .unwrap();

        assert_eq!(hotp.key, key);
        assert_eq!(hotp.counter, 5);
        assert_eq!(hotp.nb_digits, 8);
        match hotp.hash_function {
            HashFunction::Sha512 => assert!(true),
            _ => assert!(false),
        }

        let code = hotp.generate();
        assert_eq!(code.len(), 8);
        assert_eq!(code, "16848329");
    }

    #[test]
    fn test_hotp_base32key_simple() {
        let key = vec![49, 50, 51, 52, 53, 54, 55, 56, 57, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 48];
        let key_base32 = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ".to_string();

        let hotp = HOTPBuilder::new()
            .base32_key(&key_base32)
            .finalize()
            .unwrap();

        assert_eq!(hotp.key, key);
        assert_eq!(hotp.counter, 0);
        assert_eq!(hotp.nb_digits, 6);
        match hotp.hash_function {
            HashFunction::Sha1 => assert!(true),
            _ => assert!(false),
        }

        let code = hotp.generate();
        assert_eq!(code.len(), 6);
        assert_eq!(code, "755224");
    }

    #[test]
    fn test_hotp_base32key_full() {
        let key = vec![49, 50, 51, 52, 53, 54, 55, 56, 57, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 48];
        let key_base32 = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ".to_string();

        let hotp = HOTPBuilder::new()
            .base32_key(&key_base32)
            .counter(5)
            .nb_digits(8)
            .hash_function(HashFunction::Sha512)
            .finalize()
            .unwrap();

        assert_eq!(hotp.key, key);
        assert_eq!(hotp.counter, 5);
        assert_eq!(hotp.nb_digits, 8);
        match hotp.hash_function {
            HashFunction::Sha512 => assert!(true),
            _ => assert!(false),
        }

        let code = hotp.generate();
        assert_eq!(code.len(), 8);
        assert_eq!(code, "16848329");
    }

    #[test]
    fn test_hotp_digits() {
        let key_ascii = "12345678901234567890".to_string();
        match HOTPBuilder::new().ascii_key(&key_ascii).nb_digits(5).finalize() {
            Ok(_) => assert!(false),
            Err(_) => assert!(true),
        }
    }

    #[test]
    fn test_nokey() {
        match HOTPBuilder::new().finalize() {
            Ok(_) => assert!(false),
            Err(_) => assert!(true),
        }
    }

    #[test]
    fn test_invalid_hexkey() {
        let key = "!@#$%^&".to_string();
        match HOTPBuilder::new().hex_key(&key).finalize() {
            Ok(_) => assert!(false),
            Err(_) => assert!(true),
        }
    }

    #[test]
    fn test_invalid_base32key() {
        let key = "!@#$%^&".to_string();
        match HOTPBuilder::new().base32_key(&key).finalize() {
            Ok(_) => assert!(false),
            Err(_) => assert!(true),
        }
    }

    #[test]
    fn test_rfc4226_examples() {
        let key_ascii = "12345678901234567890".to_string();
        let key = vec![49, 50, 51, 52, 53, 54, 55, 56, 57, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 48];

        let examples = [
            "755224",
            "287082",
            "359152",
            "969429",
            "338314",
            "254676",
            "287922",
            "162583",
            "399871",
            "520489",
        ];
        let mut hotp1 = HOTPBuilder::new()
            .ascii_key(&key_ascii)
            .finalize()
            .unwrap();
        let mut hotp2 = HOTPBuilder::new()
            .key(&key)
            .counter(0)
            .hash_function(HashFunction::Sha1)
            .finalize()
            .unwrap();
        for count in 0..examples.len() {
            let counter = count as u64;
            assert_eq!(hotp1.counter, counter);
            assert_eq!(hotp2.counter, counter);
            let code1 = hotp1.generate();
            let code2 = hotp2.generate();
            assert_eq!(code1, examples[count]);
            assert_eq!(code2, examples[count]);
            hotp1.increment_counter();
            hotp2.increment_counter();
            assert_eq!(hotp1.counter, counter + 1);
            assert_eq!(hotp2.counter, counter + 1);
        }
    }

    #[test]
    fn test_valid_sha1_code() {
        let key_ascii = "12345678901234567890".to_string();
        let user_code = "755224".to_string();
        let valid = HOTPBuilder::new()
            .ascii_key(&key_ascii)
            .hash_function(HashFunction::Sha1)
            .finalize()
            .unwrap()
            .is_valid(&user_code);
        assert_eq!(valid, true);
    }

    #[test]
    fn test_valid_sha256_code() {
        let key_ascii = "12345678901234567890".to_string();
        let user_code = "875740".to_string();
        let valid = HOTPBuilder::new()
            .ascii_key(&key_ascii)
            .hash_function(HashFunction::Sha256)
            .finalize()
            .unwrap()
            .is_valid(&user_code);
        assert_eq!(valid, true);
    }

    #[test]
    fn test_valid_sha512_code() {
        let key_ascii = "12345678901234567890".to_string();
        let user_code = "125165".to_string();
        let valid = HOTPBuilder::new()
            .ascii_key(&key_ascii)
            .hash_function(HashFunction::Sha512)
            .finalize()
            .unwrap()
            .is_valid(&user_code);
        assert_eq!(valid, true);
    }

    #[test]
    fn test_invalid_sha1_code() {
        let key_ascii = "12345678901234567890".to_string();
        let user_code = "123456".to_string();
        let valid = HOTPBuilder::new()
            .ascii_key(&key_ascii)
            .hash_function(HashFunction::Sha1)
            .finalize()
            .unwrap()
            .is_valid(&user_code);
        assert_eq!(valid, false);
    }

    #[test]
    fn test_invalid_sha256_code() {
        let key_ascii = "12345678901234567890".to_string();
        let user_code = "123456".to_string();
        let valid = HOTPBuilder::new()
            .ascii_key(&key_ascii)
            .hash_function(HashFunction::Sha256)
            .finalize()
            .unwrap()
            .is_valid(&user_code);
        assert_eq!(valid, false);
    }

    #[test]
    fn test_invalid_sha512_code() {
        let key_ascii = "12345678901234567890".to_string();
        let user_code = "123456".to_string();
        let valid = HOTPBuilder::new()
            .ascii_key(&key_ascii)
            .hash_function(HashFunction::Sha512)
            .finalize()
            .unwrap()
            .is_valid(&user_code);
        assert_eq!(valid, false);
    }

    #[test]
    fn test_bad_code() {
        let key_ascii = "12345678901234567890".to_string();
        let user_code = "!@#$%^".to_string();
        let valid = HOTPBuilder::new()
            .ascii_key(&key_ascii)
            .finalize()
            .unwrap()
            .is_valid(&user_code);
        assert_eq!(valid, false);
    }

    #[test]
    fn test_empty_code() {
        let key_ascii = "12345678901234567890".to_string();
        let user_code = "".to_string();
        let valid = HOTPBuilder::new()
            .ascii_key(&key_ascii)
            .finalize()
            .unwrap()
            .is_valid(&user_code);
        assert_eq!(valid, false);
    }
}
