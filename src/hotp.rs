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
use otp::HashFunction;
use base32;


pub struct HOTP {
    pub key: Vec<u8>,
    pub counter: u64,
    pub nb_digits: u8,
    pub hash_function: HashFunction,
}

impl HOTP {
    fn compute_hmac<H: Digest>(&self, digest: H) -> MacResult {
        let mut hmac = Hmac::new(digest, &self.key);
        let cnt = vec![
            ((self.counter >> 56) & 0xff) as u8,
            ((self.counter >> 48) & 0xff) as u8,
            ((self.counter >> 40) & 0xff) as u8,
            ((self.counter >> 32) & 0xff) as u8,
            ((self.counter >> 24) & 0xff) as u8,
            ((self.counter >> 16) & 0xff) as u8,
            ((self.counter >> 8) & 0xff) as u8,
            (self.counter & 0xff) as u8,
        ];
        hmac.input(&cnt[..]);
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

    pub fn generate(&mut self) -> String {
        let result = match self.hash_function {
            HashFunction::Sha1 => self.compute_hmac(Sha1::new()),
            HashFunction::Sha256 => self.compute_hmac(Sha256::new()),
            HashFunction::Sha512 => self.compute_hmac(Sha512::new()),
        };
        let hs = result.code();
        let nb = self.reduce_result(&hs);
        self.counter += 1;

        format!("{:01$}", nb, self.nb_digits as usize)
    }
}

pub struct HOTPBuilder {
    key: Vec<u8>,
    counter: u64,
    nb_digits: u8,
    hash_function: HashFunction,
}

impl HOTPBuilder {
    pub fn new() -> HOTPBuilder {
        HOTPBuilder {
            key: vec![],
            counter: 0,
            nb_digits: 6,
            hash_function: HashFunction::Sha1,
        }
    }

    pub fn key(&mut self, key: &Vec<u8>) -> &mut HOTPBuilder {
        self.key = key.clone();
        self
    }

    pub fn ascii_key(&mut self, key: &String) -> &mut HOTPBuilder {
        self.key = key.clone().into_bytes();
        self
    }

    pub fn hex_key(&mut self, key: &String) -> &mut HOTPBuilder {
        self.key = key.from_hex().unwrap();
        self
    }

    pub fn base32_key(&mut self, key: &String) -> &mut HOTPBuilder {
        self.key = base32::decode(base32::Alphabet::RFC4648 { padding: false }, &key).unwrap();
        self
    }

    pub fn counter(&mut self, counter: u64) -> &mut HOTPBuilder {
        self.counter = counter;
        self
    }

    pub fn nb_digits(&mut self, nb_digits: u8) -> &mut HOTPBuilder {
        if nb_digits < 6 {
            panic!("There must be at least 6 digits.")
        }
        self.nb_digits = nb_digits;
        self
    }

    pub fn hash_function(&mut self, hash_function: HashFunction) -> &mut HOTPBuilder {
        self.hash_function = hash_function;
        self
    }

    pub fn finalize(&self) -> HOTP {
        HOTP {
            key: self.key.clone(),
            counter: self.counter,
            nb_digits: self.nb_digits,
            hash_function: self.hash_function,
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

        let mut hotp = HOTPBuilder::new()
            .key(&key)
            .finalize();

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

        let mut hotp = HOTPBuilder::new()
            .key(&key)
            .counter(5)
            .nb_digits(8)
            .hash_function(HashFunction::Sha256)
            .finalize();

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

        let mut hotp = HOTPBuilder::new()
            .ascii_key(&key_ascii)
            .finalize();

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

        let mut hotp = HOTPBuilder::new()
            .ascii_key(&key_ascii)
            .counter(5)
            .nb_digits(8)
            .hash_function(HashFunction::Sha256)
            .finalize();

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

        let mut hotp = HOTPBuilder::new()
            .hex_key(&key_hex)
            .finalize();

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

        let mut hotp = HOTPBuilder::new()
            .hex_key(&key_hex)
            .counter(5)
            .nb_digits(8)
            .hash_function(HashFunction::Sha512)
            .finalize();

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

        let mut hotp = HOTPBuilder::new()
            .base32_key(&key_base32)
            .finalize();

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

        let mut hotp = HOTPBuilder::new()
            .base32_key(&key_base32)
            .counter(5)
            .nb_digits(8)
            .hash_function(HashFunction::Sha512)
            .finalize();

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
    #[should_panic(expected = "There must be at least 6 digits.")]
    fn test_hotp_digits() {
        let key_ascii = "12345678901234567890".to_string();
        let _ = HOTPBuilder::new()
            .ascii_key(&key_ascii)
            .nb_digits(5)
            .finalize();
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
            .finalize();
        let mut hotp2 = HOTPBuilder::new()
            .key(&key)
            .counter(0)
            .hash_function(HashFunction::Sha1)
            .finalize();
        for count in 0..examples.len() {
            let counter = count as u64;
            assert_eq!(hotp1.counter, counter);
            assert_eq!(hotp2.counter, counter);
            let code1 = hotp1.generate();
            let code2 = hotp2.generate();
            assert_eq!(code1, examples[count]);
            assert_eq!(code2, examples[count]);
            assert_eq!(hotp1.counter, counter + 1);
            assert_eq!(hotp2.counter, counter + 1);
        }
    }

}
