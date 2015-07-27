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
use super::HashFunction;
use base32;
use time;
use super::HOTPBuilder;


pub struct TOTP {
    key: Vec<u8>,
    timestamp: u64,
    period: u32,
    initial_time: u64,
    nb_digits: u8,
    hash_function: HashFunction,
}

impl TOTP {
    fn get_counter(&self) -> u64 {
        (self.timestamp - self.initial_time) / self.period as u64
    }

    /// Generate the current TOTP value.
    ///
    /// # Examples
    /// ```
    /// let key_base32 = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ".to_string();
    /// let mut totp = r2fa::otp::TOTPBuilder::new()
    ///     .base32_key(&key_base32)
    ///     .finalize()
    ///     .unwrap();
    ///
    /// let code = totp.generate();
    /// assert_eq!(code.len(), 6);
    /// ```
    pub fn generate(&mut self) -> String {
        let counter = self.get_counter();
        let hotp = HOTPBuilder::new()
            .key(&self.key.clone())
            .counter(counter)
            .nb_digits(self.nb_digits)
            .hash_function(self.hash_function)
            .finalize();
        match hotp {
            Ok(mut h) => h.generate(),
            Err(e) => panic!(e),
        }
    }
}

/// # Examples
///
/// The following examples uses the same shared secret passed in various forms.
///
///```
/// let key = vec![49, 50, 51, 52, 53, 54, 55, 56, 57, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 48];
/// let mut totp = r2fa::otp::TOTPBuilder::new()
///     .key(&key)
///     .finalize()
///     .unwrap();
///```
///
///```
/// let key_ascii = "12345678901234567890".to_string();
/// let mut totp = r2fa::otp::TOTPBuilder::new()
///     .ascii_key(&key_ascii)
///     .period(42)
///     .finalize();
///```
///
///```
/// let key_hex = "3132333435363738393031323334353637383930".to_string();
/// let mut totp = r2fa::otp::TOTPBuilder::new()
///     .hex_key(&key_hex)
///     .timestamp(1234567890)
///     .finalize();
///```
///
///```
/// let key_base32 = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ".to_string();
/// let mut totp = r2fa::otp::TOTPBuilder::new()
///     .base32_key(&key_base32)
///     .nb_digits(8)
///     .hash_function(r2fa::otp::HashFunction::Sha256)
///     .finalize();
///```
pub struct TOTPBuilder {
    key: Option<Vec<u8>>,
    timestamp: u64,
    period: u32,
    initial_time: u64,
    nb_digits: u8,
    hash_function: HashFunction,
}

impl TOTPBuilder {
    /// Generates the base configuration for TOTP code generation.
    pub fn new() -> TOTPBuilder {
        TOTPBuilder {
            key: None,
            timestamp: time::now().to_timespec().sec as u64,
            period: 30,
            initial_time: 0,
            nb_digits: 6,
            hash_function: HashFunction::Sha1,
        }
    }

    /// Sets the shared secret.
    pub fn key(&mut self, key: &Vec<u8>) -> &mut TOTPBuilder {
        self.key = Some(key.clone());
        self
    }

    /// Sets the shared secret. This secret is passed as an ASCII string.
    pub fn ascii_key(&mut self, key: &String) -> &mut TOTPBuilder {
        self.key = Some(key.clone().into_bytes());
        self
    }

    /// Sets the shared secret. This secret is passed as an hexadecimal encoded string.
    pub fn hex_key(&mut self, key: &String) -> &mut TOTPBuilder {
        self.key = Some(key.from_hex().unwrap());
        self
    }

    /// Sets the shared secret. This secret is passed as a base32 encoded string.
    pub fn base32_key(&mut self, key: &String) -> &mut TOTPBuilder {
        let raw_key = base32::decode(base32::Alphabet::RFC4648 { padding: false }, &key).unwrap();
        self.key = Some(raw_key);
        self
    }

    /// Sets a custom value for the current Unix time instead of the real one.
    pub fn timestamp(&mut self, timestamp: u64) -> &mut TOTPBuilder {
        self.timestamp = timestamp;
        self
    }

    /// Sets the time step in seconds (X). Default is 30.
    pub fn period(&mut self, period: u32) -> &mut TOTPBuilder {
        self.period = period;
        self
    }

    /// Sets the Unix time to start counting time steps (T0). Default is 0.
    pub fn initial_time(&mut self, initial_time: u64) -> &mut TOTPBuilder {
        self.initial_time = initial_time;
        self
    }

    /// Sets the number of digits for the code. The minimum is 6. Default is 6.
    pub fn nb_digits(&mut self, nb_digits: u8) -> &mut TOTPBuilder {
        if nb_digits < 6 {
            panic!("There must be at least 6 digits.")
        }
        self.nb_digits = nb_digits;
        self
    }

    /// Sets the hash function. Default is Sha1.
    pub fn hash_function(&mut self, hash_function: HashFunction) -> &mut TOTPBuilder {
        self.hash_function = hash_function;
        self
    }

    /// Returns the finalized TOTP object.
    pub fn finalize(&self) -> Result<TOTP, &'static str> {
        match self.key {
            Some(ref k) => Ok(TOTP {
                key: k.clone(),
                timestamp: self.timestamp,
                initial_time: self.initial_time,
                period: self.period,
                nb_digits: self.nb_digits,
                hash_function: self.hash_function,
            }),
            None => Err("No key provided."),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::TOTPBuilder;
    use otp::HashFunction;

    #[test]
    fn test_totp_key_simple() {
        let key = vec![49, 50, 51, 52, 53, 54, 55, 56, 57, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 48];

        let mut totp = TOTPBuilder::new()
            .key(&key)
            .finalize()
            .unwrap();

        assert_eq!(totp.key, key);
        assert_eq!(totp.nb_digits, 6);
        match totp.hash_function {
            HashFunction::Sha1 => assert!(true),
            _ => assert!(false),
        }

        let code = totp.generate();
        assert_eq!(code.len(), 6);
    }

    #[test]
    fn test_totp_keu_full() {
        let key = vec![49, 50, 51, 52, 53, 54, 55, 56, 57, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 48];

        let mut totp = TOTPBuilder::new()
            .key(&key)
            .timestamp(1111111109)
            .period(70)
            .nb_digits(8)
            .hash_function(HashFunction::Sha256)
            .finalize()
            .unwrap();
        assert_eq!(totp.key, key);
        assert_eq!(totp.timestamp, 1111111109);
        assert_eq!(totp.period, 70);
        assert_eq!(totp.initial_time, 0);
        assert_eq!(totp.nb_digits, 8);

        let code = totp.generate();
        assert_eq!(code.len(), 8);
        assert_eq!(code, "04696041");
    }

        #[test]
    fn test_totp_asciikey_simple() {
        let key_ascii = "12345678901234567890".to_string();
        let key = vec![49, 50, 51, 52, 53, 54, 55, 56, 57, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 48];

        let mut totp = TOTPBuilder::new()
            .ascii_key(&key_ascii)
            .finalize()
            .unwrap();

        assert_eq!(totp.key, key);
        assert_eq!(totp.nb_digits, 6);
        match totp.hash_function {
            HashFunction::Sha1 => assert!(true),
            _ => assert!(false),
        }

        let code = totp.generate();
        assert_eq!(code.len(), 6);
    }

    #[test]
    fn test_totp_asciikeu_full() {
        let key_ascii = "12345678901234567890".to_string();
        let key = vec![49, 50, 51, 52, 53, 54, 55, 56, 57, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 48];

        let mut totp = TOTPBuilder::new()
            .ascii_key(&key_ascii)
            .timestamp(1111111109)
            .period(70)
            .nb_digits(8)
            .hash_function(HashFunction::Sha256)
            .finalize()
            .unwrap();
        assert_eq!(totp.key, key);
        assert_eq!(totp.timestamp, 1111111109);
        assert_eq!(totp.period, 70);
        assert_eq!(totp.initial_time, 0);
        assert_eq!(totp.nb_digits, 8);

        let code = totp.generate();
        assert_eq!(code.len(), 8);
        assert_eq!(code, "04696041");
    }

    #[test]
    fn test_totp_kexkey_simple() {
        let key_hex = "3132333435363738393031323334353637383930".to_string();
        let key = vec![49, 50, 51, 52, 53, 54, 55, 56, 57, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 48];

        let mut totp = TOTPBuilder::new()
            .hex_key(&key_hex)
            .finalize()
            .unwrap();

        assert_eq!(totp.key, key);
        assert_eq!(totp.nb_digits, 6);
        match totp.hash_function {
            HashFunction::Sha1 => assert!(true),
            _ => assert!(false),
        }

        let code = totp.generate();
        assert_eq!(code.len(), 6);
    }

    #[test]
    fn test_totp_hexkey_full() {
        let key_hex = "3132333435363738393031323334353637383930".to_string();
        let key = vec![49, 50, 51, 52, 53, 54, 55, 56, 57, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 48];

        let mut totp = TOTPBuilder::new()
            .hex_key(&key_hex)
            .timestamp(1111111109)
            .period(70)
            .nb_digits(8)
            .hash_function(HashFunction::Sha256)
            .finalize()
            .unwrap();
        assert_eq!(totp.key, key);
        assert_eq!(totp.timestamp, 1111111109);
        assert_eq!(totp.period, 70);
        assert_eq!(totp.initial_time, 0);
        assert_eq!(totp.nb_digits, 8);

        let code = totp.generate();
        assert_eq!(code.len(), 8);
        assert_eq!(code, "04696041");
    }

    #[test]
    fn test_totp_base32key_simple() {
        let key = vec![49, 50, 51, 52, 53, 54, 55, 56, 57, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 48];
        let key_base32 = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ".to_string();

        let mut totp = TOTPBuilder::new()
            .base32_key(&key_base32)
            .finalize()
            .unwrap();

        assert_eq!(totp.key, key);
        assert_eq!(totp.nb_digits, 6);
        match totp.hash_function {
            HashFunction::Sha1 => assert!(true),
            _ => assert!(false),
        }

        let code = totp.generate();
        assert_eq!(code.len(), 6);
    }

    #[test]
    fn test_totp_base32key_full() {
        let key = vec![49, 50, 51, 52, 53, 54, 55, 56, 57, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 48];
        let key_base32 = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ".to_string();

        let mut totp = TOTPBuilder::new()
            .base32_key(&key_base32)
            .timestamp(1111111109)
            .period(70)
            .nb_digits(8)
            .hash_function(HashFunction::Sha256)
            .finalize()
            .unwrap();
        assert_eq!(totp.key, key);
        assert_eq!(totp.timestamp, 1111111109);
        assert_eq!(totp.period, 70);
        assert_eq!(totp.initial_time, 0);
        assert_eq!(totp.nb_digits, 8);

        let code = totp.generate();
        assert_eq!(code.len(), 8);
        assert_eq!(code, "04696041");
    }

    #[test]
    fn test_nokey() {
        match TOTPBuilder::new().finalize() {
            Ok(_) => assert!(false),
            Err(_) => assert!(true),
        }
    }

    #[test]
    fn test_rfc6238_examples_sha1() {
        let key_hex = "3132333435363738393031323334353637383930".to_string();
        let examples = [
            (59,          HashFunction::Sha1,   "94287082"),
            (1111111109,  HashFunction::Sha1,   "07081804"),
            (1111111111,  HashFunction::Sha1,   "14050471"),
            (1234567890,  HashFunction::Sha1,   "89005924"),
            (2000000000,  HashFunction::Sha1,   "69279037"),
            (20000000000, HashFunction::Sha1,   "65353130"),
        ];
        for &(timestamp, hash_function, ref_code) in examples.iter() {
            let code = TOTPBuilder::new()
                .hex_key(&key_hex)
                .timestamp(timestamp)
                .nb_digits(8)
                .hash_function(hash_function)
                .finalize()
                .unwrap()
                .generate();
            assert_eq!(code.len(), 8);
            assert_eq!(code, ref_code);
        }
    }

    #[test]
    fn test_rfc6238_examples_sha256() {
        let key_hex = "3132333435363738393031323334353637383930313233343536373839303132".to_string();
        let examples = [
            (59,          HashFunction::Sha256, "46119246"),
            (1111111109,  HashFunction::Sha256, "68084774"),
            (1111111111,  HashFunction::Sha256, "67062674"),
            (1234567890,  HashFunction::Sha256, "91819424"),
            (2000000000,  HashFunction::Sha256, "90698825"),
            (20000000000, HashFunction::Sha256, "77737706"),
        ];
        for &(timestamp, hash_function, ref_code) in examples.iter() {
            let code = TOTPBuilder::new()
                .hex_key(&key_hex)
                .timestamp(timestamp)
                .nb_digits(8)
                .hash_function(hash_function)
                .finalize()
                .unwrap()
                .generate();
            assert_eq!(code.len(), 8);
            assert_eq!(code, ref_code);
        }
    }

    #[test]
    fn test_rfc6238_examples_sha512() {
        let key_hex = "31323334353637383930313233343536373839303132333435363738393031323334353637383930313233343536373839303132333435363738393031323334".to_string();
        let examples = [
            (59,          HashFunction::Sha512, "90693936"),
            (1111111109,  HashFunction::Sha512, "25091201"),
            (1111111111,  HashFunction::Sha512, "99943326"),
            (1234567890,  HashFunction::Sha512, "93441116"),
            (2000000000,  HashFunction::Sha512, "38618901"),
            (20000000000, HashFunction::Sha512, "47863826"),
        ];
        for &(timestamp, hash_function, ref_code) in examples.iter() {
            let code = TOTPBuilder::new()
                .hex_key(&key_hex)
                .timestamp(timestamp)
                .nb_digits(8)
                .hash_function(hash_function)
                .finalize()
                .unwrap()
                .generate();
            assert_eq!(code.len(), 8);
            assert_eq!(code, ref_code);
        }
    }
}
