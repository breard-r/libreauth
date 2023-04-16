#[cfg(feature = "oath-uri")]
use super::DEFAULT_KEY_URI_PARAM_POLICY;
use super::{
    Error, HashFunction, DEFAULT_LOOK_AHEAD, DEFAULT_OTP_HASH, DEFAULT_OTP_OUT_BASE,
    DEFAULT_OTP_OUT_LEN,
};
#[cfg(feature = "oath-uri")]
use crate::oath::key_uri::{KeyUriBuilder, UriType};
use hmac::{Hmac, Mac};
use sha1::Sha1;
use sha2::{Sha224, Sha256, Sha384, Sha512, Sha512_224, Sha512_256};
use sha3::{Keccak224, Keccak256, Keccak384, Keccak512, Sha3_224, Sha3_256, Sha3_384, Sha3_512};
use std::collections::HashMap;

macro_rules! compute_hmac {
    ($obj: ident, $hash: ty, $input: ident) => {{
        let mut hmac = Hmac::<$hash>::new_from_slice(&$obj.key.as_slice()).unwrap();
        hmac.update(&$input);
        hmac.finalize().into_bytes().to_vec()
    }};
}

/// Generates, manipulates and checks HOTP codes.
pub struct HOTP {
    key: Vec<u8>,
    counter: u64,
    output_len: usize,
    output_base: String,
    hash_function: HashFunction,
    look_ahead: u64,
}

impl HOTP {
    fn reduce_result(&self, hs: &[u8]) -> u32 {
        let offset = (hs[hs.len() - 1] & 0xf) as usize;
        let hash = hs[offset..offset + 4].to_vec();
        let snum: u32 = ((u32::from(hash[0]) & 0x7f) << 24)
            | ((u32::from(hash[1]) & 0xff) << 16)
            | ((u32::from(hash[2]) & 0xff) << 8)
            | (u32::from(hash[3]) & 0xff);

        let base = self.output_base.len() as u32;
        snum % base.pow(self.output_len as u32)
    }

    fn format_result(&self, nb: u32) -> String {
        let mut code = Vec::with_capacity(self.output_len);
        let mut nb = nb;
        let base_len = self.output_base.len() as u32;

        while nb > 0 {
            code.push(
                self.output_base
                    .chars()
                    .nth((nb % base_len) as usize)
                    .unwrap(),
            );
            nb /= base_len;
        }
        while code.len() != self.output_len {
            code.push(self.output_base.chars().next().unwrap());
        }
        code.reverse();
        code.iter().collect()
    }

    fn raw_generate(&self, counter: u64) -> String {
        let msg = [
            ((counter >> 56) & 0xff) as u8,
            ((counter >> 48) & 0xff) as u8,
            ((counter >> 40) & 0xff) as u8,
            ((counter >> 32) & 0xff) as u8,
            ((counter >> 24) & 0xff) as u8,
            ((counter >> 16) & 0xff) as u8,
            ((counter >> 8) & 0xff) as u8,
            (counter & 0xff) as u8,
        ];
        let result: Vec<u8> = match self.hash_function {
            HashFunction::Sha1 => compute_hmac!(self, Sha1, msg),
            HashFunction::Sha224 => compute_hmac!(self, Sha224, msg),
            HashFunction::Sha256 => compute_hmac!(self, Sha256, msg),
            HashFunction::Sha384 => compute_hmac!(self, Sha384, msg),
            HashFunction::Sha512 => compute_hmac!(self, Sha512, msg),
            HashFunction::Sha512Trunc224 => compute_hmac!(self, Sha512_224, msg),
            HashFunction::Sha512Trunc256 => compute_hmac!(self, Sha512_256, msg),
            HashFunction::Sha3_224 => compute_hmac!(self, Sha3_224, msg),
            HashFunction::Sha3_256 => compute_hmac!(self, Sha3_256, msg),
            HashFunction::Sha3_384 => compute_hmac!(self, Sha3_384, msg),
            HashFunction::Sha3_512 => compute_hmac!(self, Sha3_512, msg),
            HashFunction::Keccak224 => compute_hmac!(self, Keccak224, msg),
            HashFunction::Keccak256 => compute_hmac!(self, Keccak256, msg),
            HashFunction::Keccak384 => compute_hmac!(self, Keccak384, msg),
            HashFunction::Keccak512 => compute_hmac!(self, Keccak512, msg),
        };
        let hs = result.as_slice();
        let nb = self.reduce_result(hs);
        self.format_result(nb)
    }

    /// Generate the HOTP value.
    ///
    /// ## Examples
    /// ```
    /// let key_ascii = "12345678901234567890".to_owned();
    /// let mut hotp = libreauth::oath::HOTPBuilder::new()
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
        self.raw_generate(self.counter)
    }

    /// Returns the internal counter value.
    pub fn get_counter(&self) -> u64 {
        self.counter
    }

    /// Increments the internal counter.
    pub fn increment_counter(&mut self) -> &mut HOTP {
        self.counter += 1;
        self
    }

    fn raw_is_valid(&self, code: &str) -> (bool, u64) {
        if code.len() != self.output_len {
            return (false, self.counter);
        }
        let mut results = HashMap::new();
        let end = self.counter + 1 + self.look_ahead;
        for counter in self.counter..end {
            let r1 = self.raw_generate(counter);
            let ref_code = r1.as_str().as_bytes();
            let code = code.as_bytes();
            let (code, ref_code) = match self.hash_function {
                HashFunction::Sha1 => (
                    compute_hmac!(self, Sha1, code),
                    compute_hmac!(self, Sha1, ref_code),
                ),
                HashFunction::Sha224 => (
                    compute_hmac!(self, Sha224, code),
                    compute_hmac!(self, Sha224, ref_code),
                ),
                HashFunction::Sha256 => (
                    compute_hmac!(self, Sha256, code),
                    compute_hmac!(self, Sha256, ref_code),
                ),
                HashFunction::Sha384 => (
                    compute_hmac!(self, Sha384, code),
                    compute_hmac!(self, Sha384, ref_code),
                ),
                HashFunction::Sha512 => (
                    compute_hmac!(self, Sha512, code),
                    compute_hmac!(self, Sha512, ref_code),
                ),
                HashFunction::Sha512Trunc224 => (
                    compute_hmac!(self, Sha512_224, code),
                    compute_hmac!(self, Sha512_224, ref_code),
                ),
                HashFunction::Sha512Trunc256 => (
                    compute_hmac!(self, Sha512_256, code),
                    compute_hmac!(self, Sha512_256, ref_code),
                ),
                HashFunction::Sha3_224 => (
                    compute_hmac!(self, Sha3_224, code),
                    compute_hmac!(self, Sha3_224, ref_code),
                ),
                HashFunction::Sha3_256 => (
                    compute_hmac!(self, Sha3_256, code),
                    compute_hmac!(self, Sha3_256, ref_code),
                ),
                HashFunction::Sha3_384 => (
                    compute_hmac!(self, Sha3_384, code),
                    compute_hmac!(self, Sha3_384, ref_code),
                ),
                HashFunction::Sha3_512 => (
                    compute_hmac!(self, Sha3_512, code),
                    compute_hmac!(self, Sha3_512, ref_code),
                ),
                HashFunction::Keccak224 => (
                    compute_hmac!(self, Keccak224, code),
                    compute_hmac!(self, Keccak224, ref_code),
                ),
                HashFunction::Keccak256 => (
                    compute_hmac!(self, Keccak256, code),
                    compute_hmac!(self, Keccak256, ref_code),
                ),
                HashFunction::Keccak384 => (
                    compute_hmac!(self, Keccak384, code),
                    compute_hmac!(self, Keccak384, ref_code),
                ),
                HashFunction::Keccak512 => (
                    compute_hmac!(self, Keccak512, code),
                    compute_hmac!(self, Keccak512, ref_code),
                ),
            };
            results.insert(code == ref_code, counter);
        }
        match results.get(&true) {
            Some(c) => (true, c + 1),
            None => (false, self.counter),
        }
    }

    /// Checks if the given code is valid within the look-ahead range.
    /// For most usages, you might want to use [is_valid_sync](#method.is_valid_sync) instead.
    ///
    /// This implementation uses the [double HMAC verification](https://www.nccgroup.trust/us/about-us/newsroom-and-events/blog/2011/february/double-hmac-verification/) in order to prevent a timing side channel attack.
    ///
    /// ## Examples
    /// ```
    /// let key_ascii = "12345678901234567890".to_owned();
    /// let user_code = "755224".to_owned();
    /// let valid = libreauth::oath::HOTPBuilder::new()
    ///     .ascii_key(&key_ascii)
    ///     .finalize()
    ///     .unwrap()
    ///     .is_valid(&user_code);
    /// assert!(valid);
    /// ```
    pub fn is_valid(&self, code: &str) -> bool {
        self.raw_is_valid(code).0
    }

    /// Checks if the given code is valid within the look-ahead range. If the code was valid, updates the counter's value.
    ///
    /// This implementation uses the [double HMAC verification](https://www.nccgroup.trust/us/about-us/newsroom-and-events/blog/2011/february/double-hmac-verification/) in order to prevent a timing side channel attack.
    ///
    /// ## Examples
    /// ```
    /// // Counter: code
    /// // 0: 755224
    /// // 1: 287082
    /// // 2: 359152
    /// // 3: 969429
    /// // 4: 338314
    /// // 5: 254676
    /// let key_ascii = "12345678901234567890".to_owned();
    /// let mut checker = libreauth::oath::HOTPBuilder::new()
    ///     .ascii_key(&key_ascii)
    ///     .look_ahead(3)
    ///     .finalize()
    ///     .unwrap();
    ///
    /// // The counter starts at 0.
    /// assert_eq!(checker.get_counter(), 0);
    ///
    /// // The client's counter is synchronized.
    /// assert!(checker.is_valid_sync("755224"));
    /// assert_eq!(checker.get_counter(), 1);
    ///
    /// // The client's counter is not synchronized and out of the look-ahead range.
    /// assert!(!checker.is_valid_sync("254676"));
    /// assert_eq!(checker.get_counter(), 1);
    ///
    /// // The client's counter is not synchronized and within the look-ahead range.
    /// assert!(checker.is_valid_sync("338314"));
    /// assert_eq!(checker.get_counter(), 5);
    ///
    /// // The client's counter is synchronized.
    /// assert!(checker.is_valid_sync("254676"));
    /// assert_eq!(checker.get_counter(), 6);
    /// ```
    pub fn is_valid_sync(&mut self, code: &str) -> bool {
        let (result, new_counter) = self.raw_is_valid(code);
        self.counter = new_counter;
        result
    }

    /// Creates the Key Uri Format according to the [Google authenticator
    /// specification](https://github.com/google/google-authenticator/wiki/Key-Uri-Format).
    /// This value can be used to generete QR codes which allow easy scanning by the end user.
    /// The returned [`KeyUriBuilder`] allows for additional customizations.
    ///
    /// **WARNING**: The finalized value contains the secret key of the authentication process and
    /// should only be displayed to the corresponding user!
    ///
    /// ## Example
    ///
    /// ```
    /// let key_ascii = "12345678901234567890".to_owned();
    /// let mut hotp = libreauth::oath::HOTPBuilder::new()
    ///     .ascii_key(&key_ascii)
    ///     .finalize()
    ///     .unwrap();
    ///
    /// let uri = hotp
    ///     .key_uri_format("Provider1", "alice@example.com")
    ///     .finalize();
    ///
    /// assert_eq!(
    ///     uri,
    ///     "otpauth://hotp/Provider1:alice@example.com?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&issuer=Provider1&counter=0"
    /// );
    /// ```
    #[cfg(feature = "oath-uri")]
    pub fn key_uri_format<'a>(
        &'a self,
        issuer: &'a str,
        account_name: &'a str,
    ) -> KeyUriBuilder<'a> {
        KeyUriBuilder {
            parameters_visibility: DEFAULT_KEY_URI_PARAM_POLICY,
            uri_type: UriType::HOTP,
            key: &self.key,
            issuer,
            account_name,
            custom_label: None,
            custom_parameters: HashMap::new(),
            algo: self.hash_function,
            output_len: self.output_len,
            output_base: &self.output_base,
            counter: Some(self.counter),
            period: None,
            initial_time: None,
        }
    }
}

/// Builds an HOTP object.
///
/// ## Examples
///
/// The following examples uses the same shared secret passed in various forms.
///
/// ```
/// let key = vec![49, 50, 51, 52, 53, 54, 55, 56, 57, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 48];
/// let mut hotp = libreauth::oath::HOTPBuilder::new()
///     .key(&key)
///     .finalize()
///     .unwrap();
/// ```
///
/// ```
/// let key_ascii = "12345678901234567890".to_owned();
/// let mut hotp = libreauth::oath::HOTPBuilder::new()
///     .ascii_key(&key_ascii)
///     .counter(42)
///     .finalize()
///     .unwrap();
/// ```
///
/// ```
/// let key_hex = "3132333435363738393031323334353637383930".to_owned();
/// let mut hotp = libreauth::oath::HOTPBuilder::new()
///     .hex_key(&key_hex)
///     .counter(69)
///     .output_len(8)
///     .finalize();
/// ```
///
/// ```
/// let key_base32 = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ".to_owned();
/// let mut hotp = libreauth::oath::HOTPBuilder::new()
///     .base32_key(&key_base32)
///     .output_len(8)
///     .hash_function(libreauth::hash::HashFunction::Sha256)
///     .finalize();
/// ```
///
/// ```
/// let key_base64 = "MTIzNDU2Nzg5MDEyMzQ1Njc4OTA=".to_owned();
/// let mut hotp = libreauth::oath::HOTPBuilder::new()
///     .base64_key(&key_base64)
///     .output_len(8)
///     .hash_function(libreauth::hash::HashFunction::Sha256)
///     .finalize();
/// ```
pub struct HOTPBuilder {
    key: Option<Vec<u8>>,
    counter: u64,
    output_len: usize,
    output_base: String,
    hash_function: HashFunction,
    runtime_error: Option<Error>,
    look_ahead: u64,
}

impl Default for HOTPBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl HOTPBuilder {
    /// Generates the base configuration for HOTP code generation.
    pub fn new() -> HOTPBuilder {
        HOTPBuilder {
            key: None,
            counter: 0,
            output_len: DEFAULT_OTP_OUT_LEN,
            output_base: DEFAULT_OTP_OUT_BASE.to_string(),
            hash_function: DEFAULT_OTP_HASH,
            runtime_error: None,
            look_ahead: DEFAULT_LOOK_AHEAD,
        }
    }

    builder_common!(HOTPBuilder);

    /// Sets the counter. Default is 0.
    pub fn counter(&mut self, counter: u64) -> &mut HOTPBuilder {
        self.counter = counter;
        self
    }

    /// Sets a look-ahead parameter. Default is 0.
    pub fn look_ahead(&mut self, nb: u64) -> &mut HOTPBuilder {
        self.look_ahead = nb;
        self
    }

    /// Returns the finalized HOTP object.
    pub fn finalize(&self) -> Result<HOTP, Error> {
        if let Some(e) = self.runtime_error {
            return Err(e);
        }
        match self.code_length() {
            n if n < 1_000_000 => return Err(Error::CodeTooSmall),
            n if n > 2_147_483_648 => return Err(Error::CodeTooBig),
            _ => (),
        }
        match self.key {
            Some(ref k) => Ok(HOTP {
                key: k.clone(),
                counter: self.counter,
                output_len: self.output_len,
                output_base: self.output_base.clone(),
                hash_function: self.hash_function,
                look_ahead: self.look_ahead,
            }),
            None => Err(Error::InvalidKey),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::HOTPBuilder;
    use crate::hash::HashFunction;
    #[cfg(feature = "oath-uri")]
    use crate::oath::ParametersVisibility;

    #[test]
    fn test_hotp_key_simple() {
        let key = vec![
            49, 50, 51, 52, 53, 54, 55, 56, 57, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 48,
        ];

        let hotp = HOTPBuilder::new().key(&key).finalize().unwrap();

        assert_eq!(hotp.key, key);
        assert_eq!(hotp.counter, 0);
        assert_eq!(hotp.output_len, 6);
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
        let key = vec![
            49, 50, 51, 52, 53, 54, 55, 56, 57, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 48,
        ];

        let hotp = HOTPBuilder::new()
            .key(&key)
            .counter(5)
            .output_len(8)
            .hash_function(HashFunction::Sha256)
            .finalize()
            .unwrap();

        assert_eq!(hotp.key, key);
        assert_eq!(hotp.counter, 5);
        assert_eq!(hotp.output_len, 8);
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
        let key_ascii = "12345678901234567890".to_owned();
        let key = vec![
            49, 50, 51, 52, 53, 54, 55, 56, 57, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 48,
        ];

        let hotp = HOTPBuilder::new().ascii_key(&key_ascii).finalize().unwrap();

        assert_eq!(hotp.key, key);
        assert_eq!(hotp.counter, 0);
        assert_eq!(hotp.output_len, 6);
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
        let key_ascii = "12345678901234567890".to_owned();
        let key = vec![
            49, 50, 51, 52, 53, 54, 55, 56, 57, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 48,
        ];

        let hotp = HOTPBuilder::new()
            .ascii_key(&key_ascii)
            .counter(5)
            .output_len(8)
            .hash_function(HashFunction::Sha256)
            .finalize()
            .unwrap();

        assert_eq!(hotp.key, key);
        assert_eq!(hotp.counter, 5);
        assert_eq!(hotp.output_len, 8);
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
        let key_hex = "3132333435363738393031323334353637383930".to_owned();
        let key = vec![
            49, 50, 51, 52, 53, 54, 55, 56, 57, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 48,
        ];

        let hotp = HOTPBuilder::new().hex_key(&key_hex).finalize().unwrap();

        assert_eq!(hotp.key, key);
        assert_eq!(hotp.counter, 0);
        assert_eq!(hotp.output_len, 6);
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
        let key_hex = "3132333435363738393031323334353637383930".to_owned();
        let key = vec![
            49, 50, 51, 52, 53, 54, 55, 56, 57, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 48,
        ];

        let hotp = HOTPBuilder::new()
            .hex_key(&key_hex)
            .counter(5)
            .output_len(8)
            .hash_function(HashFunction::Sha512)
            .finalize()
            .unwrap();

        assert_eq!(hotp.key, key);
        assert_eq!(hotp.counter, 5);
        assert_eq!(hotp.output_len, 8);
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
        let key = vec![
            49, 50, 51, 52, 53, 54, 55, 56, 57, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 48,
        ];
        let key_base32 = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ".to_owned();

        let hotp = HOTPBuilder::new()
            .base32_key(&key_base32)
            .finalize()
            .unwrap();

        assert_eq!(hotp.key, key);
        assert_eq!(hotp.counter, 0);
        assert_eq!(hotp.output_len, 6);
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
        let key = vec![
            49, 50, 51, 52, 53, 54, 55, 56, 57, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 48,
        ];
        let key_base32 = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ".to_owned();

        let hotp = HOTPBuilder::new()
            .base32_key(&key_base32)
            .counter(5)
            .output_len(8)
            .hash_function(HashFunction::Sha512)
            .finalize()
            .unwrap();

        assert_eq!(hotp.key, key);
        assert_eq!(hotp.counter, 5);
        assert_eq!(hotp.output_len, 8);
        match hotp.hash_function {
            HashFunction::Sha512 => assert!(true),
            _ => assert!(false),
        }

        let code = hotp.generate();
        assert_eq!(code.len(), 8);
        assert_eq!(code, "16848329");
    }

    #[test]
    fn test_hotp_base64key_simple() {
        let key = vec![
            49, 50, 51, 52, 53, 54, 55, 56, 57, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 48,
        ];
        let key_base64 = "MTIzNDU2Nzg5MDEyMzQ1Njc4OTA=".to_owned();

        let hotp = HOTPBuilder::new()
            .base64_key(&key_base64)
            .finalize()
            .unwrap();

        assert_eq!(hotp.key, key);
        assert_eq!(hotp.counter, 0);
        assert_eq!(hotp.output_len, 6);
        match hotp.hash_function {
            HashFunction::Sha1 => assert!(true),
            _ => assert!(false),
        }

        let code = hotp.generate();
        assert_eq!(code.len(), 6);
        assert_eq!(code, "755224");
    }

    #[test]
    fn test_hotp_base64key_full() {
        let key = vec![
            49, 50, 51, 52, 53, 54, 55, 56, 57, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 48,
        ];
        let key_base64 = "MTIzNDU2Nzg5MDEyMzQ1Njc4OTA=".to_owned();

        let hotp = HOTPBuilder::new()
            .base64_key(&key_base64)
            .counter(5)
            .output_len(8)
            .hash_function(HashFunction::Sha512)
            .finalize()
            .unwrap();

        assert_eq!(hotp.key, key);
        assert_eq!(hotp.counter, 5);
        assert_eq!(hotp.output_len, 8);
        match hotp.hash_function {
            HashFunction::Sha512 => assert!(true),
            _ => assert!(false),
        }

        let code = hotp.generate();
        assert_eq!(code.len(), 8);
        assert_eq!(code, "16848329");
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
        let key = "!@#$%^&".to_owned();
        match HOTPBuilder::new().hex_key(&key).finalize() {
            Ok(_) => assert!(false),
            Err(_) => assert!(true),
        }
    }

    #[test]
    fn test_invalid_base32key() {
        let key = "!@#$%^&".to_owned();
        match HOTPBuilder::new().base32_key(&key).finalize() {
            Ok(_) => assert!(false),
            Err(_) => assert!(true),
        }
    }

    #[test]
    fn test_empty_output_base() {
        let key_ascii = "12345678901234567890".to_owned();
        let output_base = "";
        match HOTPBuilder::new()
            .ascii_key(&key_ascii)
            .output_base(&output_base)
            .finalize()
        {
            Ok(_) => assert!(false),
            Err(_) => assert!(true),
        }
    }

    #[test]
    fn test_invalid_output_base() {
        let key_ascii = "12345678901234567890".to_owned();
        let output_base = "1";
        match HOTPBuilder::new()
            .ascii_key(&key_ascii)
            .output_base(&output_base)
            .finalize()
        {
            Ok(_) => assert!(false),
            Err(_) => assert!(true),
        }
    }

    #[test]
    fn test_small_result_base10() {
        let key_ascii = "12345678901234567890".to_owned();
        match HOTPBuilder::new()
            .ascii_key(&key_ascii)
            .output_len(5)
            .finalize()
        {
            Ok(_) => assert!(false),
            Err(_) => assert!(true),
        }
    }

    #[test]
    fn test_big_result_base10() {
        let key_ascii = "12345678901234567890".to_owned();
        for nb in vec![10, 42, 69, 1024, 0xffffff] {
            match HOTPBuilder::new()
                .ascii_key(&key_ascii)
                .output_len(nb)
                .finalize()
            {
                Ok(_) => assert!(false),
                Err(_) => assert!(true),
            }
        }
    }

    #[test]
    fn test_result_ok_base10() {
        let key_ascii = "12345678901234567890".to_owned();
        match HOTPBuilder::new()
            .ascii_key(&key_ascii)
            .output_len(6)
            .finalize()
        {
            Ok(_) => assert!(true),
            Err(_) => assert!(false),
        }
        match HOTPBuilder::new()
            .ascii_key(&key_ascii)
            .output_len(9)
            .finalize()
        {
            Ok(_) => assert!(true),
            Err(_) => assert!(false),
        }
    }

    #[test]
    fn test_small_result_base64() {
        let key_ascii = "12345678901234567890".to_owned();
        let base = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ+/";
        match HOTPBuilder::new()
            .ascii_key(&key_ascii)
            .output_base(&base)
            .output_len(3)
            .finalize()
        {
            Ok(_) => assert!(false),
            Err(_) => assert!(true),
        }
    }

    #[test]
    fn test_big_result_base64() {
        let key_ascii = "12345678901234567890".to_owned();
        let base = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ+/";
        match HOTPBuilder::new()
            .ascii_key(&key_ascii)
            .output_base(&base)
            .output_len(6)
            .finalize()
        {
            Ok(_) => assert!(false),
            Err(_) => assert!(true),
        }
    }

    #[test]
    fn test_result_ok_base64() {
        let key_ascii = "12345678901234567890".to_owned();
        let base = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ+/";
        match HOTPBuilder::new()
            .ascii_key(&key_ascii)
            .output_base(&base)
            .output_len(4)
            .finalize()
        {
            Ok(_) => assert!(true),
            Err(_) => assert!(false),
        }
        match HOTPBuilder::new()
            .ascii_key(&key_ascii)
            .output_base(&base)
            .output_len(5)
            .finalize()
        {
            Ok(_) => assert!(true),
            Err(_) => assert!(false),
        }
    }

    #[test]
    fn test_rfc4226_examples() {
        let key_ascii = "12345678901234567890".to_owned();
        let key = vec![
            49, 50, 51, 52, 53, 54, 55, 56, 57, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 48,
        ];
        let hex_base = "0123456789ABCDEF";

        let examples = [
            ["755224", "93CF18"],
            ["287082", "397EEA"],
            ["359152", "2FEF30"],
            ["969429", "EF7655"],
            ["338314", "C5938A"],
            ["254676", "C083D4"],
            ["287922", "56C032"],
            ["162583", "E5B397"],
            ["399871", "23443F"],
            ["520489", "79DC69"],
        ];
        let mut hotp1 = HOTPBuilder::new().ascii_key(&key_ascii).finalize().unwrap();
        let mut hotp2 = HOTPBuilder::new()
            .key(&key)
            .counter(0)
            .hash_function(HashFunction::Sha1)
            .finalize()
            .unwrap();
        let mut hotp3 = HOTPBuilder::new()
            .ascii_key(&key_ascii)
            .output_base(&hex_base)
            .finalize()
            .unwrap();
        for count in 0..examples.len() {
            let counter = count as u64;
            assert_eq!(hotp1.counter, counter);
            assert_eq!(hotp2.counter, counter);
            assert_eq!(hotp3.counter, counter);
            let code1 = hotp1.generate();
            let code2 = hotp2.generate();
            let code3 = hotp3.generate();
            assert_eq!(code1, examples[count][0]);
            assert_eq!(code2, examples[count][0]);
            assert_eq!(code3, examples[count][1]);
            hotp1.increment_counter();
            hotp2.increment_counter();
            hotp3.increment_counter();
            assert_eq!(hotp1.counter, counter + 1);
            assert_eq!(hotp2.counter, counter + 1);
            assert_eq!(hotp3.counter, counter + 1);
        }
    }

    #[test]
    fn test_valid_sha1_code() {
        let key_ascii = "12345678901234567890".to_owned();
        let user_code = "755224".to_owned();
        let valid = HOTPBuilder::new()
            .ascii_key(&key_ascii)
            .hash_function(HashFunction::Sha1)
            .finalize()
            .unwrap()
            .is_valid(&user_code);
        assert_eq!(valid, true);
    }

    #[test]
    fn test_valid_sha224_code() {
        let key_ascii = "12345678901234567890".to_owned();
        let user_code = "893239".to_owned();
        let valid = HOTPBuilder::new()
            .ascii_key(&key_ascii)
            .hash_function(HashFunction::Sha224)
            .finalize()
            .unwrap()
            .is_valid(&user_code);
        assert_eq!(valid, true);
    }

    #[test]
    fn test_valid_sha256_code() {
        let key_ascii = "12345678901234567890".to_owned();
        let user_code = "875740".to_owned();
        let valid = HOTPBuilder::new()
            .ascii_key(&key_ascii)
            .hash_function(HashFunction::Sha256)
            .finalize()
            .unwrap()
            .is_valid(&user_code);
        assert_eq!(valid, true);
    }

    #[test]
    fn test_valid_sha384_code() {
        let key_ascii = "12345678901234567890".to_owned();
        let user_code = "502125".to_owned();
        let valid = HOTPBuilder::new()
            .ascii_key(&key_ascii)
            .hash_function(HashFunction::Sha384)
            .finalize()
            .unwrap()
            .is_valid(&user_code);
        assert_eq!(valid, true);
    }

    #[test]
    fn test_valid_sha512_code() {
        let key_ascii = "12345678901234567890".to_owned();
        let user_code = "125165".to_owned();
        let valid = HOTPBuilder::new()
            .ascii_key(&key_ascii)
            .hash_function(HashFunction::Sha512)
            .finalize()
            .unwrap()
            .is_valid(&user_code);
        assert_eq!(valid, true);
    }

    #[test]
    fn test_valid_sha512t224_code() {
        let key_ascii = "12345678901234567890".to_owned();
        let user_code = "627914".to_owned();
        let valid = HOTPBuilder::new()
            .ascii_key(&key_ascii)
            .hash_function(HashFunction::Sha512Trunc224)
            .finalize()
            .unwrap()
            .is_valid(&user_code);
        assert_eq!(valid, true);
    }

    #[test]
    fn test_valid_sha512t256_code() {
        let key_ascii = "12345678901234567890".to_owned();
        let user_code = "289990".to_owned();
        let valid = HOTPBuilder::new()
            .ascii_key(&key_ascii)
            .hash_function(HashFunction::Sha512Trunc256)
            .finalize()
            .unwrap()
            .is_valid(&user_code);
        assert_eq!(valid, true);
    }

    #[test]
    fn test_valid_sha3_224_code() {
        let key_ascii = "12345678901234567890".to_owned();
        let user_code = "228979".to_owned();
        let valid = HOTPBuilder::new()
            .ascii_key(&key_ascii)
            .hash_function(HashFunction::Sha3_224)
            .finalize()
            .unwrap()
            .is_valid(&user_code);
        assert_eq!(valid, true);
    }

    #[test]
    fn test_valid_sha3_256_code() {
        let key_ascii = "12345678901234567890".to_owned();
        let user_code = "170828".to_owned();
        let valid = HOTPBuilder::new()
            .ascii_key(&key_ascii)
            .hash_function(HashFunction::Sha3_256)
            .finalize()
            .unwrap()
            .is_valid(&user_code);
        assert_eq!(valid, true);
    }

    #[test]
    fn test_valid_sha3_384_code() {
        let key_ascii = "12345678901234567890".to_owned();
        let user_code = "133113".to_owned();
        let valid = HOTPBuilder::new()
            .ascii_key(&key_ascii)
            .hash_function(HashFunction::Sha3_384)
            .finalize()
            .unwrap()
            .is_valid(&user_code);
        assert_eq!(valid, true);
    }

    #[test]
    fn test_valid_sha3_512_code() {
        let key_ascii = "12345678901234567890".to_owned();
        let user_code = "342230".to_owned();
        let valid = HOTPBuilder::new()
            .ascii_key(&key_ascii)
            .hash_function(HashFunction::Sha3_512)
            .finalize()
            .unwrap()
            .is_valid(&user_code);
        assert_eq!(valid, true);
    }

    #[test]
    fn test_valid_keccak_224_code() {
        let key_ascii = "12345678901234567890".to_owned();
        let user_code = "839246".to_owned();
        let valid = HOTPBuilder::new()
            .ascii_key(&key_ascii)
            .hash_function(HashFunction::Keccak224)
            .finalize()
            .unwrap()
            .is_valid(&user_code);
        assert_eq!(valid, true);
    }

    #[test]
    fn test_valid_keccak_256_code() {
        let key_ascii = "12345678901234567890".to_owned();
        let user_code = "190777".to_owned();
        let valid = HOTPBuilder::new()
            .ascii_key(&key_ascii)
            .hash_function(HashFunction::Keccak256)
            .finalize()
            .unwrap()
            .is_valid(&user_code);
        assert_eq!(valid, true);
    }

    #[test]
    fn test_valid_keccak_384_code() {
        let key_ascii = "12345678901234567890".to_owned();
        let user_code = "970541".to_owned();
        let valid = HOTPBuilder::new()
            .ascii_key(&key_ascii)
            .hash_function(HashFunction::Keccak384)
            .finalize()
            .unwrap()
            .is_valid(&user_code);
        assert_eq!(valid, true);
    }

    #[test]
    fn test_valid_keccak_512_code() {
        let key_ascii = "12345678901234567890".to_owned();
        let user_code = "108634".to_owned();
        let valid = HOTPBuilder::new()
            .ascii_key(&key_ascii)
            .hash_function(HashFunction::Keccak512)
            .finalize()
            .unwrap()
            .is_valid(&user_code);
        assert_eq!(valid, true);
    }

    #[test]
    fn test_invalid_sha1_code() {
        let key_ascii = "12345678901234567890".to_owned();
        let user_code = "123456".to_owned();
        let valid = HOTPBuilder::new()
            .ascii_key(&key_ascii)
            .hash_function(HashFunction::Sha1)
            .finalize()
            .unwrap()
            .is_valid(&user_code);
        assert_eq!(valid, false);
    }

    #[test]
    fn test_invalid_sha224_code() {
        let key_ascii = "12345678901234567890".to_owned();
        let user_code = "893238".to_owned();
        let valid = HOTPBuilder::new()
            .ascii_key(&key_ascii)
            .hash_function(HashFunction::Sha224)
            .finalize()
            .unwrap()
            .is_valid(&user_code);
        assert_eq!(valid, false);
    }

    #[test]
    fn test_invalid_sha256_code() {
        let key_ascii = "12345678901234567890".to_owned();
        let user_code = "123456".to_owned();
        let valid = HOTPBuilder::new()
            .ascii_key(&key_ascii)
            .hash_function(HashFunction::Sha256)
            .finalize()
            .unwrap()
            .is_valid(&user_code);
        assert_eq!(valid, false);
    }

    #[test]
    fn test_invalid_sha384_code() {
        let key_ascii = "12345678901234567890".to_owned();
        let user_code = "502225".to_owned();
        let valid = HOTPBuilder::new()
            .ascii_key(&key_ascii)
            .hash_function(HashFunction::Sha384)
            .finalize()
            .unwrap()
            .is_valid(&user_code);
        assert_eq!(valid, false);
    }

    #[test]
    fn test_invalid_sha512_code() {
        let key_ascii = "12345678901234567890".to_owned();
        let user_code = "123456".to_owned();
        let valid = HOTPBuilder::new()
            .ascii_key(&key_ascii)
            .hash_function(HashFunction::Sha512)
            .finalize()
            .unwrap()
            .is_valid(&user_code);
        assert_eq!(valid, false);
    }

    #[test]
    fn test_invalid_sha512t224_code() {
        let key_ascii = "12345678901234567890".to_owned();
        let user_code = "627904".to_owned();
        let valid = HOTPBuilder::new()
            .ascii_key(&key_ascii)
            .hash_function(HashFunction::Sha512Trunc224)
            .finalize()
            .unwrap()
            .is_valid(&user_code);
        assert_eq!(valid, false);
    }

    #[test]
    fn test_invalid_sha512t256_code() {
        let key_ascii = "12345678901234567890".to_owned();
        let user_code = "289900".to_owned();
        let valid = HOTPBuilder::new()
            .ascii_key(&key_ascii)
            .hash_function(HashFunction::Sha512Trunc256)
            .finalize()
            .unwrap()
            .is_valid(&user_code);
        assert_eq!(valid, false);
    }

    #[test]
    fn test_invalid_sha3_224_code() {
        let key_ascii = "12345678901234567890".to_owned();
        let user_code = "128979".to_owned();
        let valid = HOTPBuilder::new()
            .ascii_key(&key_ascii)
            .hash_function(HashFunction::Sha3_224)
            .finalize()
            .unwrap()
            .is_valid(&user_code);
        assert_eq!(valid, false);
    }

    #[test]
    fn test_invalid_sha3_256_code() {
        let key_ascii = "12345678901234567890".to_owned();
        let user_code = "170823".to_owned();
        let valid = HOTPBuilder::new()
            .ascii_key(&key_ascii)
            .hash_function(HashFunction::Sha3_256)
            .finalize()
            .unwrap()
            .is_valid(&user_code);
        assert_eq!(valid, false);
    }

    #[test]
    fn test_invalid_sha3_384_code() {
        let key_ascii = "12345678901234567890".to_owned();
        let user_code = "133013".to_owned();
        let valid = HOTPBuilder::new()
            .ascii_key(&key_ascii)
            .hash_function(HashFunction::Sha3_384)
            .finalize()
            .unwrap()
            .is_valid(&user_code);
        assert_eq!(valid, false);
    }

    #[test]
    fn test_invalid_sha3_512_code() {
        let key_ascii = "12345678901234567890".to_owned();
        let user_code = "342931".to_owned();
        let valid = HOTPBuilder::new()
            .ascii_key(&key_ascii)
            .hash_function(HashFunction::Sha3_512)
            .finalize()
            .unwrap()
            .is_valid(&user_code);
        assert_eq!(valid, false);
    }

    #[test]
    fn test_invalid_keccak_224_code() {
        let key_ascii = "12345678901234567890".to_owned();
        let user_code = "839046".to_owned();
        let valid = HOTPBuilder::new()
            .ascii_key(&key_ascii)
            .hash_function(HashFunction::Keccak224)
            .finalize()
            .unwrap()
            .is_valid(&user_code);
        assert_eq!(valid, false);
    }

    #[test]
    fn test_invalid_keccak_256_code() {
        let key_ascii = "12345678901234567890".to_owned();
        let user_code = "197777".to_owned();
        let valid = HOTPBuilder::new()
            .ascii_key(&key_ascii)
            .hash_function(HashFunction::Keccak256)
            .finalize()
            .unwrap()
            .is_valid(&user_code);
        assert_eq!(valid, false);
    }

    #[test]
    fn test_invalid_keccak_384_code() {
        let key_ascii = "12345678901234567890".to_owned();
        let user_code = "970241".to_owned();
        let valid = HOTPBuilder::new()
            .ascii_key(&key_ascii)
            .hash_function(HashFunction::Keccak384)
            .finalize()
            .unwrap()
            .is_valid(&user_code);
        assert_eq!(valid, false);
    }

    #[test]
    fn test_invalid_keccak_512_code() {
        let key_ascii = "12345678901234567890".to_owned();
        let user_code = "107634".to_owned();
        let valid = HOTPBuilder::new()
            .ascii_key(&key_ascii)
            .hash_function(HashFunction::Keccak512)
            .finalize()
            .unwrap()
            .is_valid(&user_code);
        assert_eq!(valid, false);
    }

    #[test]
    fn test_bad_code() {
        let key_ascii = "12345678901234567890".to_owned();
        let user_code = "!@#$%^".to_owned();
        let valid = HOTPBuilder::new()
            .ascii_key(&key_ascii)
            .finalize()
            .unwrap()
            .is_valid(&user_code);
        assert_eq!(valid, false);
    }

    #[test]
    fn test_empty_code() {
        let key_ascii = "12345678901234567890".to_owned();
        let user_code = "".to_owned();
        let valid = HOTPBuilder::new()
            .ascii_key(&key_ascii)
            .finalize()
            .unwrap()
            .is_valid(&user_code);
        assert_eq!(valid, false);
    }

    #[test]
    #[cfg(feature = "oath-uri")]
    fn test_key_uri_format() {
        let key_ascii = "12345678901234567890".to_owned();
        let hotp = HOTPBuilder::new().ascii_key(&key_ascii).finalize().unwrap();

        let uri = hotp
            .key_uri_format("Provider 1", "alice@example.com")
            .finalize();

        assert_eq!(
            uri,
            "otpauth://hotp/Provider%201:alice@example.com?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&issuer=Provider+1&counter=0"
        );
    }

    #[test]
    #[cfg(feature = "oath-uri")]
    fn test_key_uri_format_hide_all() {
        let key_ascii = "12345678901234567890".to_owned();
        let hotp = HOTPBuilder::new()
            .output_len(7)
            .hash_function(HashFunction::Sha256)
            .ascii_key(&key_ascii)
            .finalize()
            .unwrap();

        let uri = hotp
            .key_uri_format("Provider 1", "alice@example.com")
            .parameters_visibility_policy(ParametersVisibility::HideAll)
            .finalize();

        assert_eq!(
            uri,
            "otpauth://hotp/Provider%201:alice@example.com?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&counter=0"
        );
    }

    #[test]
    #[cfg(feature = "oath-uri")]
    fn test_key_uri_format_overwrite_label() {
        let key_ascii = "12345678901234567890".to_owned();
        let hotp = HOTPBuilder::new().ascii_key(&key_ascii).finalize().unwrap();

        let uri = hotp
            .key_uri_format("Provider1", "alice@example.com")
            .overwrite_label("Provider1Label")
            .finalize();

        assert_eq!(
            uri,
            "otpauth://hotp/Provider1Label?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&issuer=Provider1&counter=0"
        );
    }

    #[test]
    #[cfg(feature = "oath-uri")]
    fn test_key_uri_format_add_parameter() {
        let key_ascii = "12345678901234567890".to_owned();
        let hotp = HOTPBuilder::new().ascii_key(&key_ascii).finalize().unwrap();

        let uri = hotp
            .key_uri_format("Provider1", "alice@example.com")
            .add_parameter("foo", "bar baz")
            .add_parameter("foo 2", "è_é")
            .finalize();

        assert_eq!(uri.len(), 141);
        assert!(uri.starts_with(
                "otpauth://hotp/Provider1:alice@example.com?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&issuer=Provider1&counter=0&"
        ));
        assert!(uri.contains("&foo=bar+baz"));
        assert!(uri.contains("&foo+2=%C3%A8_%C3%A9"));
    }
}
