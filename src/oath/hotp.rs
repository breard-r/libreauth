/*
 * Copyright Rodolphe Breard (2015)
 * Author: Rodolphe Breard (2015)
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


use super::{HashFunction, ErrorCode};
use ring;
use ::parser;
use base32;


pub struct HOTP {
    key: Vec<u8>,
    counter: u64,
    output_len: usize,
    output_base: Vec<u8>,
    hash_function: HashFunction,
}

impl HOTP {
    fn signing_key(&self) -> ring::hmac::SigningKey {
        use ring::hmac::SigningKey;
        use ring::digest::{SHA1, SHA256, SHA512};

        match self.hash_function {
            HashFunction::Sha1 => SigningKey::new(&SHA1, &self.key[..]),
            HashFunction::Sha256 => SigningKey::new(&SHA256, &self.key[..]),
            HashFunction::Sha512 => SigningKey::new(&SHA512, &self.key[..]),
        }
    }


    fn reduce_result(&self, hs: &[u8]) -> u32 {
        let offset = (hs[hs.len() - 1] & 0xf) as usize;
        let hash = hs[offset..offset + 4].to_vec();
        let snum: u32 = ((hash[0] as u32 & 0x7f) << 24) | ((hash[1] as u32 & 0xff) << 16) |
                        ((hash[2] as u32 & 0xff) << 8) |
                        (hash[3] as u32 & 0xff);

        let base = self.output_base.len() as u32;
        snum % base.pow(self.output_len as u32)
    }

    fn format_result(&self, nb: u32) -> String {
        let mut code: Vec<u8> = vec![];
        let mut nb = nb;
        let base_len = self.output_base.len() as u32;

        while nb > 0 {
            code.push(self.output_base[(nb % base_len) as usize]);
            nb = nb / base_len;
        }
        while code.len() != self.output_len {
            code.push(self.output_base[0]);
        }
        code.reverse();

        match String::from_utf8(code) {
            Ok(s) => s,
            Err(e) => panic!(e),
        }
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
        let msg: [u8; 8] = [((self.counter >> 56) & 0xff) as u8,
                            ((self.counter >> 48) & 0xff) as u8,
                            ((self.counter >> 40) & 0xff) as u8,
                            ((self.counter >> 32) & 0xff) as u8,
                            ((self.counter >> 24) & 0xff) as u8,
                            ((self.counter >> 16) & 0xff) as u8,
                            ((self.counter >> 8) & 0xff) as u8,
                            (self.counter & 0xff) as u8];
        let result = ring::hmac::sign(&self.signing_key(), &msg);

        let nb = self.reduce_result(&result.as_ref());
        self.format_result(nb)
    }

    /// Increments the internal counter.
    pub fn increment_counter(&mut self) -> &mut HOTP {
        self.counter += 1;
        self
    }

    /// Checks if the given code is valid. This implementation uses the [double HMAC verification](https://www.nccgroup.trust/us/about-us/newsroom-and-events/blog/2011/february/double-hmac-verification/) in order to prevent a timing side channel attack.
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
    /// assert_eq!(valid, true);
    /// ```
    pub fn is_valid(&self, code: &String) -> bool {
        if code.len() != self.output_len {
            return false;
        }
        let ref_code = self.generate().into_bytes();
        let code = code.clone().into_bytes();

        use ring::hmac::sign;
        let (code, ref_code) = (sign(&self.signing_key(), &code),
                                sign(&self.signing_key(), &ref_code));
        code.as_ref() == ref_code.as_ref()
    }
}

/// ## Examples
///
/// The following examples uses the same shared secret passed in various forms.
///
///```
/// let key = vec![49, 50, 51, 52, 53, 54, 55, 56, 57, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 48];
/// let mut hotp = libreauth::oath::HOTPBuilder::new()
///     .key(&key)
///     .finalize()
///     .unwrap();
///```
///
///```
/// let key_ascii = "12345678901234567890".to_owned();
/// let mut hotp = libreauth::oath::HOTPBuilder::new()
///     .ascii_key(&key_ascii)
///     .counter(42)
///     .finalize()
///     .unwrap();
///```
///
///```
/// let key_hex = "3132333435363738393031323334353637383930".to_owned();
/// let mut hotp = libreauth::oath::HOTPBuilder::new()
///     .hex_key(&key_hex)
///     .counter(69)
///     .output_len(8)
///     .finalize();
///```
///
///```
/// let key_base32 = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ".to_owned();
/// let mut hotp = libreauth::oath::HOTPBuilder::new()
///     .base32_key(&key_base32)
///     .output_len(8)
///     .hash_function(libreauth::oath::HashFunction::Sha256)
///     .finalize();
///```
pub struct HOTPBuilder {
    key: Option<Vec<u8>>,
    counter: u64,
    output_len: usize,
    output_base: Vec<u8>,
    hash_function: HashFunction,
    runtime_error: Option<ErrorCode>,
}

impl HOTPBuilder {
    /// Generates the base configuration for HOTP code generation.
    pub fn new() -> HOTPBuilder {
        HOTPBuilder {
            key: None,
            counter: 0,
            output_len: 6,
            output_base: "0123456789".to_owned().into_bytes(),
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
    pub fn finalize(&self) -> Result<HOTP, ErrorCode> {
        match self.runtime_error {
            Some(e) => return Err(e),
            None => (),
        }
        match self.code_length() {
            n if n < 1000000 => return Err(ErrorCode::CodeTooSmall),
            n if n > 2147483648 => return Err(ErrorCode::CodeTooBig),
            _ => (),
        }
        match self.key {
            Some(ref k) => {
                Ok(HOTP {
                       key: k.clone(),
                       counter: self.counter,
                       output_len: self.output_len,
                       output_base: self.output_base.clone(),
                       hash_function: self.hash_function,
                   })
            }
            None => Err(ErrorCode::InvalidKey),
        }

    }
}


#[cfg(feature = "cbindings")]
pub mod cbindings {
    use super::HOTPBuilder;
    use oath::{HashFunction, ErrorCode, c};
    use libc;
    use std;

    #[repr(C)]
    pub struct HOTPcfg {
        key: *const u8,
        key_len: libc::size_t,
        counter: libc::uint64_t,
        output_len: libc::size_t,
        output_base: *const u8,
        output_base_len: libc::size_t,
        hash_function: HashFunction,
    }

    #[no_mangle]
    pub extern "C" fn libreauth_hotp_init(cfg: *mut HOTPcfg) -> ErrorCode {
        let res: Result<&mut HOTPcfg, ErrorCode> = otp_init!(HOTPcfg, cfg, counter, 0);
        match res {
            Ok(_) => ErrorCode::Success,
            Err(errno) => errno,
        }
    }

    #[no_mangle]
    pub extern "C" fn libreauth_hotp_generate(cfg: *const HOTPcfg,
                                              code: *mut libc::uint8_t)
                                              -> ErrorCode {
        let cfg = get_value_or_errno!(c::get_cfg(cfg));
        let mut code = get_value_or_errno!(c::get_mut_code(code, cfg.output_len as usize));
        let output_base = get_value_or_errno!(c::get_output_base(cfg.output_base,
                                                                 cfg.output_base_len as usize));
        let key = get_value_or_errno!(c::get_key(cfg.key, cfg.key_len as usize));
        match HOTPBuilder::new()
                  .key(&key)
                  .output_len(cfg.output_len as usize)
                  .output_base(&output_base)
                  .hash_function(cfg.hash_function)
                  .counter(cfg.counter)
                  .finalize() {
            Ok(hotp) => {
                let ref_code = hotp.generate().into_bytes();
                c::write_code(&ref_code, code);
                ErrorCode::Success
            }
            Err(errno) => errno,
        }
    }

    #[no_mangle]
    pub extern "C" fn libreauth_hotp_is_valid(cfg: *const HOTPcfg,
                                              code: *const libc::uint8_t)
                                              -> libc::int32_t {
        let cfg = get_value_or_false!(c::get_cfg(cfg));
        let code = get_value_or_false!(c::get_code(code, cfg.output_len as usize));
        let output_base = get_value_or_false!(c::get_output_base(cfg.output_base,
                                                                 cfg.output_base_len as usize));
        let key = get_value_or_false!(c::get_key(cfg.key, cfg.key_len as usize));
        match HOTPBuilder::new()
                  .key(&key)
                  .output_len(cfg.output_len as usize)
                  .output_base(&output_base)
                  .hash_function(cfg.hash_function)
                  .counter(cfg.counter)
                  .finalize() {
            Ok(hotp) => {
                match hotp.is_valid(&code) {
                    true => 1,
                    false => 0,
                }
            }
            Err(_) => 0,
        }
    }
}


#[cfg(test)]
mod tests {
    use super::HOTPBuilder;
    use oath::HashFunction;

    #[test]
    fn test_hotp_key_simple() {
        let key = vec![49, 50, 51, 52, 53, 54, 55, 56, 57, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57,
                       48];

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
        let key = vec![49, 50, 51, 52, 53, 54, 55, 56, 57, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57,
                       48];

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
        let key = vec![49, 50, 51, 52, 53, 54, 55, 56, 57, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57,
                       48];

        let hotp = HOTPBuilder::new()
            .ascii_key(&key_ascii)
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
    fn test_hotp_asciikey_full() {
        let key_ascii = "12345678901234567890".to_owned();
        let key = vec![49, 50, 51, 52, 53, 54, 55, 56, 57, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57,
                       48];

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
        let key = vec![49, 50, 51, 52, 53, 54, 55, 56, 57, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57,
                       48];

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
        let key = vec![49, 50, 51, 52, 53, 54, 55, 56, 57, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57,
                       48];

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
        let key = vec![49, 50, 51, 52, 53, 54, 55, 56, 57, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57,
                       48];
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
        let key = vec![49, 50, 51, 52, 53, 54, 55, 56, 57, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57,
                       48];
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
        let output_base = vec![];
        match HOTPBuilder::new()
                  .ascii_key(&key_ascii)
                  .output_base(&output_base)
                  .finalize() {
            Ok(_) => assert!(false),
            Err(_) => assert!(true),
        }
    }

    #[test]
    fn test_invalid_output_base() {
        let key_ascii = "12345678901234567890".to_owned();
        let output_base = "1".to_owned().into_bytes();
        match HOTPBuilder::new()
                  .ascii_key(&key_ascii)
                  .output_base(&output_base)
                  .finalize() {
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
                  .finalize() {
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
                      .finalize() {
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
                  .finalize() {
            Ok(_) => assert!(true),
            Err(_) => assert!(false),
        }
        match HOTPBuilder::new()
                  .ascii_key(&key_ascii)
                  .output_len(9)
                  .finalize() {
            Ok(_) => assert!(true),
            Err(_) => assert!(false),
        }
    }

    #[test]
    fn test_small_result_base64() {
        let key_ascii = "12345678901234567890".to_owned();
        let base = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ+/"
            .to_owned()
            .into_bytes();
        match HOTPBuilder::new()
                  .ascii_key(&key_ascii)
                  .output_base(&base)
                  .output_len(3)
                  .finalize() {
            Ok(_) => assert!(false),
            Err(_) => assert!(true),
        }
    }

    #[test]
    fn test_big_result_base64() {
        let key_ascii = "12345678901234567890".to_owned();
        let base = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ+/"
            .to_owned()
            .into_bytes();
        match HOTPBuilder::new()
                  .ascii_key(&key_ascii)
                  .output_base(&base)
                  .output_len(6)
                  .finalize() {
            Ok(_) => assert!(false),
            Err(_) => assert!(true),
        }
    }

    #[test]
    fn test_result_ok_base64() {
        let key_ascii = "12345678901234567890".to_owned();
        let base = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ+/"
            .to_owned()
            .into_bytes();
        match HOTPBuilder::new()
                  .ascii_key(&key_ascii)
                  .output_base(&base)
                  .output_len(4)
                  .finalize() {
            Ok(_) => assert!(true),
            Err(_) => assert!(false),
        }
        match HOTPBuilder::new()
                  .ascii_key(&key_ascii)
                  .output_base(&base)
                  .output_len(5)
                  .finalize() {
            Ok(_) => assert!(true),
            Err(_) => assert!(false),
        }
    }

    #[test]
    fn test_rfc4226_examples() {
        let key_ascii = "12345678901234567890".to_owned();
        let key = vec![49, 50, 51, 52, 53, 54, 55, 56, 57, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57,
                       48];
        let hex_base = "0123456789ABCDEF".to_owned().into_bytes();

        let examples = [["755224", "93CF18"],
                        ["287082", "397EEA"],
                        ["359152", "2FEF30"],
                        ["969429", "EF7655"],
                        ["338314", "C5938A"],
                        ["254676", "C083D4"],
                        ["287922", "56C032"],
                        ["162583", "E5B397"],
                        ["399871", "23443F"],
                        ["520489", "79DC69"]];
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
}
