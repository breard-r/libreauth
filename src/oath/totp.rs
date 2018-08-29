use super::{ErrorCode, HOTPBuilder, HashFunction};
use base32;
use base64;
use hex;
use time;

/// Generates and checks TOTP codes.
pub struct TOTP {
    key: Vec<u8>,
    timestamp_offset: i64,
    positive_tolerance: u64,
    negative_tolerance: u64,
    period: u32,
    initial_time: u64,
    output_len: usize,
    output_base: Vec<u8>,
    hash_function: HashFunction,
}

impl TOTP {
    fn get_counter(&self) -> u64 {
        let timestamp = time::now().to_timespec().sec + self.timestamp_offset;
        let timestamp = timestamp as u64;
        if timestamp < self.initial_time {
            panic!("The current Unix time is below the initial time.");
        }
        (timestamp - self.initial_time) / u64::from(self.period)
    }

    /// Generate the current TOTP value.
    ///
    /// ## Examples
    /// ```
    /// let key_base32 = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ".to_owned();
    /// let mut totp = libreauth::oath::TOTPBuilder::new()
    ///     .base32_key(&key_base32)
    ///     .finalize()
    ///     .unwrap();
    ///
    /// let code = totp.generate();
    /// assert_eq!(code.len(), 6);
    /// ```
    pub fn generate(&self) -> String {
        let counter = self.get_counter();
        let hotp = HOTPBuilder::new()
            .key(&self.key.clone())
            .counter(counter)
            .output_len(self.output_len)
            .output_base(&self.output_base)
            .hash_function(self.hash_function)
            .finalize();
        match hotp {
            Ok(h) => h.generate(),
            Err(e) => panic!(e),
        }
    }

    /// Checks if the given code is valid. This implementation uses the [double HMAC verification](https://www.nccgroup.trust/us/about-us/newsroom-and-events/blog/2011/february/double-hmac-verification/) in order to prevent a timing side channel attack.
    ///
    /// ## Examples
    /// ```
    /// let key_ascii = "12345678901234567890".to_owned();
    /// let user_code = "755224".to_owned();
    /// let valid = libreauth::oath::TOTPBuilder::new()
    ///     .ascii_key(&key_ascii)
    ///     .finalize()
    ///     .unwrap()
    ///     .is_valid(&user_code);
    /// ```
    pub fn is_valid(&self, code: &str) -> bool {
        let base_counter = self.get_counter();
        for counter in
            (base_counter - self.negative_tolerance)..(base_counter + self.positive_tolerance + 1)
        {
            let hotp = HOTPBuilder::new()
                .key(&self.key.clone())
                .counter(counter)
                .output_len(self.output_len)
                .hash_function(self.hash_function)
                .finalize();
            let is_valid = match hotp {
                Ok(h) => h.is_valid(code),
                Err(e) => panic!(e),
            };
            if is_valid {
                return true;
            }
        }
        false
    }
}

/// Builds a TOTP object.
///
/// ## Examples
///
/// The following examples uses the same shared secret passed in various forms.
///
/// ```
/// let key = vec![49, 50, 51, 52, 53, 54, 55, 56, 57, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 48];
/// let mut totp = libreauth::oath::TOTPBuilder::new()
///     .key(&key)
///     .finalize()
///     .unwrap();
/// ```
///
/// ```
/// let key_ascii = "12345678901234567890".to_owned();
/// let mut totp = libreauth::oath::TOTPBuilder::new()
///     .ascii_key(&key_ascii)
///     .period(42)
///     .finalize();
/// ```
///
/// ```
/// let key_hex = "3132333435363738393031323334353637383930".to_owned();
/// let mut totp = libreauth::oath::TOTPBuilder::new()
///     .hex_key(&key_hex)
///     .timestamp(1234567890)
///     .finalize();
/// ```
///
/// ```
/// let key_base32 = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ".to_owned();
/// let mut totp = libreauth::oath::TOTPBuilder::new()
///     .base32_key(&key_base32)
///     .output_len(8)
///     .hash_function(libreauth::oath::HashFunction::Sha256)
///     .finalize();
/// ```
///
/// ```
/// let key_base64 = "MTIzNDU2Nzg5MDEyMzQ1Njc4OTA=".to_owned();
/// let mut totp = libreauth::oath::TOTPBuilder::new()
///     .base64_key(&key_base64)
///     .output_len(8)
///     .hash_function(libreauth::oath::HashFunction::Sha256)
///     .finalize();
/// ```
pub struct TOTPBuilder {
    key: Option<Vec<u8>>,
    timestamp_offset: i64,
    positive_tolerance: u64,
    negative_tolerance: u64,
    period: u32,
    initial_time: u64,
    output_len: usize,
    output_base: Vec<u8>,
    hash_function: HashFunction,
    runtime_error: Option<ErrorCode>,
}

impl Default for TOTPBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl TOTPBuilder {
    /// Generates the base configuration for TOTP code generation.
    pub fn new() -> TOTPBuilder {
        TOTPBuilder {
            key: None,
            timestamp_offset: 0,
            positive_tolerance: 0,
            negative_tolerance: 0,
            period: 30,
            initial_time: 0,
            output_len: 6,
            output_base: "0123456789".to_owned().into_bytes(),
            hash_function: HashFunction::Sha1,
            runtime_error: None,
        }
    }

    builder_common!(TOTPBuilder);

    /// Sets a custom value for the current Unix time instead of the real one.
    pub fn timestamp(&mut self, timestamp: i64) -> &mut TOTPBuilder {
        let current_timestamp = time::now().to_timespec().sec;
        self.timestamp_offset = timestamp - current_timestamp;
        self
    }

    /// Sets the number of periods ahead or behind the current one for which the user code will
    /// still be considered valid. You should not set a value higher than 2. Default is 0.
    pub fn tolerance(&mut self, tolerance: u64) -> &mut TOTPBuilder {
        self.positive_tolerance = tolerance;
        self.negative_tolerance = tolerance;
        self
    }

    /// Sets the number of periods ahead the current one for which the user code will
    /// still be considered valid. You should not set a value higher than 2. Default is 0.
    pub fn positive_tolerance(&mut self, tolerance: u64) -> &mut TOTPBuilder {
        self.positive_tolerance = tolerance;
        self
    }

    /// Sets the number of periods behind the current one for which the user code will
    /// still be considered valid. You should not set a value higher than 2. Default is 0.
    pub fn negative_tolerance(&mut self, tolerance: u64) -> &mut TOTPBuilder {
        self.negative_tolerance = tolerance;
        self
    }

    /// Sets the time step in seconds (X). May not be zero. Default is 30.
    pub fn period(&mut self, period: u32) -> &mut TOTPBuilder {
        if period == 0 {
            self.runtime_error = Some(ErrorCode::InvalidPeriod);
        } else {
            self.period = period;
        }
        self
    }

    /// Sets the Unix time to start counting time steps (T0). Default is 0.
    pub fn initial_time(&mut self, initial_time: u64) -> &mut TOTPBuilder {
        self.initial_time = initial_time;
        self
    }

    /// Returns the finalized TOTP object.
    pub fn finalize(&self) -> Result<TOTP, ErrorCode> {
        if let Some(e) = self.runtime_error {
            return Err(e);
        }
        match self.code_length() {
            n if n < 1_000_000 => return Err(ErrorCode::CodeTooSmall),
            n if n > 2_147_483_648 => return Err(ErrorCode::CodeTooBig),
            _ => (),
        }
        match self.key {
            Some(ref k) => Ok(TOTP {
                key: k.clone(),
                timestamp_offset: self.timestamp_offset,
                positive_tolerance: self.positive_tolerance,
                negative_tolerance: self.negative_tolerance,
                initial_time: self.initial_time,
                period: self.period,
                output_len: self.output_len,
                output_base: self.output_base.clone(),
                hash_function: self.hash_function,
            }),
            None => Err(ErrorCode::InvalidKey),
        }
    }
}

#[cfg(feature = "cbindings")]
pub mod cbindings {
    use super::TOTPBuilder;
    use libc;
    use oath::{c, ErrorCode, HashFunction};
    use std;
    use time;

    /// [C binding] TOTP configuration storage
    #[repr(C)]
    pub struct TOTPcfg {
        key: *const u8,
        key_len: libc::size_t,
        timestamp: libc::int64_t,
        positive_tolerance: libc::uint64_t,
        negative_tolerance: libc::uint64_t,
        period: libc::uint32_t,
        initial_time: libc::uint64_t,
        output_len: libc::size_t,
        output_base: *const u8,
        output_base_len: libc::size_t,
        hash_function: HashFunction,
    }

    /// [C binding] Initialize a `struct libreauth_totp_cfg` with the default values.
    ///
    /// ## Examples
    /// ```c
    /// struct libreauth_totp_cfg cfg;
    /// const char key[] = "12345678901234567890";
    ///
    /// uint32_t ret = libreauth_totp_init(&cfg);
    /// if (ret != LIBREAUTH_OATH_SUCCESS) {
    ///     // Handle the error.
    /// }
    /// cfg.key = key;
    /// cfg.key_len = sizeof(key);
    /// ```
    #[no_mangle]
    pub extern "C" fn libreauth_totp_init(cfg: *mut TOTPcfg) -> ErrorCode {
        let res: Result<&mut TOTPcfg, ErrorCode> = otp_init!(
            TOTPcfg,
            cfg,
            timestamp,
            time::now().to_timespec().sec,
            positive_tolerance,
            0,
            negative_tolerance,
            0,
            period,
            30,
            initial_time,
            0
        );
        match res {
            Ok(_) => ErrorCode::Success,
            Err(errno) => errno,
        }
    }

    /// [C binding] Generate a TOTP code according to the given configuration and stores it in the supplied buffer.
    ///
    /// ## Examples
    /// ```c
    /// struct libreauth_totp_cfg cfg;
    /// const char key[] = "12345678901234567890";
    /// char code[DEFAULT_BUFF_LEN + 1] = {0};
    ///
    /// uint32_t ret = libreauth_totp_init(&cfg);
    /// if (ret != LIBREAUTH_OATH_SUCCESS) {
    ///     // Handle the error.
    /// }
    /// cfg.key = key;
    /// cfg.key_len = sizeof(key);
    ///
    /// ret = libreauth_totp_generate(&cfg, code);
    /// if (ret != LIBREAUTH_OATH_SUCCESS) {
    ///     // Handle the error.
    /// }
    ///
    /// printf("TOTP code: %s\n", code);
    /// ```
    #[no_mangle]
    pub extern "C" fn libreauth_totp_generate(
        cfg: *const TOTPcfg,
        code: *mut libc::uint8_t,
    ) -> ErrorCode {
        let cfg = get_value_or_errno!(c::get_cfg(cfg));
        let code = get_value_or_errno!(c::get_mut_code(code, cfg.output_len as usize));
        let output_base = get_value_or_errno!(c::get_output_base(
            cfg.output_base,
            cfg.output_base_len as usize
        ));
        let key = get_value_or_errno!(c::get_key(cfg.key, cfg.key_len as usize));
        match TOTPBuilder::new()
            .key(&key)
            .output_len(cfg.output_len as usize)
            .output_base(&output_base)
            .hash_function(cfg.hash_function)
            .timestamp(cfg.timestamp)
            .period(cfg.period)
            .initial_time(cfg.initial_time)
            .finalize()
        {
            Ok(hotp) => {
                let ref_code = hotp.generate().into_bytes();
                c::write_code(&ref_code, code);
                ErrorCode::Success
            }
            Err(errno) => errno,
        }
    }

    /// [C binding] Initialize a `struct libreauth_totp_cfg` with the default values.
    ///
    /// ## Examples
    /// ```c
    /// struct libreauth_totp_cfg cfg;
    /// const char key[] = "12345678901234567890";
    ///
    /// uint32_t ret = libreauth_totp_init(&cfg);
    /// if (ret != LIBREAUTH_OATH_SUCCESS) {
    ///     // Handle the error.
    /// }
    /// cfg.key = key;
    /// cfg.key_len = sizeof(key);
    ///
    /// if (libreauth_totp_is_valid(&cfg, "4755224")) {
    ///     printf("Valid TOTP code\n");
    /// } else {
    ///     printf("Invalid TOTP code\n");
    /// }
    /// ```
    #[no_mangle]
    pub extern "C" fn libreauth_totp_is_valid(
        cfg: *const TOTPcfg,
        code: *const libc::uint8_t,
    ) -> libc::int32_t {
        let cfg = get_value_or_false!(c::get_cfg(cfg));
        let code = get_value_or_false!(c::get_code(code, cfg.output_len as usize));
        let output_base = get_value_or_false!(c::get_output_base(
            cfg.output_base,
            cfg.output_base_len as usize
        ));
        let key = get_value_or_false!(c::get_key(cfg.key, cfg.key_len as usize));
        match TOTPBuilder::new()
            .key(&key)
            .output_len(cfg.output_len as usize)
            .output_base(&output_base)
            .hash_function(cfg.hash_function)
            .timestamp(cfg.timestamp)
            .period(cfg.period)
            .initial_time(cfg.initial_time)
            .positive_tolerance(cfg.positive_tolerance)
            .negative_tolerance(cfg.negative_tolerance)
            .finalize()
        {
            Ok(totp) => match totp.is_valid(&code) {
                true => 1,
                false => 0,
            },
            Err(_) => 0,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::TOTPBuilder;
    use oath::HashFunction;

    #[test]
    fn test_totp_key_simple() {
        let key = vec![
            49, 50, 51, 52, 53, 54, 55, 56, 57, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 48,
        ];

        let totp = TOTPBuilder::new().key(&key).finalize().unwrap();

        assert_eq!(totp.key, key);
        assert_eq!(totp.output_len, 6);
        match totp.hash_function {
            HashFunction::Sha1 => assert!(true),
            _ => assert!(false),
        }

        let code = totp.generate();
        assert_eq!(code.len(), 6);
    }

    #[test]
    fn test_totp_keu_full() {
        let key = vec![
            49, 50, 51, 52, 53, 54, 55, 56, 57, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 48,
        ];

        let totp = TOTPBuilder::new()
            .key(&key)
            .timestamp(1111111109)
            .period(70)
            .output_len(8)
            .hash_function(HashFunction::Sha256)
            .finalize()
            .unwrap();
        assert_eq!(totp.key, key);
        assert_eq!(totp.period, 70);
        assert_eq!(totp.initial_time, 0);
        assert_eq!(totp.output_len, 8);

        let code = totp.generate();
        assert_eq!(code.len(), 8);
        assert_eq!(code, "04696041");
    }

    #[test]
    fn test_totp_asciikey_simple() {
        let key_ascii = "12345678901234567890".to_owned();
        let key = vec![
            49, 50, 51, 52, 53, 54, 55, 56, 57, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 48,
        ];

        let totp = TOTPBuilder::new().ascii_key(&key_ascii).finalize().unwrap();

        assert_eq!(totp.key, key);
        assert_eq!(totp.output_len, 6);
        match totp.hash_function {
            HashFunction::Sha1 => assert!(true),
            _ => assert!(false),
        }

        let code = totp.generate();
        assert_eq!(code.len(), 6);
    }

    #[test]
    fn test_totp_asciikeu_full() {
        let key_ascii = "12345678901234567890".to_owned();
        let key = vec![
            49, 50, 51, 52, 53, 54, 55, 56, 57, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 48,
        ];

        let totp = TOTPBuilder::new()
            .ascii_key(&key_ascii)
            .timestamp(1111111109)
            .period(70)
            .output_len(8)
            .hash_function(HashFunction::Sha256)
            .finalize()
            .unwrap();
        assert_eq!(totp.key, key);
        assert_eq!(totp.period, 70);
        assert_eq!(totp.initial_time, 0);
        assert_eq!(totp.output_len, 8);

        let code = totp.generate();
        assert_eq!(code.len(), 8);
        assert_eq!(code, "04696041");
    }

    #[test]
    fn test_totp_kexkey_simple() {
        let key_hex = "3132333435363738393031323334353637383930".to_owned();
        let key = vec![
            49, 50, 51, 52, 53, 54, 55, 56, 57, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 48,
        ];

        let totp = TOTPBuilder::new().hex_key(&key_hex).finalize().unwrap();

        assert_eq!(totp.key, key);
        assert_eq!(totp.output_len, 6);
        match totp.hash_function {
            HashFunction::Sha1 => assert!(true),
            _ => assert!(false),
        }

        let code = totp.generate();
        assert_eq!(code.len(), 6);
    }

    #[test]
    fn test_totp_hexkey_full() {
        let key_hex = "3132333435363738393031323334353637383930".to_owned();
        let key = vec![
            49, 50, 51, 52, 53, 54, 55, 56, 57, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 48,
        ];

        let totp = TOTPBuilder::new()
            .hex_key(&key_hex)
            .timestamp(1111111109)
            .period(70)
            .output_len(8)
            .hash_function(HashFunction::Sha256)
            .finalize()
            .unwrap();
        assert_eq!(totp.key, key);
        assert_eq!(totp.period, 70);
        assert_eq!(totp.initial_time, 0);
        assert_eq!(totp.output_len, 8);

        let code = totp.generate();
        assert_eq!(code.len(), 8);
        assert_eq!(code, "04696041");
    }

    #[test]
    fn test_totp_base32key_simple() {
        let key = vec![
            49, 50, 51, 52, 53, 54, 55, 56, 57, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 48,
        ];
        let key_base32 = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ".to_owned();

        let totp = TOTPBuilder::new()
            .base32_key(&key_base32)
            .finalize()
            .unwrap();

        assert_eq!(totp.key, key);
        assert_eq!(totp.output_len, 6);
        match totp.hash_function {
            HashFunction::Sha1 => assert!(true),
            _ => assert!(false),
        }

        let code = totp.generate();
        assert_eq!(code.len(), 6);
    }

    #[test]
    fn test_totp_base32key_full() {
        let key = vec![
            49, 50, 51, 52, 53, 54, 55, 56, 57, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 48,
        ];
        let key_base32 = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ".to_owned();

        let totp = TOTPBuilder::new()
            .base32_key(&key_base32)
            .timestamp(1111111109)
            .period(70)
            .output_len(8)
            .hash_function(HashFunction::Sha256)
            .finalize()
            .unwrap();
        assert_eq!(totp.key, key);
        assert_eq!(totp.period, 70);
        assert_eq!(totp.initial_time, 0);
        assert_eq!(totp.output_len, 8);

        let code = totp.generate();
        assert_eq!(code.len(), 8);
        assert_eq!(code, "04696041");
    }

    #[test]
    fn test_totp_base64key_simple() {
        let key = vec![
            49, 50, 51, 52, 53, 54, 55, 56, 57, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 48,
        ];
        let key_base64 = "MTIzNDU2Nzg5MDEyMzQ1Njc4OTA=".to_owned();

        let totp = TOTPBuilder::new()
            .base64_key(&key_base64)
            .finalize()
            .unwrap();

        assert_eq!(totp.key, key);
        assert_eq!(totp.output_len, 6);
        match totp.hash_function {
            HashFunction::Sha1 => assert!(true),
            _ => assert!(false),
        }

        let code = totp.generate();
        assert_eq!(code.len(), 6);
    }

    #[test]
    fn test_totp_base64key_full() {
        let key = vec![
            49, 50, 51, 52, 53, 54, 55, 56, 57, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 48,
        ];
        let key_base64 = "MTIzNDU2Nzg5MDEyMzQ1Njc4OTA=".to_owned();

        let totp = TOTPBuilder::new()
            .base64_key(&key_base64)
            .timestamp(1111111109)
            .period(70)
            .output_len(8)
            .hash_function(HashFunction::Sha256)
            .finalize()
            .unwrap();
        assert_eq!(totp.key, key);
        assert_eq!(totp.period, 70);
        assert_eq!(totp.initial_time, 0);
        assert_eq!(totp.output_len, 8);

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
    fn test_invalid_hexkey() {
        let key = "!@#$%^&".to_owned();
        match TOTPBuilder::new().hex_key(&key).finalize() {
            Ok(_) => assert!(false),
            Err(_) => assert!(true),
        }
    }

    #[test]
    fn test_invalid_base32key() {
        let key = "!@#$%^&".to_owned();
        match TOTPBuilder::new().base32_key(&key).finalize() {
            Ok(_) => assert!(false),
            Err(_) => assert!(true),
        }
    }

    #[test]
    fn test_small_result_base10() {
        let key_ascii = "12345678901234567890".to_owned();
        match TOTPBuilder::new()
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
            match TOTPBuilder::new()
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
        match TOTPBuilder::new()
            .ascii_key(&key_ascii)
            .output_len(6)
            .finalize()
        {
            Ok(_) => assert!(true),
            Err(_) => assert!(false),
        }
        match TOTPBuilder::new()
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
        let base = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ+/"
            .to_owned()
            .into_bytes();
        match TOTPBuilder::new()
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
        let base = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ+/"
            .to_owned()
            .into_bytes();
        match TOTPBuilder::new()
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
        let base = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ+/"
            .to_owned()
            .into_bytes();
        match TOTPBuilder::new()
            .ascii_key(&key_ascii)
            .output_base(&base)
            .output_len(4)
            .finalize()
        {
            Ok(_) => assert!(true),
            Err(_) => assert!(false),
        }
        match TOTPBuilder::new()
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
    fn test_rfc6238_examples_sha1() {
        let key_hex = "3132333435363738393031323334353637383930".to_owned();
        let examples = [
            (59, HashFunction::Sha1, "94287082"),
            (1111111109, HashFunction::Sha1, "07081804"),
            (1111111111, HashFunction::Sha1, "14050471"),
            (1234567890, HashFunction::Sha1, "89005924"),
            (2000000000, HashFunction::Sha1, "69279037"),
            (20000000000, HashFunction::Sha1, "65353130"),
        ];
        for &(timestamp, hash_function, ref_code) in examples.iter() {
            let code = TOTPBuilder::new()
                .hex_key(&key_hex)
                .timestamp(timestamp)
                .output_len(8)
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
        let key_hex = "3132333435363738393031323334353637383930313233343536373839303132".to_owned();
        let examples = [
            (59, HashFunction::Sha256, "46119246"),
            (1111111109, HashFunction::Sha256, "68084774"),
            (1111111111, HashFunction::Sha256, "67062674"),
            (1234567890, HashFunction::Sha256, "91819424"),
            (2000000000, HashFunction::Sha256, "90698825"),
            (20000000000, HashFunction::Sha256, "77737706"),
        ];
        for &(timestamp, hash_function, ref_code) in examples.iter() {
            let code = TOTPBuilder::new()
                .hex_key(&key_hex)
                .timestamp(timestamp)
                .output_len(8)
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
        let key_hex = "31323334353637383930313233343536373839303132333435363738393031323334353637383930313233343536373839303132333435363738393031323334".to_owned();
        let examples = [
            (59, HashFunction::Sha512, "90693936"),
            (1111111109, HashFunction::Sha512, "25091201"),
            (1111111111, HashFunction::Sha512, "99943326"),
            (1234567890, HashFunction::Sha512, "93441116"),
            (2000000000, HashFunction::Sha512, "38618901"),
            (20000000000, HashFunction::Sha512, "47863826"),
        ];
        for &(timestamp, hash_function, ref_code) in examples.iter() {
            let code = TOTPBuilder::new()
                .hex_key(&key_hex)
                .timestamp(timestamp)
                .output_len(8)
                .hash_function(hash_function)
                .finalize()
                .unwrap()
                .generate();
            assert_eq!(code.len(), 8);
            assert_eq!(code, ref_code);
        }
    }

    #[test]
    fn test_valid_code() {
        let key_ascii = "12345678901234567890".to_owned();
        let user_code = "94287082".to_owned();
        let valid = TOTPBuilder::new()
            .ascii_key(&key_ascii)
            .timestamp(59)
            .output_len(8)
            .finalize()
            .unwrap()
            .is_valid(&user_code);
        assert_eq!(valid, true);
    }

    #[test]
    fn test_tolerance() {
        let key_ascii = "12345678901234567890".to_owned();
        let examples = [
            (1234567890, 0, "590587", false), // +1
            (1234567890, 1, "590587", true),  // +1
            (1234567890, 1, "240500", false), // +2
            (1234567890, 2, "240500", true),  // +2
            (1234567890, 0, "980357", false), // -1
            (1234567890, 1, "980357", true),  // -1
            (1234567890, 1, "186057", false), // -2
            (1234567890, 2, "186057", true),  // -2
        ];
        for &(timestamp, tolerance, user_code, validity) in examples.iter() {
            let valid = TOTPBuilder::new()
                .ascii_key(&key_ascii)
                .timestamp(timestamp)
                .tolerance(tolerance)
                .finalize()
                .unwrap()
                .is_valid(&user_code.to_owned());
            assert_eq!(valid, validity);
        }
    }

    #[test]
    fn test_positive_tolerance() {
        let key_ascii = "12345678901234567890".to_owned();
        let examples = [
            (1234567890, 0, "590587", false), // +1
            (1234567890, 1, "590587", true),  // +1
            (1234567890, 1, "240500", false), // +2
            (1234567890, 2, "240500", true),  // +2
            (1234567890, 0, "980357", false), // -1
            (1234567890, 1, "980357", false), // -1
            (1234567890, 1, "186057", false), // -2
            (1234567890, 2, "186057", false), // -2
        ];
        for &(timestamp, tolerance, user_code, validity) in examples.iter() {
            let valid = TOTPBuilder::new()
                .ascii_key(&key_ascii)
                .timestamp(timestamp)
                .positive_tolerance(tolerance)
                .finalize()
                .unwrap()
                .is_valid(&user_code.to_owned());
            assert_eq!(valid, validity);
        }
    }

    #[test]
    fn test_negative_tolerance() {
        let key_ascii = "12345678901234567890".to_owned();
        let examples = [
            (1234567890, 0, "590587", false), // +1
            (1234567890, 1, "590587", false), // +1
            (1234567890, 1, "240500", false), // +2
            (1234567890, 2, "240500", false), // +2
            (1234567890, 0, "980357", false), // -1
            (1234567890, 1, "980357", true),  // -1
            (1234567890, 1, "186057", false), // -2
            (1234567890, 2, "186057", true),  // -2
        ];
        for &(timestamp, tolerance, user_code, validity) in examples.iter() {
            let valid = TOTPBuilder::new()
                .ascii_key(&key_ascii)
                .timestamp(timestamp)
                .negative_tolerance(tolerance)
                .finalize()
                .unwrap()
                .is_valid(&user_code.to_owned());
            assert_eq!(valid, validity);
        }
    }

    #[test]
    fn test_invalid_code() {
        let key_ascii = "12345678901234567890".to_owned();
        let user_code = "12345678".to_owned();
        let valid = TOTPBuilder::new()
            .ascii_key(&key_ascii)
            .timestamp(59)
            .output_len(8)
            .finalize()
            .unwrap()
            .is_valid(&user_code);
        assert_eq!(valid, false);
    }

    #[test]
    fn test_bad_code() {
        let key_ascii = "12345678901234567890".to_owned();
        let user_code = "!@#$%^&*".to_owned();
        let valid = TOTPBuilder::new()
            .ascii_key(&key_ascii)
            .timestamp(59)
            .output_len(8)
            .finalize()
            .unwrap()
            .is_valid(&user_code);
        assert_eq!(valid, false);
    }

    #[test]
    fn test_empty_code() {
        let key_ascii = "12345678901234567890".to_owned();
        let user_code = "".to_owned();
        let valid = TOTPBuilder::new()
            .ascii_key(&key_ascii)
            .timestamp(59)
            .output_len(8)
            .finalize()
            .unwrap()
            .is_valid(&user_code);
        assert_eq!(valid, false);
    }
}
