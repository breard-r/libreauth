#[cfg(feature = "oath-uri")]
use super::DEFAULT_KEY_URI_PARAM_POLICY;
use super::{
	Error, HOTPBuilder, HashFunction, DEFAULT_OTP_HASH, DEFAULT_OTP_OUT_BASE, DEFAULT_OTP_OUT_LEN,
	DEFAULT_TOTP_PERIOD, DEFAULT_TOTP_T0,
};
#[cfg(feature = "oath-uri")]
use crate::oath::key_uri::{KeyUriBuilder, UriType};
#[cfg(feature = "oath-uri")]
use std::collections::HashMap;
use std::time::SystemTime;

/// Generates and checks TOTP codes.
pub struct TOTP {
	key: Vec<u8>,
	timestamp_offset: i64,
	positive_tolerance: u64,
	negative_tolerance: u64,
	period: u32,
	initial_time: u64,
	output_len: usize,
	output_base: String,
	hash_function: HashFunction,
}

impl TOTP {
	fn get_counter(&self) -> u64 {
		let timestamp = SystemTime::now()
			.duration_since(SystemTime::UNIX_EPOCH)
			.unwrap()
			.as_secs() as i64;
		let timestamp = timestamp + self.timestamp_offset;
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
			Err(e) => panic!("{:?}", e),
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
			(base_counter - self.negative_tolerance)..=(base_counter + self.positive_tolerance)
		{
			let hotp = HOTPBuilder::new()
				.key(&self.key.clone())
				.counter(counter)
				.output_len(self.output_len)
				.hash_function(self.hash_function)
				.finalize();
			let is_valid = match hotp {
				Ok(h) => h.is_valid(code),
				Err(e) => panic!("{:?}", e),
			};
			if is_valid {
				return true;
			}
		}
		false
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
	/// let mut totp = libreauth::oath::TOTPBuilder::new()
	///     .ascii_key(&key_ascii)
	///     .finalize()
	///     .unwrap();
	///
	/// let uri = totp
	///     .key_uri_format("Provider1", "alice@example.com")
	///     .finalize();
	///
	/// assert_eq!(
	///     uri,
	///     "otpauth://totp/Provider1:alice@example.com?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&issuer=Provider1"
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
			uri_type: UriType::Totp,
			key: &self.key,
			issuer,
			account_name,
			custom_label: None,
			custom_parameters: HashMap::new(),
			algo: self.hash_function,
			output_len: self.output_len,
			output_base: &self.output_base,
			counter: None,
			period: Some(self.period),
			initial_time: Some(self.initial_time),
		}
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
///     .hash_function(libreauth::hash::HashFunction::Sha256)
///     .finalize();
/// ```
///
/// ```
/// let key_base64 = "MTIzNDU2Nzg5MDEyMzQ1Njc4OTA=".to_owned();
/// let mut totp = libreauth::oath::TOTPBuilder::new()
///     .base64_key(&key_base64)
///     .output_len(8)
///     .hash_function(libreauth::hash::HashFunction::Sha256)
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
	output_base: String,
	hash_function: HashFunction,
	runtime_error: Option<Error>,
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
			period: DEFAULT_TOTP_PERIOD,
			initial_time: DEFAULT_TOTP_T0,
			output_len: DEFAULT_OTP_OUT_LEN,
			output_base: DEFAULT_OTP_OUT_BASE.to_string(),
			hash_function: DEFAULT_OTP_HASH,
			runtime_error: None,
		}
	}

	builder_common!(TOTPBuilder);

	/// Sets a custom value for the current Unix time instead of the real one.
	pub fn timestamp(&mut self, timestamp: i64) -> &mut TOTPBuilder {
		let current_timestamp = SystemTime::now()
			.duration_since(SystemTime::UNIX_EPOCH)
			.unwrap()
			.as_secs() as i64;
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
			self.runtime_error = Some(Error::InvalidPeriod);
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
	pub fn finalize(&self) -> Result<TOTP, Error> {
		if let Some(e) = self.runtime_error {
			return Err(e);
		}
		match self.code_length() {
			n if n < 1_000_000 => return Err(Error::CodeTooSmall),
			n if n > 2_147_483_648 => return Err(Error::CodeTooBig),
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
			None => Err(Error::InvalidKey),
		}
	}
}

#[cfg(test)]
mod tests {
	use super::TOTPBuilder;
	use crate::hash::HashFunction;

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
		let base = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ+/";
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
		let base = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ+/";
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
		let base = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ+/";
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

	#[test]
	#[cfg(feature = "oath-uri")]
	fn test_key_uri_format() {
		let key_ascii = "12345678901234567890".to_owned();
		let totp = TOTPBuilder::new().ascii_key(&key_ascii).finalize().unwrap();

		let uri = totp
			.key_uri_format("Provider1", "alice@example.com")
			.finalize();

		assert_eq!(
			uri,
			"otpauth://totp/Provider1:alice@example.com?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&issuer=Provider1"
		);
	}

	#[test]
	#[cfg(feature = "oath-uri")]
	fn test_key_uri_label() {
		let key_ascii = "12345678901234567890".to_owned();
		let totp = TOTPBuilder::new().ascii_key(&key_ascii).finalize().unwrap();

		let uri = totp
			.key_uri_format("ö_È …", "Dërp+toto@example.com")
			.finalize();

		assert_eq!(
			uri,
			"otpauth://totp/%C3%B6_%C3%88%20%E2%80%A6:D%C3%ABrp+toto@example.com?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&issuer=%C3%B6_%C3%88+%E2%80%A6"
		);
	}

	#[test]
	#[cfg(feature = "oath-uri")]
	fn test_key_uri_format_overwrite_label() {
		let key_ascii = "12345678901234567890".to_owned();
		let totp = TOTPBuilder::new().ascii_key(&key_ascii).finalize().unwrap();

		let uri = totp
			.key_uri_format("Provider1", "alice@example.com")
			.overwrite_label("Provider1Label")
			.finalize();

		assert_eq!(
			uri,
			"otpauth://totp/Provider1Label?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&issuer=Provider1"
		);
	}

	#[test]
	#[cfg(feature = "oath-uri")]
	fn test_key_uri_format_add_parameter() {
		let key_ascii = "12345678901234567890".to_owned();
		let totp = TOTPBuilder::new().ascii_key(&key_ascii).finalize().unwrap();

		let uri = totp
			.key_uri_format("Provider1", "alice@example.com")
			.add_parameter("foo", "bar baz")
			.finalize();

		assert_eq!(
			uri,
			"otpauth://totp/Provider1:alice@example.com?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&issuer=Provider1&foo=bar+baz"
		);
	}

	#[test]
	#[cfg(feature = "oath-uri")]
	fn test_key_uri_format_output_base() {
		let key_ascii = "12345678901234567890".to_owned();
		let base = "qwertyuiop";
		let totp = TOTPBuilder::new()
			.output_base(&base)
			.ascii_key(&key_ascii)
			.finalize()
			.unwrap();

		let uri = totp
			.key_uri_format("Provider1", "alice@example.com")
			.finalize();
		assert_eq!(uri, "otpauth://totp/Provider1:alice@example.com?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&issuer=Provider1&base=qwertyuiop");
	}

	#[test]
	#[cfg(feature = "oath-uri")]
	fn test_key_uri_format_output_base_utf8() {
		let key_ascii = "12345678901234567890".to_owned();
		let base = "è_éö€…÷—☺";
		let totp = TOTPBuilder::new()
			.output_base(&base)
			.ascii_key(&key_ascii)
			.finalize()
			.unwrap();

		let uri = totp
			.key_uri_format("Provider1", "alice@example.com")
			.finalize();
		assert_eq!(uri, "otpauth://totp/Provider1:alice@example.com?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&issuer=Provider1&base=%C3%A8_%C3%A9%C3%B6%E2%82%AC%E2%80%A6%C3%B7%E2%80%94%E2%98%BA");
	}
}
