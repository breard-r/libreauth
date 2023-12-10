use super::HOTPBuilder;
use super::TOTPBuilder;
use crate::oath::{ErrorCode, HashFunction};
use crate::{
	deref_ptr, deref_ptr_mut, get_slice, get_slice_mut, get_string, get_value_or_errno,
	get_value_or_false,
};
use std::ffi::CStr;
use std::time::SystemTime;

macro_rules! otp_init {
	($cfg_type: ty, $cfg: ident, $($field: ident, $value: expr), *) => {
		if $cfg.is_null() {
			Err(ErrorCode::NullPtr)
		} else {
			let c: &mut $cfg_type = deref_ptr_mut!($cfg, ErrorCode::NullPtr);
			c.key = std::ptr::null();
			c.key_len = 0;
			c.output_len = crate::oath::DEFAULT_OTP_OUT_LEN;
			c.output_base = std::ptr::null();
			c.hash_function = crate::oath::DEFAULT_OTP_HASH;
			$(
				c.$field = $value;
			)*
				Ok(c)
		}
	}
}

/// [C binding] HOTP configuration storage
///
/// The `struct libreauth_hotp_cfg` contains the following fields:
///
/// - [key](crate::oath::HOTPBuilder::key)
/// - `key_len`: key's length, in bytes
/// - [counter](crate::oath::HOTPBuilder::counter)
/// - [output_len](crate::oath::HOTPBuilder::output_len)
/// - [output_base](crate::oath::HOTPBuilder::output_base)
/// - [hash_function](crate::hash::HashFunction)
#[repr(C)]
pub struct HOTPcfg {
	key: *const u8,
	key_len: libc::size_t,
	counter: u64,
	output_len: libc::size_t,
	output_base: *const libc::c_char,
	hash_function: HashFunction,
	look_ahead: u64,
}

/// [C binding] TOTP configuration storage
///
/// The `struct libreauth_totp_cfg` contains the following fields:
///
/// - [key](crate::oath::TOTPBuilder::method.key)
/// - `key_len`: key's length, in bytes
/// - [timestamp](crate::oath::TOTPBuilder::timestamp)
/// - [positive_tolerance](crate::oath::TOTPBuilder::positive_tolerance)
/// - [negative_tolerance](crate::oath::TOTPBuilder::negative_tolerance)
/// - [period](crate::oath::TOTPBuilder::period)
/// - [initial_time](crate::oath::TOTPBuilder::initial_time)
/// - [output_len](crate::oath::TOTPBuilder::output_len)
/// - [output_base](crate::oath::TOTPBuilder::output_base)
/// - [hash_function](crate::hash::HashFunction)
#[repr(C)]
pub struct TOTPcfg {
	key: *const u8,
	key_len: libc::size_t,
	timestamp: i64,
	positive_tolerance: u64,
	negative_tolerance: u64,
	period: u32,
	initial_time: u64,
	output_len: libc::size_t,
	output_base: *const libc::c_char,
	hash_function: HashFunction,
}

fn write_code(code: &[u8], dest: &mut [u8]) {
	let len = code.len();
	dest[..len].clone_from_slice(&code[..len]);
	dest[len] = 0;
}

fn get_cfg<T>(cfg: *const T) -> Result<&'static T, ErrorCode> {
	if cfg.is_null() {
		return Err(ErrorCode::NullPtr);
	}
	let cfg: &T = unsafe { deref_ptr!(cfg, Err(ErrorCode::NullPtr)) };
	Ok(cfg)
}

fn get_mut_cfg<T>(cfg: *mut T) -> Result<&'static mut T, ErrorCode> {
	if cfg.is_null() {
		return Err(ErrorCode::NullPtr);
	}
	let cfg: &mut T = unsafe { deref_ptr_mut!(cfg, Err(ErrorCode::NullPtr)) };
	Ok(cfg)
}

fn get_code(code: *const u8, code_len: usize) -> Result<String, ErrorCode> {
	if code.is_null() {
		return Err(ErrorCode::NullPtr);
	}
	let code = unsafe { get_slice!(code, code_len) };
	match String::from_utf8(code) {
		Ok(code) => Ok(code),
		Err(_) => Err(ErrorCode::InvalidUTF8),
	}
}

fn get_mut_code(code: *mut u8, code_len: usize) -> Result<&'static mut [u8], ErrorCode> {
	if code.is_null() {
		return Err(ErrorCode::NullPtr);
	}
	Ok(unsafe { get_slice_mut!(code, code_len + 1) })
}

fn get_output_base(output_base: *const libc::c_char) -> Result<String, ErrorCode> {
	if output_base.is_null() {
		return Ok(crate::oath::DEFAULT_OTP_OUT_BASE.to_string());
	}
	let output_base = unsafe { get_string!(output_base) };
	match output_base.len() {
		0 | 1 => Err(ErrorCode::InvalidBaseLen),
		_ => Ok(output_base),
	}
}

fn get_key(key: *const u8, key_len: usize) -> Result<Vec<u8>, ErrorCode> {
	if key.is_null() {
		Err(ErrorCode::NullPtr)
	} else {
		match key_len {
			0 => Err(ErrorCode::InvalidKeyLen),
			l => Ok(unsafe { get_slice!(key, l) }),
		}
	}
}

/// [C binding] Initialize a `struct libreauth_hotp_cfg` with the default values.
///
/// # Parameter
///
/// `cfg`: pointer to a `struct libreauth_hotp_cfg`
///
/// # Examples
///
/// ```c
/// struct libreauth_hotp_cfg cfg;
/// const char key[] = "12345678901234567890";
///
/// uint32_t ret = libreauth_hotp_init(&cfg);
/// if (ret != LIBREAUTH_OATH_SUCCESS) {
///     // Handle the error.
/// }
/// cfg.key = key;
/// cfg.key_len = strlen(key);
/// ```
///
/// # Safety
///
/// This function is a C binding and is therefore unsafe. It is not meant to be used in Rust.
#[no_mangle]
pub unsafe extern "C" fn libreauth_hotp_init(cfg: *mut HOTPcfg) -> ErrorCode {
	let res: Result<&mut HOTPcfg, ErrorCode> = otp_init!(HOTPcfg, cfg, counter, 0, look_ahead, 0);
	match res {
		Ok(_) => ErrorCode::Success,
		Err(errno) => errno,
	}
}

/// [C binding] Generate an HOTP code according to the given configuration and stores it in the supplied buffer.
///
/// # Parameters
///
/// - `cfg`: pointer to a `struct libreauth_hotp_cfg`
/// - `code`: buffer that will hold the string representing the code
///
/// # Examples
///
/// ```c
/// struct libreauth_hotp_cfg cfg;
/// const char key[] = "12345678901234567890";
/// char code[DEFAULT_BUFF_LEN + 1];
///
/// uint32_t ret = libreauth_hotp_init(&cfg);
/// if (ret != LIBREAUTH_OATH_SUCCESS) {
///     // Handle the error.
/// }
/// cfg.key = key;
/// cfg.key_len = strlen(key);
///
/// ret = libreauth_hotp_generate(&cfg, code);
/// if (ret != LIBREAUTH_OATH_SUCCESS) {
///     // Handle the error.
/// }
///
/// printf("HOTP code: %s\n", code);
/// ```
#[no_mangle]
pub extern "C" fn libreauth_hotp_generate(cfg: *const HOTPcfg, code: *mut u8) -> ErrorCode {
	let cfg = get_value_or_errno!(get_cfg(cfg));
	let code = get_value_or_errno!(get_mut_code(code, cfg.output_len));
	let output_base = get_value_or_errno!(get_output_base(cfg.output_base));
	let key = get_value_or_errno!(get_key(cfg.key, cfg.key_len));
	match HOTPBuilder::new()
		.key(&key)
		.output_len(cfg.output_len)
		.output_base(&output_base)
		.hash_function(cfg.hash_function)
		.counter(cfg.counter)
		.look_ahead(cfg.look_ahead)
		.finalize()
	{
		Ok(hotp) => {
			let ref_code = hotp.generate().into_bytes();
			write_code(&ref_code, code);
			ErrorCode::Success
		}
		Err(err) => err.into(),
	}
}

/// [C binding] Check whether or not the supplied HOTP code is valid.
///
/// # Parameters
///
/// - `cfg`: pointer to a `struct libreauth_hotp_cfg`
/// - `code`: string representing the code to check
/// - `sync`: indicates whether or not the counter's value should be synchronized (`LIBREAUTH_OATH_CTR_SYNC` or `LIBREAUTH_OATH_CTR_NOSYNC`)
///
/// # Examples
///
/// ```c
/// struct libreauth_hotp_cfg cfg;
/// const char key[] = "12345678901234567890";
///
/// uint32_t ret = libreauth_hotp_init(&cfg);
/// if (ret != LIBREAUTH_OATH_SUCCESS) {
///     // Handle the error.
/// }
/// cfg.key = key;
/// cfg.key_len = strlen(key);
///
/// if (libreauth_hotp_is_valid(&cfg, "755224", LIBREAUTH_OATH_CTR_SYNC)) {
///     printf("Valid HOTP code\n");
/// } else {
///     printf("Invalid HOTP code\n");
/// }
/// ```
#[no_mangle]
pub extern "C" fn libreauth_hotp_is_valid(cfg: *mut HOTPcfg, code: *const u8, sync: i32) -> i32 {
	let cfg = get_value_or_false!(get_mut_cfg(cfg));
	let code = get_value_or_false!(get_code(code, cfg.output_len));
	let output_base = get_value_or_false!(get_output_base(cfg.output_base));
	let key = get_value_or_false!(get_key(cfg.key, cfg.key_len));
	match HOTPBuilder::new()
		.key(&key)
		.output_len(cfg.output_len)
		.output_base(&output_base)
		.hash_function(cfg.hash_function)
		.counter(cfg.counter)
		.look_ahead(cfg.look_ahead)
		.finalize()
	{
		Ok(mut hotp) => {
			if sync == 0 {
				if hotp.is_valid(&code) {
					1
				} else {
					0
				}
			} else if hotp.is_valid_sync(&code) {
				cfg.counter = hotp.get_counter();
				1
			} else {
				0
			}
		}
		Err(_) => 0,
	}
}

/// [C binding] Generate the key URI.
///
/// # Parameters
///
/// - `cfg`: pointer to a `struct libreauth_hotp_cfg`
/// - `issuer`: string representing issuer's name
/// - `account_name`: string representing name of the user account
/// - `uri_buff`: buffer that will hold the string representing the URI
/// - `uri_buff_len`: buffer's size, in bytes
///
/// # Safety
///
/// This function is a C binding and is therefore unsafe. It is not meant to be used in Rust.
#[cfg(feature = "oath-uri")]
#[no_mangle]
pub unsafe extern "C" fn libreauth_hotp_get_uri(
	cfg: *const HOTPcfg,
	issuer: *const libc::c_char,
	account_name: *const libc::c_char,
	uri_buff: *mut u8,
	uri_buff_len: libc::size_t,
) -> ErrorCode {
	let cfg = get_value_or_errno!(get_cfg(cfg));
	let issuer = get_string!(issuer);
	let acc_name = get_string!(account_name);
	let buff = get_value_or_errno!(get_mut_code(uri_buff, uri_buff_len));
	let output_base = get_value_or_errno!(get_output_base(cfg.output_base));
	let key = get_value_or_errno!(get_key(cfg.key, cfg.key_len));
	match HOTPBuilder::new()
		.key(&key)
		.output_len(cfg.output_len)
		.output_base(&output_base)
		.hash_function(cfg.hash_function)
		.counter(cfg.counter)
		.look_ahead(cfg.look_ahead)
		.finalize()
	{
		Ok(hotp) => {
			let b = hotp
				.key_uri_format(&issuer, &acc_name)
				.finalize()
				.into_bytes();
			let len = b.len();
			if len >= uri_buff_len {
				return ErrorCode::NotEnoughSpace;
			}
			buff[..len].clone_from_slice(&b[..len]);
			buff[len] = 0;
			ErrorCode::Success
		}
		Err(err) => err.into(),
	}
}

/// [C binding] Initialize a `struct libreauth_totp_cfg` with the default values.
///
/// # Parameter
///
/// `cfg`: pointer to a `struct libreauth_totp_cfg`
///
/// # Examples
///
/// ```c
/// struct libreauth_totp_cfg cfg;
/// const char key[] = "12345678901234567890";
///
/// uint32_t ret = libreauth_totp_init(&cfg);
/// if (ret != LIBREAUTH_OATH_SUCCESS) {
///     // Handle the error.
/// }
/// cfg.key = key;
/// cfg.key_len = strlen(key);
/// ```
///
/// # Safety
///
/// This function is a C binding and is therefore unsafe. It is not meant to be used in Rust.
#[no_mangle]
pub unsafe extern "C" fn libreauth_totp_init(cfg: *mut TOTPcfg) -> ErrorCode {
	let res: Result<&mut TOTPcfg, ErrorCode> = otp_init!(
		TOTPcfg,
		cfg,
		timestamp,
		SystemTime::now()
			.duration_since(SystemTime::UNIX_EPOCH)
			.unwrap()
			.as_secs() as i64,
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
/// # Parameters
///
/// - `cfg`: pointer to a `struct libreauth_totp_cfg`
/// - `code`: pointer to a buffer large enough to hold the null-terminated string representing the code
///
/// # Examples
///
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
/// cfg.key_len = strlen(key);
///
/// ret = libreauth_totp_generate(&cfg, code);
/// if (ret != LIBREAUTH_OATH_SUCCESS) {
///     // Handle the error.
/// }
///
/// printf("TOTP code: %s\n", code);
/// ```
#[no_mangle]
pub extern "C" fn libreauth_totp_generate(cfg: *const TOTPcfg, code: *mut u8) -> ErrorCode {
	let cfg = get_value_or_errno!(get_cfg(cfg));
	let code = get_value_or_errno!(get_mut_code(code, cfg.output_len));
	let output_base = get_value_or_errno!(get_output_base(cfg.output_base));
	let key = get_value_or_errno!(get_key(cfg.key, cfg.key_len));
	match TOTPBuilder::new()
		.key(&key)
		.output_len(cfg.output_len)
		.output_base(&output_base)
		.hash_function(cfg.hash_function)
		.timestamp(cfg.timestamp)
		.period(cfg.period)
		.initial_time(cfg.initial_time)
		.finalize()
	{
		Ok(hotp) => {
			let ref_code = hotp.generate().into_bytes();
			write_code(&ref_code, code);
			ErrorCode::Success
		}
		Err(err) => err.into(),
	}
}

/// [C binding] Initialize a `struct libreauth_totp_cfg` with the default values.
///
/// # Parameters
///
/// - `cfg`: pointer to a `struct libreauth_totp_cfg`
/// - `code`: string representing the code to check
///
/// # Examples
///
/// ```c
/// struct libreauth_totp_cfg cfg;
/// const char key[] = "12345678901234567890";
///
/// uint32_t ret = libreauth_totp_init(&cfg);
/// if (ret != LIBREAUTH_OATH_SUCCESS) {
///     // Handle the error.
/// }
/// cfg.key = key;
/// cfg.key_len = strlen(key);
///
/// if (libreauth_totp_is_valid(&cfg, "4755224")) {
///     printf("Valid TOTP code\n");
/// } else {
///     printf("Invalid TOTP code\n");
/// }
/// ```
#[no_mangle]
pub extern "C" fn libreauth_totp_is_valid(cfg: *const TOTPcfg, code: *const u8) -> i32 {
	let cfg = get_value_or_false!(get_cfg(cfg));
	let code = get_value_or_false!(get_code(code, cfg.output_len));
	let output_base = get_value_or_false!(get_output_base(cfg.output_base));
	let key = get_value_or_false!(get_key(cfg.key, cfg.key_len));
	match TOTPBuilder::new()
		.key(&key)
		.output_len(cfg.output_len)
		.output_base(&output_base)
		.hash_function(cfg.hash_function)
		.timestamp(cfg.timestamp)
		.period(cfg.period)
		.initial_time(cfg.initial_time)
		.positive_tolerance(cfg.positive_tolerance)
		.negative_tolerance(cfg.negative_tolerance)
		.finalize()
	{
		Ok(totp) => {
			if totp.is_valid(&code) {
				1
			} else {
				0
			}
		}
		Err(_) => 0,
	}
}

/// [C binding] Generate the key URI.
///
/// # Parameters
///
/// - `cfg`: pointer to a `struct libreauth_totp_cfg`
/// - `issuer`: string representing issuer's name
/// - `account_name`: string representing name of the user account
/// - `uri_buff`: buffer that will hold the string representing the URI
/// - `uri_buff_len`: buffer's size, in bytes
///
/// # Safety
///
/// This function is a C binding and is therefore unsafe. It is not meant to be used in Rust.
#[cfg(feature = "oath-uri")]
#[no_mangle]
pub unsafe extern "C" fn libreauth_totp_get_uri(
	cfg: *const TOTPcfg,
	issuer: *const libc::c_char,
	account_name: *const libc::c_char,
	uri_buff: *mut u8,
	uri_buff_len: libc::size_t,
) -> ErrorCode {
	let cfg = get_value_or_errno!(get_cfg(cfg));
	let issuer = get_string!(issuer);
	let acc_name = get_string!(account_name);
	let buff = get_value_or_errno!(get_mut_code(uri_buff, uri_buff_len));
	let output_base = get_value_or_errno!(get_output_base(cfg.output_base));
	let key = get_value_or_errno!(get_key(cfg.key, cfg.key_len));
	match TOTPBuilder::new()
		.key(&key)
		.output_len(cfg.output_len)
		.output_base(&output_base)
		.hash_function(cfg.hash_function)
		.timestamp(cfg.timestamp)
		.period(cfg.period)
		.initial_time(cfg.initial_time)
		.positive_tolerance(cfg.positive_tolerance)
		.negative_tolerance(cfg.negative_tolerance)
		.finalize()
	{
		Ok(totp) => {
			let b = totp
				.key_uri_format(&issuer, &acc_name)
				.finalize()
				.into_bytes();
			let len = b.len();
			if len >= uri_buff_len {
				return ErrorCode::NotEnoughSpace;
			}
			buff[..len].clone_from_slice(&b[..len]);
			buff[len] = 0;
			ErrorCode::Success
		}
		Err(err) => err.into(),
	}
}
