use super::error::Error;
use super::{
	Algorithm, DEFAULT_USER_VERSION, Hasher, INTERNAL_VERSION, LengthCalculationMethod,
	Normalization, PasswordStorageStandard, XHMAC, std_default, std_nist,
};
use crate::hash::HashFunction;
use crate::pass::phc::PHCData;
use std::collections::HashMap;
use std::str::FromStr;

macro_rules! get_pepper {
	($pepper: ident) => {
		$pepper
			.as_ref()
			.ok_or(Error::InvalidPasswordFormat)?
			.to_vec()
	};
}

/// Builds a Hasher object.
///
/// ## Examples
///
/// ```
/// use libreauth::pass::HashBuilder;
///
/// // Hashing a password in order to store it.
/// let password = "correct horse battery staple";
/// let hasher = match HashBuilder::new().finalize() {
///     Ok(h) => h,
///     Err(e) => panic!("{:?}", e),
/// };
/// let stored_password = match hasher.hash(password) {
///     Ok(p) => p,
///     Err(e) => panic!("{:?}", e),
/// };
///
/// // Checking a password against a previously hashed one.
/// let checker = HashBuilder::from_phc(stored_password.as_str()).unwrap();
/// assert!(!checker.is_valid("bad password"));
/// assert!(checker.is_valid(password));
/// ```
///
/// Build a Hasher object with the default parameters to comply with the NIST Special Publication 800-63B. This object will be usable to hash a password.
/// ```
/// use libreauth::pass::{HashBuilder, PasswordStorageStandard};
///
/// let hasher = match HashBuilder::new_std(PasswordStorageStandard::Nist80063b).finalize() {
///     Ok(h) => h,
///     Err(e) => panic!("{:?}", e),
/// };
/// ```
///
/// Build a Hasher object with custom parameters. This object will be usable to hash a password.
/// ```
/// let hasher = match libreauth::pass::HashBuilder::new()
///     .min_len(12)
///     .algorithm(libreauth::pass::Algorithm::Pbkdf2)
///     .add_param("hmac", "sha256")
///     .add_param("norm", "nfkd")
///     .finalize() {
///     Ok(h) => h,
///     Err(e) => panic!("{:?}", e),
/// };
/// ```
pub struct HashBuilder {
	pub(crate) standard: PasswordStorageStandard,
	pub(crate) normalization: Normalization,
	pub(crate) min_len: usize,
	pub(crate) max_len: usize,
	pub(crate) algorithm: Algorithm,
	pub(crate) parameters: HashMap<String, String>,
	pub(crate) ref_salt: Option<Vec<u8>>,
	pub(crate) ref_hash: Option<Vec<u8>>,
	pub(crate) salt_len: usize,
	pub(crate) length_calculation: LengthCalculationMethod,
	pub(crate) version: usize,
	pub(crate) xhmac: XHMAC,
	pub(crate) xhmax_alg: HashFunction,
}

impl Default for HashBuilder {
	fn default() -> Self {
		Self::new()
	}
}

impl HashBuilder {
	/// Create a new HashBuilder object with default parameters.
	pub fn new() -> Self {
		Self::new_std(PasswordStorageStandard::NoStandard)
	}

	/// Create a new HashBuilder object with default parameters for a specific standard.
	pub fn new_std(std: PasswordStorageStandard) -> Self {
		match std {
			PasswordStorageStandard::NoStandard => Self {
				standard: PasswordStorageStandard::NoStandard,
				normalization: std_default::DEFAULT_NORMALIZATION,
				min_len: std_default::DEFAULT_PASSWORD_MIN_LEN,
				max_len: std_default::DEFAULT_PASSWORD_MAX_LEN,
				algorithm: std_default::DEFAULT_ALGORITHM,
				parameters: HashMap::new(),
				ref_salt: None,
				ref_hash: None,
				salt_len: std_default::DEFAULT_SALT_LEN,
				length_calculation: std_default::DEFAULT_LENGTH_CALCULATION,
				version: DEFAULT_USER_VERSION + INTERNAL_VERSION,
				xhmac: XHMAC::None,
				xhmax_alg: std_default::DEFAULT_XHMAC_ALGORITHM,
			},
			PasswordStorageStandard::Nist80063b => Self {
				standard: PasswordStorageStandard::Nist80063b,
				normalization: std_nist::DEFAULT_NORMALIZATION,
				min_len: std_nist::DEFAULT_PASSWORD_MIN_LEN,
				max_len: std_nist::DEFAULT_PASSWORD_MAX_LEN,
				algorithm: std_nist::DEFAULT_ALGORITHM,
				parameters: HashMap::new(),
				ref_salt: None,
				ref_hash: None,
				salt_len: std_nist::DEFAULT_SALT_LEN,
				length_calculation: std_nist::DEFAULT_LENGTH_CALCULATION,
				version: DEFAULT_USER_VERSION + INTERNAL_VERSION,
				xhmac: XHMAC::None,
				xhmax_alg: std_nist::DEFAULT_XHMAC_ALGORITHM,
			},
		}
	}

	/// Create a new Hasher object from a PHC formatted string.
	pub fn from_phc(data: &str) -> Result<Hasher, Error> {
		Self::from_phc_internal(data, None)
	}

	/// Create a new Hasher object from a PHC formatted string and an external pepper for an additional HMAC.
	pub fn from_phc_xhmac(data: &str, pepper: &[u8]) -> Result<Hasher, Error> {
		Self::from_phc_internal(data, Some(pepper.to_vec()))
	}

	fn from_phc_internal(data: &str, pepper: Option<Vec<u8>>) -> Result<Hasher, Error> {
		let mut phc = match PHCData::from_str(data) {
			Ok(v) => v,
			Err(_) => return Err(Error::InvalidPasswordFormat),
		};
		let lc = match phc.parameters.remove("len-calc") {
			Some(v) => match v.as_str() {
				"bytes" => LengthCalculationMethod::Bytes,
				"chars" => LengthCalculationMethod::Characters,
				_ => return Err(Error::InvalidPasswordFormat),
			},
			None => LengthCalculationMethod::Characters,
		};
		let norm = match phc.parameters.remove("norm") {
			Some(v) => match v.as_str() {
				"nfd" => Normalization::Nfd,
				"nfkd" => Normalization::Nfkd,
				"nfc" => Normalization::Nfc,
				"nfkc" => Normalization::Nfkc,
				"none" => Normalization::None,
				_ => return Err(Error::InvalidPasswordFormat),
			},
			None => Normalization::Nfkc,
		};
		let max_l = match phc.parameters.remove("pmax") {
			Some(v) => match v.parse::<usize>() {
				Ok(l) => l,
				Err(_) => return Err(Error::InvalidPasswordFormat),
			},
			None => std_default::DEFAULT_PASSWORD_MAX_LEN,
		};
		let min_l = match phc.parameters.remove("pmin") {
			Some(v) => match v.parse::<usize>() {
				Ok(l) => l,
				Err(_) => return Err(Error::InvalidPasswordFormat),
			},
			None => std_default::DEFAULT_PASSWORD_MIN_LEN,
		};
		let version = match phc.parameters.remove("ver") {
			Some(v) => match v.parse::<usize>() {
				Ok(l) => l,
				Err(_) => return Err(Error::InvalidPasswordFormat),
			},
			None => DEFAULT_USER_VERSION + INTERNAL_VERSION,
		};
		let xhmac = match phc.parameters.remove("xhmac") {
			Some(when) => match when.to_lowercase().as_str() {
				"before" => XHMAC::Before(get_pepper!(pepper)),
				"after" => XHMAC::After(get_pepper!(pepper)),
				"none" => XHMAC::None,
				_ => return Err(Error::InvalidPasswordFormat),
			},
			None => XHMAC::None,
		};
		if xhmac == XHMAC::None && pepper.is_some() {
			return Err(Error::InvalidPasswordFormat);
		}
		let xhmax_alg = match phc.parameters.remove("xhmac-alg") {
			Some(alg_str) => {
				HashFunction::from_str(&alg_str).map_err(|_| Error::InvalidPasswordFormat)?
			}
			None => std_default::DEFAULT_XHMAC_ALGORITHM,
		};
		let hash_builder = Self {
			standard: PasswordStorageStandard::NoStandard,
			normalization: norm,
			min_len: min_l,
			max_len: max_l,
			algorithm: match phc.id.as_str() {
				"argon2" => Algorithm::Argon2,
				"pbkdf2" => Algorithm::Pbkdf2,
				_ => return Err(Error::InvalidPasswordFormat),
			},
			parameters: phc.parameters.clone(),
			ref_hash: phc.hash,
			salt_len: match &phc.salt {
				Some(s) => s.len(),
				None => std_default::DEFAULT_SALT_LEN,
			},
			ref_salt: phc.salt,
			length_calculation: lc,
			version,
			xhmac,
			xhmax_alg,
		};
		hash_builder.finalize()
	}

	/// Check the compatibility between options and create a Hasher object.
	pub fn finalize(&self) -> Result<Hasher, Error> {
		match self.standard {
			PasswordStorageStandard::Nist80063b => {
				if !std_nist::is_valid(self) {
					return Err(Error::InvalidPasswordFormat);
				}
			}
			PasswordStorageStandard::NoStandard => {}
		}
		Ok(Hasher {
			normalization: self.normalization,
			min_len: self.min_len,
			max_len: self.max_len,
			algorithm: self.algorithm,
			parameters: self.parameters.clone(),
			ref_salt: self.ref_salt.clone(),
			ref_hash: self.ref_hash.clone(),
			salt_len: self.salt_len,
			length_calculation: self.length_calculation,
			version: self.version,
			xhmac: self.xhmac.clone(),
			xhmax_alg: self.xhmax_alg,
		})
	}

	/// Set the way the password will be normalized.
	pub fn normalization(&mut self, normalization: Normalization) -> &mut Self {
		self.normalization = normalization;
		self
	}

	/// Set the password hashing algorithm.
	pub fn algorithm(&mut self, algorithm: Algorithm) -> &mut Self {
		self.algorithm = algorithm;
		self.parameters = HashMap::new();
		self
	}

	/// Set the way the password length will be calculated.
	pub fn length_calculation(&mut self, method: LengthCalculationMethod) -> &mut Self {
		self.length_calculation = method;
		self
	}

	/// Set the salt length.
	///
	/// Unused if a salt is given.
	pub fn salt_len(&mut self, len: usize) -> &mut Self {
		self.salt_len = len;
		self
	}

	/// Set the password minimal length.
	pub fn min_len(&mut self, len: usize) -> &mut Self {
		self.min_len = len;
		self
	}

	/// Set the password maximal length.
	pub fn max_len(&mut self, len: usize) -> &mut Self {
		self.max_len = len;
		self
	}

	/// Add a parameter that will be used by the password hashing algorithm.
	pub fn add_param(&mut self, key: &str, value: &str) -> &mut Self {
		self.parameters.insert(key.to_string(), value.to_string());
		self
	}

	/// Set the hashing scheme version number.
	pub fn version(&mut self, version: usize) -> &mut Self {
		self.version = version + INTERNAL_VERSION;
		self
	}

	/// Set the hash function that will be used to compute the additional HMAC.
	pub fn xhmac(&mut self, hash_func: HashFunction) -> &mut Self {
		self.xhmax_alg = hash_func;
		self
	}

	/// Add an additional HMAC with a pepper before hashing the password.
	pub fn xhmac_before(&mut self, pepper: &[u8]) -> &mut Self {
		self.xhmac = XHMAC::Before(pepper.to_vec());
		self
	}

	/// Add an additional HMAC with a pepper after hashing the password.
	pub fn xhmac_after(&mut self, pepper: &[u8]) -> &mut Self {
		self.xhmac = XHMAC::After(pepper.to_vec());
		self
	}
}
