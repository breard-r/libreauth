use crate::hash::HashFunction;
use crate::key::KeyBuilder;
use crate::pass::error::Error;
use crate::pass::{std_default, HashingFunction, Normalization};
use balloon_hash::{Algorithm, Balloon, Params};
use sha2::{Sha256, Sha384, Sha512, Sha512_256};
use sha3::{Keccak256, Keccak384, Keccak512, Sha3_256, Sha3_384, Sha3_512};
use std::collections::HashMap;
use std::num::NonZeroU32;
use std::str::FromStr;

pub const DEFAULT_HASH_FUNCTION: HashFunction = HashFunction::Sha512;
const MIN_SALT_LENGTH: usize = 4; // in bytes
const MAX_SALT_LENGTH: usize = 256; // in bytes
pub const DEFAULT_SPACE: u32 = 1024;
pub const DEFAULT_TIME: u32 = 3;

macro_rules! process_balloon {
	($obj: ident, $input: ident, $hash: ty, $len: expr) => {{
		let mut out = [0u8; $len];
		let params = Params {
			s_cost: NonZeroU32::new($obj.space).unwrap(),
			t_cost: NonZeroU32::new($obj.time).unwrap(),
			p_cost: NonZeroU32::new(1).unwrap(),
		};
		let hasher = Balloon::<$hash>::new(Algorithm::Balloon, params, None);
		let _ = hasher.hash_into($input, $obj.salt.as_slice(), &mut out[..$len]);
		out.to_vec()
	}};
}

macro_rules! set_hash {
	($obj: ident, $hash: ident) => {{
		$obj.hash_function = $hash;
		Ok(())
	}};
}

pub struct BalloonHash {
	hash_function: HashFunction,
	space: u32,
	time: u32,
	salt: Vec<u8>,
	norm: Normalization,
}

impl BalloonHash {
	pub fn new() -> Self {
		Self {
			hash_function: DEFAULT_HASH_FUNCTION,
			space: DEFAULT_SPACE,
			time: DEFAULT_TIME,
			salt: KeyBuilder::new()
				.size(std_default::DEFAULT_SALT_LEN)
				.as_vec(),
			norm: Normalization::Nfkc,
		}
	}
}

impl HashingFunction for BalloonHash {
	fn get_id(&self) -> String {
		"balloon".to_string()
	}

	fn get_parameters(&self) -> HashMap<String, String> {
		let mut params = HashMap::new();
		set_normalization!(self, norm, params, "norm".to_string());
		params.insert("space".to_string(), self.space.to_string());
		params.insert("time".to_string(), self.time.to_string());
		params.insert(
			"hash".to_string(),
			self.hash_function.to_string().to_lowercase(),
		);
		params
	}

	fn set_parameter(&mut self, name: &str, value: &str) -> Result<(), Error> {
		match name {
			"space" => match value.parse::<u32>() {
				Ok(i) => {
					if i > 0 {
						self.space = i;
						Ok(())
					} else {
						Err(Error::InvalidPasswordFormat)
					}
				}
				Err(_) => Err(Error::InvalidPasswordFormat),
			},
			"time" => match value.parse::<u32>() {
				Ok(i) => {
					if i > 0 {
						self.time = i;
						Ok(())
					} else {
						Err(Error::InvalidPasswordFormat)
					}
				}
				Err(_) => Err(Error::InvalidPasswordFormat),
			},
			"hash" | "hmac" => match HashFunction::from_str(value) {
				Ok(h) => match h {
					HashFunction::Sha1 => Err(Error::InvalidPasswordFormat),
					HashFunction::Sha224 => Err(Error::InvalidPasswordFormat),
					HashFunction::Sha256 => set_hash!(self, h),
					HashFunction::Sha384 => set_hash!(self, h),
					HashFunction::Sha512 => set_hash!(self, h),
					HashFunction::Sha512Trunc224 => Err(Error::InvalidPasswordFormat),
					HashFunction::Sha512Trunc256 => set_hash!(self, h),
					HashFunction::Keccak224 => Err(Error::InvalidPasswordFormat),
					HashFunction::Keccak256 => set_hash!(self, h),
					HashFunction::Keccak384 => set_hash!(self, h),
					HashFunction::Keccak512 => set_hash!(self, h),
					HashFunction::Sha3_224 => Err(Error::InvalidPasswordFormat),
					HashFunction::Sha3_256 => set_hash!(self, h),
					HashFunction::Sha3_384 => set_hash!(self, h),
					HashFunction::Sha3_512 => set_hash!(self, h),
				},
				Err(_) => Err(Error::InvalidPasswordFormat),
			},
			_ => Err(Error::InvalidPasswordFormat),
		}
	}

	fn get_salt(&self) -> Option<Vec<u8>> {
		Some(self.salt.clone())
	}

	fn set_salt(&mut self, salt: Vec<u8>) -> Result<(), Error> {
		match salt.len() {
			MIN_SALT_LENGTH..=MAX_SALT_LENGTH => {
				self.salt = salt;
				Ok(())
			}
			_ => Err(Error::InvalidPasswordFormat),
		}
	}

	fn set_salt_len(&mut self, salt_len: usize) -> Result<(), Error> {
		let salt = KeyBuilder::new().size(salt_len).as_vec();
		self.set_salt(salt)
	}

	fn set_normalization(&mut self, norm: Normalization) -> Result<(), Error> {
		self.norm = norm;
		Ok(())
	}

	fn hash(&self, input: &[u8]) -> Vec<u8> {
		match self.hash_function {
			HashFunction::Sha1 => Vec::new(),
			HashFunction::Sha224 => Vec::new(),
			HashFunction::Sha256 => process_balloon!(self, input, Sha256, 32),
			HashFunction::Sha384 => process_balloon!(self, input, Sha384, 48),
			HashFunction::Sha512 => process_balloon!(self, input, Sha512, 64),
			HashFunction::Sha512Trunc224 => Vec::new(),
			HashFunction::Sha512Trunc256 => process_balloon!(self, input, Sha512_256, 32),
			HashFunction::Keccak224 => Vec::new(),
			HashFunction::Keccak256 => process_balloon!(self, input, Keccak256, 32),
			HashFunction::Keccak384 => process_balloon!(self, input, Keccak384, 32),
			HashFunction::Keccak512 => process_balloon!(self, input, Keccak512, 32),
			HashFunction::Sha3_224 => Vec::new(),
			HashFunction::Sha3_256 => process_balloon!(self, input, Sha3_256, 32),
			HashFunction::Sha3_384 => process_balloon!(self, input, Sha3_384, 48),
			HashFunction::Sha3_512 => process_balloon!(self, input, Sha3_512, 64),
		}
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	/// The identifier must not change with different hashing functions.
	#[test]
	fn test_id() {
		let lst = [
			BalloonHash::new(),
			BalloonHash {
				hash_function: HashFunction::Sha256,
				space: 1024,
				time: 3,
				salt: vec![0, 1, 2, 3, 4, 5],
				norm: Normalization::Nfkc,
			},
			BalloonHash {
				hash_function: HashFunction::Sha512,
				space: 1024,
				time: 3,
				salt: vec![0, 1, 2, 3, 4, 5],
				norm: Normalization::Nfkc,
			},
			BalloonHash {
				hash_function: HashFunction::Sha3_512,
				space: 1024,
				time: 3,
				salt: vec![0, 1, 2, 3, 4, 5],
				norm: Normalization::Nfkc,
			},
		];
		for h in lst.iter() {
			assert_eq!(h.get_id(), "balloon".to_string());
		}
	}

	#[test]
	fn test_get_salt() {
		let h = BalloonHash {
			hash_function: HashFunction::Sha256,
			space: 1024,
			time: 3,
			salt: vec![0, 1, 2, 3, 4, 5],
			norm: Normalization::Nfkc,
		};
		assert_eq!(h.get_salt().unwrap(), vec![0, 1, 2, 3, 4, 5]);
	}

	/// NIST SP 800-63B: the salt shall be at least 32 bits (4 bytes) in length
	#[test]
	fn test_default_salt_len() {
		let h = BalloonHash::new();
		assert!(h.get_salt().unwrap().len() >= 4);
	}

	/// NIST SP 800-63B: the salt shall be chosen arbitrarily
	#[test]
	fn test_salt_randomness() {
		assert_ne!(
			BalloonHash::new().get_salt().unwrap(),
			BalloonHash::new().get_salt().unwrap()
		);
	}

	#[test]
	fn test_vectors() {
		let lst = [
			(
				"sha256",
				1024,
				3,
				"CHhs6n",
				"DAfuHjm77",
				vec![
					0xd5, 0x75, 0x1b, 0x20, 0xce, 0x54, 0xb1, 0x76, 0x15, 0x82, 0xa2, 0xa2, 0x5b,
					0x37, 0x30, 0x25, 0xc5, 0x78, 0xe1, 0x51, 0xac, 0x58, 0x50, 0x12, 0x9d, 0x6a,
					0x44, 0x6b, 0xe4, 0x44, 0xa0, 0x11,
				],
			),
			(
				"sha256",
				2048,
				1,
				"GJd4x5G",
				"2KJo38IJsfRH",
				vec![
					0x44, 0x06, 0xc7, 0xac, 0xde, 0xb3, 0xb5, 0x29, 0xb5, 0x2b, 0xc6, 0x1b, 0x1e,
					0x0b, 0x1f, 0x2f, 0x90, 0xa3, 0x74, 0x29, 0x62, 0xb0, 0xdf, 0xf3, 0xdd, 0xa3,
					0x56, 0xd2, 0x29, 0xd8, 0x2d, 0x28,
				],
			),
			(
				"sha384",
				512,
				2,
				"tKVt",
				"KdNomtQ4d",
				vec![
					0xca, 0x4e, 0x6a, 0x21, 0x67, 0x3a, 0xcd, 0xf5, 0xa3, 0x58, 0x2a, 0xeb, 0x77,
					0x31, 0x55, 0x5e, 0x0f, 0x93, 0xa1, 0x61, 0xb6, 0xb9, 0x15, 0x4d, 0x83, 0x29,
					0x4e, 0x10, 0xcc, 0x35, 0x6a, 0x97, 0x32, 0x4a, 0x03, 0x51, 0xa2, 0x99, 0x9c,
					0x67, 0xa5, 0x0e, 0x20, 0xf2, 0xef, 0xd9, 0x87, 0x34,
				],
			),
			(
				"sha384",
				1024,
				2,
				"G3KX",
				"OHNbhPKuE",
				vec![
					0xb7, 0xee, 0x86, 0x0c, 0x9a, 0x88, 0xb4, 0x25, 0x5a, 0xc1, 0xf5, 0x63, 0x25,
					0x55, 0xc2, 0xa8, 0xb6, 0xfb, 0xcd, 0x7f, 0x6c, 0x44, 0xad, 0x8b, 0x78, 0xb0,
					0x2d, 0xd6, 0xa8, 0xd8, 0xbd, 0x76, 0x8d, 0x81, 0x86, 0x9a, 0x66, 0xad, 0x23,
					0x1d, 0xf0, 0xf9, 0xbd, 0x61, 0xed, 0x08, 0xd6, 0xea,
				],
			),
			(
				"sha512",
				512,
				1,
				"oQuyuv3Q",
				"80gfY4kIump",
				vec![
					0xf5, 0x67, 0xb2, 0xdc, 0x58, 0xcf, 0xe2, 0x43, 0xfa, 0x2f, 0x5e, 0x06, 0xc4,
					0x44, 0x0b, 0xd9, 0xa8, 0xbb, 0xdf, 0x76, 0x7d, 0xc3, 0x2b, 0x2f, 0x69, 0x73,
					0xc3, 0xb1, 0x12, 0xfe, 0xb9, 0xc4, 0xe3, 0x13, 0x57, 0xa8, 0x54, 0xb7, 0x07,
					0x94, 0x2a, 0x4c, 0x89, 0xb3, 0xdf, 0xc1, 0x17, 0x67, 0x2b, 0x3b, 0x1c, 0x49,
					0x8d, 0x14, 0xd4, 0xee, 0x57, 0x85, 0x29, 0xa5, 0xe2, 0xe1, 0x25, 0x6c,
				],
			),
			(
				"sha512",
				1024,
				3,
				"Ejj2M0Mo",
				"LdUEx0sZfn7X",
				vec![
					0x6f, 0x17, 0x15, 0x23, 0x3a, 0xbe, 0x7d, 0x35, 0x9f, 0x6c, 0x97, 0xa5, 0xe7,
					0xbe, 0x85, 0x8d, 0x79, 0xc4, 0x96, 0x10, 0x9d, 0xa0, 0x83, 0x11, 0x0a, 0x77,
					0x74, 0x65, 0x0f, 0x1e, 0xd3, 0xa3, 0x2c, 0x0c, 0xad, 0x95, 0x68, 0xa4, 0xde,
					0xba, 0x7c, 0x8d, 0x84, 0x36, 0xe0, 0x08, 0x31, 0x99, 0x61, 0x40, 0x36, 0xe9,
					0xea, 0x6e, 0xa5, 0xe1, 0x01, 0x72, 0x3f, 0xdb, 0x54, 0xe1, 0x17, 0x26,
				],
			),
		];
		for &(func, space, time, salt, key, ref result) in lst.iter() {
			let h = BalloonHash {
				hash_function: match func {
					//"sha1" => HashFunction::Sha1,
					//"sha224" => HashFunction::Sha224,
					"sha256" => HashFunction::Sha256,
					"sha384" => HashFunction::Sha384,
					"sha512" => HashFunction::Sha512,
					//"sha512t224" => HashFunction::Sha512Trunc224,
					"sha512t256" => HashFunction::Sha512Trunc256,
					//"keccak224" => HashFunction::Keccak224,
					"keccak256" => HashFunction::Keccak256,
					"keccak384" => HashFunction::Keccak384,
					"keccak512" => HashFunction::Keccak512,
					//"sha3-224" => HashFunction::Sha3_224,
					"sha3-256" => HashFunction::Sha3_256,
					"sha3-384" => HashFunction::Sha3_384,
					"sha3-512" => HashFunction::Sha3_512,
					_ => {
						panic!();
					}
				},
				space: space,
				time: time,
				salt: salt.to_string().into_bytes(),
				norm: Normalization::Nfkc,
			};
			assert_eq!(&h.hash(&key.to_string().into_bytes()), result);
		}
	}
}
