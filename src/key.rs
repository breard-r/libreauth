//! Key generation module
//!
//! ## Cryptographic security
//!
//! Many random generators are available, but not all of them are
//! cryptographically secure. That is a problem because if a secret key may
//! be predictable, the security of your system crumbles into pieces. This
//! key generation module uses the `getrandom` crate which is an interface
//! to the operating system's preferred random number source.
//!
//! ## Examples
//!
//! Generate a random key and display it in several forms.
//!
//! ```rust
//! let key = libreauth::key::KeyBuilder::new().generate();
//! println!("Key: Vec<u8>: {:?}", key.as_vec());
//! println!("Key: hex String: {}", key.as_hex());
//! println!("Key: base 32 String: {}", key.as_base32());
//! println!("Key: base 64 String: {}", key.as_base64());
//! assert!(key.as_vec() == key.as_vec());
//! assert!(key.as_hex() == key.as_hex());
//! assert!(key.as_base32() == key.as_base32());
//! assert!(key.as_base64() == key.as_base64());
//! ```
//!
//! Generate two random key and test if they are different.
//!
//! ```rust
//! let k1 = libreauth::key::KeyBuilder::new().generate().as_vec();
//! let k2 = libreauth::key::KeyBuilder::new().generate().as_vec();
//! assert!(k1 != k2);
//! ```

#[cfg(feature = "cbindings")]
mod cbindings;

#[cfg(feature = "cbindings")]
pub use self::cbindings::libreauth_keygen;
use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use getrandom::getrandom;

/// Random key builder.
#[derive(Default)]
pub struct KeyBuilder {
	size: usize,
	key: Option<Vec<u8>>,
}

impl KeyBuilder {
	/// Create a new random key builder.
	pub fn new() -> Self {
		Self {
			size: 21,
			key: None,
		}
	}

	/// Set the key size (in bytes).
	pub fn size(mut self, size: usize) -> Self {
		if size != self.size {
			self.size = size;
			self.generate()
		} else {
			self
		}
	}

	/// Generate a random key.
	pub fn generate(mut self) -> Self {
		if self.size == 0 {
			panic!();
		}
		let mut key: Vec<u8> = vec![0; self.size];
		if let Err(e) = getrandom(key.as_mut_slice()) {
			panic!("Fatal error: {}", e);
		}
		self.key = Some(key);
		self
	}

	/// Return the current key as a `Vec<u8>`.
	pub fn as_vec(&self) -> Vec<u8> {
		self.key.clone().unwrap()
	}

	/// Return the current key as an hexadecimal string.
	pub fn as_hex(&self) -> String {
		hex::encode(self.key.clone().unwrap())
	}

	/// Return the current key as a base 32 encoded string.
	pub fn as_base32(&self) -> String {
		base32::encode(
			base32::Alphabet::Rfc4648 { padding: false },
			self.key.clone().unwrap().as_slice(),
		)
	}

	/// Return the current key as a base 64 encoded string.
	pub fn as_base64(&self) -> String {
		STANDARD.encode(self.key.clone().unwrap().as_slice())
	}
}

#[cfg(test)]
mod tests {
	use super::KeyBuilder;

	#[test]
	fn test_uniqueness() {
		let k1 = KeyBuilder::new().generate().as_vec();
		let k2 = KeyBuilder::new().generate().as_vec();
		assert!(k1 != k2);
	}

	#[test]
	fn test_equality() {
		let key = KeyBuilder::new().generate();
		assert!(key.as_vec() == key.as_vec());
	}

	#[test]
	fn test_size_change() {
		let mut key = KeyBuilder::new().generate();
		let k1 = key.as_vec();
		key = key.size(42);
		let k2 = key.as_vec();
		assert!(k1 != k2);
	}

	#[test]
	fn test_size_unchanged() {
		let mut key = KeyBuilder::new().generate();
		let k1 = key.as_vec();
		key = key.size(21);
		let k2 = key.as_vec();
		assert!(k1 == k2);
	}

	#[test]
	fn test_default_len() {
		let key = KeyBuilder::new().generate().as_vec();
		assert!(key.len() == 21);
	}

	#[test]
	fn test_given_len() {
		let lst: Vec<usize> = vec![1, 12, 21, 42, 128, 256];
		for i in lst {
			let key = KeyBuilder::new().size(i).generate().as_vec();
			assert!(key.len() == i);
		}
	}

	#[test]
	#[should_panic]
	fn test_null_len() {
		KeyBuilder::new().size(0);
	}
}
