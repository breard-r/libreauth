use std::collections::HashMap;
use super::HashingFunction;
use super::ErrorCode;
use super::generate_salt;
use crypto::sha2::{Sha512,Sha256};
use crypto::sha1::Sha1;
use crypto::hmac::Hmac;
use crypto::pbkdf2::pbkdf2;

pub enum HashFunction {
    Sha1,
    Sha256,
    Sha512,
}

const DEFAULT_HASH_FUNCTION: HashFunction = HashFunction::Sha256;
const DEFAULT_SALT_LENGTH: usize = 16; // in bytes
const MIN_SALT_LENGTH: usize = 4; // in bytes
const MAX_SALT_LENGTH: usize = 256; // in bytes
const DEFAULT_ITER: u32 = 45000;
const MIN_ITER: u32 = 10000;
const MAX_ITER: u32 = 200000;

macro_rules! process_pbkdf2 {
    ($obj:ident, $input:ident, $hash:expr, $len:expr) => {{
        let mut mac = Hmac::new($hash, $input.as_slice());
        let mut result: Vec<u8> = vec![0; $len];
        pbkdf2(&mut mac, &$obj.salt, $obj.nb_iter, &mut result);
        result
    }}
}

pub struct Pbkdf2Hash {
    hash_function: HashFunction,
    nb_iter: u32,
    salt: Vec<u8>,
}

impl Pbkdf2Hash {
    pub fn new() -> Pbkdf2Hash {
        Pbkdf2Hash {
            hash_function: DEFAULT_HASH_FUNCTION,
            nb_iter: DEFAULT_ITER,
            salt: generate_salt(DEFAULT_SALT_LENGTH),
        }
    }
}

impl HashingFunction for Pbkdf2Hash {
    fn get_id(&self) -> String {
        "pbkdf2".to_string()
    }

    fn get_parameters(&self) -> HashMap<String, String> {
        let mut params = HashMap::new();
        params.insert("iter".to_string(), self.nb_iter.to_string());
        params.insert("hash".to_string(), match self.hash_function {
            HashFunction::Sha1 => "sha1".to_string(),
            HashFunction::Sha256 => "sha256".to_string(),
            HashFunction::Sha512 => "sha512".to_string(),
        });
        params
    }

    fn set_parameter(&mut self, name: String, value: String) -> Result<(), ErrorCode> {
        match name.as_str() {
            "iter" => match value.parse::<u32>() {
                    Ok(i) => match i {
                        MIN_ITER ... MAX_ITER => {
                            self.nb_iter = i;
                            Ok(())
                        },
                        _ => Err(ErrorCode::InvalidPasswordFormat),
                    },
                    Err(_) => Err(ErrorCode::InvalidPasswordFormat),
            },
            "hash" => match value.as_str() {
                "sha1" => { self.hash_function = HashFunction::Sha1; Ok(()) }
                "sha256" => { self.hash_function = HashFunction::Sha256; Ok(()) }
                "sha512" => { self.hash_function = HashFunction::Sha512; Ok(()) }
                _ => Err(ErrorCode::InvalidPasswordFormat),
            },
            _ => Err(ErrorCode::InvalidPasswordFormat),
        }
    }

    fn get_salt(&self) -> Option<Vec<u8>> {
        Some(self.salt.clone())
    }

    fn set_salt(&mut self, salt: Vec<u8>) -> Result<(), ErrorCode> {
        match salt.len() {
            MIN_SALT_LENGTH ... MAX_SALT_LENGTH => {
                self.salt = salt;
                Ok(())
            },
            _ => Err(ErrorCode::InvalidPasswordFormat),
        }
    }

    fn hash(&self, input: &Vec<u8>) -> Vec<u8> {
        match self.hash_function {
            HashFunction::Sha1 => process_pbkdf2!(self, input, Sha1::new(), 20),
            HashFunction::Sha256 => process_pbkdf2!(self, input, Sha256::new(), 32),
            HashFunction::Sha512 => process_pbkdf2!(self, input, Sha512::new(), 64),
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
            Pbkdf2Hash::new(),
            Pbkdf2Hash { hash_function: HashFunction::Sha1, nb_iter: 42, salt: vec![0, 1, 2, 3, 4, 5] },
            Pbkdf2Hash { hash_function: HashFunction::Sha256, nb_iter: 42, salt: vec![0, 1, 2, 3, 4, 5] },
            Pbkdf2Hash { hash_function: HashFunction::Sha512, nb_iter: 42, salt: vec![0, 1, 2, 3, 4, 5] },
        ];
        for h in lst.iter() {
            assert_eq!(h.get_id(), "pbkdf2".to_string());
        }
    }

    #[test]
    fn test_get_salt() {
        let h = Pbkdf2Hash { hash_function: HashFunction::Sha1, nb_iter: 42, salt: vec![0, 1, 2, 3, 4, 5] };
        assert_eq!(h.get_salt().unwrap(), vec![0, 1, 2, 3, 4, 5]);
    }

    /// NIST SP 800-63B: the salt shall be at least 32 bits (4 bytes) in length
    #[test]
    fn test_default_salt_len() {
        let h = Pbkdf2Hash::new();
        assert!(h.get_salt().unwrap().len() >= 4);
    }

    /// NIST SP 800-63B: the salt shall be chosen arbitrarily
    #[test]
    fn test_salt_randomness() {
        assert_ne!(Pbkdf2Hash::new().get_salt().unwrap(), Pbkdf2Hash::new().get_salt().unwrap());
    }

    /// NIST SP 800-63B: at least 10,000 iterations
    #[test]
    fn test_default_iterations() {
        assert!(Pbkdf2Hash::new().nb_iter >= 10000);
    }

    /// Test vectors from RFC6070
    /// Test with too many iterations or custom output length are deactivated.
    #[test]
    fn test_rfc6070() {
        let lst = [
            (1, "salt", "password", vec![0x0c as u8, 0x60, 0xc8, 0x0f, 0x96, 0x1f, 0x0e, 0x71, 0xf3, 0xa9, 0xb5, 0x24, 0xaf, 0x60, 0x12, 0x06, 0x2f, 0xe0, 0x37, 0xa6]),
            (2, "salt", "password", vec![0xea, 0x6c, 0x01, 0x4d, 0xc7, 0x2d, 0x6f, 0x8c, 0xcd, 0x1e, 0xd9, 0x2a, 0xce, 0x1d, 0x41, 0xf0, 0xd8, 0xde, 0x89, 0x57]),
            (4096, "salt", "password", vec![0x4b, 0x00, 0x79, 0x01, 0xb7, 0x65, 0x48, 0x9a, 0xbe, 0xad, 0x49, 0xd9, 0x26, 0xf7, 0x21, 0xd0, 0x65, 0xa4, 0x29, 0xc1]),
            //(16777216, "salt", "password", vec![0xee, 0xfe, 0x3d, 0x61, 0xcd, 0x4d, 0xa4, 0xe4, 0xe9, 0x94, 0x5b, 0x3d, 0x6b, 0xa2, 0x15, 0x8c, 0x26, 0x34, 0xe9, 0x84]),
            //(4096, "saltSALTsaltSALTsaltSALTsaltSALTsalt", "passwordPASSWORDpassword", vec![0x3d, 0x2e, 0xec, 0x4f, 0xe4, 0x1c, 0x84, 0x9b, 0x80, 0xc8, 0xd8, 0x36, 0x62, 0xc0, 0xe4, 0x4a, 0x8b, 0x29, 0x1a, 0x96, 0x4c, 0xf2, 0xf0, 0x70, 0x38]),
            //(4096, "sa\0lt", "pass\0word", vec![0x56, 0xfa, 0x6a, 0xa7, 0x55, 0x48, 0x09, 0x9d, 0xcc, 0x37, 0xd7, 0xf0, 0x34, 0x25, 0xe0, 0xc3]),
        ];
        for &(nb_iter, salt, key, ref result) in lst.iter() {
            let h = Pbkdf2Hash {
                hash_function: HashFunction::Sha1,
                nb_iter: nb_iter,
                salt: salt.to_string().into_bytes()
            };
            assert_eq!(
                &h.hash(&key.to_string().into_bytes()),
                result
            );
        }
    }
}
