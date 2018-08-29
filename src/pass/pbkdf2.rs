use super::{std_default, ErrorCode, HashingFunction, Normalization};
use hmac::Hmac;
use key::KeyBuilder;
use pbkdf2::pbkdf2;
use sha1::Sha1;
use sha2::{Sha224, Sha256, Sha384, Sha512, Sha512Trunc224, Sha512Trunc256};
use sha3::{Keccak224, Keccak256, Keccak384, Keccak512, Sha3_224, Sha3_256, Sha3_384, Sha3_512};
use std::collections::HashMap;

pub enum HashFunction {
    Sha1,
    Sha224,
    Sha256,
    Sha384,
    Sha512,
    Sha512Trunc224,
    Sha512Trunc256,
    Keccak224,
    Keccak256,
    Keccak384,
    Keccak512,
    Sha3_224,
    Sha3_256,
    Sha3_384,
    Sha3_512,
}

pub const DEFAULT_HASH_FUNCTION: HashFunction = HashFunction::Sha512;
const MIN_SALT_LENGTH: usize = 4; // in bytes
const MAX_SALT_LENGTH: usize = 256; // in bytes
const MIN_ITER: usize = 10_000;
const MAX_ITER: usize = 200_000;
pub const DEFAULT_ITER: usize = 45_000;

macro_rules! process_pbkdf2 {
    ($obj:ident, $input:ident, $hash:ty, $len:expr) => {{
        let mut out = [0u8; $len];
        pbkdf2::<Hmac<$hash>>($input, $obj.salt.as_slice(), $obj.nb_iter, &mut out[..$len]);
        out.to_vec()
    }};
}

pub struct Pbkdf2Hash {
    hash_function: HashFunction,
    nb_iter: usize,
    salt: Vec<u8>,
    norm: Normalization,
}

impl Pbkdf2Hash {
    pub fn new() -> Pbkdf2Hash {
        Pbkdf2Hash {
            hash_function: DEFAULT_HASH_FUNCTION,
            nb_iter: DEFAULT_ITER,
            salt: KeyBuilder::new()
                .size(std_default::DEFAULT_SALT_LEN)
                .as_vec(),
            norm: Normalization::Nfkc,
        }
    }
}

impl HashingFunction for Pbkdf2Hash {
    fn get_id(&self) -> String {
        "pbkdf2".to_string()
    }

    fn get_parameters(&self) -> HashMap<String, String> {
        let mut params = HashMap::new();
        set_normalization!(self, norm, params, "norm".to_string());
        params.insert("iter".to_string(), self.nb_iter.to_string());
        params.insert(
            "hash".to_string(),
            match self.hash_function {
                HashFunction::Sha1 => "sha1".to_string(),
                HashFunction::Sha224 => "sha224".to_string(),
                HashFunction::Sha256 => "sha256".to_string(),
                HashFunction::Sha384 => "sha384".to_string(),
                HashFunction::Sha512 => "sha512".to_string(),
                HashFunction::Sha512Trunc224 => "sha512t224".to_string(),
                HashFunction::Sha512Trunc256 => "sha512t256".to_string(),
                HashFunction::Keccak224 => "keccak224".to_string(),
                HashFunction::Keccak256 => "keccak256".to_string(),
                HashFunction::Keccak384 => "keccak384".to_string(),
                HashFunction::Keccak512 => "keccak512".to_string(),
                HashFunction::Sha3_224 => "sha3-224".to_string(),
                HashFunction::Sha3_256 => "sha3-256".to_string(),
                HashFunction::Sha3_384 => "sha3-384".to_string(),
                HashFunction::Sha3_512 => "sha3-512".to_string(),
            },
        );
        params
    }

    fn set_parameter(&mut self, name: &str, value: &str) -> Result<(), ErrorCode> {
        match name {
            "iter" => match value.parse::<usize>() {
                Ok(i) => match i {
                    MIN_ITER...MAX_ITER => {
                        self.nb_iter = i;
                        Ok(())
                    }
                    _ => Err(ErrorCode::InvalidPasswordFormat),
                },
                Err(_) => Err(ErrorCode::InvalidPasswordFormat),
            },
            "hash" => match value {
                "sha1" => {
                    self.hash_function = HashFunction::Sha1;
                    Ok(())
                }
                "sha224" => {
                    self.hash_function = HashFunction::Sha224;
                    Ok(())
                }
                "sha256" => {
                    self.hash_function = HashFunction::Sha256;
                    Ok(())
                }
                "sha384" => {
                    self.hash_function = HashFunction::Sha384;
                    Ok(())
                }
                "sha512" => {
                    self.hash_function = HashFunction::Sha512;
                    Ok(())
                }
                "sha512t224" => {
                    self.hash_function = HashFunction::Sha512Trunc224;
                    Ok(())
                }
                "sha512t256" => {
                    self.hash_function = HashFunction::Sha512Trunc256;
                    Ok(())
                }
                "keccak224" => {
                    self.hash_function = HashFunction::Keccak224;
                    Ok(())
                }
                "keccak256" => {
                    self.hash_function = HashFunction::Keccak256;
                    Ok(())
                }
                "keccak384" => {
                    self.hash_function = HashFunction::Keccak384;
                    Ok(())
                }
                "keccak512" => {
                    self.hash_function = HashFunction::Keccak512;
                    Ok(())
                }
                "sha3-224" => {
                    self.hash_function = HashFunction::Sha3_224;
                    Ok(())
                }
                "sha3-256" => {
                    self.hash_function = HashFunction::Sha3_256;
                    Ok(())
                }
                "sha3-384" => {
                    self.hash_function = HashFunction::Sha3_384;
                    Ok(())
                }
                "sha3-512" => {
                    self.hash_function = HashFunction::Sha3_512;
                    Ok(())
                }
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
            MIN_SALT_LENGTH...MAX_SALT_LENGTH => {
                self.salt = salt;
                Ok(())
            }
            _ => Err(ErrorCode::InvalidPasswordFormat),
        }
    }

    fn set_salt_len(&mut self, salt_len: usize) -> Result<(), ErrorCode> {
        let salt = KeyBuilder::new().size(salt_len).as_vec();
        self.set_salt(salt)
    }

    fn set_normalization(&mut self, norm: Normalization) -> Result<(), ErrorCode> {
        self.norm = norm;
        Ok(())
    }

    fn hash(&self, input: &[u8]) -> Vec<u8> {
        match self.hash_function {
            HashFunction::Sha1 => process_pbkdf2!(self, input, Sha1, 20),
            HashFunction::Sha224 => process_pbkdf2!(self, input, Sha224, 28),
            HashFunction::Sha256 => process_pbkdf2!(self, input, Sha256, 32),
            HashFunction::Sha384 => process_pbkdf2!(self, input, Sha384, 48),
            HashFunction::Sha512 => process_pbkdf2!(self, input, Sha512, 64),
            HashFunction::Sha512Trunc224 => process_pbkdf2!(self, input, Sha512Trunc224, 28),
            HashFunction::Sha512Trunc256 => process_pbkdf2!(self, input, Sha512Trunc256, 32),
            HashFunction::Keccak224 => process_pbkdf2!(self, input, Keccak224, 32),
            HashFunction::Keccak256 => process_pbkdf2!(self, input, Keccak256, 32),
            HashFunction::Keccak384 => process_pbkdf2!(self, input, Keccak384, 32),
            HashFunction::Keccak512 => process_pbkdf2!(self, input, Keccak512, 32),
            HashFunction::Sha3_224 => process_pbkdf2!(self, input, Sha3_224, 28),
            HashFunction::Sha3_256 => process_pbkdf2!(self, input, Sha3_256, 32),
            HashFunction::Sha3_384 => process_pbkdf2!(self, input, Sha3_384, 48),
            HashFunction::Sha3_512 => process_pbkdf2!(self, input, Sha3_512, 64),
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
            Pbkdf2Hash {
                hash_function: HashFunction::Sha1,
                nb_iter: 42,
                salt: vec![0, 1, 2, 3, 4, 5],
                norm: Normalization::Nfkc,
            },
            Pbkdf2Hash {
                hash_function: HashFunction::Sha256,
                nb_iter: 42,
                salt: vec![0, 1, 2, 3, 4, 5],
                norm: Normalization::Nfkc,
            },
            Pbkdf2Hash {
                hash_function: HashFunction::Sha512,
                nb_iter: 42,
                salt: vec![0, 1, 2, 3, 4, 5],
                norm: Normalization::Nfkc,
            },
        ];
        for h in lst.iter() {
            assert_eq!(h.get_id(), "pbkdf2".to_string());
        }
    }

    #[test]
    fn test_get_salt() {
        let h = Pbkdf2Hash {
            hash_function: HashFunction::Sha1,
            nb_iter: 42,
            salt: vec![0, 1, 2, 3, 4, 5],
            norm: Normalization::Nfkc,
        };
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
        assert_ne!(
            Pbkdf2Hash::new().get_salt().unwrap(),
            Pbkdf2Hash::new().get_salt().unwrap()
        );
    }

    /// NIST SP 800-63B: at least 10,000 iterations
    #[test]
    fn test_default_iterations() {
        assert!(Pbkdf2Hash::new().nb_iter >= 10000);
    }

    #[test]
    fn test_vectors() {
        let lst = [
            // --- BEGIN Test vectors from RFC6070 ---
            (
                "sha1",
                1,
                "salt",
                "password",
                vec![
                    0x0c as u8, 0x60, 0xc8, 0x0f, 0x96, 0x1f, 0x0e, 0x71, 0xf3, 0xa9, 0xb5, 0x24,
                    0xaf, 0x60, 0x12, 0x06, 0x2f, 0xe0, 0x37, 0xa6,
                ],
            ),
            (
                "sha1",
                2,
                "salt",
                "password",
                vec![
                    0xea, 0x6c, 0x01, 0x4d, 0xc7, 0x2d, 0x6f, 0x8c, 0xcd, 0x1e, 0xd9, 0x2a, 0xce,
                    0x1d, 0x41, 0xf0, 0xd8, 0xde, 0x89, 0x57,
                ],
            ),
            (
                "sha1",
                4096,
                "salt",
                "password",
                vec![
                    0x4b, 0x00, 0x79, 0x01, 0xb7, 0x65, 0x48, 0x9a, 0xbe, 0xad, 0x49, 0xd9, 0x26,
                    0xf7, 0x21, 0xd0, 0x65, 0xa4, 0x29, 0xc1,
                ],
            ),
            // Test with too many iterations or custom output length are deactivated.
            // (
            //     "sha1",
            //     16777216,
            //     "salt",
            //     "password",
            //     vec![
            //         0xee, 0xfe, 0x3d, 0x61, 0xcd, 0x4d, 0xa4, 0xe4, 0xe9, 0x94, 0x5b, 0x3d, 0x6b,
            //         0xa2, 0x15, 0x8c, 0x26, 0x34, 0xe9, 0x84,
            //     ],
            // ),
            // (
            //     "sha1",
            //     4096,
            //     "saltSALTsaltSALTsaltSALTsaltSALTsalt",
            //     "passwordPASSWORDpassword",
            //     vec![
            //         0x3d, 0x2e, 0xec, 0x4f, 0xe4, 0x1c, 0x84, 0x9b, 0x80, 0xc8, 0xd8, 0x36, 0x62,
            //         0xc0, 0xe4, 0x4a, 0x8b, 0x29, 0x1a, 0x96, 0x4c, 0xf2, 0xf0, 0x70, 0x38,
            //     ],
            // ),
            // (
            //     "sha1",
            //     4096,
            //     "sa\0lt",
            //     "pass\0word",
            //     vec![
            //         0x56, 0xfa, 0x6a, 0xa7, 0x55, 0x48, 0x09, 0x9d, 0xcc, 0x37, 0xd7, 0xf0, 0x34,
            //         0x25, 0xe0, 0xc3,
            //     ],
            // ),
            // --- END Test vectors from RFC6070 ---
            (
                "sha224",
                498,
                "msEf7FpL",
                "DigIpIXYIwc",
                vec![
                    0x3, 0xe8, 0x4b, 0xa7, 0x57, 0xd1, 0xcd, 0xc8, 0xd5, 0x97, 0x2, 0xb, 0xae,
                    0x86, 0xd1, 0x70, 0xec, 0x45, 0xfa, 0xf7, 0xd9, 0xb8, 0x67, 0x28, 0x5b, 0xad,
                    0xf1, 0x3e,
                ],
            ),
            (
                "sha224",
                2741,
                "y9irX",
                "JmvZv6Ut",
                vec![
                    0xa6, 0xf4, 0x7, 0x6c, 0xa3, 0xd3, 0x6a, 0xcd, 0x23, 0x86, 0xc6, 0xd1, 0x57,
                    0x93, 0x88, 0x3c, 0x1e, 0x51, 0x54, 0xcc, 0xfb, 0x3f, 0x97, 0x31, 0x92, 0x30,
                    0x72, 0x37,
                ],
            ),
            (
                "sha256",
                3853,
                "CHhs6n",
                "DAfuHjm77",
                vec![
                    0x4b, 0x99, 0xc5, 0x91, 0x14, 0xc, 0x6, 0xa3, 0x16, 0x4e, 0x1e, 0xd2, 0xbc,
                    0x99, 0x79, 0x2a, 0x74, 0x7f, 0x5d, 0xb4, 0xe0, 0xf8, 0xaf, 0xae, 0xbe, 0x79,
                    0xea, 0x6d, 0xe4, 0x5c, 0x53, 0xc0,
                ],
            ),
            (
                "sha256",
                3590,
                "GJd4x5G",
                "2KJo38IJsfRH",
                vec![
                    0x2d, 0xbf, 0x2d, 0xf5, 0xee, 0xe1, 0xe7, 0x99, 0x8b, 0x79, 0xc3, 0x69, 0xb4,
                    0x1f, 0xa8, 0x51, 0x9f, 0xa1, 0x7f, 0x51, 0x63, 0x4f, 0xbd, 0xbf, 0x7d, 0xef,
                    0x9, 0x8f, 0xc4, 0xe1, 0x34, 0xc3,
                ],
            ),
            (
                "sha384",
                480,
                "tKVt",
                "KdNomtQ4d",
                vec![
                    0x0, 0x56, 0x8b, 0x64, 0xab, 0xf9, 0x26, 0x60, 0xbb, 0x2b, 0xa8, 0x5d, 0xca,
                    0xc, 0xfb, 0xc2, 0xa0, 0x9c, 0xf6, 0x9, 0x61, 0xba, 0x6, 0x2b, 0x79, 0xd9,
                    0x8d, 0xd, 0x97, 0x63, 0xe5, 0x20, 0xd7, 0xd, 0xe1, 0xae, 0x2b, 0xb0, 0x75,
                    0x1a, 0x13, 0x14, 0xea, 0x44, 0xf0, 0xb7, 0x91, 0x8,
                ],
            ),
            (
                "sha384",
                3388,
                "G3KX",
                "OHNbhPKuE",
                vec![
                    0x89, 0xcb, 0x4c, 0xf8, 0xe4, 0xa8, 0x43, 0x7d, 0x6d, 0xef, 0xdb, 0x1f, 0x1f,
                    0x66, 0x21, 0xaa, 0xbd, 0x8f, 0x19, 0xeb, 0x9a, 0xc9, 0xbb, 0xc5, 0x64, 0xd2,
                    0xc9, 0xf, 0x57, 0x6e, 0xd9, 0xfd, 0xe8, 0xf1, 0x6c, 0x36, 0xda, 0x14, 0xa9,
                    0x23, 0xa3, 0x92, 0x10, 0x42, 0xff, 0x8d, 0x44, 0x63,
                ],
            ),
            (
                "sha512",
                2394,
                "oQuyuv3Q",
                "80gfY4kIump",
                vec![
                    0x5f, 0x1a, 0x23, 0x65, 0x2e, 0xd1, 0xa7, 0x98, 0xf3, 0xa2, 0x7d, 0xd9, 0x22,
                    0x83, 0x1e, 0xa5, 0xdb, 0x63, 0xe4, 0xcb, 0xff, 0x5a, 0x1, 0xe3, 0x4, 0x8f,
                    0x9, 0x1b, 0x7a, 0x71, 0x7b, 0x2e, 0x44, 0x99, 0x50, 0xa0, 0x45, 0x74, 0x41,
                    0x57, 0x5e, 0xbc, 0xf2, 0xb8, 0xfd, 0x54, 0xcc, 0x16, 0x88, 0x6, 0x1d, 0x4f,
                    0x8d, 0x67, 0xa, 0xad, 0xbb, 0xff, 0x32, 0x36, 0xc8, 0x9d, 0x9e, 0x7a,
                ],
            ),
            (
                "sha512",
                1605,
                "Ejj2M0Mo",
                "LdUEx0sZfn7X",
                vec![
                    0x87, 0x97, 0x2, 0x55, 0xef, 0x70, 0x99, 0x16, 0xb6, 0x99, 0x99, 0xa2, 0xd8,
                    0x7f, 0x5b, 0xaf, 0x2, 0x8c, 0xc3, 0x5, 0x8b, 0x3f, 0xba, 0xec, 0x7e, 0x79,
                    0xe6, 0xed, 0xdd, 0x28, 0x67, 0xcb, 0xb, 0xc9, 0x42, 0x1f, 0x56, 0xdf, 0xee,
                    0x64, 0xd1, 0x5c, 0x8a, 0xac, 0xc5, 0x15, 0x3b, 0x29, 0x18, 0xe5, 0x92, 0x50,
                    0x78, 0xc8, 0x7e, 0x67, 0x48, 0xf6, 0x65, 0x24, 0x48, 0xb5, 0xce, 0x2f,
                ],
            ),
        ];
        for &(func, nbi, salt, key, ref result) in lst.iter() {
            let h = Pbkdf2Hash {
                hash_function: match func {
                    "sha1" => HashFunction::Sha1,
                    "sha224" => HashFunction::Sha224,
                    "sha256" => HashFunction::Sha256,
                    "sha384" => HashFunction::Sha384,
                    "sha512" => HashFunction::Sha512,
                    "sha512t224" => HashFunction::Sha512Trunc224,
                    "sha512t256" => HashFunction::Sha512Trunc256,
                    "keccak224" => HashFunction::Keccak224,
                    "keccak256" => HashFunction::Keccak256,
                    "keccak384" => HashFunction::Keccak384,
                    "keccak512" => HashFunction::Keccak512,
                    "sha3-224" => HashFunction::Sha3_224,
                    "sha3-256" => HashFunction::Sha3_256,
                    "sha3-384" => HashFunction::Sha3_384,
                    "sha3-512" => HashFunction::Sha3_512,
                    _ => {
                        panic!();
                    }
                },
                nb_iter: nbi,
                salt: salt.to_string().into_bytes(),
                norm: Normalization::Nfkc,
            };
            assert_eq!(&h.hash(&key.to_string().into_bytes()), result);
        }
    }
}
