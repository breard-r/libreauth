use super::{
    argon2, pbkdf2, std_default, Algorithm, ErrorCode, HashedDuo, HashingFunction,
    LengthCalculationMethod, Normalization, DEFAULT_USER_VERSION, INTERNAL_VERSION, XHMAC,
};
use crate::hash::HashFunction;
use crate::key::KeyBuilder;
use crate::pass::phc::PHCData;
use hmac::{Hmac, Mac};
use sha1::Sha1;
use sha2::{Sha224, Sha256, Sha384, Sha512, Sha512_224, Sha512_256};
use sha3::{Keccak224, Keccak256, Keccak384, Keccak512, Sha3_224, Sha3_256, Sha3_384, Sha3_512};
use std::collections::HashMap;
use unicode_normalization::UnicodeNormalization;

macro_rules! get_hmac {
    ($hash_func: ty, $salt: ident, $pass: ident) => {{
        let mut hasher = Hmac::<$hash_func>::new_from_slice(&$salt)?;
        hasher.update($pass);
        Ok(hasher.finalize().into_bytes().to_vec())
    }};
}

/// Hash a password and check a password against a previously hashed one.
pub struct Hasher {
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

impl Hasher {
    fn check_password(&self, password: &str) -> Result<(), ErrorCode> {
        let pass_len = match self.length_calculation {
            LengthCalculationMethod::Bytes => password.len(),
            LengthCalculationMethod::Characters => {
                let mut len = 0;
                for _ in password.chars() {
                    len += 1;
                }
                len
            }
        };
        if pass_len < self.min_len {
            return Err(ErrorCode::PasswordTooShort);
        }
        if pass_len > self.max_len {
            return Err(ErrorCode::PasswordTooLong);
        }
        Ok(())
    }

    fn normalize_password(&self, password: &str) -> String {
        match self.normalization {
            Normalization::Nfd => password.nfd().collect::<String>(),
            Normalization::Nfkd => password.nfkd().collect::<String>(),
            Normalization::Nfc => password.nfc().collect::<String>(),
            Normalization::Nfkc => password.nfkc().collect::<String>(),
            Normalization::None => password.to_string(),
        }
    }

    fn get_hash_func(&self) -> Result<Box<dyn HashingFunction>, ErrorCode> {
        let mut hash_func: Box<dyn HashingFunction> = match self.algorithm {
            Algorithm::Argon2 => Box::new(argon2::Argon2Hash::new()),
            Algorithm::Pbkdf2 => Box::new(pbkdf2::Pbkdf2Hash::new()),
        };
        hash_func.set_normalization(self.normalization)?;
        for (k, v) in &self.parameters {
            hash_func.set_parameter(k, v)?;
        }
        match self.ref_salt {
            Some(ref s) => {
                hash_func.set_salt(s.to_vec())?;
            }
            None => {
                hash_func.set_salt_len(self.salt_len)?;
            }
        };
        Ok(hash_func)
    }

    fn apply_xhmac(&self, password: &[u8], salt: &[u8]) -> Result<Vec<u8>, ErrorCode> {
        match self.xhmax_alg {
            HashFunction::Sha1 => get_hmac!(Sha1, salt, password),
            HashFunction::Sha224 => get_hmac!(Sha224, salt, password),
            HashFunction::Sha256 => get_hmac!(Sha256, salt, password),
            HashFunction::Sha384 => get_hmac!(Sha384, salt, password),
            HashFunction::Sha512 => get_hmac!(Sha512, salt, password),
            HashFunction::Sha512Trunc224 => get_hmac!(Sha512_224, salt, password),
            HashFunction::Sha512Trunc256 => get_hmac!(Sha512_256, salt, password),
            HashFunction::Sha3_224 => get_hmac!(Sha3_224, salt, password),
            HashFunction::Sha3_256 => get_hmac!(Sha3_256, salt, password),
            HashFunction::Sha3_384 => get_hmac!(Sha3_384, salt, password),
            HashFunction::Sha3_512 => get_hmac!(Sha3_512, salt, password),
            HashFunction::Keccak224 => get_hmac!(Keccak224, salt, password),
            HashFunction::Keccak256 => get_hmac!(Keccak256, salt, password),
            HashFunction::Keccak384 => get_hmac!(Keccak384, salt, password),
            HashFunction::Keccak512 => get_hmac!(Keccak512, salt, password),
        }
    }

    fn do_hash(&self, password: &str) -> Result<HashedDuo, ErrorCode> {
        let norm_pass = self.normalize_password(password);
        match self.check_password(&norm_pass) {
            Ok(_) => {}
            Err(e) => {
                return Err(e);
            }
        };
        let norm_pass = match &self.xhmac {
            XHMAC::Before(salt) => self.apply_xhmac(password.as_bytes(), salt)?,
            _ => norm_pass.into_bytes(),
        };
        let hash_func = self.get_hash_func()?;
        let hash = hash_func.hash(&norm_pass);
        let hash = match &self.xhmac {
            XHMAC::After(salt) => self.apply_xhmac(&hash, salt)?,
            _ => hash,
        };
        let lc = match self.length_calculation {
            LengthCalculationMethod::Bytes => "bytes",
            LengthCalculationMethod::Characters => "chars",
        };
        let mut params = hash_func.get_parameters();
        params.insert("len-calc".to_string(), lc.to_string());
        params.insert("pmin".to_string(), format!("{}", self.min_len));
        params.insert("pmax".to_string(), format!("{}", self.max_len));
        params.insert("ver".to_string(), format!("{}", self.version));
        params.insert("xhmac".to_string(), self.xhmac.to_string());
        if self.xhmac.is_some() {
            params.insert(
                "xhmac-alg".to_string(),
                self.xhmax_alg.to_string().to_lowercase(),
            );
        }
        let phc = PHCData {
            id: hash_func.get_id(),
            parameters: params,
            salt: hash_func.get_salt(),
            hash: Some(hash.clone()),
        };
        match phc.to_string() {
            Ok(fmtd) => Ok(HashedDuo {
                raw: hash,
                formated: fmtd,
            }),
            Err(_) => Err(ErrorCode::InvalidPasswordFormat),
        }
    }

    pub fn hash(&self, password: &str) -> Result<String, ErrorCode> {
        Ok(self.do_hash(password)?.formated)
    }

    pub fn is_valid(&self, password: &str) -> bool {
        match self.ref_hash {
            Some(ref rh) => match self.do_hash(password) {
                Ok(hash_duo) => {
                    let salt = KeyBuilder::new()
                        .size(std_default::DEFAULT_SALT_LEN)
                        .as_vec();

                    let mut ref_hmac = match Hmac::<Sha512>::new_from_slice(&salt) {
                        Ok(h) => h,
                        Err(_) => {
                            return false;
                        }
                    };
                    ref_hmac.update(rh.as_slice());

                    let mut pass_hmac = match Hmac::<Sha512>::new_from_slice(&salt) {
                        Ok(h) => h,
                        Err(_) => {
                            return false;
                        }
                    };
                    pass_hmac.update(hash_duo.raw.as_slice());

                    ref_hmac.finalize().into_bytes() == pass_hmac.finalize().into_bytes()
                }
                Err(_) => false,
            },
            None => false,
        }
    }

    pub fn needs_update(&self, current_version: Option<usize>) -> bool {
        match current_version {
            Some(nb) => self.version < nb + INTERNAL_VERSION,
            None => self.version < DEFAULT_USER_VERSION + INTERNAL_VERSION,
        }
    }
}
