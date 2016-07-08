/*
 * Copyright Rodolphe Breard (2016)
 * Author: Rodolphe Breard (2016)
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


use super::{PASSWORD_MIN_LEN,PASSWORD_MAX_LEN};
use super::{ErrorCode,generate_salt};
use std::collections::HashMap;
use rustc_serialize::hex::{FromHex,ToHex};
use crypto::sha2::{Sha512,Sha256};
use crypto::sha1::Sha1;
use crypto::hmac::Hmac;
use crypto::pbkdf2::pbkdf2;


#[repr(C)]
#[derive(Clone, Copy)]
pub enum HashFunction {
    Sha1 = 1,
    Sha256 = 2,
    Sha512 = 3,
}

pub trait PasswordDerivationFunction {
    fn derive(&self, password: &str) -> Result<String, ErrorCode>;
    fn check_password(&self, password: &str) -> Result<bool, ErrorCode> {
        if password.len() < PASSWORD_MIN_LEN {
            return Err(ErrorCode::PasswordTooShort);
        } else if password.len() > PASSWORD_MAX_LEN {
            return Err(ErrorCode::PasswordTooLong);
        }
        Ok(true)
    }
}

pub struct Pbkdf2 {
    hash_function: HashFunction,
    nb_iter: u32,
    salt: Vec<u8>,
}

macro_rules! process_pbkdf2 {
    ($obj:ident, $pass:ident, $hash:expr, $len:expr, $id:expr) => {{
        let mut mac = Hmac::new($hash, $pass.as_bytes());
        let mut derived_pass: Vec<u8> = vec![0; $len];
        pbkdf2(&mut mac, &$obj.salt, $obj.nb_iter, &mut derived_pass);
        let out = format!("${}$i={}${}${}", $id, $obj.nb_iter, $obj.salt.to_hex(), derived_pass.to_hex());
        Ok(out)
    }}
}

impl PasswordDerivationFunction for Pbkdf2 {
    fn derive(&self, password: &str) -> Result<String, ErrorCode> {
        match self.check_password(password) {
            Ok(_) => match self.hash_function {
                HashFunction::Sha1 => process_pbkdf2!(self, password, Sha1::new(), 20, "pbkdf2"),
                HashFunction::Sha256 => process_pbkdf2!(self, password, Sha256::new(), 32, "pbkdf2_sha256"),
                HashFunction::Sha512 => process_pbkdf2!(self, password, Sha512::new(), 64, "pbkdf2_sha512"),
            },
            Err(e) => Err(e),
        }
    }
}

pub struct PasswordDerivationFunctionBuilder {
    algo: Option<String>,
    salt: Option<Vec<u8>>,
    parameters: HashMap<String, String>,
    runtime_error: Option<ErrorCode>,
}

macro_rules! get_salt {
    ($salt:expr) => {{
        match $salt.to_owned() {
            Some(s) => s,
            None => generate_salt(8),
        }
    }}
}

macro_rules! get_param {
    ($h:expr, $k:expr, $t:ty, $default:expr) => {{
        if $h.contains_key($k) {
            $h.get($k).unwrap().parse::<$t>().unwrap_or($default)
        } else {
            $default
        }
    }}
}

impl PasswordDerivationFunctionBuilder {
    pub fn new() -> PasswordDerivationFunctionBuilder {
        PasswordDerivationFunctionBuilder {
            algo: None,
            salt: None,
            parameters: HashMap::new(),
            runtime_error: None,
        }
    }

    pub fn set_reference_hash(&mut self, hash: &str) -> &mut PasswordDerivationFunctionBuilder {
        let splited: Vec<&str> = hash.split("$").collect();
        if splited.len() != 5 {
            self.runtime_error = Some(ErrorCode::InvalidPasswordFormat);
            return self;
        }

        // Extracting the algorithm
        self.algo = Some(splited[1].to_string());

        // Extracting the parameters
        let splited_params: Vec<&str> = splited[2].split(",").collect();
        for param_couple in splited_params.iter() {
            let couple: Vec<&str> = param_couple.split("=").collect();
            if couple.len() == 2 {
                self.parameters.insert(couple[0].to_string(), couple[1].to_string());
            }
        }

        // Extracting the salt
        match splited[3].from_hex() {
            Ok(some) => self.salt = Some(some),
            Err(_) => {
                self.runtime_error = Some(ErrorCode::InvalidPasswordFormat);
                return self;
            },
        }
        self
    }

    pub fn finalize(&self) -> Result<Box<PasswordDerivationFunction>, ErrorCode> {
        match self.runtime_error {
            Some(e) => Err(e),
            None => match self.algo.to_owned() {
                Some(algo) => match algo.as_ref() {
                    "pbkdf2_sha512" => {
                        let h = Pbkdf2 {
                            hash_function: HashFunction::Sha512,
                            salt: get_salt!(self.salt),
                            nb_iter: get_param!(self.parameters, "i", u32, 21000),
                        };
                        Ok(Box::new(h))
                    },
                    "pbkdf2_sha256" => {
                        let h = Pbkdf2 {
                            hash_function: HashFunction::Sha256,
                            salt: get_salt!(self.salt),
                            nb_iter: get_param!(self.parameters, "i", u32, 21000),
                        };
                        Ok(Box::new(h))
                    },
                    "pbkdf2" => {
                        let h = Pbkdf2 {
                            hash_function: match self.parameters.get("h") {
                                Some(h) => match h.as_ref() {
                                    "sha512" => HashFunction::Sha512,
                                    "sha256" => HashFunction::Sha256,
                                    _ => HashFunction::Sha1,
                                },
                                None => HashFunction::Sha1,
                            },
                            salt: get_salt!(self.salt),
                            nb_iter: get_param!(self.parameters, "i", u32, 21000),
                        };
                        Ok(Box::new(h))
                    },
                    _ => Err(ErrorCode::InvalidPasswordFormat)
                },
                None => Ok(Box::new(Pbkdf2 {
                    hash_function: HashFunction::Sha512,
                    nb_iter: 21000,
                    salt: generate_salt(8),
                })),
            },
        }
    }
}
