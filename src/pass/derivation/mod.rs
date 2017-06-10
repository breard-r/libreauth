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


mod pbkdf2;

use super::{PASSWORD_MIN_LEN,PASSWORD_MAX_LEN};
use super::{ErrorCode,generate_salt};
use super::phc::PHCData;
use std::collections::HashMap;


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
        match PHCData::from_string(&hash.to_string()) {
            Ok(r) => {
                self.algo = Some(r.id);
                self.salt = r.salt;
                self.parameters = r.parameters;
            },
            Err(_) => { self.runtime_error = Some(ErrorCode::InvalidPasswordFormat) },
        };
        self
    }

    pub fn finalize(&self) -> Result<Box<PasswordDerivationFunction>, ErrorCode> {
        match self.runtime_error {
            Some(e) => Err(e),
            None => match self.algo.to_owned() {
                Some(algo) => match algo.as_ref() {
                    "pbkdf2-sha512" => {
                        let h = pbkdf2::Pbkdf2 {
                            hash_function: HashFunction::Sha512,
                            salt: get_salt!(self.salt),
                            nb_iter: get_param!(self.parameters, "i", u32, 21000),
                        };
                        Ok(Box::new(h))
                    },
                    "pbkdf2-sha256" => {
                        let h = pbkdf2::Pbkdf2 {
                            hash_function: HashFunction::Sha256,
                            salt: get_salt!(self.salt),
                            nb_iter: get_param!(self.parameters, "i", u32, 21000),
                        };
                        Ok(Box::new(h))
                    },
                    "pbkdf2" => {
                        let h = pbkdf2::Pbkdf2 {
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
                None => Ok(Box::new(pbkdf2::Pbkdf2 {
                    hash_function: HashFunction::Sha512,
                    nb_iter: 21000,
                    salt: generate_salt(8),
                })),
            },
        }
    }
}
