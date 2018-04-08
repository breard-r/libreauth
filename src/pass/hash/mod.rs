/*
 * Copyright Rodolphe Breard (2017)
 * Author: Rodolphe Breard (2017)
 *
 * This software is a computer library whose purpose is to offer a
 * collection of tools for user authentication.
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

use std::collections::HashMap;
use super::{PASSWORD_MAX_LEN, PASSWORD_MIN_LEN};
use super::{ErrorCode, PasswordStorageStandard};
use super::phc::PHCData;

mod argon2;
mod pbkdf2;

trait HashingFunction {
    fn get_id(&self) -> String;
    fn get_parameters(&self) -> HashMap<String, String>;
    fn set_parameter(&mut self, name: String, value: String) -> Result<(), ErrorCode>;
    fn get_salt(&self) -> Option<Vec<u8>>;
    fn set_salt(&mut self, salt: Vec<u8>) -> Result<(), ErrorCode>;
    fn hash(&self, input: &Vec<u8>) -> Vec<u8>;
}

pub struct PasswordHasher {
    hashing_function: Box<HashingFunction>,
}

impl PasswordHasher {
    pub fn new(standard: PasswordStorageStandard) -> PasswordHasher {
        PasswordHasher {
            hashing_function: match standard {
                PasswordStorageStandard::NoStandard => Box::new(argon2::Argon2Hash::new()),
                PasswordStorageStandard::Nist80063b => Box::new(pbkdf2::Pbkdf2Hash::new()),
            },
        }
    }

    pub fn new_from_phc(ref_hash: &PHCData) -> Result<PasswordHasher, ErrorCode> {
        let mut func: Box<HashingFunction> = match ref_hash.id.as_ref() {
            "argon2" => Box::new(argon2::Argon2Hash::new()),
            "pbkdf2" => Box::new(pbkdf2::Pbkdf2Hash::new()),
            _ => return Err(ErrorCode::InvalidPasswordFormat),
        };
        for (name, value) in ref_hash.parameters.clone() {
            match func.set_parameter(name, value) {
                Ok(_) => {}
                Err(e) => {
                    return Err(e);
                }
            };
        }
        match ref_hash.salt {
            Some(ref salt) => match func.set_salt(salt.clone()) {
                Ok(_) => {}
                Err(e) => {
                    return Err(e);
                }
            },
            None => {}
        };
        Ok(PasswordHasher {
            hashing_function: func,
        })
    }

    pub fn hash(&self, input: &Vec<u8>) -> Result<PHCData, ErrorCode> {
        match input.len() {
            n if n < PASSWORD_MIN_LEN => {
                return Err(ErrorCode::PasswordTooShort);
            }
            n if n > PASSWORD_MAX_LEN => {
                return Err(ErrorCode::PasswordTooLong);
            }
            _ => {}
        };
        Ok(PHCData {
            id: self.hashing_function.get_id(),
            parameters: self.hashing_function.get_parameters(),
            salt: self.hashing_function.get_salt(),
            hash: Some(self.hashing_function.hash(input)),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pass_len() {
        let h = PasswordHasher::new(PasswordStorageStandard::NoStandard);
        assert!(h.hash(&vec![]).is_err());
        assert!(h.hash(&vec![1; 7]).is_err());
        assert!(h.hash(&vec![1; 8]).is_ok());
        assert!(h.hash(&vec![1; 128]).is_ok());
        assert!(h.hash(&vec![1; 129]).is_err());
        assert!(h.hash(&vec![1; 4096]).is_err());
    }

    #[test]
    fn test_from_phc() {
        for std in vec![
            PasswordStorageStandard::NoStandard,
            PasswordStorageStandard::Nist80063b,
        ] {
            match PasswordHasher::new(std).hash(&vec![1; 32]) {
                Ok(phc) => match PasswordHasher::new_from_phc(&phc) {
                    Ok(_) => {
                        assert!(true);
                    }
                    Err(_) => {
                        assert!(false);
                    }
                },
                Err(_) => {
                    assert!(false);
                }
            }
        }
    }
}
