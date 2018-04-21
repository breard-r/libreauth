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
use super::{ErrorCode, HashingFunction, Normalization};
use unicode_normalization::UnicodeNormalization;
use key::KeyBuilder;
use argon2;

const DEFAULT_SALT_LENGTH: usize = 16; // in bytes
const MIN_SALT_LENGTH: usize = 8; // in bytes
const MAX_SALT_LENGTH: usize = 256; // in bytes
const DEFAULT_PASSES: u32 = 3;
const MIN_PASSES: u32 = 1;
const MAX_PASSES: u32 = 1024;
const DEFAULT_MEM_COST: u32 = 12;
const MIN_MEM_COST: u32 = 7;
const MAX_MEM_COST: u32 = 18;
const DEFAULT_LANES: u32 = 4;
const MIN_LANES: u32 = 1;
const MAX_LANES: u32 = 128;
const DEFAULT_OUTPUT_LEN: u32 = 32;
const MIN_OUTPUT_LEN: u32 = 32;
const MAX_OUTPUT_LEN: u32 = 256;

macro_rules! set_param {
    ($obj: ident, $attr: ident, $val: ident, $t: ty, $min: expr, $max: expr) => {{
        match $val.parse::<$t>() {
            Ok(i) => match i {
                $min...$max => {
                    $obj.$attr = i;
                    Ok(())
                }
                _ => Err(ErrorCode::InvalidPasswordFormat),
            },
            Err(_) => Err(ErrorCode::InvalidPasswordFormat),
        }
    }};
}

pub struct Argon2Hash {
    passes: u32,
    mem_cost: u32,
    lanes: u32,
    output_len: u32,
    salt: Vec<u8>,
    norm: Normalization,
}

impl Argon2Hash {
    pub fn new() -> Argon2Hash {
        Argon2Hash {
            passes: DEFAULT_PASSES,
            mem_cost: DEFAULT_MEM_COST,
            lanes: DEFAULT_LANES,
            output_len: DEFAULT_OUTPUT_LEN,
            salt: KeyBuilder::new().size(DEFAULT_SALT_LENGTH).as_vec(),
            norm: Normalization::Nfkc,
        }
    }
}

impl HashingFunction for Argon2Hash {
    fn get_id(&self) -> String {
        "argon2".to_string()
    }

    fn get_parameters(&self) -> HashMap<String, String> {
        let mut params = HashMap::new();
        set_normalization!(self, norm, params, "norm".to_string());
        params.insert("passes".to_string(), self.passes.to_string());
        params.insert("mem".to_string(), self.mem_cost.to_string());
        params.insert("lanes".to_string(), self.lanes.to_string());
        params.insert("len".to_string(), self.output_len.to_string());
        params
    }

    fn set_parameter(&mut self, name: String, value: String) -> Result<(), ErrorCode> {
        match name.as_str() {
            "norm" => get_normalization!(self, norm, value),
            "passes" => set_param!(self, passes, value, u32, MIN_PASSES, MAX_PASSES),
            "mem" => set_param!(self, mem_cost, value, u32, MIN_MEM_COST, MAX_MEM_COST),
            "lanes" => set_param!(self, lanes, value, u32, MIN_LANES, MAX_LANES),
            "len" => set_param!(self, output_len, value, u32, MIN_OUTPUT_LEN, MAX_OUTPUT_LEN),
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

    fn hash(&self, input: &Vec<u8>) -> Vec<u8> {
        let pass = normalize!(self, norm, input);
        let two: u32 = 2;
        let config = argon2::Config {
            ad: &[],
            hash_length: self.output_len,
            lanes: self.lanes,
            mem_cost: two.pow(self.mem_cost),
            secret: &[],
            thread_mode: argon2::ThreadMode::Sequential,
            time_cost: self.passes,
            variant: argon2::Variant::Argon2i,
            version: argon2::Version::Version13,
        };
        argon2::hash_raw(&pass.as_slice(), &self.salt.as_slice(), &config).unwrap()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_id() {
        assert_eq!(Argon2Hash::new().get_id(), "argon2".to_string());
    }

    #[test]
    fn test_get_salt() {
        let h = Argon2Hash {
            passes: DEFAULT_PASSES,
            mem_cost: DEFAULT_MEM_COST,
            lanes: DEFAULT_LANES,
            output_len: DEFAULT_OUTPUT_LEN,
            salt: vec![0, 1, 2, 3, 4, 5],
            norm: Normalization::Nfkc,
        };
        assert_eq!(h.get_salt().unwrap(), vec![0, 1, 2, 3, 4, 5]);
    }

    #[test]
    fn test_salt_randomness() {
        assert_ne!(
            Argon2Hash::new().get_salt().unwrap(),
            Argon2Hash::new().get_salt().unwrap()
        );
    }

    /// Test vector from the PHC repository.
    /// https://github.com/P-H-C/phc-winner-argon2
    /// $ echo -n "password" | ./argon2 somesalt -i -t 2 -m 16 -p 4 -l 24 -v 13
    /// [...]
    /// Encoded: $argon2i$v=19$m=65536,t=2,p=4$c29tZXNhbHQ$RdescudvJCsgt3ub+b+dWRWJTmaaJObG
    #[test]
    fn test_argon2_v13() {
        let h = Argon2Hash {
            passes: 2,
            mem_cost: 16,
            lanes: 4,
            output_len: 24,
            salt: "somesalt".to_string().into_bytes(),
            norm: Normalization::Nfkc,
        }.hash(&"password".to_string().into_bytes());
        assert_eq!(
            h,
            vec![
                69, 215, 172, 114, 231, 111, 36, 43, 32, 183, 123, 155, 249, 191, 157, 89, 21, 137,
                78, 102, 154, 36, 230, 198,
            ],
        );
    }
}
