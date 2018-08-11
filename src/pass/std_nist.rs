/*
 * Copyright Rodolphe Breard (2018)
 * Author: Rodolphe Breard (2018)
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

use super::pbkdf2::{
    HashFunction, DEFAULT_HASH_FUNCTION as PBKDF2_DEF_HASH, DEFAULT_ITER as PBKDF2_DEF_ITER,
};
use super::{Algorithm, HashBuilder, LengthCalculationMethod, Normalization};

pub const DEFAULT_NORMALIZATION: Normalization = Normalization::Nfkc;
pub const DEFAULT_PASSWORD_MIN_LEN: usize = 8;
pub const DEFAULT_PASSWORD_MAX_LEN: usize = 128;
pub const DEFAULT_ALGORITHM: Algorithm = Algorithm::Pbkdf2;
pub const DEFAULT_LENGTH_CALCULATION: LengthCalculationMethod = LengthCalculationMethod::Characters;
pub const DEFAULT_SALT_LEN: usize = 16; // In bytes
pub const MIN_SALT_LEN: usize = 4; // In bytes
pub const PASS_MIN_MIN_LEN: usize = 8;
pub const PASS_MIN_MAX_LEN: usize = 64;
pub const NB_ITER_MIN: usize = 10000;

pub fn is_valid(h: &HashBuilder) -> bool {
    // Length calculation
    match h.length_calculation {
        LengthCalculationMethod::Characters => {}
        LengthCalculationMethod::Bytes => {
            return false;
        }
    }

    // Salt length.
    let sl = match h.ref_salt {
        Some(ref s) => s.len(),
        None => h.salt_len,
    };
    if sl < MIN_SALT_LEN {
        return false;
    }

    // Password length
    if h.min_len < PASS_MIN_MIN_LEN {
        return false;
    }
    if h.max_len < PASS_MIN_MAX_LEN {
        return false;
    }

    // Hashing function
    match h.algorithm {
        Algorithm::Argon2 => {
            return false;
        }
        Algorithm::Pbkdf2 => {
            match h.parameters.get("iter") {
                Some(si) => match si.parse::<usize>() {
                    Ok(i) => {
                        if i < NB_ITER_MIN {
                            return false;
                        }
                    }
                    Err(_) => {
                        return false;
                    }
                },
                None => {
                    if PBKDF2_DEF_ITER < NB_ITER_MIN {
                        return false;
                    }
                }
            };
            match h.parameters.get("hash") {
                Some(h) => match h.as_str() {
                    "sha1" => {}
                    "sha224" => {}
                    "sha256" => {}
                    "sha384" => {}
                    "sha512" => {}
                    "sha512t224" => {}
                    "sha512t256" => {}
                    "sha3-224" => {}
                    "sha3-256" => {}
                    "sha3-384" => {}
                    "sha3-512" => {}
                    _ => {
                        return false;
                    }
                },
                None => match PBKDF2_DEF_HASH {
                    HashFunction::Sha1 => {}
                    HashFunction::Sha224 => {}
                    HashFunction::Sha256 => {}
                    HashFunction::Sha384 => {}
                    HashFunction::Sha512 => {}
                    HashFunction::Sha512Trunc224 => {}
                    HashFunction::Sha512Trunc256 => {}
                    HashFunction::Sha3_224 => {}
                    HashFunction::Sha3_256 => {}
                    HashFunction::Sha3_384 => {}
                    HashFunction::Sha3_512 => {}
                    _ => {
                        return false;
                    }
                },
            };
        }
    };

    // Normalization
    match h.normalization {
        Normalization::Nfd => false,
        Normalization::Nfkd => true,
        Normalization::Nfc => false,
        Normalization::Nfkc => true,
        Normalization::None => false,
    }
}
