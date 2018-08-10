/*
 * Copyright Rodolphe Breard (2016-2018)
 * Author: Rodolphe Breard (2016-2018)
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

//! Password authentication module.
//!
//! It allows you to:
//!
//! - generate a fingerprint of the password that could be stored;
//! - check a password against the stored fingerprint.
//!
//!
//! ## Standards
//!
//! By default, LibreAuth has security in mind and therefore provides a decent level of security.
//!
//! Sometimes, you may be required to comply with industry or government standards. To ease such
//! requirements, LibreAuth is able to adapt itself to some standards. Please note such modes does
//! not automatically guaranty you compliance, you may have other items to check.
//!
//! ## Storage format
//!
//! The password fingerprint is stored in the [PHC] format which is very close to the modular crypt format (cf. [[1]] and [[2]]).
//!
//! ## Supported identifiers and parameters
//!
//! <table class="vcentered_table">
//!     <thead>
//!         <tr>
//!             <th>Algorithm</th>
//!             <th>Parameter name</th>
//!             <th>Parameter type</th>
//!             <th>Parameter description</th>
//!             <th>Default value</th>
//!         </tr>
//!     </thead>
//!     <tbody>
//!         <tr>
//!             <td rowspan="2" class="hash">Global parameters</td>
//!             <td>norm</td>
//!             <td>string: nfd | nfkd | nfc | nfkc | none</td>
//!             <td>Unicode normalization.</td>
//!             <td>nfkc</td>
//!         </tr>
//!         <tr>
//!             <td>len-calc</td>
//!             <td>string: bytes | chars</td>
//!             <td>Unicode string length calculation method.</td>
//!             <td>chars</td>
//!         </tr>
//!         <tr>
//!             <td rowspan="4" class="hash">argon2</td>
//!             <td>passes</td>
//!             <td>integer</td>
//!             <td>The number of block matrix iterations to perform.</td>
//!             <td>3</td>
//!         </tr>
//!         <tr>
//!             <td>mem</td>
//!             <td>integer</td>
//!             <td>Memmory cost (2^mem kibbibytes).</td>
//!             <td>12 (4096 KiB)</td>
//!         </tr>
//!         <tr>
//!             <td>lanes</td>
//!             <td>integer</td>
//!             <td>The degree of parallelism by which memory is filled during hash computation.</td>
//!             <td>4</td>
//!         </tr>
//!         <tr>
//!             <td>len</td>
//!             <td>integer</td>
//!             <td>Output length, in bytes.</td>
//!             <td>128</td>
//!         </tr>
//!         <tr>
//!             <td rowspan="2" class="hash">pbkdf2</td>
//!             <td>iter</td>
//!             <td>integer</td>
//!             <td>Number of iterations.</td>
//!             <td>45000</td>
//!         </tr>
//!         <tr>
//!             <td>hash</td>
//!             <td>string: sha1 | sha224 | sha256 | sha384 | sha512 | sha512t224 | sha512t256</td>
//!             <td>The hash function.</td>
//!             <td>sha512</td>
//!         </tr>
//!     </tbody>
//! </table>
//!
//! ## Examples
//! ```rust
//! use libreauth::pass::HashBuilder;
//!
//! // Hashing a password in order to store it.
//! let password = "correct horse battery staple".to_string();
//! let hasher = HashBuilder::new().finalize().unwrap();
//! let stored_password = hasher.hash(&password).unwrap();
//!
//! // Checking a password against a previously hashed one.
//! let checker = HashBuilder::from_phc(stored_password).unwrap();
//! assert!(! checker.is_valid(&"bad password".to_string()));
//! assert!(checker.is_valid(&password));
//! ```
//!
//! [PHC]: https://github.com/P-H-C/phc-string-format/blob/master/phc-sf-spec.md
//! [1]: https://en.wikipedia.org/wiki/Crypt_(C)#Key_Derivation_Functions_Supported_by_crypt
//! [2]: https://pythonhosted.org/passlib/modular_crypt_format.html

macro_rules! set_normalization {
    ($obj: ident, $attr: ident, $val: ident, $name: expr) => {
        $val.insert(
            $name,
            match $obj.$attr {
                Normalization::Nfd => "nfd".to_string(),
                Normalization::Nfkd => "nfkd".to_string(),
                Normalization::Nfc => "nfc".to_string(),
                Normalization::Nfkc => "nfkc".to_string(),
                Normalization::None => "none".to_string(),
            },
        );
    };
}

mod std_default;
mod std_nist;
mod argon2;
mod pbkdf2;
mod phc;

use unicode_normalization::UnicodeNormalization;
use std::collections::HashMap;
use sha2::Sha512;
use hmac::{Hmac, Mac};
use key::KeyBuilder;
use self::phc::PHCData;

/// Algorithms available to hash the password.
///
/// ## C interface
/// The C interface uses an enum of type `libreauth_pass_algo` and the members has been renamed
/// as follows:
/// <table>
///     <thead>
///         <tr>
///             <th>Rust</th>
///             <th>C</th>
///         </tr>
///     </thead>
///     <tbody>
///         <tr>
///             <td>Argon2</td>
///             <td>LIBREAUTH_PASS_ARGON2</td>
///         </tr>
///         <tr>
///             <td>Pbkdf2</td>
///             <td>LIBREAUTH_PASS_PBKDF2</td>
///         </tr>
///     </tbody>
/// </table>
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub enum Algorithm {
    Argon2 = 0,
    Pbkdf2 = 1,
}

/// Error codes used both in the rust and C interfaces.
///
/// ## C interface
/// The C interface uses an enum of type `libreauth_pass_errno` and the members has been renamed
/// as follows:
/// <table>
///     <thead>
///         <tr>
///             <th>Rust</th>
///             <th>C</th>
///         </tr>
///     </thead>
///     <tbody>
///         <tr>
///             <td>Success</td>
///             <td>LIBREAUTH_PASS_SUCCESS</td>
///         </tr>
///         <tr>
///             <td>PasswordTooShort</td>
///             <td>LIBREAUTH_PASS_PASSWORD_TOO_SHORT</td>
///         </tr>
///         <tr>
///             <td>PasswordTooLong</td>
///             <td>LIBREAUTH_PASS_PASSWORD_TOO_LONG</td>
///         </tr>
///         <tr>
///             <td>InvalidPasswordFormat</td>
///             <td>LIBREAUTH_PASS_INVALID_PASSWORD_FORMAT</td>
///         </tr>
///         <tr>
///             <td>IncompatibleOption</td>
///             <td>LIBREAUTH_PASS_INCOMPATIBLE_OPTION</td>
///         </tr>
///         <tr>
///             <td>NotEnoughSpace</td>
///             <td>LIBREAUTH_PASS_NOT_ENOUGH_SPACE</td>
///         </tr>
///         <tr>
///             <td>NullPtr</td>
///             <td>LIBREAUTH_PASS_NULL_PTR</td>
///         </tr>
///     </tbody>
/// </table>
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub enum ErrorCode {
    /// Used in C-bindings to indicate the absence of errors.
    Success = 0,
    /// The password is shorter than the miniimal length (default: [DEFAULT_PASSWORD_MIN_LEN][1]).
    ///
    /// [1]: constant.DEFAULT_PASSWORD_MIN_LEN.html
    PasswordTooShort = 1,
    /// The password is longer than the maximal length (default: [DEFAULT_PASSWORD_MAX_LEN][1]).
    ///
    /// [1]: constant.DEFAULT_PASSWORD_MAX_LEN.html
    PasswordTooLong = 2,
    /// The input does not respect the [storage format][1].
    ///
    /// [1]: index.html#storage-format
    InvalidPasswordFormat = 10,
    /// Some options you specified are incompatible.
    IncompatibleOption = 11,
    /// Used in C-bindings to indicate the storage does not have enough space to store the data.
    NotEnoughSpace = 20,
    /// Used in C-bindings to indicate a NULL pointer.
    NullPtr = 21,
}

/// Available methods to calculate the length of a UTF-8 string.
///
/// ## C interface
/// The C interface uses an enum of type `libreauth_pass_len_calc` and the members has been renamed
/// as follows:
/// <table>
///     <thead>
///         <tr>
///             <th>Rust</th>
///             <th>C</th>
///         </tr>
///     </thead>
///     <tbody>
///         <tr>
///             <td>Bytes</td>
///             <td>LIBREAUTH_PASS_BYTES</td>
///         </tr>
///         <tr>
///             <td>Characters</td>
///             <td>LIBREAUTH_PASS_CHARACTERS</td>
///         </tr>
///     </tbody>
/// </table>
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LengthCalculationMethod {
    Bytes = 0,
    Characters = 1,
}

/// Available string normalization methods.
///
/// ## C interface
/// The C interface uses an enum of type `libreauth_pass_normalization` and the members has been renamed
/// as follows:
/// <table>
///     <thead>
///         <tr>
///             <th>Rust</th>
///             <th>C</th>
///         </tr>
///     </thead>
///     <tbody>
///         <tr>
///             <td>Nfd</td>
///             <td>LIBREAUTH_PASS_NFD</td>
///         </tr>
///         <tr>
///             <td>Nfkd</td>
///             <td>LIBREAUTH_PASS_NFKD</td>
///         </tr>
///         <tr>
///             <td>Nfc</td>
///             <td>LIBREAUTH_PASS_NFC</td>
///         </tr>
///         <tr>
///             <td>Nfkc</td>
///             <td>LIBREAUTH_PASS_NFKC</td>
///         </tr>
///         <tr>
///             <td>None</td>
///             <td>LIBREAUTH_PASS_NO_NORMALIZATION</td>
///         </tr>
///     </tbody>
/// </table>
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub enum Normalization {
    Nfd = 1,
    Nfkd = 2,
    Nfc = 3,
    Nfkc = 4,
    None = 0,
}

/// Defines whether or not LibreAuth should comply with recommendations from a specific standard.
///
/// ## C interface
/// The C interface uses an enum of type `libreauth_pass_standard` and the members has been renamed
/// as follows:
/// <table>
///     <thead>
///         <tr>
///             <th>Rust</th>
///             <th>C</th>
///         </tr>
///     </thead>
///     <tbody>
///         <tr>
///             <td>NoStandard</td>
///             <td>LIBREAUTH_PASS_NOSTANDARD</td>
///         </tr>
///         <tr>
///             <td>Nist80063b</td>
///             <td>LIBREAUTH_PASS_NIST80063B</td>
///         </tr>
///     </tbody>
/// </table>
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub enum PasswordStorageStandard {
    /// Default mode of operation, safe.
    NoStandard = 0,
    /// Comply with the [NIST Special Publication 800-63B](https://pages.nist.gov/800-63-3/sp800-63b.html).
    Nist80063b = 1,
}

trait HashingFunction {
    fn get_id(&self) -> String;
    fn get_parameters(&self) -> HashMap<String, String>;
    fn set_parameter(&mut self, name: String, value: String) -> Result<(), ErrorCode>;
    fn get_salt(&self) -> Option<Vec<u8>>;
    fn set_salt(&mut self, salt: Vec<u8>) -> Result<(), ErrorCode>;
    fn set_salt_len(&mut self, salt_len: usize) -> Result<(), ErrorCode>;
    fn set_normalization(&mut self, norm: Normalization) -> Result<(), ErrorCode>;
    fn hash(&self, input: &Vec<u8>) -> Vec<u8>;
}

struct HashedDuo {
    raw: Vec<u8>,
    formated: String,
}

/// Hash a password and check a password against a previously hashed one.
pub struct Hasher {
    normalization: Normalization,
    min_len: usize,
    max_len: usize,
    algorithm: Algorithm,
    parameters: HashMap<String, String>,
    ref_salt: Option<Vec<u8>>,
    ref_hash: Option<Vec<u8>>,
    salt_len: usize,
    length_calculation: LengthCalculationMethod,
}

impl Hasher {
    fn check_password(&self, password: &String) -> Result<(), ErrorCode> {
        let pass_len = match self.length_calculation {
            LengthCalculationMethod::Bytes => password.len(),
            LengthCalculationMethod::Characters => {
                let mut len = 0;
                for _ in password.chars() {
                    len = len + 1;
                }
                len
            },
        };
        if pass_len < self.min_len {
            return Err(ErrorCode::PasswordTooShort)
        }
        if pass_len > self.max_len {
            return Err(ErrorCode::PasswordTooLong)
        }
        Ok(())
    }

    fn normalize_password(&self, password: &String) -> String {
        match self.normalization {
            Normalization::Nfd => password.nfd().collect::<String>(),
            Normalization::Nfkd => password.nfkd().collect::<String>(),
            Normalization::Nfc => password.nfc().collect::<String>(),
            Normalization::Nfkc => password.nfkc().collect::<String>(),
            Normalization::None => password.clone(),
        }
    }

    fn get_hash_func(&self) -> Box<HashingFunction> {
        let mut hash_func: Box<HashingFunction> = match self.algorithm {
            Algorithm::Argon2 => Box::new(argon2::Argon2Hash::new()),
            Algorithm::Pbkdf2 => Box::new(pbkdf2::Pbkdf2Hash::new()),
        };
        hash_func.set_normalization(self.normalization).unwrap();
        for (k, v) in self.parameters.iter() {
            hash_func.set_parameter(k.to_string(), v.to_string()).unwrap();
        }
        match self.ref_salt {
            Some(ref s) => {
                hash_func.set_salt(s.to_vec()).unwrap();
            },
            None => {
                hash_func.set_salt_len(self.salt_len).unwrap();
            },
        };
        hash_func
    }

    fn do_hash(&self, password: &String) -> Result<HashedDuo, ErrorCode> {
        let norm_pass = self.normalize_password(password);
        match self.check_password(&norm_pass) {
            Ok(_) => {},
            Err(e) => {
                return Err(e);
            },
        };
        let hash_func = self.get_hash_func();
        let hash = hash_func.hash(&norm_pass.into_bytes());
        let lc = match self.length_calculation {
            LengthCalculationMethod::Bytes => "bytes",
            LengthCalculationMethod::Characters => "chars",
        };
        let mut params = hash_func.get_parameters();
        params.insert("len-calc".to_string(), lc.to_string());
        let phc = PHCData {
            id: hash_func.get_id(),
            parameters: params,
            salt: hash_func.get_salt(),
            hash: Some(hash.clone()),
        };
        match phc.to_string() {
            Ok(formated) => Ok(HashedDuo {
                raw: hash,
                formated: formated,
            }),
            Err(_) => Err(ErrorCode::InvalidPasswordFormat),
        }
    }

    pub fn hash(&self, password: &String) -> Result<String, ErrorCode> {
        match self.do_hash(password) {
            Ok(hash_duo) => Ok(hash_duo.formated),
            Err(e) => Err(e),
        }
    }

    pub fn is_valid(&self, password: &String) -> bool {
        match self.ref_hash {
            Some(ref rh) => match self.do_hash(password) {
                Ok(hash_duo) => {
                    let salt = KeyBuilder::new().size(std_default::DEFAULT_SALT_LEN).as_vec();

                    let mut ref_hmac = match Hmac::<Sha512>::new_varkey(&salt) {
                        Ok(h) => h,
                        Err(_) => {
                            return false;
                        }
                    };
                    ref_hmac.input(rh.as_slice());

                    let mut pass_hmac = match Hmac::<Sha512>::new_varkey(&salt) {
                        Ok(h) => h,
                        Err(_) => {
                            return false;
                        }
                    };
                    pass_hmac.input(hash_duo.raw.as_slice());

                    ref_hmac.result().code() == pass_hmac.result().code()
                },
                Err(_) => false,
            },
            None => false,
        }
    }
}

/// Builds a Hasher object.
///
/// ## Examples
///
/// ```
/// use libreauth::pass::HashBuilder;
///
/// // Hashing a password in order to store it.
/// let password = "correct horse battery staple".to_string();
/// let hasher = match HashBuilder::new().finalize() {
///     Ok(h) => h,
///     Err(e) => panic!("{:?}", e),
/// };
/// let stored_password = match hasher.hash(&password) {
///     Ok(p) => p,
///     Err(e) => panic!("{:?}", e),
/// };
///
/// // Checking a password against a previously hashed one.
/// let checker = HashBuilder::from_phc(stored_password).unwrap();
/// assert!(! checker.is_valid(&"bad password".to_string()));
/// assert!(checker.is_valid(&password));
/// ```
///
/// Build a Hasher object with the default parameters to comply with the NIST Special Publication 800-63B. This object will be usable to hash a password.
/// ```
/// use libreauth::pass::{HashBuilder, PasswordStorageStandard};
///
/// let hasher = match HashBuilder::new_std(PasswordStorageStandard::Nist80063b).finalize() {
///     Ok(h) => h,
///     Err(e) => panic!("{:?}", e),
/// };
/// ```
///
/// Build a Hasher object with custom parameters. This object will be usable to hash a password.
/// ```
/// let hasher = match libreauth::pass::HashBuilder::new()
///     .min_len(12).algorithm(libreauth::pass::Algorithm::Pbkdf2)
///     .add_param("hash".to_string(), "sha512".to_string())
///     .add_param("norm".to_string(), "nfkd".to_string())
///     .finalize() {
///     Ok(h) => h,
///     Err(e) => panic!("{:?}", e),
/// };
/// ```
pub struct HashBuilder {
    standard: PasswordStorageStandard,
    normalization: Normalization,
    min_len: usize,
    max_len: usize,
    algorithm: Algorithm,
    parameters: HashMap<String, String>,
    ref_salt: Option<Vec<u8>>,
    ref_hash: Option<Vec<u8>>,
    salt_len: usize,
    length_calculation: LengthCalculationMethod,
}

impl HashBuilder {
    /// Create a new HashBuilder object with default parameters.
    pub fn new() -> HashBuilder {
        HashBuilder::new_std(PasswordStorageStandard::NoStandard)
    }

    /// Create a new HashBuilder object with default parameters for a specific standard.
    pub fn new_std(std: PasswordStorageStandard) -> HashBuilder {
        match std {
            PasswordStorageStandard::NoStandard => {
                HashBuilder {
                    standard: PasswordStorageStandard::NoStandard,
                    normalization: std_default::DEFAULT_NORMALIZATION,
                    min_len: std_default::DEFAULT_PASSWORD_MIN_LEN,
                    max_len: std_default::DEFAULT_PASSWORD_MAX_LEN,
                    algorithm: std_default::DEFAULT_ALGORITHM,
                    parameters: HashMap::new(),
                    ref_salt: None,
                    ref_hash: None,
                    salt_len: std_default::DEFAULT_SALT_LEN,
                    length_calculation: std_default::DEFAULT_LENGTH_CALCULATION,
                }
            },
            PasswordStorageStandard::Nist80063b => {
                HashBuilder {
                    standard: PasswordStorageStandard::Nist80063b,
                    normalization: std_nist::DEFAULT_NORMALIZATION,
                    min_len: std_nist::DEFAULT_PASSWORD_MIN_LEN,
                    max_len: std_nist::DEFAULT_PASSWORD_MAX_LEN,
                    algorithm: std_nist::DEFAULT_ALGORITHM,
                    parameters: HashMap::new(),
                    ref_salt: None,
                    ref_hash: None,
                    salt_len: std_nist::DEFAULT_SALT_LEN,
                    length_calculation: std_nist::DEFAULT_LENGTH_CALCULATION,
                }
            },
        }
    }

    /// Create a new Hasher object from a PHC formatted string.
    pub fn from_phc(data: String) -> Result<Hasher, ErrorCode> {
        let mut phc = match PHCData::from_bytes(&data.into_bytes()) {
            Ok(v) => v,
            Err(_) => return Err(ErrorCode::InvalidPasswordFormat),
        };
        let norm = match phc.parameters.remove("norm") {
            Some(v) => match v.as_str() {
                "nfd" => Normalization::Nfd,
                "nfkd" => Normalization::Nfkd,
                "nfc" => Normalization::Nfc,
                "nfkc" => Normalization::Nfkc,
                "none" => Normalization::None,
                _ => return Err(ErrorCode::InvalidPasswordFormat),
            },
            None => Normalization::Nfkc,
        };
        let lc = match phc.parameters.remove("len-calc") {
            Some(v) => match v.as_str() {
                "bytes" => LengthCalculationMethod::Bytes,
                "chars" => LengthCalculationMethod::Characters,
                _ => return Err(ErrorCode::InvalidPasswordFormat),
            },
            None => LengthCalculationMethod::Characters,
        };
        let hash_builder = HashBuilder {
            standard: PasswordStorageStandard::NoStandard,
            normalization: norm,
            min_len: std_default::DEFAULT_PASSWORD_MIN_LEN,
            max_len: std_default::DEFAULT_PASSWORD_MAX_LEN,
            algorithm: match phc.id.as_str() {
                "argon2" => Algorithm::Argon2,
                "pbkdf2" => Algorithm::Pbkdf2,
                _ => return Err(ErrorCode::InvalidPasswordFormat),
            },
            parameters: phc.parameters.clone(),
            ref_hash: phc.hash,
            salt_len: match &phc.salt {
                Some(ref s) => s.len(),
                None => std_default::DEFAULT_SALT_LEN,
            },
            ref_salt: phc.salt,
            length_calculation: lc,
        };
        hash_builder.finalize()
    }

    /// Check the compatibility between options and create a Hasher object.
    pub fn finalize(&self) -> Result<Hasher, ErrorCode> {
        match self.standard {
            PasswordStorageStandard::Nist80063b => {
                if ! std_nist::is_valid(self) {
                    return Err(ErrorCode::InvalidPasswordFormat);
                }
            },
            PasswordStorageStandard::NoStandard => {},
        }
        Ok(Hasher {
            normalization: self.normalization,
            min_len: self.min_len,
            max_len: self.max_len,
            algorithm: self.algorithm,
            parameters: self.parameters.clone(),
            ref_salt: self.ref_salt.clone(),
            ref_hash: self.ref_hash.clone(),
            salt_len: self.salt_len,
            length_calculation: self.length_calculation,
        })
    }

    /// Set the way the password will be normalized.
    pub fn normalization(&mut self, normalization: Normalization) -> &mut HashBuilder {
        self.normalization = normalization;
        self
    }

    /// Set the password hashing algorithm.
    pub fn algorithm(&mut self, algorithm: Algorithm) -> &mut HashBuilder {
        self.algorithm = algorithm;
        self.parameters = HashMap::new();
        self
    }

    /// Set the way the password length will be calculated.
    pub fn length_calculation(&mut self, method: LengthCalculationMethod) -> &mut HashBuilder {
        self.length_calculation = method;
        self
    }

    /// Set the salt length.
    ///
    /// Unused if a salt is given.
    pub fn salt_len(&mut self, len: usize) -> &mut HashBuilder {
        self.salt_len = len;
        self
    }

    /// Set the password minimal length.
    pub fn min_len(&mut self, len: usize) -> &mut HashBuilder {
        self.min_len = len;
        self
    }

    /// Set the password maximal length.
    pub fn max_len(&mut self, len: usize) -> &mut HashBuilder {
        self.max_len = len;
        self
    }

    /// Add a parameter that will be used by the password hashing algorithm.
    pub fn add_param(&mut self, key: String, value: String) -> &mut HashBuilder {
        self.parameters.insert(key.clone(), value.clone());
        self
    }
}

#[cfg(feature = "cbindings")]
mod cbindings {
    use super::{HashBuilder, ErrorCode, PasswordStorageStandard, Normalization, Algorithm, LengthCalculationMethod, std_nist, std_default};
    use std::ffi::CStr;
    use libc;
    use std;

    macro_rules! get_cfg {
        ($cfg: ident, $ret: expr) => {{
            match $cfg.is_null() {
                false => unsafe { & *$cfg },
                true => {
                    return $ret;
                },
            }
        }};
    }

    macro_rules! get_cfg_mut {
        ($cfg: ident, $ret: expr) => {{
            match $cfg.is_null() {
                false => unsafe { &mut *$cfg },
                true => {
                    return $ret;
                },
            }
        }};
    }

    macro_rules! get_string {
        ($ptr: ident) => {{
            unsafe {
                String::from_utf8(CStr::from_ptr($ptr).to_bytes().to_vec()).unwrap()
            }
        }};
    }

    /// [C binding] Password hasher configuration storage
    #[repr(C)]
    pub struct PassCfg {
        min_len: libc::size_t,
        max_len: libc::size_t,
        salt_len: libc::size_t,
        algorithm: Algorithm,
        length_calculation: LengthCalculationMethod,
        normalization: Normalization,
        standard: PasswordStorageStandard,
    }

    #[no_mangle]
    pub extern "C" fn libreauth_pass_init(cfg: *mut PassCfg) -> ErrorCode {
        libreauth_pass_init_std(cfg, PasswordStorageStandard::NoStandard)
    }

    #[no_mangle]
    pub extern "C" fn libreauth_pass_init_std(cfg: *mut PassCfg, std: PasswordStorageStandard) -> ErrorCode {
        match cfg.is_null() {
            false => {
                let c: &mut PassCfg = unsafe { &mut *cfg };
                match std {
                    PasswordStorageStandard::NoStandard => {
                        c.min_len = std_default::DEFAULT_PASSWORD_MIN_LEN;
                        c.max_len = std_default::DEFAULT_PASSWORD_MAX_LEN;
                        c.salt_len = std_default::DEFAULT_SALT_LEN;
                        c.algorithm = std_default::DEFAULT_ALGORITHM;
                        c.length_calculation = std_default::DEFAULT_LENGTH_CALCULATION;
                        c.normalization = std_default::DEFAULT_NORMALIZATION;
                        c.standard = std;
                    },
                    PasswordStorageStandard::Nist80063b => {
                        c.min_len = std_nist::DEFAULT_PASSWORD_MIN_LEN;
                        c.max_len = std_nist::DEFAULT_PASSWORD_MAX_LEN;
                        c.salt_len = std_nist::DEFAULT_SALT_LEN;
                        c.algorithm = std_nist::DEFAULT_ALGORITHM;
                        c.length_calculation = std_nist::DEFAULT_LENGTH_CALCULATION;
                        c.normalization = std_nist::DEFAULT_NORMALIZATION;
                        c.standard = std;
                    },
                };
                ErrorCode::Success
            },
            true => ErrorCode::NullPtr,
        }
    }

    #[no_mangle]
    pub extern "C" fn libreauth_pass_init_from_phc(cfg: *mut PassCfg, phc: *const libc::c_char) -> ErrorCode {
        let c: &mut PassCfg = get_cfg_mut!(cfg, ErrorCode::NullPtr);
        let p = get_string!(phc);
        let checker = match HashBuilder::from_phc(p) {
            Ok(ch) => ch,
            Err(e) => {
                return e;
            },
        };
        c.min_len = checker.min_len;
        c.max_len = checker.max_len;
        c.salt_len = checker.salt_len;
        c.algorithm = checker.algorithm;
        c.length_calculation = checker.length_calculation;
        c.normalization = checker.normalization;
        c.standard = PasswordStorageStandard::NoStandard;
        ErrorCode::Success
    }

    #[no_mangle]
    pub extern "C" fn libreauth_pass_hash(cfg: *const PassCfg, pass: *const libc::c_char, dest: *mut libc::uint8_t, dest_len: libc::size_t) -> ErrorCode {
        let c: &PassCfg = get_cfg!(cfg, ErrorCode::NullPtr);
        let password = get_string!(pass);
        if dest.is_null() {
            return ErrorCode::NullPtr;
        }
        let buff = unsafe { std::slice::from_raw_parts_mut(dest, dest_len) };
        let hasher = match HashBuilder::new()
            .min_len(c.min_len)
            .max_len(c.max_len)
            .salt_len(c.salt_len)
            .algorithm(c.algorithm)
            .length_calculation(c.length_calculation)
            .normalization(c.normalization)
            .finalize() {
            Ok(ch) => ch,
            Err(e) => {
                return e;
            }
        };
        match hasher.hash(&password) {
            Ok(h) => {
                let b = h.into_bytes();
                let len = b.len();
                if len >= dest_len {
                    return ErrorCode::NotEnoughSpace;
                }
                for i in 0..len {
                    buff[i] = b[i];
                }
                buff[len] = 0;
                ErrorCode::Success
            },
            Err(e) => e,
        }
    }

    #[no_mangle]
    pub extern "C" fn libreauth_pass_is_valid(pass: *const libc::c_char, reference: *const libc::c_char) -> libc::int32_t {
        let p = get_string!(pass);
        let r = get_string!(reference);
        let checker = match HashBuilder::from_phc(r) {
            Ok(ch) => ch,
            Err(_) => {
                return 0;
            },
        };
        match checker.is_valid(&p) {
            true => 1,
            false => 0,
        }
    }
}

#[cfg(feature = "cbindings")]
pub use self::cbindings::libreauth_pass_init;
#[cfg(feature = "cbindings")]
pub use self::cbindings::libreauth_pass_init_std;
#[cfg(feature = "cbindings")]
pub use self::cbindings::libreauth_pass_init_from_phc;
#[cfg(feature = "cbindings")]
pub use self::cbindings::libreauth_pass_hash;
#[cfg(feature = "cbindings")]
pub use self::cbindings::libreauth_pass_is_valid;

#[cfg(test)]
mod tests {
    use super::{HashBuilder, PasswordStorageStandard, Normalization, Algorithm, LengthCalculationMethod, std_default, std_nist};

    #[test]
    fn test_default_hashbuilder() {
        let hb = HashBuilder::new();
        assert_eq!(hb.min_len, std_default::DEFAULT_PASSWORD_MIN_LEN);
        assert_eq!(hb.max_len, std_default::DEFAULT_PASSWORD_MAX_LEN);
        assert_eq!(hb.ref_salt, None);
        assert_eq!(hb.ref_hash, None);
        match hb.standard {
            PasswordStorageStandard::NoStandard => assert!(true),
            _ => assert!(false),
        }
        match hb.normalization {
            Normalization::Nfkc => assert!(true),
            _ => assert!(false),
        }
        match hb.algorithm {
            Algorithm::Argon2 => assert!(true),
            _ => assert!(false),
        }
    }

    #[test]
    fn test_nist_hashbuilder() {
        let hb = HashBuilder::new_std(PasswordStorageStandard::Nist80063b);
        assert_eq!(hb.min_len, std_nist::DEFAULT_PASSWORD_MIN_LEN);
        assert_eq!(hb.max_len, std_nist::DEFAULT_PASSWORD_MAX_LEN);
        assert_eq!(hb.ref_salt, None);
        assert_eq!(hb.ref_hash, None);
        match hb.length_calculation {
            std_nist::DEFAULT_LENGTH_CALCULATION => assert!(true),
            _ => assert!(false),
        };
        match hb.standard {
            PasswordStorageStandard::Nist80063b => assert!(true),
            _ => assert!(false),
        }
        match hb.normalization {
            Normalization::Nfkc => assert!(true),
            _ => assert!(false),
        }
        match hb.algorithm {
            Algorithm::Pbkdf2 => assert!(true),
            _ => assert!(false),
        }
    }

    #[test]
    fn test_params() {
        let mut b = HashBuilder::new_std(PasswordStorageStandard::Nist80063b);
        let hb = b.min_len(42)
            .max_len(256)
            .length_calculation(LengthCalculationMethod::Characters)
            .normalization(Normalization::Nfkd)
            .algorithm(Algorithm::Pbkdf2)
            .add_param("iter".to_string(), "80000".to_string())
            .add_param("hash".to_string(), "sha512t256".to_string());
        assert_eq!(hb.min_len, 42);
        assert_eq!(hb.max_len, 256);
        assert_eq!(hb.ref_salt, None);
        assert_eq!(hb.ref_hash, None);
        match hb.length_calculation {
            LengthCalculationMethod::Characters => assert!(true),
            _ => assert!(false),
        };
        match hb.standard {
            PasswordStorageStandard::Nist80063b => assert!(true),
            _ => assert!(false),
        }
        match hb.normalization {
            Normalization::Nfkd => assert!(true),
            _ => assert!(false),
        }
        match hb.algorithm {
            Algorithm::Pbkdf2 => assert!(true),
            _ => assert!(false),
        }
        match hb.parameters.get("hash") {
            Some(h) => match h.as_str() {
                "sha512t256" => assert!(true),
                _ => assert!(false),
            },
            None => assert!(false),
        }
        match hb.parameters.get("iter") {
            Some(i) => match i.as_str() {
                "80000" => assert!(true),
                _ => assert!(false),
            },
            None => assert!(false),
        }
    }

    #[test]
    fn test_nfkc() {
        let s1 = String::from_utf8(vec![116, 101, 115, 116, 32, 110, 102, 107, 100, 32, 195, 164, 32, 80, 32, 32, 204, 136, 97]).unwrap(); // "test nfkd ä P  ̈a"
        let s2 = String::from_utf8(vec![116, 101, 115, 116, 32, 110, 102, 107, 100, 32, 195, 164, 32, 80, 32, 32, 204, 136, 98]).unwrap();
        let s3 = String::from_utf8(vec![116, 101, 115, 116, 32, 110, 102, 107, 100, 32, 97, 204, 136, 32, 80, 32, 32, 204, 136, 97]).unwrap(); // "test nfkd ä P  ̈a"
        let s4 = String::from_utf8(vec![116, 101, 115, 116, 32, 110, 102, 107, 100, 32, 97, 204, 136, 32, 80, 32, 32, 204, 136, 98]).unwrap();
        let hasher = HashBuilder::new().normalization(Normalization::Nfkc).finalize().unwrap();
        let stored_password = hasher.hash(&s1).unwrap();
        let checker = HashBuilder::from_phc(stored_password).unwrap();
        assert!(checker.is_valid(&s1));
        assert!(! checker.is_valid(&s2));
        assert!(checker.is_valid(&s3));
        assert!(! checker.is_valid(&s4));
    }

    #[test]
    fn test_nfkd() {
        let s1 = String::from_utf8(vec![116, 101, 115, 116, 32, 110, 102, 107, 100, 32, 195, 164, 32, 80, 32, 32, 204, 136, 97]).unwrap(); // "test nfkd ä P  ̈a"
        let s2 = String::from_utf8(vec![116, 101, 115, 116, 32, 110, 102, 107, 100, 32, 195, 164, 32, 80, 32, 32, 204, 136, 98]).unwrap();
        let s3 = String::from_utf8(vec![116, 101, 115, 116, 32, 110, 102, 107, 100, 32, 97, 204, 136, 32, 80, 32, 32, 204, 136, 97]).unwrap(); // "test nfkd ä P  ̈a"
        let s4 = String::from_utf8(vec![116, 101, 115, 116, 32, 110, 102, 107, 100, 32, 97, 204, 136, 32, 80, 32, 32, 204, 136, 98]).unwrap();
        let hasher = HashBuilder::new().normalization(Normalization::Nfkd).finalize().unwrap();
        let stored_password = hasher.hash(&s1).unwrap();
        let checker = HashBuilder::from_phc(stored_password).unwrap();
        assert!(checker.is_valid(&s1));
        assert!(! checker.is_valid(&s2));
        assert!(checker.is_valid(&s3));
        assert!(! checker.is_valid(&s4));
    }

    #[test]
    fn test_no_normalize() {
        let s1 = String::from_utf8(vec![116, 101, 115, 116, 32, 110, 102, 107, 100, 32, 195, 164, 32, 80, 32, 32, 204, 136, 97]).unwrap(); // "test nfkd ä P  ̈a"
        let s2 = String::from_utf8(vec![116, 101, 115, 116, 32, 110, 102, 107, 100, 32, 195, 164, 32, 80, 32, 32, 204, 136, 98]).unwrap();
        let s3 = String::from_utf8(vec![116, 101, 115, 116, 32, 110, 102, 107, 100, 32, 97, 204, 136, 32, 80, 32, 32, 204, 136, 97]).unwrap(); // "test nfkd ä P  ̈a"
        let s4 = String::from_utf8(vec![116, 101, 115, 116, 32, 110, 102, 107, 100, 32, 97, 204, 136, 32, 80, 32, 32, 204, 136, 98]).unwrap();
        let hasher = HashBuilder::new().normalization(Normalization::None).finalize().unwrap();
        let stored_password = hasher.hash(&s1).unwrap();
        let checker = HashBuilder::from_phc(stored_password).unwrap();
        assert!(checker.is_valid(&s1));
        assert!(! checker.is_valid(&s2));
        assert!(! checker.is_valid(&s3));
        assert!(! checker.is_valid(&s4));
    }

    #[test]
    #[should_panic]
    fn test_nist_invalid_min_len() {
        HashBuilder::new_std(PasswordStorageStandard::Nist80063b).min_len(7).finalize().unwrap();
    }

    #[test]
    #[should_panic]
    fn test_nist_invalid_max_len() {
        HashBuilder::new_std(PasswordStorageStandard::Nist80063b).max_len(63).finalize().unwrap();
    }

    #[test]
    #[should_panic]
    fn test_nist_invalid_len_calc() {
        HashBuilder::new_std(PasswordStorageStandard::Nist80063b).length_calculation(LengthCalculationMethod::Bytes).finalize().unwrap();
    }

    #[test]
    #[should_panic]
    fn test_nist_invalid_normalization_nfc() {
        HashBuilder::new_std(PasswordStorageStandard::Nist80063b).normalization(Normalization::Nfc).finalize().unwrap();
    }

    #[test]
    #[should_panic]
    fn test_nist_invalid_normalization_nfd() {
        HashBuilder::new_std(PasswordStorageStandard::Nist80063b).normalization(Normalization::Nfd).finalize().unwrap();
    }

    #[test]
    #[should_panic]
    fn test_nist_invalid_algorithm() {
        HashBuilder::new_std(PasswordStorageStandard::Nist80063b).algorithm(Algorithm::Argon2).finalize().unwrap();
    }

    #[test]
    #[should_panic]
    fn test_nist_invalid_salt_len() {
        HashBuilder::new_std(PasswordStorageStandard::Nist80063b).salt_len(3).finalize().unwrap();
    }

    #[test]
    #[should_panic]
    fn test_nist_invalid_iter() {
        HashBuilder::new_std(PasswordStorageStandard::Nist80063b).algorithm(Algorithm::Pbkdf2).add_param("iter".to_string(), "8000".to_string()).finalize().unwrap();
    }
}
