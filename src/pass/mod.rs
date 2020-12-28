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
//! <table>
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
//!             <td rowspan="7">Global parameters</td>
//!             <td>len-calc</td>
//!             <td>string: bytes | chars</td>
//!             <td>Unicode string length calculation method.</td>
//!             <td>chars</td>
//!         </tr>
//!         <tr>
//!             <td>norm</td>
//!             <td>string: nfd | nfkd | nfc | nfkc | none</td>
//!             <td>Unicode normalization.</td>
//!             <td>nfkc</td>
//!         </tr>
//!         <tr>
//!             <td>pmax</td>
//!             <td>integer</td>
//!             <td>Password maximal length.</td>
//!             <td>128</td>
//!         </tr>
//!         <tr>
//!             <td>pmin</td>
//!             <td>integer</td>
//!             <td>Password minimal length.</td>
//!             <td>8</td>
//!         </tr>
//!         <tr>
//!             <td>ver</td>
//!             <td>integer</td>
//!             <td>The password hashing version.</td>
//!             <td>Sum of the user-defined and internal version numbers.</td>
//!         </tr>
//!         <tr>
//!             <td>xhmac</td>
//!             <td>string: none | before | after</td>
//!             <td>If not none, apply an additional HMAC with an external pepper before or after hashing the password.</td>
//!             <td>none</td>
//!         </tr>
//!         <tr>
//!             <td>xhmac-alg</td>
//!             <td>string: sha1 | sha224 | sha256 | sha384 | sha512 | sha512t224 | sha512t256 | keccak224 | keccak256 | keccak384 | keccak512 | sha3-224 | sha3-256 | sha3-384 | sha3-512</td>
//!             <td>The underlying hash function to use for the HMAC.</td>
//!             <td>sha512</td>
//!         </tr>
//!         <tr>
//!             <td rowspan="4">argon2</td>
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
//!             <td>mem</td>
//!             <td>integer</td>
//!             <td>Memmory cost (2^mem kibbibytes).</td>
//!             <td>12 (4096 KiB)</td>
//!         </tr>
//!         <tr>
//!             <td>passes</td>
//!             <td>integer</td>
//!             <td>The number of block matrix iterations to perform.</td>
//!             <td>3</td>
//!         </tr>
//!         <tr>
//!             <td rowspan="2">pbkdf2</td>
//!             <td>hmac</td>
//!             <td>string: sha1 | sha224 | sha256 | sha384 | sha512 | sha512t224 | sha512t256 | keccak224 | keccak256 | keccak384 | keccak512 | sha3-224 | sha3-256 | sha3-384 | sha3-512</td>
//!             <td>The underlying hash function to use for the HMAC.</td>
//!             <td>sha512</td>
//!         </tr>
//!         <tr>
//!             <td>iter</td>
//!             <td>integer</td>
//!             <td>Number of iterations.</td>
//!             <td>45000</td>
//!         </tr>
//!     </tbody>
//! </table>
//!
//! ## Examples
//! ```rust
//! use libreauth::pass::HashBuilder;
//!
//! const PWD_SCHEME_VERSION: usize = 1;
//!
//! // Hashing a password.
//! let password = "correct horse battery staple";
//! let hasher = HashBuilder::new().version(PWD_SCHEME_VERSION).finalize().unwrap();
//! let stored_password = hasher.hash(password).unwrap();
//! // Store the result in the database.
//!
//! // Checking a password against a previously hashed one.
//! let checker = HashBuilder::from_phc(stored_password.as_str()).unwrap();
//! assert!(!checker.is_valid("bad password"));
//! assert!(checker.is_valid(password));
//! if checker.is_valid(password) && checker.needs_update(Some(PWD_SCHEME_VERSION)) {
//!   // The password hashing scheme has been updated since we stored this
//!   // password. Hence, We should hash it again and update the database.
//! }
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

pub(crate) mod argon2;
#[cfg(feature = "cbindings")]
mod cbindings;
mod error;
mod hash_builder;
mod hasher;
pub(crate) mod pbkdf2;
mod phc;
pub(crate) mod std_default;
pub(crate) mod std_nist;
#[cfg(test)]
mod tests;

#[cfg(feature = "cbindings")]
pub use self::cbindings::libreauth_pass_hash;
#[cfg(feature = "cbindings")]
pub use self::cbindings::libreauth_pass_init;
#[cfg(feature = "cbindings")]
pub use self::cbindings::libreauth_pass_init_from_phc;
#[cfg(feature = "cbindings")]
pub use self::cbindings::libreauth_pass_init_std;
#[cfg(feature = "cbindings")]
pub use self::cbindings::libreauth_pass_is_valid;
#[cfg(feature = "cbindings")]
pub use self::cbindings::PassCfg;
#[cfg(feature = "cbindings")]
pub use self::cbindings::XHMACType;
pub use error::ErrorCode;
pub use hash_builder::HashBuilder;
pub use hasher::Hasher;
use std::collections::HashMap;
use std::fmt;

const INTERNAL_VERSION: usize = 1;
const DEFAULT_USER_VERSION: usize = 0;

/// The recommended length to reserve for password hash storage.
///
/// Most applications will store passwords hash within a database which requires a fixed space.
/// This value represents the size such a fixed reserved space should be. It is intentionally
/// higher than needed in order to accept future improvements.
///
/// ## C interface
/// The C interface refers at this constant as `LIBREAUTH_PASSWORD_STORAGE_LEN`.
pub const PASSWORD_STORAGE_LEN: usize = 512;

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

#[derive(Clone, Eq, PartialEq, Debug)]
pub(crate) enum XHMAC {
    Before(Vec<u8>),
    After(Vec<u8>),
    None,
}

impl fmt::Display for XHMAC {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            XHMAC::Before(_) => "before",
            XHMAC::After(_) => "after",
            XHMAC::None => "none",
        };
        write!(f, "{}", s)
    }
}

impl XHMAC {
    pub(crate) fn is_none(&self) -> bool {
        match *self {
            XHMAC::None => true,
            _ => false,
        }
    }

    pub(crate) fn is_some(&self) -> bool {
        !self.is_none()
    }
}

trait HashingFunction {
    fn get_id(&self) -> String;
    fn get_parameters(&self) -> HashMap<String, String>;
    fn set_parameter(&mut self, name: &str, value: &str) -> Result<(), ErrorCode>;
    fn get_salt(&self) -> Option<Vec<u8>>;
    fn set_salt(&mut self, salt: Vec<u8>) -> Result<(), ErrorCode>;
    fn set_salt_len(&mut self, salt_len: usize) -> Result<(), ErrorCode>;
    fn set_normalization(&mut self, norm: Normalization) -> Result<(), ErrorCode>;
    fn hash(&self, input: &[u8]) -> Vec<u8>;
}

struct HashedDuo {
    raw: Vec<u8>,
    formated: String,
}
