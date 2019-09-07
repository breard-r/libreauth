//! Hash functions used in the library

use std::fmt;
use std::str::FromStr;

pub enum HashFunctionError {
    ImportError,
}

/// ## C interface
/// The C interface uses an enum of type `libreauth_oath_hash_function` and
/// the members has been renamed as follows:
/// <table>
///     <thead>
///         <tr>
///             <th>Rust</th>
///             <th>C</th>
///         </tr>
///     </thead>
///     <tbody>
///         <tr>
///             <td>Sha1</td>
///             <td>LIBREAUTH_HASH_SHA_1</td>
///         </tr>
///         <tr>
///             <td>Sha224</td>
///             <td>LIBREAUTH_HASH_SHA_224</td>
///         </tr>
///         <tr>
///             <td>Sha256</td>
///             <td>LIBREAUTH_HASH_SHA_256</td>
///         </tr>
///         <tr>
///             <td>Sha384</td>
///             <td>LIBREAUTH_HASH_SHA_384</td>
///         </tr>
///         <tr>
///             <td>Sha512</td>
///             <td>LIBREAUTH_HASH_SHA_512</td>
///         </tr>
///         <tr>
///             <td>Sha512Trunc224</td>
///             <td>LIBREAUTH_HASH_SHA_512_TRUNC_224</td>
///         </tr>
///         <tr>
///             <td>Sha512Trunc256</td>
///             <td>LIBREAUTH_HASH_SHA_512_TRUNC_256</td>
///         </tr>
///         <tr>
///             <td>Sha3_224</td>
///             <td>LIBREAUTH_HASH_SHA_3_224</td>
///         </tr>
///         <tr>
///             <td>Sha3_256</td>
///             <td>LIBREAUTH_HASH_SHA_3_256</td>
///         </tr>
///         <tr>
///             <td>Sha3_384</td>
///             <td>LIBREAUTH_HASH_SHA_3_384</td>
///         </tr>
///         <tr>
///             <td>Sha3_512</td>
///             <td>LIBREAUTH_HASH_SHA_3_512</td>
///         </tr>
///         <tr>
///             <td>Keccak224</td>
///             <td>LIBREAUTH_HASH_KECCAK_224</td>
///         </tr>
///         <tr>
///             <td>Keccak256</td>
///             <td>LIBREAUTH_HASH_KECCAK_256</td>
///         </tr>
///         <tr>
///             <td>Keccak384</td>
///             <td>LIBREAUTH_HASH_KECCAK_384</td>
///         </tr>
///         <tr>
///             <td>Keccak512</td>
///             <td>LIBREAUTH_HASH_KECCAK_512</td>
///         </tr>
///     </tbody>
/// </table>
#[repr(C)]
#[derive(Clone, Copy, Eq, PartialEq)]
pub enum HashFunction {
    Sha1 = 1,
    Sha224 = 2,
    Sha256 = 3,
    Sha384 = 4,
    Sha512 = 5,
    Sha512Trunc224 = 6,
    Sha512Trunc256 = 7,
    Sha3_224 = 8,
    Sha3_256 = 9,
    Sha3_384 = 10,
    Sha3_512 = 11,
    Keccak224 = 12,
    Keccak256 = 13,
    Keccak384 = 14,
    Keccak512 = 15,
}

impl fmt::Display for HashFunction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            HashFunction::Sha1 => "SHA1",
            HashFunction::Sha224 => "SHA224",
            HashFunction::Sha256 => "SHA256",
            HashFunction::Sha384 => "SHA384",
            HashFunction::Sha512 => "SHA512",
            HashFunction::Sha512Trunc224 => "SHA512-224",
            HashFunction::Sha512Trunc256 => "SHA512-256",
            HashFunction::Sha3_224 => "SHA3-224",
            HashFunction::Sha3_256 => "SHA3-256",
            HashFunction::Sha3_384 => "SHA3-384",
            HashFunction::Sha3_512 => "SHA3-512",
            HashFunction::Keccak224 => "Keccak224",
            HashFunction::Keccak256 => "Keccak256",
            HashFunction::Keccak384 => "Keccak384",
            HashFunction::Keccak512 => "Keccak512",
        };
        write!(f, "{}", s)
    }
}

impl FromStr for HashFunction {
    type Err = HashFunctionError;

    fn from_str(data: &str) -> Result<Self, Self::Err> {
        Ok(match data.to_lowercase().as_str() {
            "sha1" => HashFunction::Sha1,
            "sha224" => HashFunction::Sha224,
            "sha256" => HashFunction::Sha256,
            "sha384" => HashFunction::Sha384,
            "sha512" => HashFunction::Sha512,
            "sha512-224" | "sha512t224" => HashFunction::Sha512Trunc224,
            "sha512-256" | "sha512t256" => HashFunction::Sha512Trunc256,
            "sha3-224" => HashFunction::Sha3_224,
            "sha3-256" => HashFunction::Sha3_256,
            "sha3-384" => HashFunction::Sha3_384,
            "sha3-512" => HashFunction::Sha3_512,
            "keccak224" => HashFunction::Keccak224,
            "keccak256" => HashFunction::Keccak256,
            "keccak384" => HashFunction::Keccak384,
            "keccak512" => HashFunction::Keccak512,
            _ => {
                return Err(HashFunctionError::ImportError);
            }
        })
    }
}
