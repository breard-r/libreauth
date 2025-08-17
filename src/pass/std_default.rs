use super::{Algorithm, LengthCalculationMethod, Normalization};
use crate::hash::HashFunction;

pub const DEFAULT_NORMALIZATION: Normalization = Normalization::Nfkc;
pub const DEFAULT_PASSWORD_MIN_LEN: usize = 8;
pub const DEFAULT_PASSWORD_MAX_LEN: usize = 128;
pub const DEFAULT_ALGORITHM: Algorithm = Algorithm::Argon2;
pub const DEFAULT_LENGTH_CALCULATION: LengthCalculationMethod = LengthCalculationMethod::CodePoints;
pub const DEFAULT_SALT_LEN: usize = 16; // In bytes
pub const DEFAULT_XHMAC_ALGORITHM: HashFunction = HashFunction::Sha512;
