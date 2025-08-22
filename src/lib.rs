//!
//! [![LibreAuth on crates.io](https://img.shields.io/crates/v/libreauth.svg)](https://crates.io/crates/libreauth)
//! [![LibreAuth on docs.rs](https://docs.rs/libreauth/badge.svg)](https://docs.rs/libreauth/)
//! [![License: CeCILL-C](https://img.shields.io/badge/license-CeCILL--C-green.svg)](http://cecill.info/licences/Licence_CeCILL-C_V1-en.html)
//! [![License: CeCILL-2.1](https://img.shields.io/badge/license-CeCILL%202.1-blue.svg)](http://cecill.info/licences/Licence_CeCILL_V2.1-en.html)
//! [![REUSE status](https://api.reuse.software/badge/codeberg.org/rbd/libreauth)](https://api.reuse.software/info/codeberg.org/rbd/libreauth)
//!
//! LibreAuth is a collection of tools for user authentication.
//!
//!

#[cfg(feature = "cbindings")]
pub(crate) mod c_helpers;
#[cfg(feature = "hash")]
pub mod hash;
#[cfg(feature = "key")]
pub mod key;
#[cfg(feature = "oath")]
pub mod oath;
#[cfg(feature = "pass")]
pub mod pass;
