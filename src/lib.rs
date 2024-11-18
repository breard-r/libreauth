//!
//! [![Build Status](https://github.com/breard-r/libreauth/actions/workflows/ci.yml/badge.svg)](https://github.com/breard-r/libreauth/actions/workflows/ci.yml)
//! [![LibreAuth on crates.io](https://img.shields.io/crates/v/libreauth.svg)](https://crates.io/crates/libreauth)
//! [![LibreAuth on docs.rs](https://docs.rs/libreauth/badge.svg)](https://docs.rs/libreauth/)
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
