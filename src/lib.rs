//!
//! [![Build Status](https://api.travis-ci.org/breard-r/libreauth.svg?branch=master)](https://travis-ci.org/breard-r/libreauth)
//! [![LibreAuth on crates.io](https://img.shields.io/crates/v/libreauth.svg)](https://crates.io/crates/libreauth)
//! [![LibreAuth on docs.rs](https://docs.rs/libreauth/badge.svg)](https://docs.rs/libreauth/)
//!
//! LibreAuth is a collection of tools for user authentication.
//!
//!

#[cfg(feature = "key")]
pub mod key;
#[cfg(feature = "oath")]
pub mod oath;
#[cfg(feature = "pass")]
pub mod pass;
