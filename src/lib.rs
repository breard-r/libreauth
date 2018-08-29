//!
//! [![Build Status](https://api.travis-ci.org/breard-r/libreauth.svg?branch=master)](https://travis-ci.org/breard-r/libreauth)
//! [![LibreAuth on crates.io](https://img.shields.io/crates/v/libreauth.svg)](https://crates.io/crates/libreauth)
//! [![LibreAuth on docs.rs](https://docs.rs/libreauth/badge.svg)](https://docs.rs/libreauth/)
//!
//! LibreAuth is a collection of tools for user authentication.
//!
//!

extern crate argon2;
extern crate hmac;
extern crate pbkdf2;
extern crate sha1;
extern crate sha2;
extern crate sha3;

extern crate base32;
extern crate base64;
extern crate hex;
extern crate rand;
extern crate time;
extern crate unicode_normalization;
#[macro_use]
extern crate nom;

pub mod key;
pub mod oath;
pub mod pass;

#[cfg(feature = "cbindings")]
extern crate libc;
