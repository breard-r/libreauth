//!
//! [![Build Status](https://api.travis-ci.org/breard-r/libreauth.svg?branch=master)](https://travis-ci.org/breard-r/libreauth)
//! [![LibreAuth on crates.io](https://img.shields.io/crates/v/libreauth.svg)](https://crates.io/crates/libreauth)
//! [![LibreAuth on docs.rs](https://docs.rs/libreauth/badge.svg)](https://docs.rs/libreauth/)
//!
//! LibreAuth is a collection of tools for user authentication.
//!
//!

pub mod key;
pub mod oath;
pub mod pass;

#[cfg(feature = "cbindings")]
extern crate libc;
