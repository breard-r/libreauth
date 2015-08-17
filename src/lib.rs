//
// Copyright (c) 2015 Rodolphe Breard
// 
// Permission to use, copy, modify, and/or distribute this software for any
// purpose with or without fee is hereby granted, provided that the above
// copyright notice and this permission notice appear in all copies.
// 
// THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
// WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
// MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
// ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
// WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
// ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
// OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
//

//!
//! [![Build Status](https://api.travis-ci.org/breard-r/r2fa.svg?branch=master)](https://travis-ci.org/breard-r/r2fa)
//! [![R2FA on crates.io](https://img.shields.io/crates/v/r2fa.svg)](https://crates.io/crates/r2fa)
//! [![R2FA on GitHub](https://img.shields.io/github/license/breard-r/r2fa.svg)](https://github.com/breard-r/r2fa)
//!
//! Rust Two-Factor Authentication (R2FA) is a collection of tools for two-factor authentication.
//!
//!
//! ## Features
//! - HOTP - HMAC-based One-time Password Algorithm ([RFC 4226](https://tools.ietf.org/html/rfc4226))
//!   - the key can be passed as bytes, an ASCII string, an hexadicimal string or a base32 string
//!   - customizable counter
//!   - customizable hash function (sha1, sha256, sha512)
//!   - customizable output length
//!   - customizable output alphabet
//! - TOTP - Time-based One-time Password Algorithm ([RFC 6238](https://tools.ietf.org/html/rfc6238))
//!   - the key can be passed as bytes, an ASCII string, an hexadicimal string or a base32 string
//!   - customizable timestamp
//!   - customizable period
//!   - customizable initial time (T0)
//!   - customizable hash function (sha1, sha256, sha512)
//!   - customizable output length
//!   - customizable output alphabet
//!

extern crate rustc_serialize;
extern crate base32;
extern crate crypto;
extern crate time;

pub mod oath;

#[cfg(feature = "cbindings")]
extern crate libc;
