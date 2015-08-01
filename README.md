# R2FA

[![Build Status](https://api.travis-ci.org/breard-r/r2fa.svg?branch=master)](https://travis-ci.org/breard-r/r2fa)
[![R2FA on crates.io](https://img.shields.io/crates/v/r2fa.svg)](https://crates.io/crates/r2fa)
[![R2FA on GitHub](https://img.shields.io/github/license/breard-r/r2fa.svg)](https://github.com/breard-r/r2fa)

Rust Two-Factor Authentication (R2FA) is a collection of tools for two-factor authentication.


## Features

- [x] HOTP - HMAC-based One-time Password Algorithm ([RFC 4226](https://tools.ietf.org/html/rfc4226))
  - [x] the key can be passed as bytes, an ASCII string, an hexadicimal string or a base32 string
  - [x] customizable counter
  - [x] customizable hash function (sha1, sha256, sha512)
  - [x] customizable output length
  - [x] customizable output alphabet
- [x] TOTP - Time-based One-time Password Algorithm ([RFC 6238](https://tools.ietf.org/html/rfc6238))
  - [x] the key can be passed as bytes, an ASCII string, an hexadicimal string or a base32 string
  - [x] customizable timestamp
  - [x] customizable period
  - [x] customizable initial time (T0)
  - [x] customizable hash function (sha1, sha256, sha512)
  - [x] customizable output length
  - [x] customizable output alphabet
- [ ] U2F - Universal 2nd Factor ([FIDO Alliance](https://fidoalliance.org/specifications/download/))


## Installation

You can find R2FA on [crates.io](https://crates.io/crates/r2fa) and include it in your `Cargo.toml`:

```toml
r2fa = "^0.1.0"
```


## Quick example

More examples are available in the [documentation](https://what.tf/r2fa/).

```rust
extern crate r2fa;
use r2fa::otp::TOTPBuilder;

let key = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ".to_string();
let code = TOTPBuilder::new()
    .base32_key(&key)
    .finalize()
    .unwrap()
    .generate();
assert_eq!(code.len(), 6);
```
