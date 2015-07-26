# R2FA

Rust Two-Factor Authentication (R2FA) is a collection of tools for two-factor authentication.


## Features

- [x] HOTP - HMAC-based One-time Password Algorithm ([RFC 4226](https://tools.ietf.org/html/rfc4226))
  - [x] the key can be passed as bytes, an ASCII string, an hexadicimal string or a base32 string
  - [x] customizable counter
  - [x] customizable hash function (sha1, sha256, sha512)
  - [x] customizable output length (6 digits min)
- [x] TOTP - Time-based One-time Password Algorithm ([RFC 6238](https://tools.ietf.org/html/rfc6238))
  - [x] the key can be passed as bytes, an ASCII string, an hexadicimal string or a base32 string
  - [x] customizable timestamp
  - [x] customizable period
  - [x] customizable initial time (T0)
  - [x] customizable hash function (sha1, sha256, sha512)
  - [x] customizable output length (6 digits min)
- [ ] U2F - Universal 2nd Factor ([FIDO Alliance](https://fidoalliance.org/specifications/download/))


## Installation

You can find R2FA on [crates.io](https://crates.io/crates/r2fa) and include it in your `Cargo.toml`:

```toml
r2fa = "^0.1.0"
```
