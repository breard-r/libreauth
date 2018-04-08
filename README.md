# LibreAuth

[![Build Status](https://api.travis-ci.org/breard-r/libreauth.svg?branch=master)](https://travis-ci.org/breard-r/libreauth)
[![LibreAuth on crates.io](https://img.shields.io/crates/v/libreauth.svg)](https://crates.io/crates/libreauth)
[![LibreAuth on docs.rs](https://docs.rs/libreauth/badge.svg)](https://docs.rs/libreauth/)


LibreAuth is a collection of tools for user authentication.


## Features

- Password / passphrase authentication
  - [x] no character-set limitation
  - [x] reasonable lenth limit ([security vs. DOS](http://arstechnica.com/security/2013/09/long-passwords-are-good-but-too-much-length-can-be-bad-for-security/))
  - [x] strong, evolutive and retro-compatible password hashing functions
  - [x] optional NIST Special Publication 800-63B compatibility
- HOTP - HMAC-based One-time Password Algorithm ([OATH](http://www.openauthentication.org/) - [RFC 4226](https://tools.ietf.org/html/rfc4226))
  - [x] the key can be passed as bytes, an ASCII string, an hexadicimal string, a base32 string or a base64 string
  - [x] customizable counter
  - [x] customizable hash function (sha1, sha256, sha512)
  - [x] customizable output length
  - [x] customizable output alphabet
- TOTP - Time-based One-time Password Algorithm ([OATH](http://www.openauthentication.org/) - [RFC 6238](https://tools.ietf.org/html/rfc6238))
  - [x] the key can be passed as bytes, an ASCII string, an hexadicimal string, a base32 string or a base64 string
  - [x] customizable timestamp
  - [x] customizable period
  - [x] customizable initial time (T0)
  - [x] customizable hash function (sha1, sha256, sha512)
  - [x] customizable output length
  - [x] customizable output alphabet
  - [x] customizable positive and negative period tolerance
- Random key generation
  - [x] uses the platform's secure entropy source
  - [x] customizable size
  - [x] customizable output format (Vec<u8>, hexadicimal string, base32 string, base64 string)
- ~~U2F - Universal 2nd Factor~~ ([FIDO Alliance](https://fidoalliance.org/specifications/download/)) :warning: Not started
  - [ ] virtual device API
  - [ ] client API
  - [ ] server API


## Using within a Rust project

You can find LibreAuth on [crates.io](https://crates.io/crates/libreauth) and include it in your `Cargo.toml`:

```toml
libreauth = "*"
```


## Using outside Rust

In order to build LibreAuth, you will need both the [rust compiler](https://github.com/rust-lang/rust) and [cargo](https://github.com/rust-lang/cargo).

```ShellSession
$ git clone https://github.com/breard-r/libreauth.git
$ cd libreauth
$ make
$ make install prefix=/usr
```


## Quick examples


### Rust

More examples are available in the [documentation](https://docs.rs/libreauth/).

```rust
extern crate libreauth;
use libreauth::oath::TOTPBuilder;

let key = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ".to_string();
let code = TOTPBuilder::new()
    .base32_key(&key)
    .finalize()
    .unwrap()
    .generate();
assert_eq!(code.len(), 6);
```

### C

```C
#include <stdio.h>
#include <libreauth.h>

int main(void) {
  struct libreauth_totp_cfg cfg;
  char   code[7], key[] = "12345678901234567890";

  if (libreauth_totp_init(&cfg) != LIBREAUTH_OTP_SUCCESS) {
    return 1;
  }
  cfg.key = key;
  cfg.key_len = sizeof(key);
  if (libreauth_totp_generate(&cfg, code) != LIBREAUTH_OTP_SUCCESS) {
    return 2;
  }

  printf("%s\n", code);

  return 0;
}
```

```ShellSession
$ cc -o totp totp.c -llibreauth
$ ./totp
848085
```

### Python

Python bindings are available. See the [Python LibreAuth](https://github.com/breard-r/py-libreauth) project.
