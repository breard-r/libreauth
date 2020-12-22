# LibreAuth

[![Build Status](https://api.travis-ci.org/breard-r/libreauth.svg?branch=main)](https://travis-ci.org/breard-r/libreauth)
[![LibreAuth on crates.io](https://img.shields.io/crates/v/libreauth.svg)](https://crates.io/crates/libreauth)
[![LibreAuth on docs.rs](https://docs.rs/libreauth/badge.svg)](https://docs.rs/libreauth/)
[![License: CeCILL-C](https://img.shields.io/badge/license-CeCILL--C-green.svg)](http://cecill.info/licences/Licence_CeCILL-C_V1-en.html)
[![License: CeCILL-2.1](https://img.shields.io/badge/license-CeCILL%202.1-blue.svg)](http://cecill.info/licences/Licence_CeCILL_V2.1-en.html)


LibreAuth is a collection of tools for user authentication.


## Features

- Password / passphrase authentication
  - [x] no character-set limitation
  - [x] reasonable lenth limit ([security vs. DOS](http://arstechnica.com/security/2013/09/long-passwords-are-good-but-too-much-length-can-be-bad-for-security/))
  - [x] strong, evolutive and retro-compatible password hashing functions
  - [x] NFKC normalization for Unicode passwords
  - [x] optional NIST Special Publication 800-63B compatibility
  - [x] optional additional HMAC with an external salt before or after hashing the password
- HOTP - HMAC-based One-time Password Algorithm ([OATH](http://www.openauthentication.org/) - [RFC 4226](https://tools.ietf.org/html/rfc4226))
  - [x] the key can be passed as bytes, an ASCII string, an hexadicimal string, a base32 string or a base64 string
  - [x] customizable counter
  - [x] customizable hash function (sha1, full sha2 family, sha3/Keccak fixed-size families)
  - [x] customizable output length
  - [x] customizable output alphabet
- TOTP - Time-based One-time Password Algorithm ([OATH](http://www.openauthentication.org/) - [RFC 6238](https://tools.ietf.org/html/rfc6238))
  - [x] the key can be passed as bytes, an ASCII string, an hexadicimal string, a base32 string or a base64 string
  - [x] customizable timestamp
  - [x] customizable period
  - [x] customizable initial time (T0)
  - [x] customizable hash function (sha1, full sha2 family, sha3/Keccak fixed-size families)
  - [x] customizable output length
  - [x] customizable output alphabet
  - [x] customizable positive and negative period tolerance
- Random key generation
  - [x] uses the platform's secure entropy source
  - [x] customizable size
  - [x] customizable output format (Vec<u8>, hexadecimal string, base32 string, base64 string)
- ~~WebAuthn - Web Authentication: An API for accessing Public Key Credentials Level 1~~ ([W3C](https://www.w3.org/TR/webauthn/)) :warning: Not started yet
  - [ ] authenticator API
  - [ ] server API


## Status

The project itself is still in development and therefore should not be used in production before version 1.0.0. Below is the list of features that will be present in the first stable version and their individual status.

- OATH HOTP/TOTP: almost ready!
  * :white_check_mark: lot of features
  * :white_check_mark: stable API
  * :warning: lack of peer review
- Password / passphrase authentication: not ready yet.
  * :white_check_mark: sane defaults
  * :bangbang: almost stable API
  * :warning: lack of peer review
- Random key generation: almost ready!
  * :warning: almost stable API
  * :warning: lack of peer review


## Using within a Rust project

You can find LibreAuth on [crates.io](https://crates.io/crates/libreauth) and include it in your `Cargo.toml`:

```toml
libreauth = "*"
```

Modules can be cherry-picked using `default-features = false` and then using only the features you want.

```toml
[dependencies.libreauth]
version = "*"
default-features = false
features = ["key", "oath", "pass"]
```


## Using outside Rust

In order to build LibreAuth, you will need the [Rust](https://www.rust-lang.org/) compiler and its package manager, Cargo. The minimal required Rust version is 1.41, although it is recommended to use the latest stable one.

```ShellSession
$ make
$ make install
```


## Quick examples


### Rust

More examples are available in the [documentation](https://docs.rs/libreauth/).

```rust
use libreauth::oath::TOTPBuilder;

fn main() {
    let key = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ".to_string();
    let code = TOTPBuilder::new()
        .base32_key(&key)
        .finalize()
        .unwrap()
        .generate();
    assert_eq!(code.len(), 6);
}
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
  cfg.key_len = strlen(key);
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


## License

LibreAuth is a free software available either under the CeCILL-C or the CeCILL 2.1 license. For a quick summary of those licenses, you can read the [frequently asked questions](http://cecill.info/faq.en.html) on the licenses' website. A full copy of those licenses are available in this repository both in english and french.

While the CeCILL 2.1 is the original LibreAuth license, future versions may be published only under the CeCILL-C license. This change occurs because CeCILL 2.1 isn't really suited for a library since it is a "viral" license.
