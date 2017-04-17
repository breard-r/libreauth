# LibreAuth

[![Build Status](https://api.travis-ci.org/breard-r/libreauth.svg?branch=master)](https://travis-ci.org/breard-r/libreauth)
[![LibreAuth on crates.io](https://img.shields.io/crates/v/libreauth.svg)](https://crates.io/crates/libreauth)

LibreAuth is a collection of tools for user authentication.


## Features

- Password / passphrase authentication
  - [ ] no character-set limitation
  - [ ] reasonable lenth limit ([security vs. DOS](http://arstechnica.com/security/2013/09/long-passwords-are-good-but-too-much-length-can-be-bad-for-security/))
  - [ ] strong, evolutive and retro-compatible password derivation functions
  - [ ] crypt() compatibility
- HOTP - HMAC-based One-time Password Algorithm ([OATH](http://www.openauthentication.org/) - [RFC 4226](https://tools.ietf.org/html/rfc4226))
  - [x] the key can be passed as bytes, an ASCII string, an hexadicimal string or a base32 string
  - [x] customizable counter
  - [x] customizable hash function (sha1, sha256, sha512)
  - [x] customizable output length
  - [x] customizable output alphabet
- TOTP - Time-based One-time Password Algorithm ([OATH](http://www.openauthentication.org/) - [RFC 6238](https://tools.ietf.org/html/rfc6238))
  - [x] the key can be passed as bytes, an ASCII string, an hexadicimal string or a base32 string
  - [x] customizable timestamp
  - [x] customizable period
  - [x] customizable initial time (T0)
  - [x] customizable hash function (sha1, sha256, sha512)
  - [x] customizable output length
  - [x] customizable output alphabet
  - [x] customizable positive and negative period tolerance
- YubiKey OTP ([Yubico](https://developers.yubico.com/OTP/))
  - [ ] virtual device API
  - [ ] client API
  - [ ] server API
- U2F - Universal 2nd Factor ([FIDO Alliance](https://fidoalliance.org/specifications/download/))
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

More examples are available in the [documentation](https://what.tf/libreauth/).

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

```Python
from ctypes.util import find_library
from struct import Struct
from ctypes import *

class TOTPcfg(Structure):
    _fields_ = [
        ('key', c_char_p),
        ('key_len', c_size_t),
        ('timestamp', c_longlong),
        ('period', c_uint),
        ('initial_time', c_ulonglong),
        ('output_len', c_size_t),
        ('output_base', c_char_p),
        ('output_base_len', c_size_t),
        ('hash_function', c_int),
    ]

def get_totp():
    key = b'12345678901234567890'
    lib_path = find_library('libreauth') or 'target/release/liblibreauth.so'
    lib = cdll.LoadLibrary(lib_path)
    cfg = TOTPcfg()
    if lib.libreauth_totp_init(byref(cfg)) != 0:
        return
    cfg.key_len = len(key)
    cfg.key = c_char_p(key)
    code = create_string_buffer(b'\000' * cfg.output_len)
    if lib.libreauth_totp_generate(byref(cfg), code) != 0:
        return
    return str(code.value, encoding="utf-8")

if __name__ == '__main__':
    code = get_totp()
    print('{}'.format(code))
```
