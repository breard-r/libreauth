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


## Using within a Rust project

You can find R2FA on [crates.io](https://crates.io/crates/r2fa) and include it in your `Cargo.toml`:

```toml
r2fa = "*"
```


## Using outside Rust

In order to build R2FA, you will need both the [rust compiler](https://github.com/rust-lang/rust) and [cargo](https://github.com/rust-lang/cargo).

```ShellSession
$ git clone https://github.com/breard-r/r2fa.git
$ cd r2fa
$ make
$ make install prefix=/usr
```


## Quick examples


### Rust

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

### C

```C
#include <stdio.h>
#include <r2fa.h>

int main(void) {
  struct r2fa_totp_cfg cfg;
  char   code[7], key[] = "12345678901234567890";

  if (r2fa_totp_init(&cfg) != R2FA_OTP_SUCCESS) {
    return 1;
  }
  cfg.key = key;
  cfg.key_len = sizeof(key);
  if (r2fa_totp_generate(&cfg, code) != R2FA_OTP_SUCCESS) {
    return 2;
  }

  printf("%s\n", code);

  return 0;
}
```

```ShellSession
$ cc -o totp totp.c -lr2fa
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
    lib_path = find_library('r2fa') or 'target/release/libr2fa.so'
    lib = cdll.LoadLibrary(lib_path)
    cfg = TOTPcfg()
    if lib.r2fa_totp_init(byref(cfg)) != 0:
        return
    cfg.key_len = len(key)
    cfg.key = c_char_p(key)
    code = create_string_buffer(b'\000' * cfg.output_len)
    if lib.r2fa_totp_generate(byref(cfg), code) != 0:
        return
    return str(code.value, encoding="utf-8")

if __name__ == '__main__':
    code = get_totp()
    print('{}'.format(code))
```
