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
//! This module provides C-bindings and therefore should not be used within Rust projects.
//!

use super::{HashFunction, HOTPBuilder, TOTPBuilder};
use libc;
use time;
use std;


#[repr(C)]
pub struct HOTPcfg {
    key: *const u8,
    key_len: libc::size_t,
    counter: libc::uint64_t,
    output_len: libc::size_t,
    output_base: *const u8,
    output_base_len: libc::size_t,
    hash_function: HashFunction,
}

#[repr(C)]
pub struct TOTPcfg {
    key: *const u8,
    key_len: libc::size_t,
    timestamp: libc::int64_t,
    period: libc::uint32_t,
    initial_time: libc::uint64_t,
    output_len: libc::size_t,
    output_base: *const u8,
    output_base_len: libc::size_t,
    hash_function: HashFunction,
}

macro_rules! otp_init {
    ($t:ty, $cfg:ident, $($field:ident, $value:expr), *) => {
        match $cfg.is_null() {
            false => {
                let c: &mut $t = unsafe { &mut *$cfg };
                c.key = std::ptr::null();
                c.key_len = 0;
                c.output_len = 6;
                c.output_base = std::ptr::null();
                c.output_base_len = 0;
                c.hash_function = HashFunction::Sha1;
                $(
                    c.$field = $value;
                )*
                0
            }
            true => 1,
        }
    }
}

macro_rules! otp_generate {
    ($t:ty, $builder:ident, $cfg:ident, $code:ident, $($field:ident), *) => {{
        if $cfg.is_null() || $code.is_null() {
            return 1
        }
        let cfg: &$t = unsafe { &*$cfg };
        if cfg.key.is_null() || cfg.key_len == 0 {
            return 2
        }
        let output_base: Vec<u8> = match cfg.output_base.is_null() {
            true => "0123456789".to_string().into_bytes(),
            false => unsafe { std::slice::from_raw_parts(cfg.output_base, cfg.output_base_len as usize).to_owned() },
        };
        let mut code = unsafe { std::slice::from_raw_parts_mut($code, cfg.output_len as usize + 1) } ;
        let key: Vec<u8> = unsafe { std::slice::from_raw_parts(cfg.key, cfg.key_len as usize).to_owned() };

        let otp = $builder
            .key(&key)
            .output_len(cfg.output_len as usize)
            .output_base(&output_base)
            .hash_function(cfg.hash_function)
            $(
                .$field(cfg.$field)
             )*
            .finalize();
        match otp {
            Ok(otp) => {
                let raw_code = otp.generate().into_bytes();
                let len: usize = cfg.output_len as usize;
                for i in 0..len {
                    code[i] = raw_code[i];
                }
                code[len] = 0;
            },
            Err(_) => return 3,
        };
    }}
}

#[no_mangle]
pub extern fn r2fa_hotp_init(cfg: *mut HOTPcfg) -> libc::int32_t {
    otp_init!(HOTPcfg, cfg,
        counter, 0
    )
}

#[no_mangle]
pub extern fn r2fa_hotp_generate(cfg: *const HOTPcfg, code: *mut u8) -> libc::int32_t {
    let mut builder = HOTPBuilder::new();
    otp_generate!(HOTPcfg, builder, cfg, code,
        counter
    );
    0
}

#[no_mangle]
pub extern fn r2fa_totp_init(cfg: *mut TOTPcfg) -> libc::int32_t {
    otp_init!(TOTPcfg, cfg,
        timestamp, time::now().to_timespec().sec,
        period, 30,
        initial_time, 0
    )
}

#[no_mangle]
pub extern fn r2fa_totp_generate(cfg: *const TOTPcfg, code: *mut u8) -> libc::int32_t {
    let mut builder = TOTPBuilder::new();
    otp_generate!(TOTPcfg, builder, cfg, code,
        timestamp,
        period,
        initial_time
    );
    0
}
