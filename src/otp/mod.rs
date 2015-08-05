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

#[repr(C)]
#[derive(Clone, Copy)]
pub enum HashFunction {
    Sha1 = 1,
    Sha256 = 2,
    Sha512 = 3,
}

macro_rules! builder_common {
    ($t:ty) => {
        /// Sets the shared secret.
        pub fn key(&mut self, key: &Vec<u8>) -> &mut $t {
            self.key = Some(key.clone());
            self
        }

        /// Sets the shared secret. This secret is passed as an ASCII string.
        pub fn ascii_key(&mut self, key: &String) -> &mut $t {
            self.key = Some(key.clone().into_bytes());
            self
        }

        /// Sets the shared secret. This secret is passed as an hexadecimal encoded string.
        pub fn hex_key(&mut self, key: &String) -> &mut $t {
            match key.from_hex() {
                Ok(k) => { self.key = Some(k); }
                Err(_) => { self.runtime_error = Some("Invalid key."); }
            }
            self
        }

        /// Sets the shared secret. This secret is passed as a base32 encoded string.
        pub fn base32_key(&mut self, key: &String) -> &mut $t {
            match base32::decode(base32::Alphabet::RFC4648 { padding: false }, &key) {
                Some(k) => { self.key = Some(k); }
                None => { self.runtime_error = Some("Invalid key."); }
            }
            self
        }

        fn code_length(&self) -> usize {
            let base_len = self.output_base.len();
            base_len.pow(self.output_len as u32)
        }

        /// Sets the number of characters for the code. The minimum and maximum values depends the base. Default is 6.
        pub fn output_len(&mut self, output_len: usize) -> &mut $t {
            self.output_len = output_len;
            self
        }

        /// Sets the base used to represents the output code. Default is "0123456789".to_string().into_bytes().
        pub fn output_base(&mut self, base: &Vec<u8>) -> &mut $t {
            self.output_base = base.clone();
            self
        }

        /// Sets the hash function. Default is Sha1.
        pub fn hash_function(&mut self, hash_function: HashFunction) -> &mut $t {
            self.hash_function = hash_function;
            self
        }
    }
}

#[cfg(feature = "cbindings")]
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

#[cfg(feature = "cbindings")]
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

pub mod hotp;
pub mod totp;

pub type HOTPBuilder = hotp::HOTPBuilder;
pub type TOTPBuilder = totp::TOTPBuilder;
