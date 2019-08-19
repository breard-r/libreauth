use crate::oath::HashFunction;

#[derive(Eq, PartialEq)]
pub(crate) enum UriType {
    TOTP,
    HOTP,
}

/// Creates the Key Uri Format according to the [Google authenticator
/// specification](https://github.com/google/google-authenticator/wiki/Key-Uri-Format) by calling
/// `key_uri_format()` on [`HOTP`] or [`TOTP`]. This value can be used to generete QR
/// codes which allow easy scanning by the end user.
///
/// **WARNING**: The finalized value contains the secret key of the authentication process and
/// should only be displayed to the corresponding user!
///
/// ## Example
///
/// ```
/// let key_ascii = "12345678901234567890".to_owned();
/// let mut totp = libreauth::oath::TOTPBuilder::new()
///     .ascii_key(&key_ascii)
///     .finalize()
///     .unwrap();
///
/// let uri = totp
///     .key_uri_format("Provider1", "alice@gmail.com")
///     .finalize();
///
/// assert_eq!(
///     uri,
///     "otpauth://totp/Provider1:alice%40gmail.com?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&issuer=Provider1&algorithm=SHA1&digits=6&period=30"
/// );
/// ```
pub struct KeyUriBuilder<'a> {
    pub(crate) uri_type: UriType,
    pub(crate) key: &'a Vec<u8>,
    pub(crate) issuer: &'a str,
    pub(crate) add_issuer_param: bool,
    pub(crate) account_name: &'a str,
    pub(crate) custom_label: Option<&'a str>,
    pub(crate) custom_parameters: Option<&'a str>,
    pub(crate) encode_parameters: bool, // URL-encode custom parameter?
    pub(crate) algo: Option<HashFunction>,
    pub(crate) digits: Option<usize>,
    pub(crate) counter: Option<u64>,
    pub(crate) period: Option<u32>,
}

impl<'a> KeyUriBuilder<'a> {
    /// Do not append the issuer to the parameters section.
    pub fn disable_issuer(mut self) -> Self {
        self.add_issuer_param = false;
        self
    }

    /// Do not append the hash function to the parameters section.
    pub fn disable_hash_function(mut self) -> Self {
        self.algo = None;
        self
    }

    /// Do not append digits to the parameters section.
    pub fn disable_digits(mut self) -> Self {
        self.digits = None;
        self
    }

    /// Do not append the period to the parameters section. If this is a builder for a HOTP key, calling this
    /// method has no effect.
    pub fn disable_period(mut self) -> Self {
        self.period = None;
        self
    }

    /// Completely overwrite the default `{issuer}:{account_name}` label with a custom one.
    ///
    /// ## Example
    ///
    /// ```
    /// let key_ascii = "12345678901234567890".to_owned();
    /// let mut totp = libreauth::oath::TOTPBuilder::new()
    ///     .ascii_key(&key_ascii)
    ///     .finalize()
    ///     .unwrap();
    ///
    /// let uri = totp
    ///     .key_uri_format("Provider1", "alice@gmail.com")
    ///     .overwrite_label("Provider1Label")
    ///     .finalize();
    ///
    /// assert_eq!(
    ///     uri,
    ///     "otpauth://totp/Provider1Label?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&issuer=Provider1&algorithm=SHA1&digits=6&period=30"
    /// );
    /// ```
    pub fn overwrite_label(mut self, label: &'a str) -> Self {
        self.custom_label = Some(label);
        self
    }

    /// Completely overwrite the default parameters section with a custom one.
    /// Set `url_encode` to `true` to have it URL-encoded.
    ///
    /// ## Example
    ///
    /// ```
    /// let key_ascii = "12345678901234567890".to_owned();
    /// let mut totp = libreauth::oath::TOTPBuilder::new()
    ///     .ascii_key(&key_ascii)
    ///     .finalize()
    ///     .unwrap();
    ///
    /// let uri = totp
    ///     .key_uri_format("Provider1", "alice@gmail.com")
    ///     .overwrite_parameters("Provider1Parameters", false)
    ///     .finalize();
    ///
    /// assert_eq!(
    ///     uri,
    ///     "otpauth://totp/Provider1:alice%40gmail.com?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&Provider1Parameters"
    /// );
    /// ```
    pub fn overwrite_parameters(mut self, parameters: &'a str, url_encode: bool) -> Self {
        self.custom_parameters = Some(parameters);
        self.encode_parameters = url_encode;
        self
    }

    /// Generate the final format.
    pub fn finalize(&self) -> String {
        let secret_final = base32::encode(
            base32::Alphabet::RFC4648 { padding: false },
            self.key.as_slice(),
        );

        use self::UriType::*;
        let uri_type_final = match self.uri_type {
            TOTP => "totp",
            HOTP => "hotp",
        };

        // Create the label according to the recommendations,
        // unless a custom label was set (overwritten).
        let label_final = match self.custom_label {
            Some(label) => label.to_string(), // Custom label
            None => format!(
                "{}:{}",
                url_encode(self.issuer),
                url_encode(self.account_name)
            ),
        };

        // Create the parameters structure according to the specification,
        // unless custom parameters were set (overwritten).
        let parameters_final = match self.custom_parameters {
            Some(parameters) => {
                // Custom parameters
                // Make sure the parameters section starts with `&`
                let mut prefix = String::new();
                if !parameters.starts_with('&') {
                    prefix.push('&');
                }

                if self.encode_parameters {
                    prefix.push_str(&url_encode(parameters));
                } else {
                    prefix.push_str(parameters);
                }
                prefix
            }
            None => {
                // STRONGLY RECOMMENDED: The issuer parameter is a string value indicating the
                // provider or service this account is associated with. If the issuer parameter
                // is absent, issuer information may be taken from the issuer prefix of the label.
                // If both issuer parameter and issuer label prefix are present, they should be equal.
                let issuer_final = if self.add_issuer_param {
                    format!("&issuer={}", url_encode(self.issuer))
                } else {
                    String::new()
                };

                // OPTIONAL: The algorithm may have the values: SHA1 (Default), SHA256, SHA512.
                let mut algo_final = "";
                if let Some(algo) = self.algo {
                    algo_final = match algo {
                        HashFunction::Sha1 => "&algorithm=SHA1",
                        HashFunction::Sha224 => "&algorithm=SHA224",
                        HashFunction::Sha256 => "&algorithm=SHA256",
                        HashFunction::Sha384 => "&algorithm=SHA384",
                        HashFunction::Sha512 => "&algorithm=SHA512",
                        HashFunction::Sha512Trunc224 => "&algorithm=SHA512T224",
                        HashFunction::Sha512Trunc256 => "&algorithm=SHA512T256",
                        HashFunction::Sha3_224 => "&algorithm=SHA3-224",
                        HashFunction::Sha3_256 => "&algorithm=SHA3-256",
                        HashFunction::Sha3_384 => "&algorithm=SHA3-384",
                        HashFunction::Sha3_512 => "&algorithm=SHA3-512",
                        HashFunction::Keccak224 => "&algorithm=KECCAK224",
                        HashFunction::Keccak256 => "&algorithm=KECCAK256",
                        HashFunction::Keccak384 => "&algorithm=KECCAK384",
                        HashFunction::Keccak512 => "&algorithm=KECCAK512",
                    };
                }

                // OPTIONAL: The digits parameter may have the values 6 or 8, and determines how
                // long of a one-time passcode to display to the user. The default is 6.
                let mut digits_final = String::new();
                if let Some(digits) = self.digits {
                    digits_final = format!("&digits={}", digits);
                }

                // REQUIRED if type is hotp: The counter parameter is required when provisioning
                // a key for use with HOTP. It will set the initial counter value.
                let counter_final = if self.uri_type == HOTP {
                    // Unwraping here is safe, since the counter is required for HOTP.
                    // Panicing would indicate a bug in `HOTP.key_uri_format()`.
                    format!("&counter={}", self.counter.unwrap())
                } else {
                    String::new()
                };

                // OPTIONAL only if type is totp: The period parameter defines a period that a
                // TOTP code will be valid for, in seconds. The default value is 30.
                let mut period_final = String::new();
                if let Some(period) = self.period {
                    period_final = format!("&period={}", period);
                }

                format!(
                    "{issuer}{algo}{digits}{counter}{period}",
                    issuer = issuer_final,
                    algo = algo_final,
                    digits = digits_final,
                    counter = counter_final,
                    period = period_final,
                )
            }
        };

        format!(
            "otpauth://{uri_type}/{label}?secret={secret}{params}",
            uri_type = uri_type_final,
            label = label_final,
            secret = secret_final,
            params = parameters_final,
        )
    }
}

/// The source code within this function was taken from the
/// [rust_urlencoding](https://github.com/bt/rust_urlencoding) library.
///
/// Copyright (c) 2016 Bertram Truong
///
/// Permission is hereby granted, free of charge, to any person obtaining a copy
/// of this software and associated documentation files (the "Software"), to deal
/// in the Software without restriction, including without limitation the rights
/// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
/// copies of the Software, and to permit persons to whom the Software is
/// furnished to do so, subject to the following conditions:
///
/// The above copyright notice and this permission notice shall be included in
/// all copies or substantial portions of the Software.
///
/// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
/// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
/// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
/// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
/// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
/// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
/// THE SOFTWARE.
fn url_encode(data: &str) -> String {
    let mut escaped = String::new();
    for b in data.as_bytes().iter() {
        match *b as char {
            // Accepted characters
            'A'..='Z' | 'a'..='z' | '0'..='9' | '-' | '_' | '.' | '~' => escaped.push(*b as char),

            // Everything else is percent-encoded
            b => escaped.push_str(format!("%{:02X}", b as u32).as_str()),
        };
    }
    escaped
}
