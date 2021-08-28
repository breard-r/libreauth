use super::{
    DEFAULT_OTP_HASH, DEFAULT_OTP_OUT_BASE, DEFAULT_OTP_OUT_LEN, DEFAULT_TOTP_PERIOD,
    DEFAULT_TOTP_T0,
};
use crate::oath::HashFunction;
use std::collections::HashMap;
use url::Url;

macro_rules! do_insert_param {
    ($s: ident, $uri: ident, $elem: expr, $name: expr, $def: expr, $is_gauth: expr, $force_param: expr) => {{
        let incl = if $force_param {
            true
        } else {
            match $s.parameters_visibility {
                ParametersVisibility::ShowAll => true,
                ParametersVisibility::ShowNonDefault => $elem != $def,
                ParametersVisibility::GAuthOnly => $is_gauth,
                ParametersVisibility::GAuthNonDefaultExt => $is_gauth || $elem != $def,
                ParametersVisibility::HideAll => false,
            }
        };
        if incl {
            $uri.query_pairs_mut()
                .append_pair($name, &$elem.to_string());
        }
    }};
}

macro_rules! insert_param {
    ($s: ident, $uri: ident, $elem: expr, $name: expr, $def: expr, $is_gauth: expr) => {{
        do_insert_param!($s, $uri, $elem, $name, $def, $is_gauth, false)
    }};
}

macro_rules! insert_param_opt {
    ($s: ident, $uri: ident, $elem: expr, $name: expr, $def: expr, $is_gauth: expr) => {{
        if let Some(e) = $elem {
            do_insert_param!($s, $uri, e, $name, $def, $is_gauth, false);
        }
    }};
}

macro_rules! insert_param_opt_f {
    ($s: ident, $uri: ident, $elem: expr, $name: expr, $def: expr, $is_gauth: expr) => {{
        if let Some(e) = $elem {
            do_insert_param!($s, $uri, e, $name, $def, $is_gauth, true);
        }
    }};
}

#[derive(Eq, PartialEq)]
pub(crate) enum UriType {
    TOTP,
    HOTP,
}

/// Defines the base policy for showing or hiding parameters in a Key URI.
#[derive(Eq, PartialEq)]
pub enum ParametersVisibility {
    /// Shows all possible parameters.
    ShowAll,
    /// Shows only parameters with non-default values.
    ShowNonDefault,
    /// Shows all parameters defined in the Google's Key Uri Format and hide extensions.
    GAuthOnly,
    /// Shows all parameters except those with default values that are not part of the Google's Key Uri Format.
    GAuthNonDefaultExt,
    /// Hides all parameters except `secret` and, for HOTP, `counter`.
    HideAll,
}

/// Creates the Key Uri Format according to the [Google authenticator
/// specification](https://github.com/google/google-authenticator/wiki/Key-Uri-Format) by calling
/// `key_uri_format()` on [`HOTP`](crate::oath::HOTP::key_uri_format) or [`TOTP`](crate::oath::TOTP::key_uri_format).
/// This value can be used to generete QR codes which allow easy scanning by the end user.
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
///     .key_uri_format("Provider1", "alice@example.com")
///     .finalize();
///
/// assert_eq!(
///     uri,
///     "otpauth://totp/Provider1:alice@example.com?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&issuer=Provider1"
/// );
/// ```
pub struct KeyUriBuilder<'a> {
    pub(crate) parameters_visibility: ParametersVisibility,
    pub(crate) uri_type: UriType,
    pub(crate) key: &'a Vec<u8>,
    pub(crate) issuer: &'a str,
    pub(crate) account_name: &'a str,
    pub(crate) custom_label: Option<&'a str>,
    pub(crate) custom_parameters: HashMap<&'a str, &'a str>,
    pub(crate) algo: HashFunction,
    pub(crate) output_len: usize,
    pub(crate) output_base: &'a str,
    pub(crate) counter: Option<u64>,
    pub(crate) period: Option<u32>,
    pub(crate) initial_time: Option<u64>,
}

impl<'a> KeyUriBuilder<'a> {
    /// Set the visibility policy for parameters.
    ///
    /// ## Example
    ///
    /// ```
    /// use libreauth::oath::{ParametersVisibility, TOTPBuilder };
    ///
    /// let key_ascii = "12345678901234567890".to_owned();
    /// let mut totp = TOTPBuilder::new()
    ///     .ascii_key(&key_ascii)
    ///     .finalize()
    ///     .unwrap();
    ///
    /// let uri = totp
    ///     .key_uri_format("Provider1", "alice@example.com")
    ///     .parameters_visibility_policy(ParametersVisibility::HideAll)
    ///     .finalize();
    ///
    /// assert_eq!(
    ///     uri,
    ///     "otpauth://totp/Provider1:alice@example.com?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"
    /// );
    /// ```
    pub fn parameters_visibility_policy(mut self, policy: ParametersVisibility) -> Self {
        self.parameters_visibility = policy;
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
    ///     .key_uri_format("Provider1", "alice@example.com")
    ///     .overwrite_label("Provider1Label")
    ///     .finalize();
    ///
    /// assert_eq!(
    ///     uri,
    ///     "otpauth://totp/Provider1Label?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&issuer=Provider1"
    /// );
    /// ```
    pub fn overwrite_label(mut self, label: &'a str) -> Self {
        self.custom_label = Some(label);
        self
    }

    /// Add a custom key/value parameter.
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
    ///     .key_uri_format("Provider1", "alice@example.com")
    ///     .add_parameter("foo", "bar")
    ///     .finalize();
    ///
    /// assert_eq!(
    ///     uri,
    ///     "otpauth://totp/Provider1:alice@example.com?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&issuer=Provider1&foo=bar"
    /// );
    /// ```
    pub fn add_parameter(mut self, key: &'a str, value: &'a str) -> Self {
        self.custom_parameters.insert(key, value);
        self
    }

    /// Generate the final format.
    #[allow(clippy::cognitive_complexity)]
    pub fn finalize(&self) -> String {
        let mut uri = Url::parse("otpauth://").unwrap();

        let uri_type_final = match self.uri_type {
            UriType::TOTP => "totp",
            UriType::HOTP => "hotp",
        };
        uri.set_host(Some(uri_type_final)).unwrap();

        let label_final = match self.custom_label {
            Some(label) => format!("/{}", label),
            None => format!("/{}:{}", self.issuer, self.account_name),
        };
        uri.set_path(&label_final);

        let secret_final = base32::encode(
            base32::Alphabet::RFC4648 { padding: false },
            self.key.as_slice(),
        );
        uri.query_pairs_mut().append_pair("secret", &secret_final);

        insert_param!(self, uri, self.issuer, "issuer", "", true);
        insert_param!(self, uri, self.algo, "algorithm", DEFAULT_OTP_HASH, true);
        insert_param!(
            self,
            uri,
            self.output_len,
            "digits",
            DEFAULT_OTP_OUT_LEN,
            true
        );
        insert_param!(
            self,
            uri,
            self.output_base,
            "base",
            DEFAULT_OTP_OUT_BASE,
            false
        );
        insert_param_opt_f!(self, uri, self.counter, "counter", 0, true);
        insert_param_opt!(self, uri, self.period, "period", DEFAULT_TOTP_PERIOD, true);
        insert_param_opt!(self, uri, self.initial_time, "t0", DEFAULT_TOTP_T0, false);
        if !self.custom_parameters.is_empty() {
            for (k, v) in &self.custom_parameters {
                uri.query_pairs_mut().append_pair(k, v);
            }
            return uri.into();
        }

        uri.into()
    }
}
