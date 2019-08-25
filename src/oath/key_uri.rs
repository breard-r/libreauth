use super::{DEFAULT_OTP_HASH, DEFAULT_OTP_OUT_LEN, DEFAULT_TOTP_PERIOD, DEFAULT_TOTP_T0};
use crate::oath::HashFunction;
use url::Url;
use urlencoding::encode as url_encode;

macro_rules! insert_param {
    ($s: ident, $uri: ident, $elem: expr, $name: expr, $def: expr, $is_gauth: expr) => {{
        let incl = match $s.parameters_visibility {
            ParametersVisibility::ShowAll => true,
            ParametersVisibility::ShowNonDefault => $elem != $def,
            ParametersVisibility::GAuthOnly => $is_gauth,
            ParametersVisibility::GAuthNonDefaultExt => $is_gauth || $elem != $def,
            ParametersVisibility::HideAll => false,
        };
        if incl {
            $uri.query_pairs_mut()
                .append_pair($name, &$elem.to_string());
        }
    }};
}

macro_rules! insert_param_opt {
    ($s: ident, $uri: ident, $elem: expr, $name: expr, $def: expr, $is_gauth: expr) => {{
        if let Some(e) = $elem {
            insert_param!($s, $uri, e, $name, $def, $is_gauth);
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
    /// Hides all parameters except `secret`.
    HideAll,
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
    pub(crate) parameters_visibility: ParametersVisibility,
    pub(crate) uri_type: UriType,
    pub(crate) key: &'a Vec<u8>,
    pub(crate) issuer: &'a str,
    pub(crate) account_name: &'a str,
    pub(crate) custom_label: Option<&'a str>,
    pub(crate) custom_parameters: Option<&'a str>,
    pub(crate) encode_parameters: bool, // URL-encode custom parameter?
    pub(crate) algo: HashFunction,
    pub(crate) output_len: usize,
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
    ///     .key_uri_format("Provider1", "alice@gmail.com")
    ///     .parameters_visibility_policy(ParametersVisibility::HideAll)
    ///     .finalize();
    ///
    /// assert_eq!(
    ///     uri,
    ///     "otpauth://totp/Provider1:alice%40gmail.com?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"
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

    /// Overwrite the parameters other than `secret` with given string.
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
        let mut uri = Url::parse("otpauth://").unwrap();

        let uri_type_final = match self.uri_type {
            UriType::TOTP => "totp",
            UriType::HOTP => "hotp",
        };
        uri.set_host(Some(uri_type_final)).unwrap();

        // Create the label according to the recommendations,
        // unless a custom label was set (overwritten).
        let label_final = match self.custom_label {
            Some(label) => label.to_string(),
            None => format!(
                "{}:{}",
                url_encode(self.issuer),
                url_encode(self.account_name)
            ),
        };
        uri.set_path(&label_final);

        let secret_final = base32::encode(
            base32::Alphabet::RFC4648 { padding: false },
            self.key.as_slice(),
        );
        uri.query_pairs_mut().append_pair("secret", &secret_final);

        if let Some(params) = self.custom_parameters {
            if self.parameters_visibility == ParametersVisibility::HideAll {
                return uri.into_string();
            }

            let final_params = if self.encode_parameters {
                url_encode(params)
            } else {
                params.to_string()
            };
            return format!("{}&{}", uri.as_str(), final_params);
        };

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
        insert_param_opt!(self, uri, self.counter, "counter", 0, true);
        insert_param_opt!(self, uri, self.period, "period", DEFAULT_TOTP_PERIOD, true);
        insert_param_opt!(self, uri, self.initial_time, "t0", DEFAULT_TOTP_T0, false);

        uri.into_string()
    }
}
