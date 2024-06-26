/// Error codes used in the C interface.
///
/// ## C interface
/// The C interface uses an enum of type `libreauth_pass_errno` and the members has been renamed
/// as follows:
/// <table>
///     <thead>
///         <tr>
///             <th>Rust</th>
///             <th>C</th>
///         </tr>
///     </thead>
///     <tbody>
///         <tr>
///             <td>Success</td>
///             <td>LIBREAUTH_PASS_SUCCESS</td>
///         </tr>
///         <tr>
///             <td>PasswordTooShort</td>
///             <td>LIBREAUTH_PASS_PASSWORD_TOO_SHORT</td>
///         </tr>
///         <tr>
///             <td>PasswordTooLong</td>
///             <td>LIBREAUTH_PASS_PASSWORD_TOO_LONG</td>
///         </tr>
///         <tr>
///             <td>InvalidPasswordFormat</td>
///             <td>LIBREAUTH_PASS_INVALID_PASSWORD_FORMAT</td>
///         </tr>
///         <tr>
///             <td>IncompatibleOption</td>
///             <td>LIBREAUTH_PASS_INCOMPATIBLE_OPTION</td>
///         </tr>
///         <tr>
///             <td>NotEnoughSpace</td>
///             <td>LIBREAUTH_PASS_NOT_ENOUGH_SPACE</td>
///         </tr>
///         <tr>
///             <td>NullPtr</td>
///             <td>LIBREAUTH_PASS_NULL_PTR</td>
///         </tr>
///         <tr>
///             <td>InvalidKeyLen</td>
///             <td>LIBREAUTH_PASS_INVALID_KEY_LEN</td>
///         </tr>
///     </tbody>
/// </table>
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub enum ErrorCode {
	/// Used in C-bindings to indicate the absence of errors.
	Success = 0,
	/// The password is shorter than the minimal length.
	PasswordTooShort = 1,
	/// The password is longer than the maximal length.
	PasswordTooLong = 2,
	/// The input does not respect the [storage format](crate::pass).
	InvalidPasswordFormat = 10,
	/// Some options you specified are incompatible.
	IncompatibleOption = 11,
	/// Used in C-bindings to indicate the storage does not have enough space to store the data.
	NotEnoughSpace = 20,
	/// Used in C-bindings to indicate a NULL pointer.
	NullPtr = 21,
	/// Used in C-bindings to indicate an invalid key length.
	InvalidKeyLen = 22,
}

/// Errors for the Rust interface.
///
/// *To implement `std::error::Error`, the `stderror` feature must be activated*
#[derive(Clone, Copy, Debug)]
#[cfg_attr(feature = "thiserror", derive(thiserror::Error))]
pub enum Error {
	#[cfg_attr(
		feature = "thiserror",
		error("Password was shorter than the minimal length (actual {actual}, min {min})")
	)]
	PasswordTooShort { min: usize, actual: usize },
	#[cfg_attr(
		feature = "thiserror",
		error("Password was longer than the maximal length (actual {actual}, max {max})")
	)]
	PasswordTooLong { max: usize, actual: usize },
	#[cfg_attr(
		feature = "thiserror",
		error("Input does not respect the storage format")
	)]
	InvalidPasswordFormat,
}

impl From<Error> for ErrorCode {
	fn from(error: Error) -> Self {
		match error {
			Error::PasswordTooShort { min: _, actual: _ } => ErrorCode::PasswordTooShort,
			Error::PasswordTooLong { max: _, actual: _ } => ErrorCode::PasswordTooLong,
			Error::InvalidPasswordFormat => ErrorCode::InvalidPasswordFormat,
		}
	}
}

impl From<digest::InvalidLength> for ErrorCode {
	fn from(_error: digest::InvalidLength) -> Self {
		ErrorCode::InvalidPasswordFormat
	}
}

impl From<hmac::digest::InvalidLength> for Error {
	fn from(_error: hmac::digest::InvalidLength) -> Self {
		Error::InvalidPasswordFormat
	}
}
