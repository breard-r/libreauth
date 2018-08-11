# Change Log
All notable changes to this project will be documented in this file.
This project adheres to [Semantic Versioning](http://semver.org/).


## [0.10.0] - 2018-08-11

### Changed
- Password API has been completely rewrote.


## [0.9.0] - 2018-04-22

### Added
- OATH support for sha224, sha384, sha512 trunc 224 and sha512 trunc 256.
- OATH support for sha3-224, sha3-256, sha3-384, sha3-512, Keccak224, Keccak256, Keccak384, Keccak512.
- NFKC normalization for Unicode passwords.

### Changed
- Identifiers for sha256 and sha512 has been changed (compatibility break).


## [0.8.0] - 2018-04-08

### Added
- base64 key support

### Changed
- The `key` module does no more implicitly call `generate()` when requesting the key in a certain form.


## [0.7.0] - 2018-04-04

### Added
- Random key generation module.

### Changed
- Dependencies have been updated.


## [0.6.1] - 2017-12-17

### Changed
- Python test and examples have been removed;
- small documentation improvements.


## [0.6.0] - 2017-11-26

### Added
- Password authentication.

### Changed
- The `rust-crypto` crate has been replaced by several crates from the RustCrypto project (although the name is very similar, those are two different projects);
- the oath module does not not expose sub-modules anymore.


## [0.5.3] - 2017-04-17

### Added
- TOTP tolerance.

### Changed
- The oath module does not not expose sub-modules anymore;
- header guards now uses "#pragma once";
- C tests now uses C11 standard and clang.


## [0.5.2] - 2016-06-26

### Changed
- The project has been renamed LibreAuth (previous name: R2FA);
- the license has been changed to the CeCILL Free Software License Agreement v2.1;
- the otp module has been renamed oath.

### Removed
- The otp::c (oath::c) module is not public anymore.


## [0.5.1] - 2015-08-07
This release fixed a buffer overflow in the C-bindings tests. Because this issue did not influence the Rust part of the code in any way, the crate has not be updated.


## [0.5.0] - 2015-08-06

### Added
- C-bindings for OTP validation.

### Changed
- Errors are now represented by an enumeration instead of strings;
- the C unit test suite has been rewritten.

### Fixed
- An integer overflow has been fixed in code length calculation.


## [0.4.2] - 2015-08-04
This release is a cleanup release. No public interface has been changed.


## [0.4.1] - 2015-08-03

### Added
- C-bindings are now part of this library and therefore no longer distributed in a separated project.


## [0.4.0] - 2015-08-01

Last version without a changelog.
