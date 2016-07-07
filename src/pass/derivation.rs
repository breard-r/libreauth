/*
 * Copyright Rodolphe Breard (2016)
 * Author: Rodolphe Breard (2016)
 *
 * This software is a computer program whose purpose is to [describe
 * functionalities and technical features of your software].
 *
 * This software is governed by the CeCILL  license under French law and
 * abiding by the rules of distribution of free software.  You can  use,
 * modify and/ or redistribute the software under the terms of the CeCILL
 * license as circulated by CEA, CNRS and INRIA at the following URL
 * "http://www.cecill.info".
 *
 * As a counterpart to the access to the source code and  rights to copy,
 * modify and redistribute granted by the license, users are provided only
 * with a limited warranty  and the software's author,  the holder of the
 * economic rights,  and the successive licensors  have only  limited
 * liability.
 *
 * In this respect, the user's attention is drawn to the risks associated
 * with loading,  using,  modifying and/or developing or reproducing the
 * software by the user in light of its specific status of free software,
 * that may mean  that it is complicated to manipulate,  and  that  also
 * therefore means  that it is reserved for developers  and  experienced
 * professionals having in-depth computer knowledge. Users are therefore
 * encouraged to load and test the software's suitability as regards their
 * requirements in conditions enabling the security of their systems and/or
 * data to be ensured and,  more generally, to use and operate it in the
 * same conditions as regards security.
 *
 * The fact that you are presently reading this means that you have had
 * knowledge of the CeCILL license and that you accept its terms.
 */


use super::{PASSWORD_MIN_LEN,PASSWORD_MAX_LEN};
use super::{ErrorCode,generate_salt};
use rustc_serialize::hex::{FromHex,ToHex};
use crypto::sha2::{Sha512,Sha256};
use crypto::sha1::Sha1;
use crypto::hmac::Hmac;
use crypto::pbkdf2::pbkdf2;



fn pbkdf2_sha512_fn(password: &str, salt: &Vec<u8>) -> Result<Vec<u8>, ErrorCode> {
    let nb_iter = 21000;
    let mut mac = Hmac::new(Sha512::new(), password.as_bytes());
    let mut out: Vec<u8> = vec![0; 64];
    pbkdf2(&mut mac, &salt, nb_iter, &mut out);
    Ok(out)
}

fn pbkdf2_sha256_fn(password: &str, salt: &Vec<u8>) -> Result<Vec<u8>, ErrorCode> {
    let nb_iter = 21000;
    let mut mac = Hmac::new(Sha256::new(), password.as_bytes());
    let mut out: Vec<u8> = vec![0; 32];
    pbkdf2(&mut mac, &salt, nb_iter, &mut out);
    Ok(out)
}

pub fn pbkdf2_fn(password: &str, salt: &Vec<u8>) -> Result<Vec<u8>, ErrorCode> {
    let nb_iter = 21000;
    let mut mac = Hmac::new(Sha1::new(), password.as_bytes());
    let mut out: Vec<u8> = vec![0; 20];
    pbkdf2(&mut mac, &salt, nb_iter, &mut out);
    Ok(out)
}

pub fn get_salt(password: &str) -> Result<Vec<u8>, ErrorCode> {
    let splited: Vec<&str> = password.split("$").collect();
    if splited.len() != 6 {
        return Err(ErrorCode::InvalidPasswordFormat);
    }
    match splited[3].from_hex() {
        Ok(some) => Ok(some),
        Err(_) => Err(ErrorCode::InvalidPasswordFormat),
    }
}


pub struct DerivationAlgorithmModel {
    algo: &'static str,
    salt_len: usize,
    derivation_func: fn(&str, &Vec<u8>) -> Result<Vec<u8>, ErrorCode>,
}

impl DerivationAlgorithmModel {
    pub fn check_type(&self, password: &str) -> bool {
        let begin_str = format!("${}$", self.algo);
        password.starts_with(begin_str.as_str())
    }

    pub fn derivate_with_salt(&self, password: &str, salt: &Vec<u8>) -> Result<String, ErrorCode> {
        if password.len() < PASSWORD_MIN_LEN {
            return Err(ErrorCode::PasswordTooShort);
        }
        if password.len() > PASSWORD_MAX_LEN {
            return Err(ErrorCode::PasswordTooLong);
        }
        let derivated_pass = match (self.derivation_func)(password, salt) {
            Ok(some) => some.to_hex(),
            Err(err) => return Err(err),
        };
        let out = format!("${}${}${}${}$", self.algo, "0", &salt.to_hex(), derivated_pass);
        Ok(out)
    }

    pub fn derivate(&self, password: &str) -> Result<String, ErrorCode> {
        if password.len() < PASSWORD_MIN_LEN {
            return Err(ErrorCode::PasswordTooShort);
        }
        if password.len() > PASSWORD_MAX_LEN {
            return Err(ErrorCode::PasswordTooLong);
        }
        let salt: Vec<u8> = generate_salt(self.salt_len);
        let ret = self.derivate_with_salt(password, &salt);
        ret
    }
}

pub const ALGORITHMS: [DerivationAlgorithmModel; 3] = [
    //DerivationAlgorithmModel {algo: "argon2i", salt_len: 8, derivation_func: argon2i_fn},
    //DerivationAlgorithmModel {algo: "scrypt", salt_len: 8, derivation_func: scrypt_fn},
    //DerivationAlgorithmModel {algo: "bcrypt", salt_len: 8, derivation_func: bcrypt_fn},
    DerivationAlgorithmModel {algo: "pbkdf2-sha512", salt_len: 8, derivation_func: pbkdf2_sha512_fn},
    DerivationAlgorithmModel {algo: "pbkdf2-sha256", salt_len: 8, derivation_func: pbkdf2_sha256_fn},
    DerivationAlgorithmModel {algo: "pbkdf2", salt_len: 8, derivation_func: pbkdf2_fn},
];

#[cfg(test)]
mod tests {
    use super::{pbkdf2_sha512_fn,pbkdf2_sha256_fn,pbkdf2_fn};
    use super::{get_salt,ALGORITHMS};
    use rustc_serialize::hex::ToHex;

    #[test]
    fn test_pbkdf2_sha512() {
        let password_list = [
            ("123456", "584a53b5f4e1f4dda9375e3a7cd4f01acff74870b78f8bb9a23befcc31768df3d1906ce51d0d04d2a90081dc88e43bfe0402ab513c72a6286adb12c0933ee7fa"),
            ("password", "20725ad1d811c2cbdd8bf4eecabb5967321459eb1c3c24554a474dcdf61b445e9f07832ed61de02962f35ea7ff46178f2718081861caf4097c394f096d01eb58"),
            ("password123", "c538516ce1350cf7d48cc6b59119fa1d94fab9f1b92a2c603c2b78f8fd1800b99d9a4447ddfc1c5c297bdb53cfdf9f736d831854e824af7cadf97a2144b93f6b"),
            ("correct horse battery staple", "2f66e6548c1b43af774db726f6ea40d19aed21ffdb592b2a830b0b01bd59d97da1b7080470f25d1734f1331a71b2216a06296e2e7b826d5b57ba5ae103c6414a"),
        ];
        let salt: Vec<u8> = vec![0x45, 0x21, 0x78, 0x03];
        for tpl in password_list.iter() {
            let derivated_pass = match pbkdf2_sha512_fn(tpl.0, &salt) {
                Ok(some) => some.to_hex(),
                Err(_) => "".to_owned(),
            };
            assert_eq!(derivated_pass, tpl.1);
        };
    }

    #[test]
    fn test_pbkdf2_sha256() {
        let password_list = [
            ("123456", "195fa9514d87912819296880d769bcfb69a0b2384f817fc3b7390763a29a6e79"),
            ("password", "fb06696ab762cd18c9583cf94411ed98233b27a623c950727e258407139f770c"),
            ("password123", "a607a72c2c92357a4568b998c5f708f801f0b1ffbaea205357e08e4d325830c9"),
        ];
        let salt: Vec<u8> = vec![0x45, 0x21, 0x78, 0x03];
        for tpl in password_list.iter() {
            let derivated_pass = match pbkdf2_sha256_fn(tpl.0, &salt) {
                Ok(some) => some.to_hex(),
                Err(_) => "".to_owned(),
            };
            assert_eq!(derivated_pass, tpl.1);
        };
    }

    #[test]
    fn test_pbkdf2() {
        let password_list = [
            ("123456", "bcaff7fa9e1ad924eddc33c13407894ddf82baba"),
            ("password", "17722502224e6e1b5c3e004f19895184ea8102a6"),
            ("password123", "2f009b19e42805922b698a0367c39efcfc5d2477"),
        ];
        let salt: Vec<u8> = vec![0x45, 0x21, 0x78, 0x03];
        for tpl in password_list.iter() {
            let derivated_pass = match pbkdf2_fn(tpl.0, &salt) {
                Ok(some) => some.to_hex(),
                Err(_) => "".to_owned(),
            };
            assert_eq!(derivated_pass, tpl.1);
        };
    }

    #[test]
    fn test_get_salt() {
        let stored_hash = "$pbkdf2-sha256$0$45217803$a607a72c2c92357a4568b998c5f708f801f0b1ffbaea205357e08e4d325830c9$";
        let ref_salt: Vec<u8> = vec![0x45, 0x21, 0x78, 0x03];
        let salt = get_salt(stored_hash).unwrap();
        assert_eq!(salt, ref_salt);
    }

    #[test]
    fn test_check_type() {
        let password_list = [
            ("pbkdf2-sha256", "$pbkdf2-sha256$0$45217803$a607a72c2c92357a4568b998c5f708f801f0b1ffbaea205357e08e4d325830c9$"),
            ("pbkdf2", "$pbkdf2$0$45217803$bcaff7fa9e1ad924eddc33c13407894ddf82baba$"),
            ("nothing", "$derp$0$45217803$a607a72c2c92357a4568b998c5f708f801f0b1ffbaea205357e08e4d325830c9$"),
        ];
        for tpl in password_list.iter() {
            for algo in ALGORITHMS.iter() {
                let is_type = algo.check_type(tpl.1);
                let ref_type = algo.algo == tpl.0;
                assert_eq!(is_type, ref_type);
            }
        }
    }
}
