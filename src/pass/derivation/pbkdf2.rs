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


use std::collections::HashMap;
use ::pass::phc::PHCData;
use super::{HashFunction,PasswordDerivationFunction};
use pass::ErrorCode;
use crypto::sha2::{Sha512,Sha256};
use crypto::sha1::Sha1;
use crypto::hmac::Hmac;
use crypto::pbkdf2::pbkdf2;


pub struct Pbkdf2 {
    pub hash_function: HashFunction,
    pub nb_iter: u32,
    pub salt: Vec<u8>,
}

fn to_hex(v: Vec<u8>) -> String {
    let mut s = "".to_string();
    for e in v.iter() {
        s += format!("{:02x}", e).as_str();
    }
    s
}

macro_rules! process_pbkdf2 {
    ($obj:ident, $pass:ident, $hash:expr, $len:expr, $id:expr) => {{
        let mut mac = Hmac::new($hash, $pass.as_bytes());
        let mut derived_pass: Vec<u8> = vec![0; $len];
        pbkdf2(&mut mac, &$obj.salt, $obj.nb_iter, &mut derived_pass);
        let mut params = HashMap::new();
        params.insert("i".to_string(), format!("{}", $obj.nb_iter));
        let out = PHCData {
            id: $id.to_string(),
            parameters: params,
            salt: Some($obj.salt.clone()),
            hash: Some(derived_pass),
        };
        match out.to_string() {
            Ok(v) => Ok(v),
            Err(_) => Err(ErrorCode::InvalidPasswordFormat),
        }
    }}
}

impl PasswordDerivationFunction for Pbkdf2 {
    fn derive(&self, password: &str) -> Result<String, ErrorCode> {
        match self.check_password(password) {
            Ok(_) => match self.hash_function {
                HashFunction::Sha1 => process_pbkdf2!(self, password, Sha1::new(), 20, "pbkdf2"),
                HashFunction::Sha256 => process_pbkdf2!(self, password, Sha256::new(), 32, "pbkdf2-sha256"),
                HashFunction::Sha512 => process_pbkdf2!(self, password, Sha512::new(), 64, "pbkdf2-sha512"),
            },
            Err(e) => Err(e),
        }
    }
}
