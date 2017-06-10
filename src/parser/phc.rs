/*
 * Copyright Rodolphe Breard (2017)
 * Author: Rodolphe Breard (2017)
 *
 * This software is a computer library whose purpose is to offer a
 * collection of tools for user authentication.
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
use nom::{IResult,is_alphanumeric};
use base64;

pub static PHC_BASE64: base64::Config = base64::Config {char_set: base64::CharacterSet::Standard, pad: false};

fn to_b64(data: Option<Vec<u8>>) -> Option<Vec<u8>> {
    match data {
        Some(v) => match base64::decode_config(v.as_slice(), PHC_BASE64) {
            Ok(r) => Some(r),
            Err(_) => None,
        },
        None => None,
    }
}

#[inline]
fn is_b42(chr: u8) -> bool {
    (chr >= 0x41 && chr <= 0x5a) ||
    (chr >= 0x61 && chr <= 0x7a) ||
    (chr >= 0x30 && chr <= 0x39) ||
    chr == 0x2b ||
    chr == 0x2f
}

named!(get_id<String>, do_parse!(
    tag!("$") >>
    id: take_while1!(is_alphanumeric) >>
    (String::from_utf8(id.to_vec()).unwrap())
));

named!(get_phc_part<Vec<u8>>, do_parse!(
    tag!("$") >>
    data: take_while!(is_b42) >>
    (data.to_vec())
));

named!(get_param_elem<(String, String)>, do_parse!(
    name: take_while1!(is_alphanumeric) >>
    tag!("=") >>
    value: take_while1!(is_alphanumeric) >>
    opt!(complete!(tag!(","))) >>
    (String::from_utf8(name.to_vec()).unwrap(), String::from_utf8(value.to_vec()).unwrap())
));

named!(get_params<HashMap<String, String>>, fold_many0!(get_param_elem, HashMap::new(), |mut hm: HashMap<_, _>, (k, v)| {
    hm.insert(k, v);
    hm
}));

named!(parse_params<HashMap<String, String>>, do_parse!(
    tag!("$") >>
    params: get_params >>
    (params)
));

named!(get_phc<PHCData>, do_parse!(
    id: get_id >>
    parameters: opt!(complete!(parse_params)) >>
    salt: cond!(parameters.is_some(), complete!(get_phc_part)) >>
    hash: cond!(salt.is_some(), complete!(get_phc_part)) >>
    ( PHCData {
        id: id,
        parameters: match parameters {
            Some(p) => p,
            None => HashMap::new(),
        },
        salt: to_b64(salt),
        hash: to_b64(hash),
    })
));

pub struct PHCData {
    id: String,
    parameters: HashMap<String, String>,
    salt: Option<Vec<u8>>,
    hash: Option<Vec<u8>>,
}

impl PHCData {
    pub fn from_string(s: &String) -> Result<PHCData, ()> {
        match get_phc(s.as_str().as_bytes()) {
            IResult::Done(r, v) => {
                match r.len() {
                    0 => Ok(v),
                    _ => { Err(()) },
                }
            },
            _ => { Err(()) },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::PHCData;

    #[test]
    fn test_valid_data_id() {
        match PHCData::from_string(&"$dummy".to_string()) {
            Ok(phc) => {
                assert_eq!(phc.id, "dummy".to_string());
                assert!(phc.parameters.is_empty());
                assert_eq!(phc.salt, None);
                assert_eq!(phc.hash, None);
            },
            Err(_) => assert!(false),
        }
    }

    #[test]
    fn test_valid_data_params() {
        match PHCData::from_string(&"$dummy$i=42".to_string()) {
            Ok(phc) => {
                assert_eq!(phc.id, "dummy".to_string());
                assert_eq!(phc.parameters.len(), 1);
                match phc.parameters.get("i") {
                    Some(v) => assert_eq!(v, "42"),
                    None => assert!(false),
                }
                assert_eq!(phc.salt, None);
                assert_eq!(phc.hash, None);
            },
            Err(_) => assert!(false),
        }
    }

    #[test]
    fn test_valid_data_salt() {
        match PHCData::from_string(&"$dummy$i=42$YXN1cmUu".to_string()) {
            Ok(phc) => {
                assert_eq!(phc.id, "dummy".to_string());
                assert_eq!(phc.parameters.len(), 1);
                match phc.parameters.get("i") {
                    Some(v) => assert_eq!(v, "42"),
                    None => assert!(false),
                }
                match phc.salt {
                    Some(p) => assert_eq!(p, vec![0x61, 0x73, 0x75, 0x72, 0x65, 0x2e]),
                    None => assert!(false),
                };
                assert_eq!(phc.hash, None);
            },
            Err(_) => assert!(false),
        }
    }

    #[test]
    fn test_valid_data_full() {
        match PHCData::from_string(&"$dummy$i=42$YXN1cmUu$YW55IGNhcm5hbCBwbGVhc3Vy".to_string()) {
            Ok(phc) => {
                assert_eq!(phc.id, "dummy".to_string());
                assert_eq!(phc.parameters.len(), 1);
                match phc.parameters.get("i") {
                    Some(v) => assert_eq!(v, "42"),
                    None => assert!(false),
                }
                match phc.salt {
                    Some(p) => assert_eq!(p, vec![0x61, 0x73, 0x75, 0x72, 0x65, 0x2e]),
                    None => assert!(false),
                };
                match phc.hash {
                    Some(p) => assert_eq!(p, vec![0x61, 0x6e, 0x79, 0x20, 0x63, 0x61, 0x72, 0x6e, 0x61, 0x6c, 0x20, 0x70, 0x6c, 0x65, 0x61, 0x73, 0x75, 0x72]),
                    None => assert!(false),
                };
            },
            Err(_) => assert!(false),
        }
    }

    #[test]
    fn test_multiple_params() {
        match PHCData::from_string(&"$dummy$i=42,plop=asdfg,21=abcd12efg$YXN1cmUu".to_string()) {
            Ok(phc) => {
                assert_eq!(phc.parameters.len(), 3);
                match phc.parameters.get("i") {
                    Some(v) => assert_eq!(v, "42"),
                    None => assert!(false),
                }
                match phc.parameters.get("plop") {
                    Some(v) => assert_eq!(v, "asdfg"),
                    None => assert!(false),
                }
                match phc.parameters.get("21") {
                    Some(v) => assert_eq!(v, "abcd12efg"),
                    None => assert!(false),
                }
            },
            Err(_) => assert!(false),
        }
    }

    #[test]
    fn test_invalid_data() {
        let data = [
            "", // does not start with $<id>
            "$", // still no id
            "$@zerty", // id must be alphanumerical
            "$test$YXN1cmUu", // parameters may not be ommited
            "$test$=42", // missing parameter name
            "$test$i@=42", // parameter name must be alphanumerical
            "$test$i=?", // parameter value must be alphanumerical
            "$test$i", // missing parameter value and delimiter
            "$test$i=", // missing parameter value
            "$test$i=$YXN1cmUu", // missing parameter value
            "$test$i=42$YXN1cmUr%w", // invalid character in salt
            "$test$i=42$YXN1cmUr%w$YW55IGNhcm5hbCBwbGVhc3Vy", // invalid character in salt
            "$test$i=$YXN1cmUu$YW55IGNhcm5hbCBwbGVhc3V=", // no padding allowed
        ];
        for s in data.iter() {
            match PHCData::from_string(&s.to_string()) {
                Ok(p) => {
                    println!("*** Debug ***");
                    println!("input data: {}", s);
                    println!("id: {}", p.id);
                    for (k, v) in p.parameters.iter() {
                        println!(" - {} => {}", k, v);
                    }
                    match p.salt {
                        Some(s) => println!("salt: {:?}", s),
                        None => println!("No salt found."),
                    };
                    match p.hash {
                        Some(s) => println!("hash: {:?}", s),
                        None => println!("No hash found."),
                    };
                    assert!(false);
                },
                Err(_) => assert!(true),
            }
        }
    }
}
