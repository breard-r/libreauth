use base64::engine::general_purpose::STANDARD_NO_PAD;
use base64::Engine;
use nom::bytes::complete::{tag, take_while, take_while1};
use nom::combinator::{map_res, opt};
use nom::multi::fold_many0;
use nom::sequence::{preceded, separated_pair, terminated};
use nom::IResult;
use std::collections::HashMap;

fn from_b64(data: &str) -> Result<Option<Vec<u8>>, ()> {
	Ok(match data.len() {
		0 => None,
		_ => match STANDARD_NO_PAD.decode(data.as_bytes()) {
			Ok(r) => Some(r),
			Err(_) => None,
		},
	})
}

fn to_b64(data: &[u8]) -> String {
	STANDARD_NO_PAD.encode(data)
}

fn is_b64(chr: char) -> bool {
	chr.is_ascii_alphanumeric() || chr == '+' || chr == '/'
}

fn is_id_char(chr: char) -> bool {
	(chr.is_ascii_alphabetic() && chr.is_ascii_lowercase()) || chr.is_ascii_digit() || chr == '-'
}

fn is_param_name_char(chr: char) -> bool {
	(chr.is_ascii_alphabetic() && chr.is_ascii_lowercase()) || chr.is_ascii_digit() || chr == '-'
}

fn is_param_value_char(chr: char) -> bool {
	chr.is_ascii_alphanumeric() || chr == '+' || chr == '-' || chr == '.' || chr == '/'
}

fn get_id(input: &str) -> IResult<&str, &str> {
	preceded(tag("$"), take_while1(is_id_char))(input)
}

fn get_phc_part(input: &str) -> IResult<&str, Option<Vec<u8>>> {
	if input.is_empty() {
		return Ok((input, None));
	}
	map_res(preceded(tag("$"), take_while(is_b64)), from_b64)(input)
}

// TODO: replace by the not-yet implemented nom::opt()
fn get_phc_part_if(input: &str, cond: bool) -> IResult<&str, Option<Vec<u8>>> {
	if cond {
		get_phc_part(input)
	} else {
		Ok((input, None))
	}
}

fn get_param_elem(input: &str) -> IResult<&str, (&str, &str)> {
	terminated(
		separated_pair(
			take_while1(is_param_name_char),
			tag("="),
			take_while1(is_param_value_char),
		),
		opt(tag(",")),
	)(input)
}

fn get_params(input: &str) -> IResult<&str, HashMap<String, String>> {
	fold_many0(
		get_param_elem,
		HashMap::new,
		|mut hm: HashMap<_, _>, (k, v)| {
			hm.insert(k.to_string(), v.to_string());
			hm
		},
	)(input)
}

fn parse_params(input: &str) -> IResult<&str, HashMap<String, String>> {
	preceded(tag("$"), get_params)(input)
}

fn get_phc(input: &str) -> IResult<&str, PHCData> {
	let (input, id) = get_id(input)?;
	let (input, parameters) = opt(parse_params)(input)?;
	let (input, salt) = get_phc_part_if(input, parameters.is_some())?;
	let (input, hash) = get_phc_part_if(input, salt.is_some())?;
	let parameters = parameters.unwrap_or_default();
	let data = PHCData {
		id: id.to_string(),
		parameters,
		salt,
		hash,
	};
	Ok((input, data))
}

pub struct PHCData {
	pub id: String,
	pub parameters: HashMap<String, String>,
	pub salt: Option<Vec<u8>>,
	pub hash: Option<Vec<u8>>,
}

impl PHCData {
	pub fn from_str(s: &str) -> Result<PHCData, ()> {
		match get_phc(s) {
			Ok((r, v)) => match r.len() {
				0 => Ok(v),
				_ => Err(()),
			},
			Err(_) => Err(()),
		}
	}

	pub fn to_string(&self) -> Result<String, ()> {
		if self.id.is_empty() {
			return Err(());
		}
		let mut res = String::from("$");
		res += self.id.as_str();

		if self.parameters.is_empty() && self.salt.is_none() {
			return Ok(res);
		}
		res += "$";
		for (i, (k, v)) in self.parameters.iter().enumerate() {
			res += &match i {
				0 => format!("{}={}", k, v),
				_ => format!(",{}={}", k, v),
			};
		}

		match self.salt {
			Some(ref s) => {
				res += "$";
				res += to_b64(s).as_str();
				match self.hash {
					Some(ref h) => {
						res += "$";
						res += to_b64(h).as_str();
						Ok(res)
					}
					None => Ok(res),
				}
			}
			None => Ok(res),
		}
	}
}

#[cfg(test)]
mod tests {
	use super::PHCData;

	#[test]
	fn test_to_string_same() {
		let data = [
			"$test",
			"$test$i=42",
			"$test$$YXN1cmUu",
			"$test$i=42$YXN1cmUu",
			"$test$i=42$YXN1cmUu$YW55IGNhcm5hbCBwbGVhc3Vy",
			"$test$$YXN1cmUu$YW55IGNhcm5hbCBwbGVhc3Vy",
			"$pbkdf2$i=1000$RSF4Aw$xvdfA4H7QJQ1w/4jGcjBEIjCvsc",
			"$pbkdf2-sha256$t-y=./42+a-1$RSF4Aw$xvdfA4H7QJQ1w/4jGcjBEIjCvsc",
			"$pbkdf2$$RSF4Aw",
			"$pbkdf2$i=21000$RSF4Aw$LwCbGeQoBZIraYoDZ8Oe/PxdJHc",
		];
		for ref_str in data.iter() {
			let phc = PHCData::from_str(ref_str);
			assert!(phc.is_ok());
			let phc_str = phc.unwrap().to_string();
			assert!(phc_str.is_ok());
			assert_eq!(phc_str.unwrap(), ref_str.to_string());
		}
	}

	#[test]
	fn test_to_string_diff() {
		let data = [
			("$test$", "$test"),
			("$test$$", "$test"),
			("$test$$YXN1cmUu$", "$test$$YXN1cmUu"),
			("$test$i=42$YXN1cmUu$", "$test$i=42$YXN1cmUu"),
		];
		for &(str_extra, ref_str) in data.iter() {
			let phc = PHCData::from_str(str_extra);
			assert!(phc.is_ok());
			let phc_str = phc.unwrap().to_string();
			assert!(phc_str.is_ok());
			assert_eq!(phc_str.unwrap(), ref_str.to_string());
		}
	}

	#[test]
	fn test_valid_data_id() {
		let phc = PHCData::from_str("$dummy");
		assert!(phc.is_ok());
		let phc = phc.unwrap();
		assert_eq!(phc.id, "dummy".to_string());
		assert!(phc.parameters.is_empty());
		assert_eq!(phc.salt, None);
		assert_eq!(phc.hash, None);
	}

	#[test]
	fn test_valid_data_params() {
		let phc = PHCData::from_str("$dummy$i=42");
		assert!(phc.is_ok());
		let phc = phc.unwrap();
		assert_eq!(phc.id, "dummy".to_string());
		assert_eq!(phc.parameters.len(), 1);
		match phc.parameters.get("i") {
			Some(v) => assert_eq!(v, "42"),
			None => assert!(false),
		}
		assert_eq!(phc.salt, None);
		assert_eq!(phc.hash, None);
	}

	#[test]
	fn test_valid_data_salt() {
		let phc = PHCData::from_str("$dummy$i=42$YXN1cmUu");
		assert!(phc.is_ok());
		let phc = phc.unwrap();
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
	}

	#[test]
	fn test_valid_data_full() {
		let phc = PHCData::from_str("$dummy$i=42$YXN1cmUu$YW55IGNhcm5hbCBwbGVhc3Vy");
		assert!(phc.is_ok());
		let phc = phc.unwrap();
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
			Some(p) => assert_eq!(
				p,
				vec![
					0x61, 0x6e, 0x79, 0x20, 0x63, 0x61, 0x72, 0x6e, 0x61, 0x6c, 0x20, 0x70, 0x6c,
					0x65, 0x61, 0x73, 0x75, 0x72,
				]
			),
			None => assert!(false),
		};
	}

	#[test]
	fn test_multiple_params() {
		let phc = PHCData::from_str("$dummy$i=42,plop=asdfg,21=abcd12efg$YXN1cmUu");
		assert!(phc.is_ok());
		let phc = phc.unwrap();
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
	}

	#[test]
	fn test_invalid_data() {
		let data = [
			"",                                               // does not start with $<id>
			"$",                                              // still no id
			"$@zerty",                                        // id must be alphanumerical
			"$test$YXN1cmUu",                                 // parameters may not be ommited
			"$test$=42",                                      // missing parameter name
			"$test$i@=42",                                    // parameter name must be alphanumerical
			"$test$i=?",                                      // parameter value must be alphanumerical
			"$test$i",                                        // missing parameter value and delimiter
			"$test$i=",                                       // missing parameter value
			"$test$i=$YXN1cmUu",                              // missing parameter value
			"$test$i=42$YXN1cmUr%w",                          // invalid character in salt
			"$test$i=42$YXN1cmUr%w$YW55IGNhcm5hbCBwbGVhc3Vy", // invalid character in salt
			"$test$i=42$YXN1cmUu$YW55IGNhcm5hbCBwbGVhc3V=",   // no padding allowed
			"$test$i=42$$YW55IGNhcm5hbCBwbGVhc3Vy",           // missing salt
		];
		for s in data.iter() {
			let phc = PHCData::from_str(s);
			assert!(phc.is_err());
		}
	}
}
