use crate::pass::LengthCalculationMethod;
use std::io::Cursor;
use unicode_reader::{CodePoints, Graphemes};

pub(crate) fn password_length(password: &str, method: LengthCalculationMethod) -> usize {
	match method {
		LengthCalculationMethod::Bytes => password.len(),
		LengthCalculationMethod::Characters => {
			let mut len = 0;
			for _ in password.chars() {
				len += 1;
			}
			len
		}
		LengthCalculationMethod::CodePoints => CodePoints::from(Cursor::new(password)).count(),
		LengthCalculationMethod::Graphemes => Graphemes::from(Cursor::new(password)).count(),
	}
}
