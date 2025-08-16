#[doc(hidden)]
#[macro_export]
macro_rules! deref_ptr {
	($cfg: ident, $ret: expr) => {{
		if $cfg.is_null() {
			return $ret;
		} else {
			unsafe { &*$cfg }
		}
	}};
}

#[doc(hidden)]
#[macro_export]
macro_rules! deref_ptr_mut {
	($cfg: ident, $ret: expr) => {{
		if $cfg.is_null() {
			return $ret;
		} else {
			unsafe { &mut *$cfg }
		}
	}};
}

#[doc(hidden)]
#[macro_export]
macro_rules! get_slice {
	($buff: expr, $buff_size: expr) => {{ unsafe { std::slice::from_raw_parts($buff, $buff_size).to_owned() } }};
}

#[doc(hidden)]
#[macro_export]
macro_rules! get_slice_mut {
	($buff: expr, $buff_size: expr) => {{ unsafe { std::slice::from_raw_parts_mut($buff, $buff_size) } }};
}

#[doc(hidden)]
#[macro_export]
macro_rules! get_string {
	($ptr: expr) => {{ unsafe { String::from_utf8(CStr::from_ptr($ptr).to_bytes().to_vec()).unwrap() } }};
}

#[doc(hidden)]
#[macro_export]
macro_rules! get_value_or_errno {
	($val: expr) => {{
		match $val {
			Ok(v) => v,
			Err(errno) => return errno,
		}
	}};
}

#[doc(hidden)]
#[macro_export]
macro_rules! get_value_or_false {
	($val: expr) => {{
		match $val {
			Ok(v) => v,
			Err(_) => return 0,
		}
	}};
}
