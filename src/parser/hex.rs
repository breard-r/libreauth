/*
 * Copyright Rodolphe Breard (2017)
 * Author: Rodolphe Breard (2017)
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


use nom::{IResult,be_u8,is_hex_digit};

fn hex_ascii_to_val(c: u8) -> u8 {
    match c {
        b'0'...b'9' => c - b'0',
        b'a'...b'f' => c - b'a' + 10,
        b'A'...b'F' => c - b'A' + 10,
        _ => 0,
    }
}

named!(get_hex_char<u8>, verify!(be_u8, is_hex_digit));

named!(get_hex_couple<Vec<u8>>, count!(get_hex_char, 2));

named!(parse_hex_couple<u8>, map!(get_hex_couple, |v: Vec<u8>| hex_ascii_to_val(v[0]) * 16 + hex_ascii_to_val(v[1])));

named!(parse_hex_str<Vec<u8>>, fold_many0!(parse_hex_couple, Vec::new(), |mut acc: Vec<_>, item| {
     acc.push(item);
     acc
}));

pub fn from_hex(s: &String) -> Result<Vec<u8>, ()> {
    match parse_hex_str(s.as_str().as_bytes()) {
        IResult::Done(r, i) => {
            match r.len() {
                0 => Ok(i.to_vec()),
                _ => Err(()),
            }
        },
        _ => Err(()),
    }
}
