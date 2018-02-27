//! Merkle nibble types.

use rlp::{RlpStream, Rlp};
use std::cmp::min;

/// Represents a nibble. A 16-variant value.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Nibble {
    N0, N1, N2, N3, N4, N5, N6, N7,
    N8, N9, N10, N11, N12, N13, N14, N15,
}

impl From<usize> for Nibble {
    fn from(val: usize) -> Nibble {
        match val {
            0 => Nibble::N0, 1 => Nibble::N1, 2 => Nibble::N2, 3 =>
            Nibble::N3, 4 => Nibble::N4, 5 => Nibble::N5, 6 =>
            Nibble::N6, 7 => Nibble::N7, 8 => Nibble::N8, 9 =>
            Nibble::N9, 10 => Nibble::N10, 11 => Nibble::N11, 12 =>
            Nibble::N12, 13 => Nibble::N13, 14 => Nibble::N14, 15 =>
            Nibble::N15, _ => panic!(),
        }
    }
}

impl Into<usize> for Nibble {
    fn into(self) -> usize {
        match self {
            Nibble::N0 => 0, Nibble::N1 => 1, Nibble::N2 => 2,
            Nibble::N3 => 3, Nibble::N4 => 4, Nibble::N5 => 5,
            Nibble::N6 => 6, Nibble::N7 => 7, Nibble::N8 => 8,
            Nibble::N9 => 9, Nibble::N10 => 10, Nibble::N11 => 11,
            Nibble::N12 => 12, Nibble::N13 => 13, Nibble::N14 => 14,
            Nibble::N15 => 15,
        }
    }
}

impl From<u8> for Nibble {
    fn from(val: u8) -> Nibble {
        match val {
            0 => Nibble::N0, 1 => Nibble::N1, 2 => Nibble::N2, 3 =>
            Nibble::N3, 4 => Nibble::N4, 5 => Nibble::N5, 6 =>
            Nibble::N6, 7 => Nibble::N7, 8 => Nibble::N8, 9 =>
            Nibble::N9, 10 => Nibble::N10, 11 => Nibble::N11, 12 =>
            Nibble::N12, 13 => Nibble::N13, 14 => Nibble::N14, 15 =>
            Nibble::N15, _ => panic!(),
        }
    }
}

impl Into<u8> for Nibble {
    fn into(self) -> u8 {
        match self {
            Nibble::N0 => 0, Nibble::N1 => 1, Nibble::N2 => 2,
            Nibble::N3 => 3, Nibble::N4 => 4, Nibble::N5 => 5,
            Nibble::N6 => 6, Nibble::N7 => 7, Nibble::N8 => 8,
            Nibble::N9 => 9, Nibble::N10 => 10, Nibble::N11 => 11,
            Nibble::N12 => 12, Nibble::N13 => 13, Nibble::N14 => 14,
            Nibble::N15 => 15,
        }
    }
}

/// A nibble type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NibbleType {
    Leaf,
    Extension
}

/// A nibble vector.
pub type NibbleVec = Vec<Nibble>;
/// A nibble slice.
pub type NibbleSlice<'a> = &'a [Nibble];

/// Given a key, return the corresponding nibble.
pub fn from_key(key: &[u8]) -> NibbleVec {
    let mut vec = NibbleVec::new();

    for i in 0..(key.len()*2) {
        if i & 1 == 0 { // even
            vec.push(((key[i / 2] & 0xf0) >> 4).into());
        } else {
            vec.push((key[i / 2] & 0x0f).into());
        }
    }

    vec
}

/// Given a nibble, return the corresponding key.
pub fn into_key(nibble: NibbleSlice) -> Vec<u8> {
    let mut ret = Vec::new();

    for i in 0..nibble.len() {
        if i & 1 == 0 { // even
            let value: u8 = nibble[i].into();
            ret.push(value << 4);
        } else {
            let value: u8 = nibble[i].into();
            ret[i / 2] |= value;
        }
    }

    ret
}

/// Decode a nibble from RLP.
pub fn decode(rlp: &Rlp) -> (NibbleVec, NibbleType) {
    let mut vec = NibbleVec::new();

    let data = rlp.data();
    let start_odd = if data[0] & 0b00010000 == 0b00010000 { true } else { false };
    let start_index = if start_odd { 1 } else { 2 };
    let is_leaf = data[0] & 0b00100000 == 0b00100000;

    let len = data.len() * 2;

    for i in start_index..len {
        if i & 1 == 0 { // even
            vec.push(((data[i / 2] & 0xf0) >> 4).into());
        } else {
            vec.push((data[i / 2] & 0x0f).into());
        }
    }

    (vec, if is_leaf { NibbleType::Leaf } else { NibbleType::Extension })
}

/// Encode a nibble into the given RLP stream.
pub fn encode(vec: NibbleSlice, typ: NibbleType, s: &mut RlpStream) {
    let mut ret: Vec<u8> = Vec::new();

    if vec.len() & 1 == 0 { // even
        ret.push(0b00000000);

        for i in 0..vec.len() {
            if i & 1 == 0 {
                let v: u8 = vec[i].into();
                ret.push(v << 4);
            } else {
                let end = ret.len() - 1;
                let v: u8 = vec[i].into();
                ret[end] |= v;
            }
        }
    } else {
        ret.push(0b00010000);

        for i in 0..vec.len() {
            if i & 1 == 0 {
                let end = ret.len() - 1;
                let v: u8 = vec[i].into();
                ret[end] |= v;
            } else {
                let v: u8 = vec[i].into();
                ret.push(v << 4);
            }
        }
    }

    ret[0] |= match typ {
        NibbleType::Leaf => 0b00100000,
        NibbleType::Extension => 0b00000000
    };

    s.append(&ret);
}

/// Common prefix for two nibbles.
pub fn common<'a, 'b>(a: NibbleSlice<'a>, b: NibbleSlice<'b>) -> NibbleSlice<'a> {
    let mut common_len = 0;

    for i in 0..min(a.len(), b.len()) {
        if a[i] == b[i] {
            common_len += 1;
        } else {
            break;
        }
    }

    &a[0..common_len]
}

/// Common prefix for two nibbles. Return the sub nibbles.
pub fn common_with_sub<'a, 'b>(
    a: NibbleSlice<'a>, b: NibbleSlice<'b>
) -> (NibbleSlice<'a>, NibbleVec, NibbleVec) {
    let common = common(a, b);
    let asub = a[common.len()..].into();
    let bsub = b[common.len()..].into();

    (common, asub, bsub)
}

/// Common prefix for all provided nibbles.
pub fn common_all<'a, T: Iterator<Item=NibbleSlice<'a>>>(mut iter: T) -> NibbleSlice<'a> {
    let first = match iter.next() {
        Some(val) => val,
        None => return &[],
    };
    let second = match iter.next() {
        Some(val) => val,
        None => return first,
    };

    let mut common_cur = common(first, second);
    for key in iter {
        common_cur = common(common_cur, key);
    }

    common_cur
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn from_into_key() {
        let key = vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 244, 233, 188];

        assert_eq!(key, into_key(&from_key(&key)));
    }
}
