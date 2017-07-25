use rlp::{RlpStream, Encodable, Decodable, Rlp, Prototype};
use std::ops::Deref;

pub struct NibbleSlice<'a> {
    data: &'a [u8],
    start_odd: bool,
    end_odd: bool,
    is_leaf: bool,
}

impl<'a, 'view> NibbleSlice<'a> where 'a: 'view {
    pub fn is_leaf(&self) -> bool {
        self.is_leaf
    }

    pub fn decode(rlp: &Rlp<'a>) -> Self {
        let data = rlp.data();
        let start_odd = if data[0] & 16 == 16 { true } else { false };
        let is_leaf = data[0] & 32 == 32;

        if start_odd {
            NibbleSlice {
                data: data,
                start_odd: true,
                end_odd: false,
                is_leaf
            }
        } else {
            NibbleSlice {
                data: &data[1..],
                start_odd: false,
                end_odd: false,
                is_leaf
            }
        }
    }

    pub fn sub_slice(&'view self, from: usize, to: usize, is_leaf: bool) -> Self { // Exclusive of to
        let to = to - 1; // Turn it to inclusive of to.
        assert!(from <= to && from < self.len() && to < self.len());

        let start_i = (from + if self.start_odd { 1 } else { 0 }) / 2;
        let end_i = (to + if self.start_odd { 1 } else { 0 }) / 2;

        let start_odd = if from & 1 == 1 && self.start_odd {
            false
        } else if from & 1 == 1 && !self.start_odd {
            true
        } else if from & 1 == 0 && self.start_odd {
            true
        } else {
            false
        };
        let end_odd = if to & 1 == 1 && self.start_odd {
            false
        } else if to & 1 == 1 && !self.start_odd {
            true
        } else if to & 1 == 0 && self.start_odd {
            true
        } else {
            false
        };

        NibbleSlice {
            data: &self.data[start_i..(end_i+1)],
            start_odd, end_odd, is_leaf
        }
    }

    pub fn sub_leaf(&'view self, from: usize, to: usize) -> LeafNibbleSlice<'a> {
        LeafNibbleSlice::from_generic(self.sub_slice(from, to, true))
    }

    pub fn sub_extension(&'view self, from: usize, to: usize) -> ExtensionNibbleSlice<'a> {
        ExtensionNibbleSlice::from_generic(self.sub_slice(from, to, false))
    }

    pub fn new(key: &'a [u8], is_leaf: bool) -> Self {
        NibbleSlice {
            data: key,
            start_odd: false,
            end_odd: false,
            is_leaf
        }
    }

    pub fn len(&self) -> usize {
        self.data.len() * 2 -
            if self.start_odd { 1 } else { 0 } -
            if self.end_odd { 1 } else { 0 }
    }

    pub fn at(&self, pos: usize) -> u8 {
        assert!(pos < self.len());
        if self.start_odd {
            if pos & 1 == 0 { // even
                self.data[(pos + 1) / 2] & 0x0f
            } else {
                (self.data[(pos + 1) / 2] & 0xf0) >> 4
            }
        } else {
            if pos & 1 == 0 { // even
                (self.data[pos / 2] & 0xf0) >> 4
            } else {
                self.data[pos / 2] & 0x0f
            }
        }
    }
}

impl<'a> Encodable for NibbleSlice<'a> {
    fn rlp_append(&self, s: &mut RlpStream) {
        let mut ret = Vec::new();
        if (self.start_odd && self.end_odd) || (!self.start_odd && !self.end_odd) {
            ret.push(0b00000000);

            for i in 0..self.len() {
                if i & 1 == 0 { // even
                    ret.push(self.at(i) << 4);
                } else {
                    let end = ret.len()-1;
                    ret[end] &= self.at(i);
                }
            }
        } else {
            ret.push(0b00010000);

            for i in 0..self.len() {
                if i & 1 == 0 { // even
                    let end = ret.len()-1;
                    ret[end] &= self.at(i);
                } else {
                    ret.push(self.at(i) << 4);
                }
            }
        }

        ret[0] &= if self.is_leaf {
            0b00100000
        } else {
            0b00000000
        };

        s.append(&ret);
    }
}

pub struct LeafNibbleSlice<'a>(NibbleSlice<'a>);

impl<'a> LeafNibbleSlice<'a> {
    pub fn from_generic(n: NibbleSlice<'a>) -> Self {
        assert!(n.is_leaf);
        LeafNibbleSlice(n)
    }

    pub fn new(key: &'a [u8]) -> Self {
        LeafNibbleSlice(NibbleSlice::new(key, true))
    }
}

impl<'a> Encodable for LeafNibbleSlice<'a> {
    fn rlp_append(&self, s: &mut RlpStream) {
        self.0.rlp_append(s)
    }
}

impl<'a> Deref for LeafNibbleSlice<'a> {
    type Target = NibbleSlice<'a>;

    fn deref(&self) -> &NibbleSlice<'a> {
        &self.0
    }
}

pub struct ExtensionNibbleSlice<'a>(NibbleSlice<'a>);

impl<'a> ExtensionNibbleSlice<'a> {
    pub fn from_generic(n: NibbleSlice<'a>) -> Self {
        assert!(!n.is_leaf);
        ExtensionNibbleSlice(n)
    }

    pub fn new(key: &'a [u8]) -> Self {
        ExtensionNibbleSlice(NibbleSlice::new(key, false))
    }
}

impl<'a> Encodable for ExtensionNibbleSlice<'a> {
    fn rlp_append(&self, s: &mut RlpStream) {
        self.0.rlp_append(s)
    }
}

impl<'a> Deref for ExtensionNibbleSlice<'a> {
    type Target = NibbleSlice<'a>;

    fn deref(&self) -> &NibbleSlice<'a> {
        &self.0
    }
}
