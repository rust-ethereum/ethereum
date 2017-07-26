use rlp::{RlpStream, Encodable, Decodable, Rlp, Prototype};
use std::ops::Deref;
use std::cmp::min;
use std::hash::{Hash, Hasher};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NibbleType {
    Leaf,
    Extension
}

#[derive(Debug, Clone)]
pub struct NibbleSlice<'a> {
    data: &'a [u8],
    start_odd: bool,
    end_odd: bool
}

impl<'a> Hash for NibbleSlice<'a> {
    fn hash<H: Hasher>(&self, state: &mut H) {
        for i in 0..self.len() {
            self.at(i).hash(state);
        }
    }
}

impl<'a> Eq for NibbleSlice<'a> { }

impl<'a> PartialEq for NibbleSlice<'a> {
    fn eq(&self, other: &NibbleSlice<'a>) -> bool {
        if self.len() != other.len() {
            return false;
        }

        for i in 0..self.len() {
            if self.at(i) != other.at(i) {
                return false;
            }
        }

        return true;
    }
}

impl<'a, 'view> NibbleSlice<'a> where 'a: 'view {
    pub fn decode(rlp: &Rlp<'a>) -> (Self, NibbleType) {
        let data = rlp.data();
        let start_odd = if data[0] & 0b00010000 == 0b00010000 { true } else { false };
        let is_leaf = data[0] & 0b00100000 == 0b00100000;

        (
            if start_odd {
                NibbleSlice {
                    data: data,
                    start_odd: true,
                    end_odd: false,
                }
            } else {
                NibbleSlice {
                    data: &data[1..],
                    start_odd: false,
                    end_odd: false,
                }
            },
            if is_leaf {
                NibbleType::Leaf
            } else {
                NibbleType::Extension
            }
        )
    }

    pub fn encode(&self, s: &mut RlpStream, typ: NibbleType) {
        let mut ret = Vec::new();
        if (self.start_odd && self.end_odd) || (!self.start_odd && !self.end_odd) {
            ret.push(0b00000000);

            for i in 0..self.len() {
                if i & 1 == 0 { // even
                    ret.push(self.at(i) << 4);
                } else {
                    let end = ret.len()-1;
                    ret[end] |= self.at(i);
                }
            }
        } else {
            ret.push(0b00010000);

            for i in 0..self.len() {
                if i & 1 == 0 { // even
                    let end = ret.len()-1;
                    ret[end] |= self.at(i);
                } else {
                    ret.push(self.at(i) << 4);
                }
            }
        }

        ret[0] |= match typ {
            NibbleType::Leaf => 0b00100000,
            NibbleType::Extension => 0b00000000
        };

        s.append(&ret);
    }

    pub fn sub(&'view self, from: usize, to: usize) -> Self { // Exclusive of to
        if from == to {
            return NibbleSlice {
                data: &[],
                start_odd: false,
                end_odd: false
            };
        }

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
            start_odd, end_odd
        }
    }

    pub fn new(key: &'a [u8]) -> Self {
        NibbleSlice {
            data: key,
            start_odd: false,
            end_odd: false
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

    pub fn starts_with(&self, other: &NibbleSlice) -> bool {
        if self.len() < other.len() {
            return false;
        }
        for i in 0..other.len() {
            if self.at(i) != other.at(i) {
                return false;
            }
        }
        return true;
    }

    pub fn common(&self, other: &NibbleSlice) -> NibbleSlice {
        let mut common_len = 0;

        for i in 0..min(self.len(), other.len()) {
            if self.at(i) == other.at(i) {
                common_len += 1;
            } else {
                break;
            }
        }

        self.sub(0, common_len)
    }
}
