mod nibble;

pub use self::nibble::{NibbleSlice, LeafNibbleSlice, ExtensionNibbleSlice};

use rlp::{self, RlpStream, Encodable, Decodable, Rlp, Prototype};
use bigint::H256;
use std::borrow::Borrow;

#[derive(Debug, PartialEq, Eq)]
pub enum MerkleNode<'a> {
    Blank,
    Leaf(LeafNibbleSlice<'a>, &'a [u8]),
    Extension(ExtensionNibbleSlice<'a>, MerkleValue<'a>),
    Branch([MerkleValue<'a>; 16], Option<&'a [u8]>),
}

impl<'a> MerkleNode<'a> {
    pub fn decode(rlp: &Rlp<'a>) -> Self {
        match rlp.prototype() {
            Prototype::Data(0) => MerkleNode::Blank,
            Prototype::List(2) => {
                let nibble = NibbleSlice::decode(&rlp.at(0));
                if nibble.is_leaf() {
                    let nibble = LeafNibbleSlice::from_generic(nibble);
                    MerkleNode::Leaf(nibble, rlp.at(1).data())
                } else {
                    let nibble = ExtensionNibbleSlice::from_generic(nibble);
                    MerkleNode::Extension(nibble, MerkleValue::decode(&rlp.at(1)))
                }
            },
            Prototype::List(17) => {
                let mut nodes = [MerkleValue::Empty, MerkleValue::Empty,
                                 MerkleValue::Empty, MerkleValue::Empty,
                                 MerkleValue::Empty, MerkleValue::Empty,
                                 MerkleValue::Empty, MerkleValue::Empty,
                                 MerkleValue::Empty, MerkleValue::Empty,
                                 MerkleValue::Empty, MerkleValue::Empty,
                                 MerkleValue::Empty, MerkleValue::Empty,
                                 MerkleValue::Empty, MerkleValue::Empty];
                for i in 0..16 {
                    nodes[i] = MerkleValue::decode(&rlp.at(i));
                }
                let value = if rlp.at(16).is_empty() {
                    None
                } else {
                    Some(rlp.at(16).data())
                };
                MerkleNode::Branch(nodes, value)
            },
            _ => panic!(),
        }
    }

    pub fn inlinable(&self) -> bool {
        rlp::encode(self).to_vec().len() < 32
    }
}

impl<'a> Encodable for MerkleNode<'a> {
    fn rlp_append(&self, s: &mut RlpStream) {
        match self {
            &MerkleNode::Blank => {
                s.append_empty_data();
            },
            &MerkleNode::Leaf(ref nibble, ref value) => {
                s.begin_list(2);
                s.append(nibble);
                s.append(value);
            },
            &MerkleNode::Extension(ref nibble, ref value) => {
                s.begin_list(2);
                s.append(nibble);
                s.append(value);
            },
            &MerkleNode::Branch(ref nodes, ref value) => {
                s.begin_list(17);
                for i in 0..16 {
                    s.append(&nodes[i]);
                }
                match value {
                    &Some(ref value) => s.append(value),
                    &None => s.append_empty_data(),
                };
            }
        }
    }
}

#[derive(Debug, Eq, PartialEq)]
pub enum MerkleValue<'a> {
    Empty,
    Full(Box<MerkleNode<'a>>),
    Hash(H256),
}

impl<'a> MerkleValue<'a> {
    pub fn decode(rlp: &Rlp<'a>) -> Self {
        if rlp.is_empty() {
            return MerkleValue::Empty;
        }

        if rlp.size() == 32 {
            return MerkleValue::Hash(rlp.as_val());
        }

        if rlp.size() < 32 {
            return MerkleValue::Full(Box::new(MerkleNode::decode(rlp)));
        }

        panic!();
    }
}

impl<'a> Encodable for MerkleValue<'a> {
    fn rlp_append(&self, s: &mut RlpStream) {
        match self {
            &MerkleValue::Empty => {
                s.append_empty_data();
            },
            &MerkleValue::Full(ref node) => {
                debug_assert!(node.inlinable());
                let node: &MerkleNode = node.borrow();
                s.append(node);
            },
            &MerkleValue::Hash(ref hash) => {
                s.append(hash);
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use rlp::{self, Rlp};
    use super::{LeafNibbleSlice, MerkleNode};

    #[test]
    fn encode_decode() {
        let key = [6, 7, 8, 9, 10, 11, 12, 13, 14, 15];
        let val = [1, 2, 3, 4, 5];
        let node = MerkleNode::Leaf(LeafNibbleSlice::new(&key), &val);
        let rlp_raw = rlp::encode(&node);
        let decoded_node: MerkleNode = MerkleNode::decode(&Rlp::new(&rlp_raw));
        assert_eq!(node, decoded_node);
    }
}
