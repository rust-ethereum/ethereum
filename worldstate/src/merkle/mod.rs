mod nibble;
mod node;

pub use self::nibble::{NibbleSlice, NibbleType};
pub use self::node::{MerkleNode, MerkleValue};

use crypto::keccak256;
use rlp;
use std::collections::HashMap;
use std::cmp::min;

pub fn build<'a>(map: &HashMap<NibbleSlice<'a>, &'a [u8]>) -> MerkleNode<'a> {
    if map.len() == 0 {
        panic!();
    }

    if map.len() == 1 {
        let key = map.keys().next().unwrap();
        return MerkleNode::Leaf(key.clone(), map.get(&key).unwrap().clone());
    }

    let common = {
        let mut iter = map.keys();

        let mut common = iter.next().unwrap().common(iter.next().unwrap());
        for key in iter {
            common = common.common(key);
        }

        common
    };

    if common.len() > 0 {
        let mut sub_map = HashMap::new();
        for (key, value) in map {
            sub_map.insert(key.sub(common.len(), key.len()), value.clone());
        }
        let node = build(&sub_map);
        let value = if node.inlinable() {
            MerkleValue::Full(Box::new(node))
        } else {
            MerkleValue::Hash(keccak256(&rlp::encode(&node).to_vec()))
        };
        return MerkleNode::Extension(common, value);
    }

    let mut nodes = [MerkleValue::Empty, MerkleValue::Empty,
                     MerkleValue::Empty, MerkleValue::Empty,
                     MerkleValue::Empty, MerkleValue::Empty,
                     MerkleValue::Empty, MerkleValue::Empty,
                     MerkleValue::Empty, MerkleValue::Empty,
                     MerkleValue::Empty, MerkleValue::Empty,
                     MerkleValue::Empty, MerkleValue::Empty,
                     MerkleValue::Empty, MerkleValue::Empty];

    for i in 0..16 {
        let mut sub_map = HashMap::new();
        for (key, value) in map {
            if key.at(0) == i as u8 {
                sub_map.insert(key.sub(1, key.len()), value.clone());
            }
        }
        let node = build(&sub_map);
        let value = if node.inlinable() {
            MerkleValue::Full(Box::new(node))
        } else {
            MerkleValue::Hash(keccak256(&rlp::encode(&node).to_vec()))
        };
        nodes[i] = value;
    }

    let additional = {
        let mut additional = None;
        for (key, value) in map {
            if key.len() == 0 {
                additional = Some(value.clone())
            }
        }
        additional
    };

    return MerkleNode::Branch(nodes, additional);
}
