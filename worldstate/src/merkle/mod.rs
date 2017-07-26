mod nibble;
mod node;

pub use self::nibble::{NibbleSlice, NibbleType};
pub use self::node::{MerkleNode, MerkleValue};

use crypto::keccak256;
use rlp;
use bigint::H256;
use std::collections::HashMap;
use std::cmp::min;

pub fn build_hash<'a>(map: &HashMap<&'a [u8], &'a [u8]>) -> H256 {
    let mut node_map = HashMap::new();

    for (key, value) in map {
        node_map.insert(NibbleSlice::new(key), value.clone());
    }

    let node = build_node(&node_map);

    keccak256(&rlp::encode(&node).to_vec())
}

pub fn build_node<'a>(map: &HashMap<NibbleSlice<'a>, &'a [u8]>) -> MerkleNode<'a> {
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
        debug_assert!(sub_map.len() > 0);
        let node = build_node(&sub_map);
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
        let value = if sub_map.len() == 0 {
            MerkleValue::Empty
        } else {
            let node = build_node(&sub_map);
            if node.inlinable() {
                MerkleValue::Full(Box::new(node))
            } else {
                MerkleValue::Hash(keccak256(&rlp::encode(&node).to_vec()))
            }
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

#[cfg(test)]
mod tests {
    use super::{build_node, build_hash};
    use std::collections::HashMap;
    use std::str::FromStr;
    use bigint::H256;

    #[test]
    fn test_simple_hash() {
        let key1 = [1, 2, 3, 4, 5, 6, 7, 8];
        let value1 = [9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20];

        let key2 = [1, 2, 3, 5, 6, 7, 8, 9];
        let value2 = [9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20];

        let key3 = [1, 2, 4, 5, 6, 7, 8, 9];
        let value3 = [9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20];

        let mut map = HashMap::new();
        map.insert(key1.as_ref(), value1.as_ref());
        map.insert(key2.as_ref(), value2.as_ref());
        map.insert(key3.as_ref(), value3.as_ref());

        assert_eq!(build_hash(&map), H256::from_str("0x93449281d65dfbf69fa473311939d18595cbbb9e7f7a41ad10d7e62407561816").unwrap());
    }
}
