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
            if key.len() > 0 && key.at(0) == i as u8 {
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
    use etcommon_util::read_hex;

    #[test]
    fn insert_middle_leaf() {
        let mut map = HashMap::new();
        map.insert("key1aa".as_bytes(), "0123456789012345678901234567890123456789xxx".as_bytes());
        map.insert("key1".as_bytes(), "0123456789012345678901234567890123456789Very_Long".as_bytes());
        map.insert("key2bb".as_bytes(), "aval3".as_bytes());
        map.insert("key2".as_bytes(), "short".as_bytes());
        map.insert("key3cc".as_bytes(), "aval3".as_bytes());
        map.insert("key3".as_bytes(), "1234567890123456789012345678901".as_bytes());

        assert_eq!(build_hash(&map), H256::from_str("0xcb65032e2f76c48b82b5c24b3db8f670ce73982869d38cd39a624f23d62a9e89").unwrap());
    }

    #[test]
    fn single_item() {
        let mut map = HashMap::new();
        map.insert("A".as_bytes(), "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".as_bytes());

        assert_eq!(build_hash(&map), H256::from_str("0xd23786fb4a010da3ce639d66d5e904a11dbc02746d1ce25029e53290cabf28ab").unwrap());
    }

    #[test]
    fn foo() {
        let mut map = HashMap::new();
        map.insert("foo".as_bytes(), "bar".as_bytes());
        map.insert("food".as_bytes(), "bass".as_bytes());

        assert_eq!(build_hash(&map), H256::from_str("0x17beaa1648bafa633cda809c90c04af50fc8aed3cb40d16efbddee6fdf63c4c3").unwrap());
    }

    #[test]
    fn testy() {
        let mut map = HashMap::new();
        map.insert("test".as_bytes(), "test".as_bytes());
        map.insert("te".as_bytes(), "testy".as_bytes());

        assert_eq!(build_hash(&map), H256::from_str("0x8452568af70d8d140f58d941338542f645fcca50094b20f3c3d8c3df49337928").unwrap());
    }

    #[test]
    fn sub_genesis() {
        let k1 = read_hex("0x204188718653cd7e50f3fd51a820db66112517ca190c637e7cdd80782d56").unwrap();
        let v1 = vec![248, 78, 128, 138, 21, 45, 2, 199, 225, 74, 246, 128, 0, 0, 160, 86, 232, 31, 23, 27, 204, 85, 166, 255, 131, 69, 230, 146, 192, 248, 110, 91, 72, 224, 27, 153, 108, 173, 192, 1, 98, 47, 181, 227, 99, 180, 33, 160, 197, 210, 70, 1, 134, 247, 35, 60, 146, 126, 125, 178, 220, 199, 3, 192, 229, 0, 182, 83, 202, 130, 39, 59, 123, 250, 216, 4, 93, 133, 164, 112];
        let k2 = read_hex("0xa390953f116afb00f89fbedb2f8e77297e4e7e1749e2ef0e32e17808e4ad").unwrap();
        let v2 = vec![248, 77, 128, 137, 108, 107, 147, 91, 139, 189, 64, 0, 0, 160, 86, 232, 31, 23, 27, 204, 85, 166, 255, 131, 69, 230, 146, 192, 248, 110, 91, 72, 224, 27, 153, 108, 173, 192, 1, 98, 47, 181, 227, 99, 180, 33, 160, 197, 210, 70, 1, 134, 247, 35, 60, 146, 126, 125, 178, 220, 199, 3, 192, 229, 0, 182, 83, 202, 130, 39, 59, 123, 250, 216, 4, 93, 133, 164, 112];

        let mut map = HashMap::new();
        map.insert(k1.as_slice(), v1.as_slice());
        map.insert(k2.as_slice(), v2.as_slice());

        assert_eq!(build_hash(&map), H256::from_str("bcb5ffb5c6c3e43ef07550fa30af86d66b4015ee3f64aaf70cd0bf8fcc60a9c6").unwrap());
    }
}
