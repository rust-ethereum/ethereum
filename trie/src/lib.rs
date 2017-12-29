extern crate bigint;
extern crate rlp;
extern crate sha3;
#[cfg(test)] extern crate hexutil;

use bigint::H256;
use rlp::Rlp;
use sha3::{Digest, Keccak256};
use std::collections::HashMap;
use merkle::{MerkleValue, MerkleNode};
use merkle::nibble::{self, NibbleVec, NibbleSlice, Nibble};

macro_rules! empty_nodes {
    () => (
        [MerkleValue::Empty, MerkleValue::Empty,
         MerkleValue::Empty, MerkleValue::Empty,
         MerkleValue::Empty, MerkleValue::Empty,
         MerkleValue::Empty, MerkleValue::Empty,
         MerkleValue::Empty, MerkleValue::Empty,
         MerkleValue::Empty, MerkleValue::Empty,
         MerkleValue::Empty, MerkleValue::Empty,
         MerkleValue::Empty, MerkleValue::Empty]
    )
}

macro_rules! empty_trie_hash {
    () => {
        {
            use std::str::FromStr;

            H256::from_str("0x56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421").unwrap()
        }
    }
}

pub mod merkle;
mod ops;

pub trait DatabaseHandle {
    fn get<'a>(&'a self, key: H256) -> &'a [u8];
}

pub struct Change {
    pub adds: Vec<(H256, Vec<u8>)>,
    pub removes: Vec<H256>,
}

impl Default for Change {
    fn default() -> Self {
        Change {
            adds: Vec::new(),
            removes: Vec::new(),
        }
    }
}

impl Change {
    pub fn add_raw(&mut self, key: H256, value: Vec<u8>) {
        self.adds.push((key, value));
    }

    pub fn add_node<'a, 'b, 'c>(&'a mut self, node: &'c MerkleNode<'b>) {
        let subnode = rlp::encode(node).to_vec();
        let hash = H256::from(Keccak256::digest(&subnode).as_slice());
        self.adds.push((hash, subnode));
    }

    pub fn add_value<'a, 'b, 'c>(&'a mut self, node: &'c MerkleNode<'b>) -> MerkleValue<'b> {
        if node.inlinable() {
            MerkleValue::Full(Box::new(node.clone()))
        } else {
            let subnode = rlp::encode(node).to_vec();
            let hash = H256::from(Keccak256::digest(&subnode).as_slice());
            self.adds.push((hash, subnode));
            MerkleValue::Hash(hash)
        }
    }

    pub fn remove_raw(&mut self, key: H256) {
        self.removes.push(key)
    }

    pub fn remove_node<'a, 'b, 'c>(&'a mut self, node: &'c MerkleNode<'b>) -> bool {
        if node.inlinable() {
            false
        } else {
            let subnode = rlp::encode(node).to_vec();
            let hash = H256::from(Keccak256::digest(&subnode).as_slice());
            self.removes.push(hash);
            true
        }
    }

    pub fn merge(&mut self, other: &Change) {
        for v in &other.adds {
            self.adds.push(v.clone());
        }

        for v in &other.removes {
            self.removes.push(v.clone());
        }
    }
}

#[derive(Clone, Debug)]
pub struct Trie<D: DatabaseHandle> {
    database: D,
    root: H256,
}

impl<D: DatabaseHandle> Trie<D> {
    pub fn empty(database: D) -> Self {
        Self {
            database,
            root: empty_trie_hash!()
        }
    }

    pub fn existing(database: D, root: H256) -> Self {
        if root == empty_trie_hash!() {
            return Self::empty(database);
        }

        Self {
            database,
            root
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{DatabaseGuard, Trie};
    use std::collections::HashMap;
    use std::str::FromStr;
    use std::cell::UnsafeCell;
    use bigint::H256;
    use hexutil::read_hex;

    #[test]
    fn trie_middle_leaf() {
        let mut map = HashMap::new();
        map.insert("key1aa".as_bytes().into(), "0123456789012345678901234567890123456789xxx".as_bytes().into());
        map.insert("key1".as_bytes().into(), "0123456789012345678901234567890123456789Very_Long".as_bytes().into());
        map.insert("key2bb".as_bytes().into(), "aval3".as_bytes().into());
        map.insert("key2".as_bytes().into(), "short".as_bytes().into());
        map.insert("key3cc".as_bytes().into(), "aval3".as_bytes().into());
        map.insert("key3".as_bytes().into(), "1234567890123456789012345678901".as_bytes().into());

        let mut database: HashMap<H256, Vec<u8>> = HashMap::new();
        let mut trie: Trie<HashMap<H256, Vec<u8>>> = Trie::build(database, &map);

        assert_eq!(trie.root(), H256::from_str("0xcb65032e2f76c48b82b5c24b3db8f670ce73982869d38cd39a624f23d62a9e89").unwrap());
        assert_eq!(trie.get_raw("key2bb".as_bytes()), Some("aval3".as_bytes().into()));
        assert_eq!(trie.get_raw("key2bbb".as_bytes()), None);
        let prev_hash = trie.root();
        trie.insert_raw("key2bbb".as_bytes().into(), "aval4".as_bytes().into());
        assert_eq!(trie.get_raw("key2bbb".as_bytes()), Some("aval4".as_bytes().into()));
        trie.remove_raw("key2bbb".as_bytes());
        assert_eq!(trie.get_raw("key2bbb".as_bytes()), None);
        assert_eq!(prev_hash, trie.root());
    }

    #[test]
    fn insert_middle_leaf() {
        let mut database: HashMap<H256, Vec<u8>> = HashMap::new();
        let mut trie = Trie::empty(database);

        trie.insert_raw("key1aa".as_bytes().into(),
                        "0123456789012345678901234567890123456789xxx".as_bytes().into());
        trie.insert_raw("key1".as_bytes().into(),
                        "0123456789012345678901234567890123456789Very_Long".as_bytes().into());
        trie.insert_raw("key2bb".as_bytes().into(),
                        "aval3".as_bytes().into());
        trie.insert_raw("key2".as_bytes().into(),
                        "short".as_bytes().into());
        trie.insert_raw("key3cc".as_bytes().into(),
                        "aval3".as_bytes().into());
        trie.insert_raw("key3".as_bytes().into(),
                        "1234567890123456789012345678901".as_bytes().into());
        assert_eq!(trie.root(), H256::from_str("0xcb65032e2f76c48b82b5c24b3db8f670ce73982869d38cd39a624f23d62a9e89").unwrap());
    }

    #[test]
    fn insert_animals() {
        let mut database: HashMap<H256, Vec<u8>> = HashMap::new();
        let mut trie = Trie::empty(database);

        trie.insert_raw("doe".as_bytes().into(),
                        "reindeer".as_bytes().into());
        trie.insert_raw("dog".as_bytes().into(),
                        "puppy".as_bytes().into());
        trie.insert_raw("dogglesworth".as_bytes().into(),
                        "cat".as_bytes().into());

        let mut all_key_values: HashMap<Vec<u8>, Vec<u8>> = HashMap::new();
        all_key_values.insert("doe".as_bytes().into(), "reindeer".as_bytes().into());
        all_key_values.insert("dog".as_bytes().into(), "puppy".as_bytes().into());
        all_key_values.insert("dogglesworth".as_bytes().into(), "cat".as_bytes().into());

        for (key, value) in trie.iter() {
            assert_eq!(all_key_values.get(&key), Some(&value));
            all_key_values.remove(&key);
        }

        assert_eq!(trie.root(), H256::from_str("0x8aad789dff2f538bca5d8ea56e8abe10f4c7ba3a5dea95fea4cd6e7c3a1168d3").unwrap());
    }

    #[test]
    fn insert_single_item() {
        let mut database: HashMap<H256, Vec<u8>> = HashMap::new();
        let mut trie = Trie::empty(database);

        trie.insert_raw("A".as_bytes().into(),
                    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".as_bytes().into());

        assert_eq!(trie.root(), H256::from_str("0xd23786fb4a010da3ce639d66d5e904a11dbc02746d1ce25029e53290cabf28ab").unwrap());
    }

    #[test]
    fn testy() {
        let mut database: HashMap<H256, Vec<u8>> = HashMap::new();
        let mut trie = Trie::empty(database);

        trie.insert_raw("test".as_bytes().into(),
                        "test".as_bytes().into());
        trie.insert_raw("te".as_bytes().into(),
                        "testy".as_bytes().into());

        assert_eq!(trie.root(), H256::from_str("0x8452568af70d8d140f58d941338542f645fcca50094b20f3c3d8c3df49337928").unwrap());
    }

    #[test]
    fn sub_genesis() {
        let mut database: HashMap<H256, Vec<u8>> = HashMap::new();
        let mut trie = Trie::empty(database);

        let k1 = read_hex("0x204188718653cd7e50f3fd51a820db66112517ca190c637e7cdd80782d56").unwrap();
        let v1 = vec![248, 78, 128, 138, 21, 45, 2, 199, 225, 74, 246, 128, 0, 0, 160, 86, 232, 31, 23, 27, 204, 85, 166, 255, 131, 69, 230, 146, 192, 248, 110, 91, 72, 224, 27, 153, 108, 173, 192, 1, 98, 47, 181, 227, 99, 180, 33, 160, 197, 210, 70, 1, 134, 247, 35, 60, 146, 126, 125, 178, 220, 199, 3, 192, 229, 0, 182, 83, 202, 130, 39, 59, 123, 250, 216, 4, 93, 133, 164, 112];
        let k2 = read_hex("0xa390953f116afb00f89fbedb2f8e77297e4e7e1749e2ef0e32e17808e4ad").unwrap();
        let v2 = vec![248, 77, 128, 137, 108, 107, 147, 91, 139, 189, 64, 0, 0, 160, 86, 232, 31, 23, 27, 204, 85, 166, 255, 131, 69, 230, 146, 192, 248, 110, 91, 72, 224, 27, 153, 108, 173, 192, 1, 98, 47, 181, 227, 99, 180, 33, 160, 197, 210, 70, 1, 134, 247, 35, 60, 146, 126, 125, 178, 220, 199, 3, 192, 229, 0, 182, 83, 202, 130, 39, 59, 123, 250, 216, 4, 93, 133, 164, 112];

        trie.insert_raw(k1, v1);
        trie.insert_raw(k2, v2);

        assert_eq!(trie.root(), H256::from_str("bcb5ffb5c6c3e43ef07550fa30af86d66b4015ee3f64aaf70cd0bf8fcc60a9c6").unwrap());
    }

    #[test]
    fn trie_insert() {
        let mut map = HashMap::new();

        let mut database: HashMap<H256, Vec<u8>> = HashMap::new();
        let mut trie: Trie<HashMap<H256, Vec<u8>>> = Trie::build(database, &map);

        trie.insert_raw("foo".as_bytes().into(), "bar".as_bytes().into());
        trie.insert_raw("food".as_bytes().into(), "bass".as_bytes().into());

        assert_eq!(trie.root(), H256::from_str("0x17beaa1648bafa633cda809c90c04af50fc8aed3cb40d16efbddee6fdf63c4c3").unwrap());
    }

    #[test]
    fn trie_delete() {
        let mut map = HashMap::new();

        let mut database: HashMap<H256, Vec<u8>> = HashMap::new();
        let mut trie: Trie<HashMap<H256, Vec<u8>>> = Trie::build(database, &map);

        trie.insert_raw("fooa".as_bytes().into(), "bar".as_bytes().into());
        trie.insert_raw("food".as_bytes().into(), "bass".as_bytes().into());
        let prev_hash = trie.root();
        trie.insert_raw("fooc".as_bytes().into(), "basss".as_bytes().into());
        trie.remove_raw("fooc".as_bytes());
        assert_eq!(trie.root(), prev_hash);
    }

    #[test]
    fn trie_empty() {
        let mut map = HashMap::new();

        let mut database: HashMap<H256, Vec<u8>> = HashMap::new();
        let mut trie: Trie<HashMap<H256, Vec<u8>>> = Trie::build(database, &map);

        assert_eq!(H256::from("0x56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421"),
                   trie.root());
    }
}
