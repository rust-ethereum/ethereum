extern crate bigint;
extern crate rlp;
extern crate sha3;
#[cfg(test)] extern crate hexutil;

use bigint::H256;
use rlp::Rlp;
use sha3::{Digest, Keccak256};
use std::collections::{HashMap, HashSet};
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
mod memory;

use ops::{insert, delete, build, get};

pub use memory::SingletonMemoryTrieMut;

pub trait DatabaseHandle {
    fn get<'a>(&'a self, key: H256) -> &'a [u8];
}

pub struct Change {
    pub adds: HashMap<H256, Vec<u8>>,
    pub removes: HashSet<H256>,
}

impl Default for Change {
    fn default() -> Self {
        Change {
            adds: HashMap::new(),
            removes: HashSet::new(),
        }
    }
}

impl Change {
    pub fn add_raw(&mut self, key: H256, value: Vec<u8>) {
        self.adds.insert(key, value);
        self.removes.remove(&key);
    }

    pub fn add_node<'a, 'b, 'c>(&'a mut self, node: &'c MerkleNode<'b>) {
        let subnode = rlp::encode(node).to_vec();
        let hash = H256::from(Keccak256::digest(&subnode).as_slice());
        self.add_raw(hash, subnode);
    }

    pub fn add_value<'a, 'b, 'c>(&'a mut self, node: &'c MerkleNode<'b>) -> MerkleValue<'b> {
        if node.inlinable() {
            MerkleValue::Full(Box::new(node.clone()))
        } else {
            let subnode = rlp::encode(node).to_vec();
            let hash = H256::from(Keccak256::digest(&subnode).as_slice());
            self.add_raw(hash, subnode);
            MerkleValue::Hash(hash)
        }
    }

    pub fn remove_raw(&mut self, key: H256) {
        self.adds.remove(&key);
        self.removes.insert(key);
    }

    pub fn remove_node<'a, 'b, 'c>(&'a mut self, node: &'c MerkleNode<'b>) -> bool {
        if node.inlinable() {
            false
        } else {
            let subnode = rlp::encode(node).to_vec();
            let hash = H256::from(Keccak256::digest(&subnode).as_slice());
            self.remove_raw(hash);
            true
        }
    }

    pub fn merge(&mut self, other: &Change) {
        for (key, value) in &other.adds {
            self.add_raw(*key, value.clone());
        }

        for v in &other.removes {
            self.remove_raw(*v);
        }
    }
}

pub fn empty_trie_hash() -> H256 {
    empty_trie_hash!()
}

pub fn insert<D: DatabaseHandle>(
    root: H256, database: &D, key: &[u8], value: &[u8]
) -> (H256, Change) {
    let mut change = Change::default();
    let nibble = nibble::from_key(key);

    let (new, subchange) = if root == empty_trie_hash!() {
        insert::insert_by_empty(nibble, value)
    } else {
        let old = MerkleNode::decode(&Rlp::new(database.get(root)));
        change.remove_raw(root);
        insert::insert_by_node(old, nibble, value, database)
    };
    change.merge(&subchange);
    change.add_node(&new);

    let hash = H256::from(Keccak256::digest(&rlp::encode(&new).to_vec()).as_slice());
    (hash, change)
}

pub fn insert_empty<D: DatabaseHandle>(
    database: &D, key: &[u8], value: &[u8]
) -> (H256, Change) {
    insert(empty_trie_hash!(), database, key, value)
}

pub fn delete<D: DatabaseHandle>(
    root: H256, database: &D, key: &[u8]
) -> (H256, Change) {
    let mut change = Change::default();
    let nibble = nibble::from_key(key);

    let (new, subchange) = if root == empty_trie_hash!() {
        return (root, change)
    } else {
        let old = MerkleNode::decode(&Rlp::new(database.get(root)));
        change.remove_raw(root);
        delete::delete_by_node(old, nibble, database)
    };
    change.merge(&subchange);

    match new {
        Some(new) => {
            change.add_node(&new);

            let hash = H256::from(Keccak256::digest(&rlp::encode(&new).to_vec()).as_slice());
            (hash, change)
        },
        None => {
            (empty_trie_hash!(), change)
        },
    }
}

pub fn build(map: &HashMap<Vec<u8>, Vec<u8>>) -> (H256, Change) {
    let mut change = Change::default();

    if map.len() == 0 {
        return (empty_trie_hash!(), change);
    }

    let mut node_map = HashMap::new();
    for (key, value) in map {
        node_map.insert(nibble::from_key(key.as_ref()), value.as_ref());
    }

    let (node, subchange) = build::build_node(&node_map);
    change.merge(&subchange);
    change.add_node(&node);

    let hash = H256::from(Keccak256::digest(&rlp::encode(&node).to_vec()).as_slice());
    (hash, change)
}

pub fn get<'a, 'b, D: DatabaseHandle>(
    root: H256, database: &'a D, key: &'b [u8]
) -> Option<&'a [u8]> {
    if root == empty_trie_hash!() {
        None
    } else {
        let nibble = nibble::from_key(key);
        let node = MerkleNode::decode(&Rlp::new(database.get(root)));
        get::get_by_node(node, nibble, database)
    }
}
