extern crate bigint;
extern crate rlp;
extern crate sha3;
#[cfg(test)] extern crate hexutil;
#[cfg(test)] extern crate trie_test;

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
mod memory;

use ops::insert;
use ops::delete;

pub use memory::SingletonMemoryTrieMut;

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

    pub fn insert(&self, key: &[u8], value: &[u8]) -> (H256, Change) {
        let mut change = Change::default();
        let nibble = nibble::from_key(key);

        let (new, subchange) = if self.root == empty_trie_hash!() {
            insert::insert_by_empty(nibble, value)
        } else {
            let old = MerkleNode::decode(&Rlp::new(self.database.get(self.root)));
            change.remove_raw(self.root);
            insert::insert_by_node(old, nibble, value, &self.database)
        };
        change.merge(&subchange);
        change.add_node(&new);

        let hash = H256::from(Keccak256::digest(&rlp::encode(&new).to_vec()).as_slice());
        (hash, change)
    }

    pub fn delete(&self, key: &[u8]) -> (H256, Change) {
        let mut change = Change::default();
        let nibble = nibble::from_key(key);

        let (new, subchange) = if self.root == empty_trie_hash!() {
            return (self.root, change)
        } else {
            let old = MerkleNode::decode(&Rlp::new(self.database.get(self.root)));
            change.remove_raw(self.root);
            delete::delete_by_node(old, nibble, &self.database)
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
}
