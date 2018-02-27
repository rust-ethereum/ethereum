//! Merkle trie implementation for Ethereum.

#![deny(unused_import_braces, unused_imports,
        unused_comparisons, unused_must_use,
        unused_variables, non_shorthand_field_patterns,
        unreachable_code)]

extern crate bigint;
extern crate rlp;
extern crate sha3;
#[cfg(test)] extern crate hexutil;

use bigint::H256;
use rlp::Rlp;
use sha3::{Digest, Keccak256};
use std::collections::{HashMap, HashSet};
use merkle::{MerkleValue, MerkleNode, nibble};

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

pub const EMPTY_TRIE_HASH: H256 = H256([0x56, 0xe8, 0x1f, 0x17, 0x1b, 0xcc, 0x55, 0xa6,
                                        0xff, 0x83, 0x45, 0xe6, 0x92, 0xc0, 0xf8, 0x6e,
                                        0x5b, 0x48, 0xe0, 0x1b, 0x99, 0x6c, 0xad, 0xc0,
                                        0x01, 0x62, 0x2f, 0xb5, 0xe3, 0x63, 0xb4, 0x21]);

pub mod merkle;
mod ops;
mod error;

use ops::{insert, delete, build, get};
pub use error::Error;

/// An immutable database handle.
pub trait DatabaseHandle {
    /// Get a raw value from the database.
    fn get<'a>(&'a self, key: H256) -> Option<&'a [u8]>;

    fn get_with_error<'a>(&'a self, key: H256) -> Result<&'a [u8], Error> {
        match self.get(key) {
            Some(value) => Ok(value),
            None => Err(Error::Require(key)),
        }
    }
}

impl<'a> DatabaseHandle for &'a HashMap<H256, Vec<u8>> {
    fn get(&self, hash: H256) -> Option<&[u8]> {
        HashMap::get(self, &hash).map(|v| v.as_ref())
    }
}

/// Change for a merkle trie operation.
pub struct Change {
    /// Additions to the database.
    pub adds: HashMap<H256, Vec<u8>>,
    /// Removals to the database.
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
    /// Change to add a new raw value.
    pub fn add_raw(&mut self, key: H256, value: Vec<u8>) {
        self.adds.insert(key, value);
        self.removes.remove(&key);
    }

    /// Change to add a new node.
    pub fn add_node<'a, 'b, 'c>(&'a mut self, node: &'c MerkleNode<'b>) {
        let subnode = rlp::encode(node).to_vec();
        let hash = H256::from(Keccak256::digest(&subnode).as_slice());
        self.add_raw(hash, subnode);
    }

    /// Change to add a new node, and return the value added.
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

    /// Change to remove a raw key.
    pub fn remove_raw(&mut self, key: H256) {
        self.adds.remove(&key);
        self.removes.insert(key);
    }

    /// Change to remove a node. Return whether there's any node being
    /// removed.
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

    /// Merge another change to this change.
    pub fn merge(&mut self, other: &Change) {
        for (key, value) in &other.adds {
            self.add_raw(*key, value.clone());
        }

        for v in &other.removes {
            self.remove_raw(*v);
        }
    }
}

/// Insert to a merkle trie. Return the new root hash and the changes.
pub fn insert<D: DatabaseHandle>(
    root: H256, database: &D, key: &[u8], value: &[u8]
) -> Result<(H256, Change), Error> {
    let mut change = Change::default();
    let nibble = nibble::from_key(key);

    let (new, subchange) = if root == EMPTY_TRIE_HASH {
        insert::insert_by_empty(nibble, value)
    } else {
        let old = MerkleNode::decode(&Rlp::new(database.get_with_error(root)?));
        change.remove_raw(root);
        insert::insert_by_node(old, nibble, value, database)?
    };
    change.merge(&subchange);
    change.add_node(&new);

    let hash = H256::from(Keccak256::digest(&rlp::encode(&new).to_vec()).as_slice());
    Ok((hash, change))
}

/// Insert to an empty merkle trie. Return the new root hash and the
/// changes.
pub fn insert_empty<D: DatabaseHandle>(
    key: &[u8], value: &[u8]
) -> (H256, Change) {
    let mut change = Change::default();
    let nibble = nibble::from_key(key);

    let (new, subchange) = insert::insert_by_empty(nibble, value);
    change.merge(&subchange);
    change.add_node(&new);

    let hash = H256::from(Keccak256::digest(&rlp::encode(&new).to_vec()).as_slice());
    (hash, change)
}

/// Delete a key from a markle trie. Return the new root hash and the
/// changes.
pub fn delete<D: DatabaseHandle>(
    root: H256, database: &D, key: &[u8]
) -> Result<(H256, Change), Error> {
    let mut change = Change::default();
    let nibble = nibble::from_key(key);

    let (new, subchange) = if root == EMPTY_TRIE_HASH {
        return Ok((root, change))
    } else {
        let old = MerkleNode::decode(&Rlp::new(database.get_with_error(root)?));
        change.remove_raw(root);
        delete::delete_by_node(old, nibble, database)?
    };
    change.merge(&subchange);

    match new {
        Some(new) => {
            change.add_node(&new);

            let hash = H256::from(Keccak256::digest(&rlp::encode(&new).to_vec()).as_slice());
            Ok((hash, change))
        },
        None => {
            Ok((EMPTY_TRIE_HASH, change))
        },
    }
}

/// Build a merkle trie from a map. Return the root hash and the
/// changes.
pub fn build(map: &HashMap<Vec<u8>, Vec<u8>>) -> (H256, Change) {
    let mut change = Change::default();

    if map.len() == 0 {
        return (EMPTY_TRIE_HASH, change);
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

/// Get a value given the root hash and the database.
pub fn get<'a, 'b, D: DatabaseHandle>(
    root: H256, database: &'a D, key: &'b [u8]
) -> Result<Option<&'a [u8]>, Error> {
    if root == EMPTY_TRIE_HASH {
        Ok(None)
    } else {
        let nibble = nibble::from_key(key);
        let node = MerkleNode::decode(&Rlp::new(database.get_with_error(root)?));
        get::get_by_node(node, nibble, database)
    }
}
