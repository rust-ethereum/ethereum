extern crate etcommon_bigint as bigint;
extern crate etcommon_rlp as rlp;
extern crate etcommon_crypto as crypto;
extern crate etcommon_util;

pub mod merkle;

use bigint::H256;
use rlp::Rlp;
use crypto::keccak256;
use std::collections::HashMap;
use merkle::{NibbleSlice, MerkleValue, MerkleNode};
use std::ops::{Deref, DerefMut};
use std::borrow::Borrow;
use std::clone::Clone;

pub trait Database {
    fn get<'a>(&'a self, hash: H256) -> &'a [u8];
    fn set<'a, 'b>(&'a mut self, hash: H256, value: &'b [u8]);
}

pub struct Trie<D: Deref<Target=Database> + DerefMut<Target=Database> + Clone> {
    database: D,
    root: H256,
}

impl<D: Deref<Target=Database> + DerefMut<Target=Database> + Clone> Trie<D> {
    fn build_node<'a>(database: &mut D, map: &HashMap<NibbleSlice<'a>, &'a [u8]>) -> MerkleNode<'a> {
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
            let node = Self::build_node(database, &sub_map);
            let value = if node.inlinable() {
                MerkleValue::Full(Box::new(node))
            } else {
                let sub_node = rlp::encode(&node).to_vec();
                let hash = keccak256(&sub_node);
                database.set(hash, &sub_node);
                MerkleValue::Hash(hash)
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
                let node = Self::build_node(database, &sub_map);
                if node.inlinable() {
                    MerkleValue::Full(Box::new(node))
                } else {
                    let sub_node = rlp::encode(&node).to_vec();
                    let hash = keccak256(&sub_node);
                    database.set(hash, &sub_node);
                    MerkleValue::Hash(hash)
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

    pub fn build<'a>(mut database: D, map: &HashMap<&'a [u8], &'a [u8]>) -> Self {
        let mut node_map = HashMap::new();

        for (key, value) in map {
            node_map.insert(NibbleSlice::new(key), value.clone());
        }

        let node = Self::build_node(&mut database, &node_map);
        let hash = keccak256(&rlp::encode(&node).to_vec());

        Trie {
            database,
            root: hash
        }
    }
    
    fn get_by_value<'a, 'b>(&'a self, nibble: NibbleSlice<'b>, value: MerkleValue<'a>) -> Option<&'a [u8]> {
        match value {
            MerkleValue::Empty => None,
            MerkleValue::Full(ref sub_node) => {
                let sub_node: &MerkleNode<'a> = sub_node.borrow();
                let sub_node: MerkleNode<'a> = (*sub_node).clone();
                self.get_by_node(
                    nibble,
                    sub_node)
            },
            MerkleValue::Hash(h) => {
                let node = MerkleNode::decode(&Rlp::new(self.database.get(self.root)));
                self.get_by_node(nibble, node)
            },
        }
    }

    fn get_by_node<'a, 'b>(&'a self, nibble: NibbleSlice<'b>, node: MerkleNode<'a>) -> Option<&'a [u8]> {
        match node {
            MerkleNode::Leaf(ref node_nibble, ref node_value) => {
                let node_nibble = node_nibble.clone();
                if node_nibble == nibble {
                    Some(node_value.clone())
                } else {
                    None
                }
            },
            MerkleNode::Extension(ref node_nibble, ref node_value) => {
                if nibble.starts_with(node_nibble) {
                    let node_value: MerkleValue<'a> = (*node_value).clone();
                    self.get_by_value(nibble.sub(node_nibble.len(), nibble.len()),
                                      node_value)
                } else {
                    None
                }
            },
            MerkleNode::Branch(ref nodes, ref additional) => {
                if nibble.len() == 0 {
                    additional.clone()
                } else {
                    let node = &nodes[nibble.at(0) as usize];
                    self.get_by_value(nibble.sub(1, nibble.len()), node.clone())
                }
            },
        }
    }

    fn get_by_nibble<'a, 'b>(&'a self, nibble: NibbleSlice<'b>) -> Option<&'a [u8]> {
        let node = MerkleNode::decode(&Rlp::new(self.database.get(self.root)));
        self.get_by_node(nibble, node)
    }

    fn get_by_key<'a, 'b>(&'a self, key: &'b [u8]) -> Option<&'a [u8]> {
        self.get_by_nibble(NibbleSlice::<'a>::new(key))
    }

    pub fn get<'a, 'b>(&'a self, key: &'b [u8]) -> Option<&'a [u8]> {
        self.get_by_key(key)
    }
}
