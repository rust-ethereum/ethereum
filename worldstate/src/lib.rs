extern crate etcommon_bigint as bigint;
extern crate etcommon_rlp as rlp;
extern crate etcommon_crypto as crypto;
extern crate etcommon_util;

pub mod merkle;

use bigint::H256;
use rlp::Rlp;
use merkle::{NibbleSlice, MerkleValue, MerkleNode};
use std::ops::Deref;
use std::borrow::Borrow;
use std::clone::Clone;

pub trait Database {
    fn get(&self, hash: H256) -> &[u8];
}

pub struct Trie<D: Deref<Target=Database> + Clone> {
    database: D,
    root: H256,
}

impl<D: Deref<Target=Database> + Clone> Trie<D> {
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
