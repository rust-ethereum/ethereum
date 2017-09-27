use database::DatabaseGuard;
use merkle::{MerkleNode, MerkleValue};
use merkle::nibble::{into_key, NibbleVec};
use rlp::{self, Rlp};

use std::ops::Deref;
use std::marker::PhantomData;

pub struct FixedMerkleIterator<'a, D: DatabaseGuard + 'a, K, V> {
    iter: MerkleIterator<'a, D>,
    _marker: PhantomData<(K, V)>
}

impl<'a, D: DatabaseGuard + 'a, K: rlp::Decodable, V: rlp::Decodable> FixedMerkleIterator<'a, D, K, V> {
    pub fn new(iter: MerkleIterator<'a, D>) -> Self {
        FixedMerkleIterator {
            iter, _marker: PhantomData
        }
    }
}

impl<'a, D: DatabaseGuard + 'a, K: rlp::Decodable, V: rlp::Decodable> Iterator for FixedMerkleIterator<'a, D, K, V> {
    type Item = (K, V);

    fn next(&mut self) -> Option<(K, V)> {
        if let Some((raw_key, raw_value)) = self.iter.next() {
            let key = rlp::decode(&raw_key);
            let value = rlp::decode(&raw_value);
            Some((key, value))
        } else {
            None
        }
    }
}

pub struct MerkleIterator<'a, D: DatabaseGuard + 'a> {
    database: &'a D,
    prefix: NibbleVec,
    value: Vec<u8>,
    index: usize,
    child: Option<Box<MerkleIterator<'a, D>>>,
    is_empty: bool,
}

impl<'a, D: DatabaseGuard + 'a> MerkleIterator<'a, D> {
    pub fn new(database: &'a D, value: Vec<u8>) -> Self {
        Self {
            database, value,
            index: 0, child: None, prefix: NibbleVec::new(),
            is_empty: false,
        }
    }

    pub fn empty(database: &'a D) -> Self {
        Self {
            database,
            value: Vec::new(), index: 0, child: None, prefix: NibbleVec::new(),
            is_empty: true,
        }
    }
}

fn prepare_value_as_child<'a, D: DatabaseGuard + 'a>(
    database: &'a D, prefix: NibbleVec, subnibble: NibbleVec, value: MerkleValue
) -> Option<Box<MerkleIterator<'a, D>>> {
    let mut nibble = prefix.clone();
    nibble.extend(subnibble);

    match value {
        MerkleValue::Empty => None,
        MerkleValue::Full(sub_node) => {
            let value = rlp::encode(sub_node.deref()).to_vec();
            Some(Box::new(
                MerkleIterator {
                    database: database,
                    prefix: nibble,
                    value, index: 0, child: None,
                    is_empty: false,
                }
            ))
        },
        MerkleValue::Hash(h) => {
            let value = database.get(h).unwrap();
            Some(Box::new(
                MerkleIterator {
                    database: database,
                    prefix: nibble,
                    value, index: 0, child: None,
                    is_empty: false,
                }
            ))
        }
    }
}

impl<'a, D: DatabaseGuard + 'a> Iterator for MerkleIterator<'a, D> {
    type Item = (Vec<u8>, Vec<u8>);

    fn next(&mut self) -> Option<(Vec<u8>, Vec<u8>)> {
        if self.is_empty {
            return None;
        }

        let node = MerkleNode::decode(&Rlp::new(&self.value));

        match node {
            MerkleNode::Leaf(node_nibble, node_value) => {
                debug_assert!(self.child.is_none());

                if self.index == 0 {
                    self.index += 1;

                    let mut nibble = self.prefix.clone();
                    nibble.extend(node_nibble);

                    Some((into_key(&nibble), node_value.into()))
                } else {
                    None
                }
            },
            MerkleNode::Extension(node_nibble, node_value) => {
                if self.index == 0 {
                    debug_assert!(self.child.is_none());

                    self.child = prepare_value_as_child(
                        self.database, self.prefix.clone(), node_nibble, node_value);

                    if self.child.is_some() {
                        self.index += 1;
                        self.child.as_mut().unwrap().next()
                    } else {
                        None
                    }
                } else {
                    debug_assert!(self.child.is_some());

                    self.child.as_mut().unwrap().next()
                }
            },
            MerkleNode::Branch(nodes, additional) => {
                debug_assert!(self.index <= 17);
                while self.index <= 16 {
                    if self.index < 16 {
                        if self.child.is_some() {
                            match self.child.as_mut().unwrap().next() {
                                Some(val) => return Some(val),
                                None => {
                                    self.child = None;
                                },
                            }
                        } else {
                            let value = nodes[self.index].clone();
                            let subnibble = vec![self.index.into()];
                            self.index += 1;
                            self.child = prepare_value_as_child(
                                self.database, self.prefix.clone(), subnibble, value);
                        }
                    } else {
                        self.index += 1;
                        match additional {
                            Some(val) => return Some((into_key(&self.prefix), val.into())),
                            None => (),
                        }
                    }
                }
                None
            },
        }
    }
}
