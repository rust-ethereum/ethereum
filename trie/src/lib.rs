extern crate bigint;
extern crate rlp;
extern crate sha3;
#[cfg(test)] extern crate hexutil;

pub mod merkle;

use bigint::H256;
use rlp::Rlp;
use sha3::{Digest, Keccak256};
use std::collections::HashMap;
use merkle::{MerkleValue, MerkleNode};
use merkle::nibble::{self, NibbleVec, NibbleSlice, Nibble};
use std::ops::{Deref, DerefMut};
use std::borrow::Borrow;
use std::clone::Clone;

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

fn empty_trie_hash() -> H256 {
    H256::from("0x56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421")
}

pub trait Database {
    fn get<'a>(&'a self, hash: H256) -> Option<&'a [u8]>;
    fn set<'a, 'b>(&'a self, hash: H256, value: &'b [u8]);
}

pub struct Trie<D: Database> {
    database: D,
    root: H256,
}

impl<D: Database> Trie<D> {
    pub fn root(&self) -> H256 {
        self.root
    }

    pub fn is_empty(&self) -> bool {
        self.root() == empty_trie_hash()
    }

    pub fn empty(database: D) -> Self {
        Self {
            database,
            root: empty_trie_hash()
        }
    }

    fn copy_nodes<'a, 'b>(old_nodes: &'a [MerkleValue<'b>]) -> [MerkleValue<'b>; 16] {
        debug_assert!(old_nodes.len() == 16);
        let mut nodes = empty_nodes!();
        for i in 0..16 {
            nodes[i] = old_nodes[i].clone();
        }
        nodes
    }

    fn build_value<'a, 'b>(database: &'a D, node: MerkleNode<'b>) -> MerkleValue<'b> {
        if node.inlinable() {
            MerkleValue::Full(Box::new(node))
        } else {
            let subnode = rlp::encode(&node).to_vec();
            let hash = H256::from(Keccak256::digest(&subnode).as_slice());
            database.set(hash, &subnode);
            MerkleValue::Hash(hash)
        }
    }

    fn build_submap<'a, 'b: 'a, T: Iterator<Item=(&'a NibbleVec, &'a &'b [u8])>>(
        common_len: usize, map: T
    ) -> HashMap<NibbleVec, &'b [u8]> {
        let mut submap = HashMap::new();
        for (key, value) in map {
            submap.insert(key.split_at(common_len).1.into(), value.clone());
        }
        submap
    }

    fn build_node<'a, 'b>(database: &'a D, map: &HashMap<NibbleVec, &'b [u8]>) -> MerkleNode<'b> {
        if map.len() == 0 {
            panic!();
        }

        if map.len() == 1 {
            let key = map.keys().next().unwrap();
            return MerkleNode::Leaf(key.clone(), map.get(key).unwrap().clone());
        }

        debug_assert!(map.len() > 1);

        let common: NibbleSlice = nibble::common_all(map.keys().map(|v| v.as_ref()));

        if common.len() > 1 {
            let submap = Self::build_submap(common.len(), map.iter());
            debug_assert!(submap.len() > 0);
            let node = Self::build_node(database, &submap);
            let value = Self::build_value(database, node);
            return MerkleNode::Extension(common.into(), value);
        }

        let mut nodes = empty_nodes!();

        for i in 0..16 {
            let nibble_index: Nibble = i.into();

            let submap = Self::build_submap(1, map.iter().filter(|&(key, value)| {
                key.len() > 0 && key[0] == nibble_index
            }));
            let value = if submap.len() == 0 {
                MerkleValue::Empty
            } else {
                let node = Self::build_node(database, &submap);
                Self::build_value(database, node)
            };
            nodes[i] = value;
        }

        let additional = map.iter()
            .filter(|&(key, value)| key.len() == 0).next()
            .map(|(key, value)| value.clone());

        return MerkleNode::Branch(nodes, additional);
    }

    pub fn build<'a>(mut database: D, map: &HashMap<&'a [u8], &'a [u8]>) -> Self {
        if map.len() == 0 {
            return Self::empty(database);
        }

        let mut node_map = HashMap::new();
        for (key, value) in map {
            node_map.insert(nibble::from_key(key), value.clone());
        }

        let node = Self::build_node(&mut database, &node_map);
        let root_rlp = rlp::encode(&node).to_vec();
        let hash = H256::from(Keccak256::digest(&root_rlp).as_slice());
        database.set(hash, &root_rlp);

        Trie {
            database,
            root: hash
        }
    }
    
    fn get_by_value<'a, 'b>(&'a self, nibble: NibbleVec, value: MerkleValue<'a>) -> Option<&'a [u8]> {
        match value {
            MerkleValue::Empty => None,
            MerkleValue::Full(ref sub_node) => {
                let sub_node: &MerkleNode<'a> = sub_node.borrow();
                let sub_node: MerkleNode<'a> = (*sub_node).clone();
                self.get_by_node(nibble, sub_node)
            },
            MerkleValue::Hash(h) => {
                let node = MerkleNode::decode(&Rlp::new(match self.database.get(h) {
                    Some(val) => val,
                    None => return None,
                }));
                self.get_by_node(nibble, node)
            },
        }
    }

    fn get_by_node<'a, 'b>(&'a self, nibble: NibbleVec, node: MerkleNode<'a>) -> Option<&'a [u8]> {
        match node {
            MerkleNode::Leaf(ref node_nibble, ref node_value) => {
                if *node_nibble == nibble {
                    Some(node_value.clone())
                } else {
                    None
                }
            },
            MerkleNode::Extension(ref node_nibble, ref node_value) => {
                if nibble.starts_with(node_nibble) {
                    self.get_by_value(nibble.split_at(node_nibble.len()).1.into(),
                                      node_value.clone())
                } else {
                    None
                }
            },
            MerkleNode::Branch(ref nodes, ref additional) => {
                if nibble.len() == 0 {
                    additional.clone()
                } else {
                    let nibble_index: usize = nibble[0].into();
                    let node = &nodes[nibble_index];
                    self.get_by_value(nibble.split_at(1).1.into(), node.clone())
                }
            },
        }
    }

    pub fn get<'a, 'b>(&'a self, key: &'b [u8]) -> Option<&'a [u8]> {
        if self.is_empty() {
            return None;
        }

        let nibble = nibble::from_key(key);
        let node = MerkleNode::decode(&Rlp::new(match self.database.get(self.root) {
            Some(val) => val,
            None => return None,
        }));
        self.get_by_node(nibble, node)
    }

    fn insert_by_value<'a, 'b: 'a>(
        &'a self, nibble: NibbleVec, merkle: MerkleValue<'a>, value: &'b [u8]
    ) -> MerkleValue<'a> {
        match merkle {
            MerkleValue::Empty => {
                let mut node_map = HashMap::new();
                node_map.insert(nibble, value);

                let new_node = Self::build_node(&self.database, &node_map);
                Self::build_value(&self.database, new_node)
            },
            MerkleValue::Full(ref sub_node) => {
                let sub_node: &MerkleNode<'a> = sub_node.borrow();
                let sub_node: MerkleNode<'a> = (*sub_node).clone();

                let new_node = self.insert_by_node(nibble, sub_node, value);
                Self::build_value(&self.database, new_node)
            },
            MerkleValue::Hash(h) => {
                let node = MerkleNode::decode(&Rlp::new(match self.database.get(h) {
                    Some(val) => val,
                    None => panic!(),
                }));
                let new_node = self.insert_by_node(nibble, node, value);
                Self::build_value(&self.database, new_node)
            }
        }
    }

    fn insert_by_node<'a, 'b: 'a>(
        &'a self, nibble: NibbleVec, node: MerkleNode<'a>, value: &'b [u8]
    ) -> MerkleNode<'a> {
        match node {
            MerkleNode::Leaf(ref node_nibble, ref node_value) => {
                let mut node_map = HashMap::new();
                node_map.insert(node_nibble.clone(), node_value.clone());
                node_map.insert(nibble, value);

                Self::build_node(&self.database, &node_map)
            },
            MerkleNode::Extension(ref node_nibble, ref node_value) => {
                if nibble.starts_with(node_nibble) {
                    MerkleNode::Extension(
                        node_nibble.clone(),
                        self.insert_by_value(nibble.split_at(node_nibble.len()).1.into(),
                                             node_value.clone(), value))
                } else {
                    let common = nibble::common(&nibble, &node_nibble);
                    let rest_len = node_nibble.len() - common.len() - 1;
                    debug_assert!(node_nibble.len() - common.len() > 0);
                    debug_assert!(nibble.len() - common.len() > 0);
                    let rest_at: usize = node_nibble[common.len()].into();
                    let insert_at: usize = nibble[common.len()].into();

                    let rest = if rest_len > 1 {
                        let new_node = MerkleNode::Extension(
                            node_nibble.split_at(common.len()).1.into(),
                            node_value.clone());
                        Self::build_value(&self.database, new_node)
                    } else if rest_len == 1 {
                        let mut nodes = empty_nodes!();
                        let nibble_index: usize = node_nibble[node_nibble.len() - 1].into();
                        nodes[nibble_index] = node_value.clone();
                        let new_node = MerkleNode::Branch(nodes, None);
                        Self::build_value(&self.database, new_node)
                    } else /* if rest_len == 0 */ {
                        node_value.clone()
                    };

                    let branched_node = {
                        let mut nodes = empty_nodes!();
                        nodes[rest_at] = rest;
                        nodes[insert_at] = self.insert_by_value(
                            nibble.split_at(common.len()).1.into(),
                            MerkleValue::Empty, value);
                        MerkleNode::Branch(nodes, None)
                    };
                    let branched = Self::build_value(&self.database, branched_node.clone());

                    if common.len() > 1 {
                        MerkleNode::Extension(common.into(), branched)
                    } else if common.len() == 1 {
                        let mut nodes = empty_nodes!();
                        let nibble_index: usize = common[0].into();
                        nodes[nibble_index] = branched;
                        MerkleNode::Branch(nodes, None)
                    } else /* if common.len() == 0 */ {
                        branched_node
                    }
                }
            },
            MerkleNode::Branch(ref node_nodes, ref node_additional) => {
                let mut nodes = Self::copy_nodes(node_nodes);
                if nibble.len() == 0 {
                    MerkleNode::Branch(nodes, Some(value))
                } else {
                    let nibble_index: usize = nibble[0].into();
                    let prev = nodes[nibble_index].clone();
                    nodes[nibble_index] = self.insert_by_value(
                        nibble.split_at(1).1.into(), prev, value);
                    MerkleNode::Branch(nodes, node_additional.clone())
                }
            },
        }
    }

    pub fn insert<'a, 'b: 'a>(&'a mut self, key: &'b [u8], value: &'b [u8]) {
        let hash = {
            let node = if self.is_empty() {
                let mut node_map = HashMap::new();
                node_map.insert(nibble::from_key(key), value.clone());

                Self::build_node(&self.database, &node_map)
            } else {
                let nibble = nibble::from_key(key);
                let node = MerkleNode::decode(&Rlp::new(match self.database.get(self.root) {
                    Some(val) => val,
                    None => panic!(),
                }));
                self.insert_by_node(nibble, node, value)
            };

            let root_rlp = rlp::encode(&node).to_vec();
            let hash = H256::from(Keccak256::digest(&root_rlp).as_slice());
            self.database.set(hash, &root_rlp);

            hash
        };

        self.root = hash;
    }

    fn remove_by_value<'a, 'b: 'a>(
        &'a self, nibble: NibbleVec, merkle: MerkleValue<'a>
    ) -> MerkleValue<'a> {
        match merkle {
            MerkleValue::Empty => {
                MerkleValue::Empty
            },
            MerkleValue::Full(ref sub_node) => {
                let sub_node: &MerkleNode<'a> = sub_node.borrow();
                let sub_node: MerkleNode<'a> = (*sub_node).clone();

                let new_node = self.remove_by_node(nibble, sub_node);
                if new_node.is_none() {
                    MerkleValue::Empty
                } else {
                    let new_node = new_node.unwrap();
                    Self::build_value(&self.database, new_node)
                }
            },
            MerkleValue::Hash(h) => {
                let node = MerkleNode::decode(&Rlp::new(match self.database.get(h) {
                    Some(val) => val,
                    None => panic!(),
                }));
                let new_node = self.remove_by_node(nibble, node);
                if new_node.is_none() {
                    MerkleValue::Empty
                } else {
                    let new_node = new_node.unwrap();
                    Self::build_value(&self.database, new_node)
                }
            },
        }
    }

    fn remove_by_node<'a, 'b: 'a>(
        &'a self, nibble: NibbleVec, node: MerkleNode<'a>
    ) -> Option<MerkleNode<'a>> {
        fn find_subnode<'a: 'b, 'b, D: Database>(database: &'a D, value: MerkleValue<'b>) -> MerkleNode<'b> {
            match value {
                MerkleValue::Empty => panic!(),
                MerkleValue::Hash(h) =>
                    MerkleNode::decode(&Rlp::new(match database.get(h) {
                        Some(val) => val,
                        None => panic!(),
                    })),
                MerkleValue::Full(f) => {
                    let t: &MerkleNode = &f;
                    t.clone()
                },
            }
        }

        match node {
            MerkleNode::Leaf(ref node_nibble, ref node_value) => {
                if *node_nibble == nibble {
                    None
                } else {
                    Some(MerkleNode::Leaf(node_nibble.clone(), node_value.clone()))
                }
            },
            MerkleNode::Extension(ref node_nibble, ref node_value) => {
                if nibble.starts_with(node_nibble) {
                    let value = self.remove_by_value(
                        nibble.split_at(node_nibble.len()).1.into(),
                        node_value.clone());
                    let subnode = find_subnode(&self.database, value.clone());
                    match subnode {
                        MerkleNode::Leaf(mut sub_nibble, sub_value) => {
                            let mut node_nibble = node_nibble.clone();
                            node_nibble.append(&mut sub_nibble);
                            Some(MerkleNode::Leaf(node_nibble, sub_value))
                        },
                        _ => Some(MerkleNode::Extension(node_nibble.clone(), value)),
                    }
                } else {
                    Some(MerkleNode::Extension(node_nibble.clone(), node_value.clone()))
                }
            },
            MerkleNode::Branch(ref node_nodes, ref node_additional) => {
                let mut nodes = Self::copy_nodes(node_nodes);
                let mut additional = node_additional.clone();

                if nibble.len() > 0 {
                    let nibble_index: usize = nibble[0].into();
                    nodes[nibble_index] = self.remove_by_value(
                        nibble.split_at(1).1.into(),
                        nodes[nibble_index].clone());
                } else {
                    additional = None;
                }

                let value_count = additional.iter().count() +
                    nodes.iter().filter(|v| v != &&MerkleValue::Empty).count();

                if value_count == 0 {
                    None
                } else if value_count == 1 {
                    if additional.is_some() {
                        Some(MerkleNode::Leaf(NibbleVec::new(), additional.unwrap()))
                    } else { // one value in nodes and no values in additional
                        let (value_index, value) = nodes
                            .iter().enumerate().filter(|&(_, value)| {
                                value != &MerkleValue::Empty
                            }).next()
                            .map(|(value_index, value)| (value_index, value.clone())).unwrap();
                        let value_nibble: Nibble = value_index.into();

                        let subnode = find_subnode(&self.database, value);
                        match subnode {
                            MerkleNode::Leaf(mut sub_nibble, sub_value) => {
                                sub_nibble.insert(0, value_index.into());
                                Some(MerkleNode::Leaf(sub_nibble, sub_value))
                            },
                            MerkleNode::Extension(mut sub_nibble, sub_value) => {
                                sub_nibble.insert(0, value_index.into());
                                Some(MerkleNode::Extension(sub_nibble, sub_value))
                            },
                            MerkleNode::Branch(sub_nodes, sub_additional) => {
                                let value_count = sub_additional.iter().count() +
                                    sub_nodes.iter().filter(|v| v != &&MerkleValue::Empty).count();

                                if value_count > 1 {
                                    Some(MerkleNode::Branch(nodes, additional))
                                } else {
                                    if sub_additional.is_some() {
                                        let nibble = vec![value_nibble];
                                        Some(MerkleNode::Leaf(nibble, sub_additional.unwrap()))
                                    } else {
                                        let (sub_value_index, sub_value) = sub_nodes
                                            .iter().enumerate().filter(|&(_, value)| {
                                                value != &MerkleValue::Empty
                                            }).next()
                                            .map(|(value_index, value)|
                                                 (value_index, value.clone())).unwrap();
                                        let sub_value_nibble: Nibble = sub_value_index.into();

                                        let sub_subnode = find_subnode(&self.database, sub_value.clone());
                                        match sub_subnode.clone() {
                                            MerkleNode::Leaf(mut sub_nibble, sub_value) => {
                                                sub_nibble.insert(0, value_nibble);
                                                sub_nibble.insert(1, sub_value_nibble);
                                                Some(MerkleNode::Leaf(sub_nibble, sub_value))
                                            },
                                            MerkleNode::Extension(mut sub_nibble, sub_value) => {
                                                sub_nibble.insert(0, value_nibble);
                                                sub_nibble.insert(1, sub_value_nibble);
                                                Some(MerkleNode::Extension(sub_nibble, sub_value))
                                            },
                                            MerkleNode::Branch(_, _) => {
                                                let sub_nibble = vec![ value_nibble, sub_value_nibble ];
                                                Some(MerkleNode::Extension(sub_nibble, sub_value))
                                            },
                                        }
                                    }
                                }
                            },
                        }
                    }
                } else {
                    Some(MerkleNode::Branch(nodes, additional))
                }
            },
        }
    }

    pub fn remove<'a, 'b: 'a>(&'a mut self, key: &'b [u8]) {
        if self.is_empty() {
            return;
        }

        let nibble = nibble::from_key(key);
        let node = MerkleNode::decode(&Rlp::new(match self.database.get(self.root) {
            Some(val) => val,
            None => panic!(),
        }));

        let hash = {
            let new_node = self.remove_by_node(nibble, node);
            if new_node.is_none() {
                empty_trie_hash()
            } else {
                let new_node = new_node.unwrap();
                let root_rlp = rlp::encode(&new_node).to_vec();
                let hash = H256::from(Keccak256::digest(&root_rlp).as_slice());
                self.database.set(hash, &root_rlp);
                hash
            }
        };

        self.root = hash;
    }
}

#[cfg(test)]
mod tests {
    use super::{Database, Trie};
    use std::collections::HashMap;
    use std::str::FromStr;
    use std::cell::UnsafeCell;
    use bigint::H256;
    use hexutil::read_hex;

    impl Database for UnsafeCell<HashMap<H256, Vec<u8>>> {
        fn get<'a>(&'a self, hash: H256) -> Option<&'a [u8]> {
            let db: *mut HashMap<H256, Vec<u8>> = self.get();
            unsafe { (&*db).get(&hash).map(|v| v.as_ref()) }
        }

        fn set<'a>(&'a self, hash: H256, value: &'a [u8]) {
            let db: *mut HashMap<H256, Vec<u8>> = self.get();
            unsafe { (&mut *db).insert(hash, value.into()); }
        }
    }

    #[test]
    fn trie_middle_leaf() {
        let mut map = HashMap::new();
        map.insert("key1aa".as_bytes(), "0123456789012345678901234567890123456789xxx".as_bytes());
        map.insert("key1".as_bytes(), "0123456789012345678901234567890123456789Very_Long".as_bytes());
        map.insert("key2bb".as_bytes(), "aval3".as_bytes());
        map.insert("key2".as_bytes(), "short".as_bytes());
        map.insert("key3cc".as_bytes(), "aval3".as_bytes());
        map.insert("key3".as_bytes(), "1234567890123456789012345678901".as_bytes());

        let mut database: UnsafeCell<HashMap<H256, Vec<u8>>> = UnsafeCell::new(HashMap::new());
        let mut trie: Trie<UnsafeCell<HashMap<H256, Vec<u8>>>> = Trie::build(database, &map);

        assert_eq!(trie.get("key2bb".as_bytes()), Some("aval3".as_bytes()));
        assert_eq!(trie.get("key2bbb".as_bytes()), None);
        let prev_hash = trie.root();
        trie.insert("key2bbb".as_bytes(), "aval4".as_bytes());
        assert_eq!(trie.get("key2bbb".as_bytes()), Some("aval4".as_bytes()));
        trie.remove("key2bbb".as_bytes());
        assert_eq!(trie.get("key2bbb".as_bytes()), None);
        assert_eq!(prev_hash, trie.root());
    }

    #[test]
    fn trie_insert() {
        let mut map = HashMap::new();

        let mut database: UnsafeCell<HashMap<H256, Vec<u8>>> = UnsafeCell::new(HashMap::new());
        let mut trie: Trie<UnsafeCell<HashMap<H256, Vec<u8>>>> = Trie::build(database, &map);

        trie.insert("foo".as_bytes(), "bar".as_bytes());
        trie.insert("food".as_bytes(), "bass".as_bytes());

        assert_eq!(trie.root(), H256::from_str("0x17beaa1648bafa633cda809c90c04af50fc8aed3cb40d16efbddee6fdf63c4c3").unwrap());
    }

    #[test]
    fn trie_delete() {
        let mut map = HashMap::new();

        let mut database: UnsafeCell<HashMap<H256, Vec<u8>>> = UnsafeCell::new(HashMap::new());
        let mut trie: Trie<UnsafeCell<HashMap<H256, Vec<u8>>>> = Trie::build(database, &map);

        trie.insert("fooa".as_bytes(), "bar".as_bytes());
        trie.insert("food".as_bytes(), "bass".as_bytes());
        let prev_hash = trie.root();
        trie.insert("fooc".as_bytes(), "basss".as_bytes());
        trie.remove("fooc".as_bytes());
        assert_eq!(trie.root(), prev_hash);
    }

    #[test]
    fn trie_empty() {
        let mut map = HashMap::new();

        let mut database: UnsafeCell<HashMap<H256, Vec<u8>>> = UnsafeCell::new(HashMap::new());
        let mut trie: Trie<UnsafeCell<HashMap<H256, Vec<u8>>>> = Trie::build(database, &map);

        assert_eq!(H256::from("0x56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421"),
                   trie.root());
    }
}
