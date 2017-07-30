extern crate etcommon_bigint as bigint;
extern crate etcommon_rlp as rlp;
extern crate etcommon_crypto as crypto;
extern crate etcommon_util;

pub mod merkle;

pub trait Database {
    fn get(&self, hash: H256) -> &[u8];
    fn set(&self, hash: H256, value: &[u8]);
}

pub struct Trie<D: Deref<Database> + Clone> {
    database: D,
    root: H256,
}

impl<D: Deref<Database>> Trie<D> {
    fn get_by_value(&self, nibble: NibbleSlice, value: MerkleValue) -> Option<&[u8]> {
        match value {
            Empty => None,
            Full(ref sub_node) => {
                self.get_by_node(
                    nibble,
                    sub_node)
            },
            Hash(h) => {
                let sub_trie = Trie {
                    database: self.database.clone(),
                    root: h
                };
                sub_trie.get_by_nibble(
                    nibble)
            },
        }
    }

    fn get_by_node(&self, nibble: NibbleSlice, node: MerkleNode) -> Option<&[u8]> {
        match node {
            MerkleNode::Leaf(ref node_nibble, ref node_value) => {
                if node_nibble == nibble {
                    Some(node_value)
                } else {
                    None
                }
            },
            MerkleNode::Extension(ref node_nibble, ref node_value) => {
                if nibble.starts_with(node_nibble) {
                    self.get_by_value(nibble.sub(node_nibble.len(), nibble.len()),
                                      node_value)
                } else {
                    None
                }
            },
            MerkelNode::Branch(ref nodes, ref additional) => {
                if nibble.len() == 0 {
                    additional
                } else {
                    let node = &nodes[nibble.at(0)];
                    self.get_by_value(nibble.sub(1, nibble.len()), node)
                }
            },
        }
    }

    fn get_by_nibble(&self, nibble: NibbleSlice) -> Option<&[u8]> {
        let node = MerkleNode::decode(Rlp::new(self.database.get(self.root)));
        self.get_by_node(nibble, node)
    }

    fn get_by_key(&self, key: &[u8]) -> Option<&[u8]> {
        self.get_by_nibble(NibbleSlice::new(key))
    }

    pub fn get(&self, key: &[u8]) -> Option<&[u8]> {
        self.get_by_key(key)
    }
}
