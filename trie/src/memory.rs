use bigint::H256;
use {DatabaseHandle, Trie};

use std::collections::HashMap;

impl<'a> DatabaseHandle for &'a HashMap<H256, Vec<u8>> {
    fn get(&self, hash: H256) -> &[u8] {
        HashMap::get(self, &hash).unwrap()
    }
}

pub struct SingletonMemoryTrieMut {
    database: HashMap<H256, Vec<u8>>,
    root: H256,
}

impl Default for SingletonMemoryTrieMut {
    fn default() -> Self {
        Self {
            database: HashMap::new(),
            root: empty_trie_hash!(),
        }
    }
}
