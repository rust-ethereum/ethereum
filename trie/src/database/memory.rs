use ::Trie;
use super::DatabaseGuard;
use bigint::H256;
use std::collections::HashMap;
use std::sync::Mutex;

pub struct MemoryDatabase(Mutex<HashMap<H256, Vec<u8>>>);
pub struct MemoryDatabaseGuard<'a>(&'a Mutex<HashMap<H256, Vec<u8>>>);

impl MemoryDatabase {
    pub fn new() -> Self {
        MemoryDatabase(Mutex::new(HashMap::new()))
    }

    pub fn create_trie<'a>(&'a self, root: H256) -> Trie<MemoryDatabaseGuard<'a>> {
        Trie::existing(MemoryDatabaseGuard(&self.0), root)
    }

    pub fn create_empty<'a>(&'a self) -> Trie<MemoryDatabaseGuard<'a>> {
        self.create_trie(empty_trie_hash!())
    }
}

impl Default for MemoryDatabase {
    fn default() -> MemoryDatabase {
        Self::new()
    }
}

impl<'a> DatabaseGuard for MemoryDatabaseGuard<'a> {
    fn get(&self, hash: H256) -> Option<Vec<u8>> {
        self.0.lock().unwrap().get(&hash).map(|v| v.clone())
    }

    fn set(&mut self, hash: H256, value: Vec<u8>) {
        self.0.lock().unwrap().insert(hash, value);
    }
}
