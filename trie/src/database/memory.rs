use ::Trie;
use super::{Database, DatabaseOwned, DatabaseGuard};
use bigint::H256;
use std::collections::HashMap;
use std::sync::Mutex;

pub struct MemoryDatabase(Mutex<HashMap<H256, Vec<u8>>>);
pub struct MemoryDatabaseGuard<'a>(&'a Mutex<HashMap<H256, Vec<u8>>>);

impl MemoryDatabase {
    pub fn new() -> Self {
        MemoryDatabase(Mutex::new(HashMap::new()))
    }
}

impl<'a> Database<'a> for MemoryDatabase {
    type Guard = MemoryDatabaseGuard<'a>;

    fn create_trie(&'a self, root: H256) -> Trie<Self::Guard> {
        Trie::existing(MemoryDatabaseGuard(&self.0), root)
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
