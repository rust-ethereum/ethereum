extern crate bigint;
#[macro_use]
extern crate trie;
extern crate rlp;
extern crate sha3;
#[cfg(test)] extern crate hexutil;

pub mod gc;
mod memory;
mod mutable;
mod cache;

use cache::Cache;
use bigint::H256;
use trie::DatabaseHandle;

pub use memory::*;
pub use mutable::*;

pub trait CachedDatabaseHandle {
    fn get(&self, key: H256) -> Vec<u8>;
}

pub struct CachedHandle<D: CachedDatabaseHandle> {
    db: D,
    cache: Cache,
}

impl<D: CachedDatabaseHandle> CachedHandle<D> {
    pub fn new(db: D) -> Self {
        Self {
            db,
            cache: Cache::new(),
        }
    }
}

impl<D: CachedDatabaseHandle> DatabaseHandle for CachedHandle<D> {
    fn get(&self, key: H256) -> Option<&[u8]> {
        if !self.cache.contains_key(key) {
            Some(self.cache.insert(key, self.db.get(key)))
        } else {
            Some(self.cache.get(key).unwrap())
        }
    }
}
