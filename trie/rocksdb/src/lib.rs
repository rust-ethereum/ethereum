extern crate trie;
extern crate trie_memory;
extern crate bigint;
extern crate parity_rocksdb as rocksdb;

use bigint::H256;
use trie::{Change, DatabaseHandle, get, insert, delete};
use trie_memory::{CachedDatabaseHandle, CachedHandle, TrieMut};
use rocksdb::{DB, Writable};

pub struct RocksDatabaseHandle<'a>(&'a DB);

impl<'a> CachedDatabaseHandle for RocksDatabaseHandle<'a> {
    fn get(&self, key: H256) -> Vec<u8> {
        let value = self.0.get(key.as_ref()).unwrap().unwrap();
        value.as_ref().into()
    }
}

impl<'a> RocksDatabaseHandle<'a> {
    pub fn new(db: &'a DB) -> Self {
        RocksDatabaseHandle(db)
    }
}

pub type RocksHandle<'a> = CachedHandle<RocksDatabaseHandle<'a>>;

pub struct RocksMemoryTrieMut<'a> {
    handle: RocksHandle<'a>,
    change: Change,
    root: H256,
    db: &'a DB,
    cached: bool,
}

impl<'a, 'b> DatabaseHandle for &'b RocksMemoryTrieMut<'a> {
    fn get(&self, key: H256) -> Option<&[u8]> {
        if self.change.adds.contains_key(&key) {
            self.change.adds.get(&key).map(|v| v.as_ref())
        } else {
            self.handle.get(key)
        }
    }
}

impl<'a> TrieMut for RocksMemoryTrieMut<'a> {
    fn root(&self) -> H256 {
        self.root
    }

    fn insert(&mut self, key: &[u8], value: &[u8]) {
        self.clear_cache();

        let (new_root, change) = insert(self.root, &&*self, key, value).unwrap();

        self.change.merge(&change);
        self.root = new_root;
    }

    fn delete(&mut self, key: &[u8]) {
        self.clear_cache();

        let (new_root, change) = delete(self.root, &&*self, key).unwrap();

        self.change.merge(&change);
        self.root = new_root;
    }

    fn get(&self, key: &[u8]) -> Option<Vec<u8>> {
        get(self.root, &self, key).unwrap().map(|v| v.into())
    }
}

impl<'a> RocksMemoryTrieMut<'a> {
    fn clear_cache(&mut self) {
        if !self.cached {
            self.handle = RocksHandle::new(RocksDatabaseHandle::new(self.db.clone()));
        }
    }

    pub fn new(db: &'a DB, root: H256, cached: bool) -> Self {
        Self {
            handle: RocksHandle::new(RocksDatabaseHandle::new(db.clone())),
            change: Change::default(),
            root,
            db,
            cached,
        }
    }

    pub fn new_cached(db: &'a DB, root: H256) -> Self { Self::new(db, root, true) }
    pub fn new_uncached(db: &'a DB, root: H256) -> Self { Self::new(db, root, false) }

    pub fn apply(self) -> Result<(), String> {
        for (key, value) in self.change.adds {
            self.db.put(key.as_ref(), &value)?;
        }

        for key in self.change.removes {
            self.db.delete(key.as_ref())?;
        }

        Ok(())
    }
}
