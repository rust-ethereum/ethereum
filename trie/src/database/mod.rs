mod memory;

use super::{SecureTrie, FixedTrie, FixedSecureTrie, Trie};

pub use self::memory::{MemoryDatabase, MemoryDatabaseGuard};

use bigint::H256;
use rlp;
use std::collections::HashMap;
use std::cell::RefCell;

pub trait Database<'a> {
    type Guard: DatabaseGuard + 'a;

    fn create_guard(&'a self) -> Self::Guard;
    fn create_trie(&'a self, root: H256) -> Trie<Self::Guard> {
        Trie::existing(self.create_guard(), root)
    }
    fn create_empty(&'a self) -> Trie<Self::Guard> {
        self.create_trie(empty_trie_hash!())
    }
    fn create_secure_trie(&'a self, root: H256) -> SecureTrie<Self::Guard> {
        SecureTrie::new(self.create_trie(root))
    }
    fn create_secure_empty(&'a self) -> SecureTrie<Self::Guard> {
        SecureTrie::new(self.create_empty())
    }
    fn create_fixed_trie<K: rlp::Encodable + rlp::Decodable, V: rlp::Encodable + rlp::Decodable>(&'a self, root: H256) -> FixedTrie<Self::Guard, K, V> {
        FixedTrie::new(self.create_trie(root))
    }
    fn create_fixed_empty<K: rlp::Encodable + rlp::Decodable, V: rlp::Encodable + rlp::Decodable>(&'a self) -> FixedTrie<Self::Guard, K, V> {
        FixedTrie::new(self.create_empty())
    }
    fn create_fixed_secure_trie<K: AsRef<[u8]>, V: rlp::Encodable + rlp::Decodable>(&'a self, root: H256) -> FixedSecureTrie<Self::Guard, K, V> {
        FixedSecureTrie::new(self.create_secure_trie(root))
    }
    fn create_fixed_secure_empty<K: AsRef<[u8]>, V: rlp::Encodable + rlp::Decodable>(&'a self) -> FixedSecureTrie<Self::Guard, K, V> {
        FixedSecureTrie::new(self.create_secure_empty())
    }
}

pub trait DatabaseOwned: for<'a> Database<'a> {}
impl<T> DatabaseOwned for T where T: for<'a> Database<'a> {}

pub trait DatabaseGuard {
    fn get(&self, hash: H256) -> Option<Vec<u8>>;
    fn set(&mut self, hash: H256, value: Vec<u8>);
}

impl DatabaseGuard for HashMap<H256, Vec<u8>> {
    fn get<'a>(&'a self, hash: H256) -> Option<Vec<u8>> {
        self.get(&hash).map(|v| v.clone())
    }

    fn set<'a>(&'a mut self, hash: H256, value: Vec<u8>) {
        self.insert(hash, value);
    }
}

pub struct Change<'a, D: 'a> {
    database: &'a D,
    cache: RefCell<HashMap<H256, Vec<u8>>>,

    inserted: Vec<H256>,
    freed: Vec<H256>,
}

impl<'a, D: DatabaseGuard> Change<'a, D> {
    pub fn new(database: &'a D) -> Self {
        Self {
            database,
            cache: RefCell::new(HashMap::new()),

            inserted: Vec::new(),
            freed: Vec::new(),
        }
    }

    pub fn get<'b>(&'b self, hash: H256) -> Option<Vec<u8>> {
        if self.cache.borrow().contains_key(&hash) {
            self.cache.borrow().get(&hash).map(|v| v.clone())
        } else {
            let val = self.database.get(hash);
            if val.is_some() {
                self.cache.borrow_mut().insert(hash, val.clone().unwrap());
            }
            val
        }
    }

    pub fn set<'b, 'c>(&'b mut self, hash: H256, value: Vec<u8>) {
        self.cache.borrow_mut().insert(hash, value);
        self.inserted.push(hash);
    }

    pub fn free<'b>(&'b mut self, hash: H256) {
        self.freed.push(hash);
    }

    pub fn inserted<'b>(&'b self) -> &'b [H256] {
        self.inserted.as_ref()
    }

    pub fn freed<'b>(&'b self) -> &'b [H256] {
        self.freed.as_ref()
    }
}

impl<'a, D: DatabaseGuard> From<Change<'a, D>> for ChangeSet {
    fn from(val: Change<'a, D>) -> Self {
        ChangeSet {
            cache: val.cache,
            inserted: val.inserted,
            freed: val.freed,
        }
    }
}

pub struct ChangeSet {
    cache: RefCell<HashMap<H256, Vec<u8>>>,

    inserted: Vec<H256>,
    freed: Vec<H256>,
}

impl ChangeSet {
    pub fn drain<D: DatabaseGuard>(self, database: &mut D, nofree: bool) {
        if !nofree { unimplemented!() }

        for h in self.inserted {
            database.set(h, self.cache.borrow().get(&h).unwrap().clone())
        }
    }
}
