use bigint::H256;
use trie::{Change, DatabaseHandle, get, insert, delete};
use TrieMut;

pub trait ItemCounter {
    fn increase(&mut self, key: H256) -> usize;
    fn decrease(&mut self, key: H256) -> usize;
}

pub trait DatabaseMut {
    fn get(&self, key: H256) -> &[u8];
    fn set(&mut self, key: H256, value: Option<&[u8]>);
}

struct DatabaseMutHandle<'a, D: DatabaseMut + 'a>(&'a D);

impl<'a, D: DatabaseMut> DatabaseHandle for DatabaseMutHandle<'a, D> {
    fn get(&self, key: H256) -> Option<&[u8]> {
        Some(DatabaseMut::get(self.0, key))
    }
}

pub struct TrieCollection<D: DatabaseMut, C: ItemCounter> {
    database: D,
    counter: C,
}

impl<D: DatabaseMut, C: ItemCounter> TrieCollection<D, C> {
    pub fn new(database: D, counter: C) -> Self {
        Self { database, counter }
    }

    pub fn trie_for<'a>(&'a self, root: H256) -> DatabaseTrieMut<'a, D> {
        DatabaseTrieMut {
            database: &self.database,
            change: Change::default(),
            root: root
        }
    }

    pub fn apply<'a>(&'a mut self, trie: DatabaseTrieMut<'a, D>) {
        for (key, value) in trie.change.adds {
            self.database.set(key, Some(&value));
            self.counter.increase(key);
        }

        for key in trie.change.removes {
            let r = self.counter.decrease(key);
            if r == 0 {
                self.database.set(key, None);
            }
        }
    }
}

pub struct DatabaseTrieMut<'a, D: DatabaseMut + 'a> {
    database: &'a D,
    change: Change,
    root: H256,
}

impl<'a, D: DatabaseMut> TrieMut for DatabaseTrieMut<'a, D> {
    fn root(&self) -> H256 {
        self.root
    }

    fn insert(&mut self, key: &[u8], value: &[u8]) {
        let (new_root, change) = insert(self.root, &DatabaseMutHandle(self.database), key, value).unwrap();

        self.change.merge(&change);
        self.root = new_root;
    }

    fn delete(&mut self, key: &[u8]) {
        let (new_root, change) = delete(self.root, &DatabaseMutHandle(self.database), key).unwrap();

        self.change.merge(&change);
        self.root = new_root;
    }

    fn get(&self, key: &[u8]) -> Option<Vec<u8>> {
        get(self.root, &DatabaseMutHandle(self.database), key).unwrap().map(|v| v.into())
    }
}
