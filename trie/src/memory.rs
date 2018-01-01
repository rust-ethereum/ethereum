use bigint::H256;
use {DatabaseHandle, Trie, Change};

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

impl SingletonMemoryTrieMut {
    fn apply_change(&mut self, change: Change) {
        for add in change.adds {
            self.database.insert(add.0, add.1);
        }

        for remove in change.removes {
            self.database.remove(&remove);
        }
    }

    pub fn insert(&mut self, key: &[u8], value: &[u8]) {
        let (new_root, change) = {
            let trie = Trie::existing(&self.database, self.root);
            trie.insert(key, value)
        };

        self.apply_change(change);
        self.root = new_root;
    }

    pub fn delete(&mut self, key: &[u8]) {
        let (new_root, change) = {
            let trie = Trie::existing(&self.database, self.root);
            trie.delete(key)
        };

        self.apply_change(change);
        self.root = new_root;
    }
}

#[cfg(test)]
mod tests {
    use super::SingletonMemoryTrieMut;
    use merkle::MerkleNode;
    use rlp::Rlp;

    use trie_test::{DatabaseGuard, Trie};
    use std::collections::HashMap;
    use std::str::FromStr;
    use std::cell::UnsafeCell;
    use bigint::H256;
    use hexutil::read_hex;

    #[test]
    fn trie_middle_leaf() {
        let mut map = HashMap::new();
        map.insert("key1aa".as_bytes().into(), "0123456789012345678901234567890123456789xxx".as_bytes().into());
        map.insert("key1".as_bytes().into(), "0123456789012345678901234567890123456789Very_Long".as_bytes().into());
        map.insert("key2bb".as_bytes().into(), "aval3".as_bytes().into());
        map.insert("key2".as_bytes().into(), "short".as_bytes().into());
        map.insert("key3cc".as_bytes().into(), "aval3".as_bytes().into());
        map.insert("key3".as_bytes().into(), "1234567890123456789012345678901".as_bytes().into());

        let mut database: HashMap<H256, Vec<u8>> = HashMap::new();
        let mut trie: Trie<HashMap<H256, Vec<u8>>> = Trie::build(database, &map);

        assert_eq!(trie.root(), H256::from_str("0xcb65032e2f76c48b82b5c24b3db8f670ce73982869d38cd39a624f23d62a9e89").unwrap());
        assert_eq!(trie.get_raw("key2bb".as_bytes()), Some("aval3".as_bytes().into()));
        assert_eq!(trie.get_raw("key2bbb".as_bytes()), None);

        let mut mtrie = SingletonMemoryTrieMut::default();
        for (key, value) in &map {
            mtrie.insert(key, value);
        }

        assert_eq!(trie.database, mtrie.database);

        mtrie.insert("key2bbb".as_bytes(), "aval4".as_bytes());
        mtrie.delete("key2bbb".as_bytes());

        assert_eq!(trie.database, mtrie.database);
    }

    #[test]
    fn trie_two_keys() {
        let mut mtrie = SingletonMemoryTrieMut::default();
        mtrie.insert("key1".as_bytes(), "aval1".as_bytes());
        mtrie.insert("key2bb".as_bytes(), "aval3".as_bytes());
        let db1 = mtrie.database.clone();

        mtrie.insert("key2bbb".as_bytes(), "aval4".as_bytes());
        mtrie.delete("key2bbb".as_bytes());

        assert_eq!(db1, mtrie.database);
    }
}
