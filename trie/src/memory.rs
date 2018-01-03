use bigint::H256;
use {DatabaseHandle, Change, insert, delete, build, get};

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

    pub fn build(map: &HashMap<Vec<u8>, Vec<u8>>) -> Self {
        let (new_root, change) = build(map);

        let mut ret = Self::default();
        ret.apply_change(change);
        ret.root = new_root;

        ret
    }

    pub fn insert(&mut self, key: &[u8], value: &[u8]) {
        let (new_root, change) = insert(self.root, &&self.database, key, value);

        self.apply_change(change);
        self.root = new_root;
    }

    pub fn delete(&mut self, key: &[u8]) {
        let (new_root, change) = delete(self.root, &&self.database, key);

        self.apply_change(change);
        self.root = new_root;
    }

    pub fn get(&self, key: &[u8]) -> Option<Vec<u8>> {
        get(self.root, &&self.database, key).map(|v| v.into())
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

        let mut btrie = SingletonMemoryTrieMut::build(&map);

        let mut database: HashMap<H256, Vec<u8>> = HashMap::new();
        let mut trie: Trie<HashMap<H256, Vec<u8>>> = Trie::build(database, &map);

        assert_eq!(trie.database, btrie.database);

        assert_eq!(trie.root(), H256::from_str("0xcb65032e2f76c48b82b5c24b3db8f670ce73982869d38cd39a624f23d62a9e89").unwrap());
        assert_eq!(trie.get_raw("key2bb".as_bytes()), Some("aval3".as_bytes().into()));
        assert_eq!(btrie.get("key2bb".as_bytes()), Some("aval3".as_bytes().into()));
        assert_eq!(trie.get_raw("key2bbb".as_bytes()), None);
        assert_eq!(btrie.get("key2bbb".as_bytes()), None);

        let mut mtrie = SingletonMemoryTrieMut::default();
        for (key, value) in &map {
            mtrie.insert(key, value);
        }

        assert_eq!(trie.database, mtrie.database);

        mtrie.insert("key2bbb".as_bytes(), "aval4".as_bytes());
        mtrie.delete("key2bbb".as_bytes());

        assert_eq!(trie.database, mtrie.database);

        for (key, value) in &map {
            mtrie.delete(key);
        }

        assert!(mtrie.database.len() == 0);
        assert!(mtrie.root == empty_trie_hash!());
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
