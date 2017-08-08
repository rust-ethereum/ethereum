use super::merkle::MerkleNode;
use bigint::H256;
use rlp::Rlp;
use std::collections::HashMap;
use std::cell::{RefCell, UnsafeCell};

pub struct Cache {
    cache: UnsafeCell<Vec<Vec<u8>>>,
    map: RefCell<HashMap<H256, usize>>,
}

impl Cache {
    pub fn new() -> Cache {
        Cache {
            cache: UnsafeCell::new(Vec::new()),
            map: RefCell::new(HashMap::new())
        }
    }

    pub fn insert<'a>(&'a self, key: H256, value: Vec<u8>) -> MerkleNode<'a> {
        let cache = unsafe { &mut *self.cache.get() };
        let index = cache.len();
        self.map.borrow_mut().insert(key, index);
        cache.push(value);
        MerkleNode::decode(&Rlp::new(&cache[index]))
    }
}
