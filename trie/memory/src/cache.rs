use trie::merkle::MerkleNode;
use bigint::H256;
use rlp::Rlp;
use std::ptr;
use std::collections::HashMap;
use std::cell::{RefCell, Cell};

pub struct Cache {
    map: RefCell<HashMap<H256, usize>>,

    cache_head: Cell<*mut Node>,
    cache_len: Cell<usize>,
}

struct Node {
    next: *mut Node,
    value: Vec<u8>,
}

impl Drop for Cache {
    fn drop(&mut self) {
        if self.cache_head.get().is_null() {
            return;
        }

        let mut all_ptrs = Vec::new();
        all_ptrs.push(self.cache_head.get());

        let mut cur_node = unsafe { &*self.cache_head.get() };

        loop {
            if cur_node.next.is_null() {
                break;
            }

            all_ptrs.push(cur_node.next);
            cur_node = unsafe { &*cur_node.next };
        }

        for ptr in all_ptrs {
            unsafe { Box::from_raw(ptr); }
        }
    }
}

impl Cache {
    fn at<'a>(&'a self, index: usize) -> Option<&'a [u8]> {
        if self.cache_head.get().is_null() {
            return None;
        }

        let mut cur_index = self.cache_len.get() - 1;
        let mut cur_node = unsafe { &*self.cache_head.get() };

        loop {
            if cur_index < index {
                return None;
            }

            if cur_index == index {
                return Some(cur_node.value.as_ref());
            }

            if cur_node.next.is_null() {
                return None;
            }

            cur_index -= 1;
            cur_node = unsafe { &*cur_node.next };
        }
    }

    pub fn new() -> Cache {
        Cache {
            map: RefCell::new(HashMap::new()),

            cache_head: Cell::new(ptr::null_mut()),
            cache_len: Cell::new(0),
        }
    }

    pub fn insert<'a>(&'a self, key: H256, value: Vec<u8>) -> &'a [u8] {
        let index = self.cache_len.get();
        self.cache_len.set(self.cache_len.get() + 1);

        self.map.borrow_mut().insert(key, index);
        let node_ptr = Box::into_raw(Box::new(Node {
            next: self.cache_head.get(),
            value: value,
        }));
        self.cache_head.set(node_ptr);

        self.at(index).unwrap()
    }

    pub fn get<'a>(&'a self, key: H256) -> Option<&'a [u8]> {
        let mut map = self.map.borrow_mut();
        match map.get(&key) {
            Some(index) => Some(self.at(*index).unwrap()),
            None => None,
        }
    }

    pub fn contains_key(&self, key: H256) -> bool {
        let mut map = self.map.borrow_mut();
        map.contains_key(&key)
    }
}
