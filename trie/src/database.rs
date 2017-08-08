use bigint::H256;
use std::collections::HashMap;
use std::cell::RefCell;

pub trait Database {
    fn get(&self, hash: H256) -> Option<Vec<u8>>;
    fn set(&mut self, hash: H256, value: Vec<u8>);
}

impl Database for HashMap<H256, Vec<u8>> {
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

impl<'a, D: Database> Change<'a, D> {
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

impl<'a, D: Database> From<Change<'a, D>> for ChangeSet {
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
    pub fn drain<D: Database>(self, database: &mut D, nofree: bool) {
        if !nofree { unimplemented!() }

        for h in self.inserted {
            database.set(h, self.cache.borrow().get(&h).unwrap().clone())
        }
    }
}
