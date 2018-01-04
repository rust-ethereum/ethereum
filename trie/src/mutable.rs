use bigint::H256;
use rlp::{self, Rlp};
use sha3::{Digest, Keccak256};

use std::marker::PhantomData;

pub trait TrieMut {
    fn root(&self) -> H256;
    fn insert(&mut self, key: &[u8], value: &[u8]);
    fn delete(&mut self, key: &[u8]);
    fn get(&self, key: &[u8]) -> Option<Vec<u8>>;
}

#[derive(Clone, Debug)]
pub struct AnyTrieMut<T: TrieMut>(T);

impl<T: TrieMut + Default> Default for AnyTrieMut<T> {
    fn default() -> Self {
        AnyTrieMut::new(T::default())
    }
}

impl<T: TrieMut> AnyTrieMut<T> {
    pub fn to_trie(self) -> T {
        self.0
    }

    pub fn new(trie: T) -> Self {
        AnyTrieMut(trie)
    }

    pub fn root(&self) -> H256 {
        self.0.root()
    }

    pub fn insert<K: rlp::Encodable, V: rlp::Encodable>(&mut self, key: &K, value: &V) {
        let key = rlp::encode(key).to_vec();
        let value = rlp::encode(value).to_vec();

        self.0.insert(&key, &value)
    }

    pub fn delete<K: rlp::Encodable>(&mut self, key: &K) {
        let key = rlp::encode(key).to_vec();

        self.0.delete(&key)
    }

    pub fn get<K: rlp::Encodable, V: rlp::Decodable>(&self, key: &K) -> Option<V> {
        let key = rlp::encode(key).to_vec();
        let value = self.0.get(&key);

        match value {
            Some(value) => Some(rlp::decode(&value)),
            None => None,
        }
    }
}

#[derive(Clone, Debug)]
pub struct FixedTrieMut<T: TrieMut, K: rlp::Encodable, V: rlp::Encodable + rlp::Decodable>(AnyTrieMut<T>, PhantomData<(K, V)>);

impl<T: TrieMut + Default, K: rlp::Encodable, V: rlp::Encodable + rlp::Decodable> Default for FixedTrieMut<T, K, V> {
    fn default() -> Self {
        FixedTrieMut::new(T::default())
    }
}

impl<T: TrieMut, K: rlp::Encodable, V: rlp::Encodable + rlp::Decodable> FixedTrieMut<T, K, V> {
    pub fn to_trie(self) -> T {
        self.0.to_trie()
    }

    pub fn new(trie: T) -> Self {
        FixedTrieMut(AnyTrieMut::new(trie), PhantomData)
    }

    pub fn root(&self) -> H256 {
        self.0.root()
    }

    pub fn insert(&mut self, key: &K, value: &V) {
        self.0.insert(key, value)
    }

    pub fn delete(&mut self, key: &K) {
        self.0.delete(key)
    }

    pub fn get(&self, key: &K) -> Option<V> {
        self.0.get(key)
    }
}

#[derive(Clone, Debug)]
pub struct SecureTrieMut<T: TrieMut>(T);

impl<T: TrieMut + Default> Default for SecureTrieMut<T> {
    fn default() -> Self {
        SecureTrieMut::new(T::default())
    }
}

impl<T: TrieMut> SecureTrieMut<T> {
    pub fn to_trie(self) -> T {
        self.0
    }

    pub fn new(trie: T) -> Self {
        SecureTrieMut(trie)
    }

    fn secure_key<K: AsRef<[u8]>>(key: &K) -> Vec<u8> {
        Keccak256::digest(key.as_ref()).as_slice().into()
    }

    pub fn root(&self) -> H256 {
        self.0.root()
    }

    pub fn insert<K: AsRef<[u8]>>(&mut self, key: &K, value: &[u8]) {
        self.0.insert(&Self::secure_key(key), value)
    }

    pub fn delete<K: AsRef<[u8]>>(&mut self, key: &K) {
        self.0.delete(&Self::secure_key(key))
    }

    pub fn get<K: AsRef<[u8]>>(&self, key: &K) -> Option<Vec<u8>> {
        self.0.get(&Self::secure_key(key))
    }
}

#[derive(Clone, Debug)]
pub struct AnySecureTrieMut<T: TrieMut>(SecureTrieMut<T>);

impl<T: TrieMut + Default> Default for AnySecureTrieMut<T> {
    fn default() -> Self {
        AnySecureTrieMut::new(T::default())
    }
}

impl<T: TrieMut> AnySecureTrieMut<T> {
    pub fn to_trie(self) -> T {
        self.0.to_trie()
    }

    pub fn new(trie: T) -> Self {
        AnySecureTrieMut(SecureTrieMut::new(trie))
    }

    pub fn root(&self) -> H256 {
        self.0.root()
    }

    pub fn insert<K: AsRef<[u8]>, V: rlp::Encodable>(&mut self, key: &K, value: &V) {
        self.0.insert(&key, &rlp::encode(value).to_vec())
    }

    pub fn delete<K: AsRef<[u8]>>(&mut self, key: &K) {
        self.0.delete(&key)
    }

    pub fn get<K: AsRef<[u8]>, V: rlp::Decodable>(&self, key: &K) -> Option<V> {
        let value = self.0.get(&key);

        match value {
            Some(value) => Some(rlp::decode(&value)),
            None => None,
        }
    }
}

#[derive(Clone, Debug)]
pub struct FixedSecureTrieMut<T: TrieMut, K: AsRef<[u8]>, V: rlp::Encodable + rlp::Decodable>(AnySecureTrieMut<T>, PhantomData<(K, V)>);

impl<T: TrieMut + Default, K: AsRef<[u8]>, V: rlp::Encodable + rlp::Decodable> Default for FixedSecureTrieMut<T, K, V> {
    fn default() -> Self {
        FixedSecureTrieMut::new(T::default())
    }
}

impl<T: TrieMut, K: AsRef<[u8]>, V: rlp::Encodable + rlp::Decodable> FixedSecureTrieMut<T, K, V> {
    pub fn to_trie(self) -> T {
        self.0.to_trie()
    }

    pub fn new(trie: T) -> Self {
        FixedSecureTrieMut(AnySecureTrieMut::new(trie), PhantomData)
    }

    pub fn root(&self) -> H256 {
        self.0.root()
    }

    pub fn insert(&mut self, key: &K, value: &V) {
        self.0.insert(key, value)
    }

    pub fn delete(&mut self, key: &K) {
        self.0.delete(key)
    }

    pub fn get(&self, key: &K) -> Option<V> {
        self.0.get(key)
    }
}
