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

pub struct AnyTrieMut<T: TrieMut>(T);

impl<T: TrieMut + Default> Default for AnyTrieMut<T> {
    fn default() -> Self {
        AnyTrieMut::new(T::default())
    }
}

impl<T: TrieMut> AnyTrieMut<T> {
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

pub struct FixedTrieMut<T: TrieMut, K: rlp::Encodable, V: rlp::Encodable + rlp::Decodable>(T, PhantomData<(K, V)>);

impl<T: TrieMut + Default, K: rlp::Encodable, V: rlp::Encodable + rlp::Decodable> Default for FixedTrieMut<T, K, V> {
    fn default() -> Self {
        FixedTrieMut::new(T::default())
    }
}

impl<T: TrieMut, K: rlp::Encodable, V: rlp::Encodable + rlp::Decodable> FixedTrieMut<T, K, V> {
    pub fn new(trie: T) -> Self {
        FixedTrieMut(trie, PhantomData)
    }

    pub fn root(&self) -> H256 {
        self.0.root()
    }

    pub fn insert(&mut self, key: &K, value: &V) {
        let key = rlp::encode(key).to_vec();
        let value = rlp::encode(value).to_vec();

        self.0.insert(&key, &value)
    }

    pub fn delete(&mut self, key: &K) {
        let key = rlp::encode(key).to_vec();

        self.0.delete(&key)
    }

    pub fn get(&self, key: &K) -> Option<V> {
        let key = rlp::encode(key).to_vec();
        let value = self.0.get(&key);

        match value {
            Some(value) => Some(rlp::decode(&value)),
            None => None,
        }
    }
}

pub struct SecureTrieMut<T: TrieMut>(T);

impl<T: TrieMut + Default> Default for SecureTrieMut<T> {
    fn default() -> Self {
        SecureTrieMut::new(T::default())
    }
}

impl<T: TrieMut> SecureTrieMut<T> {
    pub fn new(trie: T) -> Self {
        SecureTrieMut(trie)
    }

    fn secure_key(key: &[u8]) -> Vec<u8> {
        Keccak256::digest(key.as_ref()).as_slice().into()
    }
}

impl<T: TrieMut> TrieMut for SecureTrieMut<T> {
    fn root(&self) -> H256 {
        self.0.root()
    }

    fn insert(&mut self, key: &[u8], value: &[u8]) {
        let key = Self::secure_key(key);

        self.0.insert(&key, value)
    }

    fn delete(&mut self, key: &[u8]) {
        let key = Self::secure_key(key);

        self.0.delete(&key)
    }

    fn get(&self, key: &[u8]) -> Option<Vec<u8>> {
        let key = Self::secure_key(key);

        self.0.get(&key)
    }
}

pub type FixedSecureTrieMut<T, K, V> = FixedTrieMut<SecureTrieMut<T>, K, V>;
pub type AnySecureTrieMut<T> = AnyTrieMut<SecureTrieMut<T>>;
