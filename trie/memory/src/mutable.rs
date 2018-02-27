use bigint::H256;
use sha3::{Digest, Keccak256};
use rlp::{self, Rlp};

use std::marker::PhantomData;

/// Represents a trie that is mutable.
pub trait TrieMut {
    /// Get the root hash of the current trie.
    fn root(&self) -> H256;
    /// Insert a value to the trie.
    fn insert(&mut self, key: &[u8], value: &[u8]);
    /// Delete a value in the trie.
    fn delete(&mut self, key: &[u8]);
    /// Get a value in the trie.
    fn get(&self, key: &[u8]) -> Option<Vec<u8>>;
}

/// Represents a mutable trie that is operated on any RLP values.
#[derive(Clone, Debug)]
pub struct AnyTrieMut<T: TrieMut>(T);

impl<T: TrieMut + Default> Default for AnyTrieMut<T> {
    fn default() -> Self {
        AnyTrieMut::new(T::default())
    }
}

impl<T: TrieMut> AnyTrieMut<T> {
    /// Into the underlying TrieMut object.
    pub fn to_trie(self) -> T {
        self.0
    }

    /// Initialize a new mutable trie.
    pub fn new(trie: T) -> Self {
        AnyTrieMut(trie)
    }

    /// Get the root hash of the current trie.
    pub fn root(&self) -> H256 {
        self.0.root()
    }

    /// Insert a value to the trie.
    pub fn insert<K: rlp::Encodable, V: rlp::Encodable>(&mut self, key: &K, value: &V) {
        let key = rlp::encode(key).to_vec();
        let value = rlp::encode(value).to_vec();

        self.0.insert(&key, &value)
    }

    /// Delete a value in the trie.
    pub fn delete<K: rlp::Encodable>(&mut self, key: &K) {
        let key = rlp::encode(key).to_vec();

        self.0.delete(&key)
    }

    /// Get a value in the trie.
    pub fn get<K: rlp::Encodable, V: rlp::Decodable>(&self, key: &K) -> Option<V> {
        let key = rlp::encode(key).to_vec();
        let value = self.0.get(&key);

        match value {
            Some(value) => Some(rlp::decode(&value)),
            None => None,
        }
    }
}

/// Represents a mutable trie that is operated on a fixed RLP value type.
#[derive(Clone, Debug)]
pub struct FixedTrieMut<T: TrieMut, K: rlp::Encodable, V: rlp::Encodable + rlp::Decodable>(AnyTrieMut<T>, PhantomData<(K, V)>);

impl<T: TrieMut + Default, K: rlp::Encodable, V: rlp::Encodable + rlp::Decodable> Default for FixedTrieMut<T, K, V> {
    fn default() -> Self {
        FixedTrieMut::new(T::default())
    }
}

impl<T: TrieMut, K: rlp::Encodable, V: rlp::Encodable + rlp::Decodable> FixedTrieMut<T, K, V> {
    /// Into the underlying TrieMut object.
    pub fn to_trie(self) -> T {
        self.0.to_trie()
    }

    /// Initialize a new mutable trie.
    pub fn new(trie: T) -> Self {
        FixedTrieMut(AnyTrieMut::new(trie), PhantomData)
    }

    /// Get the root hash of the current trie.
    pub fn root(&self) -> H256 {
        self.0.root()
    }

    /// Insert a value to the trie.
    pub fn insert(&mut self, key: &K, value: &V) {
        self.0.insert(key, value)
    }

    /// Delete a value in the trie.
    pub fn delete(&mut self, key: &K) {
        self.0.delete(key)
    }

    /// Get a value in the trie.
    pub fn get(&self, key: &K) -> Option<V> {
        self.0.get(key)
    }
}

/// Represents a secure mutable trie where the key is hashed.
#[derive(Clone, Debug)]
pub struct SecureTrieMut<T: TrieMut>(T);

impl<T: TrieMut + Default> Default for SecureTrieMut<T> {
    fn default() -> Self {
        SecureTrieMut::new(T::default())
    }
}

impl<T: TrieMut> SecureTrieMut<T> {
    /// Into the underlying TrieMut object.
    pub fn to_trie(self) -> T {
        self.0
    }

    /// Initialize a new mutable trie.
    pub fn new(trie: T) -> Self {
        SecureTrieMut(trie)
    }

    fn secure_key<K: AsRef<[u8]>>(key: &K) -> Vec<u8> {
        Keccak256::digest(key.as_ref()).as_slice().into()
    }

    /// Get the root hash of the current trie.
    pub fn root(&self) -> H256 {
        self.0.root()
    }

    /// Insert a value to the trie.
    pub fn insert<K: AsRef<[u8]>>(&mut self, key: &K, value: &[u8]) {
        self.0.insert(&Self::secure_key(key), value)
    }

    /// Delete a value in the trie.
    pub fn delete<K: AsRef<[u8]>>(&mut self, key: &K) {
        self.0.delete(&Self::secure_key(key))
    }

    /// Get a value in the trie.
    pub fn get<K: AsRef<[u8]>>(&self, key: &K) -> Option<Vec<u8>> {
        self.0.get(&Self::secure_key(key))
    }
}

/// Represents a secure mutable trie where the key is hashed, and
/// operated on any RLP values.
#[derive(Clone, Debug)]
pub struct AnySecureTrieMut<T: TrieMut>(SecureTrieMut<T>);

impl<T: TrieMut + Default> Default for AnySecureTrieMut<T> {
    fn default() -> Self {
        AnySecureTrieMut::new(T::default())
    }
}

impl<T: TrieMut> AnySecureTrieMut<T> {
    /// Into the underlying TrieMut object.
    pub fn to_trie(self) -> T {
        self.0.to_trie()
    }

    /// Initialize a new mutable trie.
    pub fn new(trie: T) -> Self {
        AnySecureTrieMut(SecureTrieMut::new(trie))
    }

    /// Get the root hash of the current trie.
    pub fn root(&self) -> H256 {
        self.0.root()
    }

    /// Insert a value to the trie.
    pub fn insert<K: AsRef<[u8]>, V: rlp::Encodable>(&mut self, key: &K, value: &V) {
        self.0.insert(&key, &rlp::encode(value).to_vec())
    }

    /// Delete a value in the trie.
    pub fn delete<K: AsRef<[u8]>>(&mut self, key: &K) {
        self.0.delete(&key)
    }

    /// Get a value in the trie.
    pub fn get<K: AsRef<[u8]>, V: rlp::Decodable>(&self, key: &K) -> Option<V> {
        let value = self.0.get(&key);

        match value {
            Some(value) => Some(rlp::decode(&value)),
            None => None,
        }
    }
}

/// Represents a secure mutable trie where the key is hashed, and
/// operated on a fixed RLP value type.
#[derive(Clone, Debug)]
pub struct FixedSecureTrieMut<T: TrieMut, K: AsRef<[u8]>, V: rlp::Encodable + rlp::Decodable>(AnySecureTrieMut<T>, PhantomData<(K, V)>);

impl<T: TrieMut + Default, K: AsRef<[u8]>, V: rlp::Encodable + rlp::Decodable> Default for FixedSecureTrieMut<T, K, V> {
    fn default() -> Self {
        FixedSecureTrieMut::new(T::default())
    }
}

impl<T: TrieMut, K: AsRef<[u8]>, V: rlp::Encodable + rlp::Decodable> FixedSecureTrieMut<T, K, V> {
    /// Into the underlying TrieMut object.
    pub fn to_trie(self) -> T {
        self.0.to_trie()
    }

    /// Initialize a new mutable trie.
    pub fn new(trie: T) -> Self {
        FixedSecureTrieMut(AnySecureTrieMut::new(trie), PhantomData)
    }

    /// Get the root hash of the current trie.
    pub fn root(&self) -> H256 {
        self.0.root()
    }

    /// Insert a value to the trie.
    pub fn insert(&mut self, key: &K, value: &V) {
        self.0.insert(key, value)
    }

    /// Delete a value in the trie.
    pub fn delete(&mut self, key: &K) {
        self.0.delete(key)
    }

    /// Get a value in the trie.
    pub fn get(&self, key: &K) -> Option<V> {
        self.0.get(key)
    }
}
