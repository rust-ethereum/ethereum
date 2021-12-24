//! Utility functions for Ethereum.

use ethereum_types::H256;
use hash256_std_hasher::Hash256StdHasher;
use hash_db::Hasher;
use rlp::{Encodable, RlpStream};
use sha3::{Digest, Keccak256};

pub fn enveloped<T: Encodable>(id: u8, v: &T, s: &mut RlpStream) {
	let encoded = rlp::encode(v);
	let mut out = alloc::vec![0; 1 + encoded.len()];
	out[0] = id;
	out[1..].copy_from_slice(&encoded);
	out.rlp_append(s)
}

/// Concrete `Hasher` impl for the Keccak-256 hash
#[derive(Default, Debug, Clone, PartialEq)]
pub struct KeccakHasher;
impl Hasher for KeccakHasher {
	type Out = H256;

	type StdHasher = Hash256StdHasher;

	const LENGTH: usize = 32;

	fn hash(x: &[u8]) -> Self::Out {
		H256::from_slice(Keccak256::digest(x).as_slice())
	}
}

/// Generates a trie root hash for a vector of key-value tuples
pub fn trie_root<I, K, V>(input: I) -> H256
where
	I: IntoIterator<Item = (K, V)>,
	K: AsRef<[u8]> + Ord,
	V: AsRef<[u8]>,
{
	triehash::trie_root::<KeccakHasher, _, _, _>(input)
}

/// Generates a key-hashed (secure) trie root hash for a vector of key-value tuples.
pub fn sec_trie_root<I, K, V>(input: I) -> H256
where
	I: IntoIterator<Item = (K, V)>,
	K: AsRef<[u8]>,
	V: AsRef<[u8]>,
{
	triehash::sec_trie_root::<KeccakHasher, _, _, _>(input)
}

/// Generates a trie root hash for a vector of values
pub fn ordered_trie_root<I, V>(input: I) -> H256
where
	I: IntoIterator<Item = V>,
	V: AsRef<[u8]>,
{
	triehash::ordered_trie_root::<KeccakHasher, I>(input)
}
