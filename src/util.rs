//! Utility functions for Ethereum.

use alloc::vec::Vec;

use ethereum_types::H256;
use hash256_std_hasher::Hash256StdHasher;
use hash_db::Hasher;
use sha3::{Digest, Keccak256};
use trie_root::Value as TrieStreamValue;

/// Concrete `Hasher` impl for the Keccak-256 hash
#[derive(Default, Debug, Clone, PartialEq, Eq)]
pub struct KeccakHasher;
impl Hasher for KeccakHasher {
	type Out = H256;
	type StdHasher = Hash256StdHasher;
	const LENGTH: usize = 32;

	fn hash(x: &[u8]) -> Self::Out {
		H256::from_slice(Keccak256::digest(x).as_slice())
	}
}

/// Concrete `TrieStream` impl for the ethereum trie.
#[derive(Default)]
pub struct Hash256RlpTrieStream {
	stream: rlp::RlpStream,
}

impl trie_root::TrieStream for Hash256RlpTrieStream {
	fn new() -> Self {
		Self {
			stream: rlp::RlpStream::new(),
		}
	}

	fn append_empty_data(&mut self) {
		self.stream.append_empty_data();
	}

	fn begin_branch(
		&mut self,
		_maybe_key: Option<&[u8]>,
		_maybe_value: Option<TrieStreamValue>,
		_has_children: impl Iterator<Item = bool>,
	) {
		// an item for every possible nibble/suffix
		// + 1 for data
		self.stream.begin_list(17);
	}

	fn append_empty_child(&mut self) {
		self.stream.append_empty_data();
	}

	fn end_branch(&mut self, value: Option<TrieStreamValue>) {
		match value {
			Some(value) => match value {
				TrieStreamValue::Inline(value) => self.stream.append(&value),
				TrieStreamValue::Node(value) => self.stream.append(&value),
			},
			None => self.stream.append_empty_data(),
		};
	}

	fn append_leaf(&mut self, key: &[u8], value: TrieStreamValue) {
		self.stream.begin_list(2);
		self.stream.append_iter(hex_prefix_encode(key, true));
		match value {
			TrieStreamValue::Inline(value) => self.stream.append(&value),
			TrieStreamValue::Node(value) => self.stream.append(&value),
		};
	}

	fn append_extension(&mut self, key: &[u8]) {
		self.stream.begin_list(2);
		self.stream.append_iter(hex_prefix_encode(key, false));
	}

	fn append_substream<H: Hasher>(&mut self, other: Self) {
		let out = other.out();
		match out.len() {
			0..=31 => self.stream.append_raw(&out, 1),
			_ => self.stream.append(&H::hash(&out).as_ref()),
		};
	}

	fn out(self) -> Vec<u8> {
		self.stream.out().freeze().into()
	}
}

// Copy from `triehash` crate.
/// Hex-prefix Notation. First nibble has flags: oddness = 2^0 & termination = 2^1.
///
/// The "termination marker" and "leaf-node" specifier are completely equivalent.
///
/// Input values are in range `[0, 0xf]`.
///
/// ```markdown
///  [0,0,1,2,3,4,5]   0x10012345 // 7 > 4
///  [0,1,2,3,4,5]     0x00012345 // 6 > 4
///  [1,2,3,4,5]       0x112345   // 5 > 3
///  [0,0,1,2,3,4]     0x00001234 // 6 > 3
///  [0,1,2,3,4]       0x101234   // 5 > 3
///  [1,2,3,4]         0x001234   // 4 > 3
///  [0,0,1,2,3,4,5,T] 0x30012345 // 7 > 4
///  [0,0,1,2,3,4,T]   0x20001234 // 6 > 4
///  [0,1,2,3,4,5,T]   0x20012345 // 6 > 4
///  [1,2,3,4,5,T]     0x312345   // 5 > 3
///  [1,2,3,4,T]       0x201234   // 4 > 3
/// ```
fn hex_prefix_encode(nibbles: &[u8], leaf: bool) -> impl Iterator<Item = u8> + '_ {
	let inlen = nibbles.len();
	let oddness_factor = inlen % 2;

	let first_byte = {
		let mut bits = ((inlen as u8 & 1) + (2 * leaf as u8)) << 4;
		if oddness_factor == 1 {
			bits += nibbles[0];
		}
		bits
	};
	core::iter::once(first_byte).chain(
		nibbles[oddness_factor..]
			.chunks(2)
			.map(|ch| ch[0] << 4 | ch[1]),
	)
}

/// Generates a trie root hash for a vector of key-value tuples
pub fn trie_root<I, K, V>(input: I) -> H256
where
	I: IntoIterator<Item = (K, V)>,
	K: AsRef<[u8]> + Ord,
	V: AsRef<[u8]>,
{
	trie_root::trie_root::<KeccakHasher, Hash256RlpTrieStream, _, _, _>(input, None)
}

/// Generates a key-hashed (secure) trie root hash for a vector of key-value tuples.
pub fn sec_trie_root<I, K, V>(input: I) -> H256
where
	I: IntoIterator<Item = (K, V)>,
	K: AsRef<[u8]>,
	V: AsRef<[u8]>,
{
	trie_root::sec_trie_root::<KeccakHasher, Hash256RlpTrieStream, _, _, _>(input, None)
}

/// Generates a trie root hash for a vector of values
pub fn ordered_trie_root<I, V>(input: I) -> H256
where
	I: IntoIterator<Item = V>,
	V: AsRef<[u8]>,
{
	trie_root::trie_root::<KeccakHasher, Hash256RlpTrieStream, _, _, _>(
		input
			.into_iter()
			.enumerate()
			.map(|(i, v)| (rlp::encode(&i), v)),
		None,
	)
}

#[cfg(test)]
mod tests {
	use ethereum_types::H256;
	use hash256_std_hasher::Hash256StdHasher;
	use hex_literal::hex;
	use sha3::{Digest, Keccak256};

	#[derive(Default, Debug, Clone, PartialEq, Eq)]
	struct KeccakHasher15;
	impl hash_db15::Hasher for KeccakHasher15 {
		type Out = H256;
		type StdHasher = Hash256StdHasher;
		const LENGTH: usize = 32;

		fn hash(x: &[u8]) -> Self::Out {
			H256::from_slice(Keccak256::digest(x).as_slice())
		}
	}

	#[test]
	fn test_trie_root() {
		let v = vec![
			("doe", "reindeer"),
			("dog", "puppy"),
			("dogglesworth", "cat"),
		];
		let root = hex!("8aad789dff2f538bca5d8ea56e8abe10f4c7ba3a5dea95fea4cd6e7c3a1168d3");

		let before = triehash::trie_root::<KeccakHasher15, _, _, _>(v.clone());
		assert_eq!(before.0, root);

		let after = super::trie_root::<_, _, _>(v);
		assert_eq!(after.0, root);
	}

	#[test]
	fn test_sec_trie_root() {
		let v = vec![
			("doe", "reindeer"),
			("dog", "puppy"),
			("dogglesworth", "cat"),
		];
		let root = hex!("d4cd937e4a4368d7931a9cf51686b7e10abb3dce38a39000fd7902a092b64585");

		let before = triehash::sec_trie_root::<KeccakHasher15, _, _, _>(v.clone());
		assert_eq!(before.0, root);

		let after = super::sec_trie_root::<_, _, _>(v);
		assert_eq!(after.0, root);
	}

	#[test]
	fn test_ordered_trie_root() {
		let v = &["doe", "reindeer"];
		let root = hex!("e766d5d51b89dc39d981b41bda63248d7abce4f0225eefd023792a540bcffee3");

		let before = triehash::ordered_trie_root::<KeccakHasher15, _>(v);
		assert_eq!(before.0, root);

		let after = super::ordered_trie_root::<_, _>(v);
		assert_eq!(after.0, root);
	}
}
