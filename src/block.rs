use crate::{
	util::ordered_trie_root, Header, PartialHeader, TransactionAny, TransactionV0, TransactionV1,
	TransactionV2,
};
use alloc::vec::Vec;
use ethereum_types::H256;
use rlp::{Decodable, DecoderError, Encodable, Rlp, RlpStream};
use sha3::{Digest, Keccak256};

#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(
	feature = "with-codec",
	derive(codec::Encode, codec::Decode, scale_info::TypeInfo)
)]
#[cfg_attr(feature = "with-serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Block<T> {
	pub header: Header,
	pub transactions: Vec<T>,
	pub ommers: Vec<Header>,
}

impl<T: Encodable> Encodable for Block<T> {
	fn rlp_append(&self, s: &mut RlpStream) {
		s.begin_list(3);
		s.append(&self.header);
		s.append_list(&self.transactions);
		s.append_list(&self.ommers);
	}
}

impl<T: Decodable> Decodable for Block<T> {
	fn decode(rlp: &Rlp) -> Result<Self, DecoderError> {
		Ok(Self {
			header: rlp.val_at(0)?,
			transactions: rlp.list_at(1)?,
			ommers: rlp.list_at(2)?,
		})
	}
}

impl<T: Encodable> Block<T> {
	#[must_use]
	pub fn new(partial_header: PartialHeader, transactions: Vec<T>, ommers: Vec<Header>) -> Self {
		let ommers_hash =
			H256::from_slice(Keccak256::digest(&rlp::encode_list(&ommers)[..]).as_slice());
		let transactions_root =
			ordered_trie_root(transactions.iter().map(|r| rlp::encode(r).freeze()));

		Self {
			header: Header::new(partial_header, ommers_hash, transactions_root),
			transactions,
			ommers,
		}
	}
}

pub type BlockV0 = Block<TransactionV0>;
pub type BlockV1 = Block<TransactionV1>;
pub type BlockV2 = Block<TransactionV2>;
pub type BlockAny = Block<TransactionAny>;

impl<T> From<BlockV0> for Block<T>
where
	T: From<TransactionV0> + From<TransactionV1>,
{
	fn from(t: BlockV0) -> Self {
		Self {
			header: t.header,
			transactions: t.transactions.into_iter().map(|t| t.into()).collect(),
			ommers: t.ommers,
		}
	}
}

impl From<BlockV1> for BlockV2 {
	fn from(t: BlockV1) -> Self {
		Self {
			header: t.header,
			transactions: t.transactions.into_iter().map(|t| t.into()).collect(),
			ommers: t.ommers,
		}
	}
}
