use crate::{Header, PartialHeader, Transaction};
use alloc::vec::Vec;
use ethereum_types::H256;
use rlp_derive::{RlpDecodable, RlpEncodable};
use sha3::{Digest, Keccak256};

#[derive(Clone, Debug, PartialEq, Eq, RlpEncodable, RlpDecodable)]
#[cfg_attr(feature = "codec", derive(codec::Encode, codec::Decode))]
pub struct Block {
	pub header: Header,
	pub transactions: Vec<Transaction>,
	pub ommers: Vec<Header>,
}

impl Block {
	#[must_use]
	pub fn new(
		partial_header: PartialHeader,
		transactions: Vec<Transaction>,
		ommers: Vec<Header>,
	) -> Self {
		let ommers_hash =
			H256::from_slice(Keccak256::digest(&rlp::encode_list(&ommers)[..]).as_slice());
		let transactions_root =
			H256::from_slice(Keccak256::digest(&rlp::encode_list(&transactions)[..]).as_slice());

		Self {
			header: Header::new(partial_header, ommers_hash, transactions_root),
			transactions,
			ommers,
		}
	}
}
