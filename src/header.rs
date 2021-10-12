use ethereum_types::{Bloom, H160, H256, H64, U256};
use rlp_derive::{RlpDecodable, RlpEncodable};
use sha3::{Digest, Keccak256};

use crate::Bytes;

#[derive(Clone, Debug, PartialEq, Eq, RlpEncodable, RlpDecodable)]
#[cfg_attr(
	feature = "with-codec",
	derive(codec::Encode, codec::Decode, scale_info::TypeInfo)
)]
#[cfg_attr(feature = "with-serde", derive(serde::Serialize, serde::Deserialize))]
/// Ethereum header definition.
pub struct Header {
	pub parent_hash: H256,
	pub ommers_hash: H256,
	pub beneficiary: H160,
	pub state_root: H256,
	pub transactions_root: H256,
	pub receipts_root: H256,
	pub logs_bloom: Bloom,
	pub difficulty: U256,
	pub number: U256,
	pub gas_limit: U256,
	pub gas_used: U256,
	pub timestamp: u64,
	pub extra_data: Bytes,
	pub mix_hash: H256,
	pub nonce: H64,
}

impl Header {
	#[must_use]
	pub fn new(partial_header: PartialHeader, ommers_hash: H256, transactions_root: H256) -> Self {
		Self {
			parent_hash: partial_header.parent_hash,
			ommers_hash,
			beneficiary: partial_header.beneficiary,
			state_root: partial_header.state_root,
			transactions_root,
			receipts_root: partial_header.receipts_root,
			logs_bloom: partial_header.logs_bloom,
			difficulty: partial_header.difficulty,
			number: partial_header.number,
			gas_limit: partial_header.gas_limit,
			gas_used: partial_header.gas_used,
			timestamp: partial_header.timestamp,
			extra_data: partial_header.extra_data,
			mix_hash: partial_header.mix_hash,
			nonce: partial_header.nonce,
		}
	}

	#[must_use]
	pub fn hash(&self) -> H256 {
		H256::from_slice(Keccak256::digest(&rlp::encode(self)).as_slice())
	}
}

#[derive(Clone, Debug, PartialEq, Eq)]
/// Partial header definition without ommers hash and transactions root.
pub struct PartialHeader {
	pub parent_hash: H256,
	pub beneficiary: H160,
	pub state_root: H256,
	pub receipts_root: H256,
	pub logs_bloom: Bloom,
	pub difficulty: U256,
	pub number: U256,
	pub gas_limit: U256,
	pub gas_used: U256,
	pub timestamp: u64,
	pub extra_data: Bytes,
	pub mix_hash: H256,
	pub nonce: H64,
}

impl From<Header> for PartialHeader {
	fn from(header: Header) -> PartialHeader {
		Self {
			parent_hash: header.parent_hash,
			beneficiary: header.beneficiary,
			state_root: header.state_root,
			receipts_root: header.receipts_root,
			logs_bloom: header.logs_bloom,
			difficulty: header.difficulty,
			number: header.number,
			gas_limit: header.gas_limit,
			gas_used: header.gas_used,
			timestamp: header.timestamp,
			extra_data: header.extra_data,
			mix_hash: header.mix_hash,
			nonce: header.nonce,
		}
	}
}
