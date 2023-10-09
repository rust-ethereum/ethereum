use ethereum_types::{Bloom, H160, H256, H64, U256};
use sha3::{Digest, Keccak256};
use std::cell::Cell;
use rlp::{Encodable, Decodable};

use crate::Bytes;

#[derive(Clone, Debug, PartialEq, Eq)]
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
	pub base_fee: U256,
	#[cfg_attr(feature = "with-serde", serde(skip))]
	hash_cache: Cell<Option<H256>>,
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
			base_fee: partial_header.base_fee,
			hash_cache: Cell::new(None),
		}
	}

	#[must_use]
	pub fn hash(&mut self) -> H256 {
		let h = &self.hash_cache;
		if h.get().is_some() {
			let val = H256::from_slice(Keccak256::digest(&rlp::encode(self)).as_slice());
			h.set(Some(val));
		}
		h.get().unwrap()
	}
}


impl Encodable for Header {
	fn rlp_append(&self, s: &mut rlp::RlpStream) {
		s
			.begin_list(16)
			.append(&self.parent_hash)
			.append(&self.ommers_hash)
			.append(&self.beneficiary)
			.append(&self.state_root)
			.append(&self.transactions_root)
			.append(&self.receipts_root)
			.append(&self.logs_bloom)
			.append(&self.difficulty)
			.append(&self.number)
			.append(&self.gas_limit)
			.append(&self.gas_used)
			.append(&self.timestamp)
			.append(&self.extra_data)
			.append(&self.mix_hash)
			.append(&self.nonce)
			.append(&self.base_fee);
	}
}

impl Decodable for Header {
	fn decode(rlp: &rlp::Rlp<'_>) -> Result<Self, rlp::DecoderError> {
		Ok(Header {
			parent_hash: rlp.val_at(0)?,
			ommers_hash: rlp.val_at(1)?,
			beneficiary: rlp.val_at(2)?,
			state_root: rlp.val_at(3)?,
			transactions_root: rlp.val_at(4)?,
			receipts_root: rlp.val_at(5)?,
			logs_bloom: rlp.val_at(6)?,
			difficulty: rlp.val_at(7)?,
			number: rlp.val_at(8)?,
			gas_limit: rlp.val_at(9)?,
			gas_used: rlp.val_at(10)?,
			timestamp: rlp.val_at(11)?,
			extra_data: rlp.val_at(12)?,
			mix_hash: rlp.val_at(13)?,
			nonce: rlp.val_at(14)?,
			base_fee: rlp.val_at(15)?,
			hash_cache: Cell::new(None),
		})
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
	pub base_fee: U256,
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
			base_fee: header.base_fee,
		}
	}
}
