use alloc::vec::Vec;

use ethereum_types::{Address, H256, U256};
use rlp::{DecoderError, Rlp, RlpStream};
use sha3::{Digest, Keccak256};

use crate::{
	transaction::{AccessList, TransactionAction},
	Bytes,
};

/// EIP-7702 transaction type as defined in the specification
pub const SET_CODE_TX_TYPE: u8 = 0x04;

/// EIP-7702 authorization message magic prefix
pub const AUTHORIZATION_MAGIC: u8 = 0x05;

#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(
	feature = "with-scale",
	derive(
		scale_codec::Encode,
		scale_codec::Decode,
		scale_codec::DecodeWithMemTracking,
		scale_info::TypeInfo
	)
)]
#[cfg_attr(feature = "with-serde", derive(serde::Serialize, serde::Deserialize))]
pub struct AuthorizationListItem {
	pub chain_id: u64,
	pub address: Address,
	pub nonce: U256,
	pub y_parity: bool,
	pub r: H256,
	pub s: H256,
}

impl rlp::Encodable for AuthorizationListItem {
	fn rlp_append(&self, s: &mut RlpStream) {
		s.begin_list(6);
		s.append(&self.chain_id);
		s.append(&self.address);
		s.append(&self.nonce);
		s.append(&self.y_parity);
		s.append(&U256::from_big_endian(&self.r[..]));
		s.append(&U256::from_big_endian(&self.s[..]));
	}
}

impl rlp::Decodable for AuthorizationListItem {
	fn decode(rlp: &Rlp) -> Result<Self, DecoderError> {
		if rlp.item_count()? != 6 {
			return Err(DecoderError::RlpIncorrectListLen);
		}

		Ok(Self {
			chain_id: rlp.val_at(0)?,
			address: rlp.val_at(1)?,
			nonce: rlp.val_at(2)?,
			y_parity: rlp.val_at(3)?,
			r: H256::from(rlp.val_at::<U256>(4)?.to_big_endian()),
			s: H256::from(rlp.val_at::<U256>(5)?.to_big_endian()),
		})
	}
}

pub type AuthorizationList = Vec<AuthorizationListItem>;

#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(
	feature = "with-scale",
	derive(
		scale_codec::Encode,
		scale_codec::Decode,
		scale_codec::DecodeWithMemTracking,
		scale_info::TypeInfo
	)
)]
#[cfg_attr(feature = "with-serde", derive(serde::Serialize, serde::Deserialize))]
pub struct EIP7702Transaction {
	pub chain_id: u64,
	pub nonce: U256,
	pub max_priority_fee_per_gas: U256,
	pub max_fee_per_gas: U256,
	pub gas_limit: U256,
	pub destination: TransactionAction,
	pub value: U256,
	pub data: Bytes,
	pub access_list: AccessList,
	pub authorization_list: AuthorizationList,
	pub odd_y_parity: bool,
	pub r: H256,
	pub s: H256,
}

impl EIP7702Transaction {
	pub fn hash(&self) -> H256 {
		let encoded = rlp::encode(self);
		let mut out = alloc::vec![0; 1 + encoded.len()];
		out[0] = SET_CODE_TX_TYPE;
		out[1..].copy_from_slice(&encoded);
		H256::from_slice(Keccak256::digest(&out).as_slice())
	}

	pub fn to_message(self) -> EIP7702TransactionMessage {
		EIP7702TransactionMessage {
			chain_id: self.chain_id,
			nonce: self.nonce,
			max_priority_fee_per_gas: self.max_priority_fee_per_gas,
			max_fee_per_gas: self.max_fee_per_gas,
			gas_limit: self.gas_limit,
			destination: self.destination,
			value: self.value,
			data: self.data,
			access_list: self.access_list,
			authorization_list: self.authorization_list,
		}
	}
}

impl rlp::Encodable for EIP7702Transaction {
	fn rlp_append(&self, s: &mut RlpStream) {
		s.begin_list(13);
		s.append(&self.chain_id);
		s.append(&self.nonce);
		s.append(&self.max_priority_fee_per_gas);
		s.append(&self.max_fee_per_gas);
		s.append(&self.gas_limit);
		s.append(&self.destination);
		s.append(&self.value);
		s.append(&self.data);
		s.append_list(&self.access_list);
		s.append_list(&self.authorization_list);
		s.append(&self.odd_y_parity);
		s.append(&U256::from_big_endian(&self.r[..]));
		s.append(&U256::from_big_endian(&self.s[..]));
	}
}

impl rlp::Decodable for EIP7702Transaction {
	fn decode(rlp: &Rlp) -> Result<Self, DecoderError> {
		if rlp.item_count()? != 13 {
			return Err(DecoderError::RlpIncorrectListLen);
		}

		Ok(Self {
			chain_id: rlp.val_at(0)?,
			nonce: rlp.val_at(1)?,
			max_priority_fee_per_gas: rlp.val_at(2)?,
			max_fee_per_gas: rlp.val_at(3)?,
			gas_limit: rlp.val_at(4)?,
			destination: rlp.val_at(5)?,
			value: rlp.val_at(6)?,
			data: rlp.val_at(7)?,
			access_list: rlp.list_at(8)?,
			authorization_list: rlp.list_at(9)?,
			odd_y_parity: rlp.val_at(10)?,
			r: H256::from(rlp.val_at::<U256>(11)?.to_big_endian()),
			s: H256::from(rlp.val_at::<U256>(12)?.to_big_endian()),
		})
	}
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EIP7702TransactionMessage {
	pub chain_id: u64,
	pub nonce: U256,
	pub max_priority_fee_per_gas: U256,
	pub max_fee_per_gas: U256,
	pub gas_limit: U256,
	pub destination: TransactionAction,
	pub value: U256,
	pub data: Bytes,
	pub access_list: AccessList,
	pub authorization_list: AuthorizationList,
}

impl EIP7702TransactionMessage {
	pub fn hash(&self) -> H256 {
		let encoded = rlp::encode(self);
		let mut out = alloc::vec![0; 1 + encoded.len()];
		out[0] = SET_CODE_TX_TYPE;
		out[1..].copy_from_slice(&encoded);
		H256::from_slice(Keccak256::digest(&out).as_slice())
	}
}

impl rlp::Encodable for EIP7702TransactionMessage {
	fn rlp_append(&self, s: &mut RlpStream) {
		s.begin_list(10);
		s.append(&self.chain_id);
		s.append(&self.nonce);
		s.append(&self.max_priority_fee_per_gas);
		s.append(&self.max_fee_per_gas);
		s.append(&self.gas_limit);
		s.append(&self.destination);
		s.append(&self.value);
		s.append(&self.data);
		s.append_list(&self.access_list);
		s.append_list(&self.authorization_list);
	}
}

impl From<EIP7702Transaction> for EIP7702TransactionMessage {
	fn from(t: EIP7702Transaction) -> Self {
		t.to_message()
	}
}
