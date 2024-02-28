use alloc::vec::Vec;

use ethereum_types::{Address, H256, U256};
use rlp::{DecoderError, Rlp, RlpStream};
use sha3::{Digest, Keccak256};

use crate::{transaction::TransactionAction, Bytes};

#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(
	feature = "with-scale",
	derive(scale_codec::Encode, scale_codec::Decode, scale_info::TypeInfo)
)]
#[cfg_attr(feature = "with-serde", derive(serde::Serialize, serde::Deserialize))]
pub struct AccessListItem {
	pub address: Address,
	pub storage_keys: Vec<H256>,
}

impl rlp::Encodable for AccessListItem {
	fn rlp_append(&self, s: &mut RlpStream) {
		s.begin_list(2);
		s.append(&self.address);
		s.append_list(&self.storage_keys);
	}
}

impl rlp::Decodable for AccessListItem {
	fn decode(rlp: &Rlp) -> Result<Self, DecoderError> {
		Ok(Self {
			address: rlp.val_at(0)?,
			storage_keys: rlp.list_at(1)?,
		})
	}
}

pub type AccessList = Vec<AccessListItem>;

#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(
	feature = "with-scale",
	derive(scale_codec::Encode, scale_codec::Decode, scale_info::TypeInfo)
)]
#[cfg_attr(feature = "with-serde", derive(serde::Serialize, serde::Deserialize))]
pub struct EIP2930Transaction {
	pub chain_id: u64,
	pub nonce: U256,
	pub gas_price: U256,
	pub gas_limit: U256,
	pub action: TransactionAction,
	pub value: U256,
	pub input: Bytes,
	pub access_list: AccessList,
	pub odd_y_parity: bool,
	pub r: H256,
	pub s: H256,
}

impl EIP2930Transaction {
	pub fn hash(&self) -> H256 {
		let encoded = rlp::encode(self);
		let mut out = alloc::vec![0; 1 + encoded.len()];
		out[0] = 1;
		out[1..].copy_from_slice(&encoded);
		H256::from_slice(Keccak256::digest(&out).as_slice())
	}

	pub fn to_message(self) -> EIP2930TransactionMessage {
		EIP2930TransactionMessage {
			chain_id: self.chain_id,
			nonce: self.nonce,
			gas_price: self.gas_price,
			gas_limit: self.gas_limit,
			action: self.action,
			value: self.value,
			input: self.input,
			access_list: self.access_list,
		}
	}
}

impl rlp::Encodable for EIP2930Transaction {
	fn rlp_append(&self, s: &mut RlpStream) {
		s.begin_list(11);
		s.append(&self.chain_id);
		s.append(&self.nonce);
		s.append(&self.gas_price);
		s.append(&self.gas_limit);
		s.append(&self.action);
		s.append(&self.value);
		s.append(&self.input);
		s.append_list(&self.access_list);
		s.append(&self.odd_y_parity);
		s.append(&U256::from_big_endian(&self.r[..]));
		s.append(&U256::from_big_endian(&self.s[..]));
	}
}

impl rlp::Decodable for EIP2930Transaction {
	fn decode(rlp: &Rlp) -> Result<Self, DecoderError> {
		if rlp.item_count()? != 11 {
			return Err(DecoderError::RlpIncorrectListLen);
		}

		Ok(Self {
			chain_id: rlp.val_at(0)?,
			nonce: rlp.val_at(1)?,
			gas_price: rlp.val_at(2)?,
			gas_limit: rlp.val_at(3)?,
			action: rlp.val_at(4)?,
			value: rlp.val_at(5)?,
			input: rlp.val_at(6)?,
			access_list: rlp.list_at(7)?,
			odd_y_parity: rlp.val_at(8)?,
			r: {
				let mut rarr = [0_u8; 32];
				rlp.val_at::<U256>(9)?.to_big_endian(&mut rarr);
				H256::from(rarr)
			},
			s: {
				let mut sarr = [0_u8; 32];
				rlp.val_at::<U256>(10)?.to_big_endian(&mut sarr);
				H256::from(sarr)
			},
		})
	}
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EIP2930TransactionMessage {
	pub chain_id: u64,
	pub nonce: U256,
	pub gas_price: U256,
	pub gas_limit: U256,
	pub action: TransactionAction,
	pub value: U256,
	pub input: Bytes,
	pub access_list: AccessList,
}

impl EIP2930TransactionMessage {
	pub fn hash(&self) -> H256 {
		let encoded = rlp::encode(self);
		let mut out = alloc::vec![0; 1 + encoded.len()];
		out[0] = 1;
		out[1..].copy_from_slice(&encoded);
		H256::from_slice(Keccak256::digest(&out).as_slice())
	}
}

impl rlp::Encodable for EIP2930TransactionMessage {
	fn rlp_append(&self, s: &mut RlpStream) {
		s.begin_list(8);
		s.append(&self.chain_id);
		s.append(&self.nonce);
		s.append(&self.gas_price);
		s.append(&self.gas_limit);
		s.append(&self.action);
		s.append(&self.value);
		s.append(&self.input);
		s.append_list(&self.access_list);
	}
}

impl From<EIP2930Transaction> for EIP2930TransactionMessage {
	fn from(t: EIP2930Transaction) -> Self {
		t.to_message()
	}
}
