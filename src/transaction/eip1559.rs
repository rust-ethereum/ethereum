#[cfg(not(feature = "std"))]
use alloc::vec;

use ethereum_types::{H256, U256};
use rlp::{DecoderError, Rlp, RlpStream};
use sha3::{Digest, Keccak256};

use crate::{
	transaction::{AccessList, TransactionAction},
	Bytes,
};

#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(
	feature = "with-codec",
	derive(codec::Encode, codec::Decode, scale_info::TypeInfo)
)]
#[cfg_attr(feature = "with-serde", derive(serde::Serialize, serde::Deserialize))]
pub struct EIP1559Transaction {
	pub chain_id: u64,
	pub nonce: U256,
	pub max_priority_fee_per_gas: U256,
	pub max_fee_per_gas: U256,
	pub gas_limit: U256,
	pub action: TransactionAction,
	pub value: U256,
	pub input: Bytes,
	pub access_list: AccessList,
	pub odd_y_parity: bool,
	pub r: H256,
	pub s: H256,
}

impl EIP1559Transaction {
	pub fn hash(&self) -> H256 {
		let encoded = rlp::encode(self);
		let mut out = vec![0; 1 + encoded.len()];
		out[0] = 2;
		out[1..].copy_from_slice(&encoded);
		H256::from_slice(Keccak256::digest(&out).as_slice())
	}

	pub fn to_message(self) -> EIP1559TransactionMessage {
		EIP1559TransactionMessage {
			chain_id: self.chain_id,
			nonce: self.nonce,
			max_priority_fee_per_gas: self.max_priority_fee_per_gas,
			max_fee_per_gas: self.max_fee_per_gas,
			gas_limit: self.gas_limit,
			action: self.action,
			value: self.value,
			input: self.input,
			access_list: self.access_list,
		}
	}
}

impl rlp::Encodable for EIP1559Transaction {
	fn rlp_append(&self, s: &mut RlpStream) {
		s.begin_list(12);
		s.append(&self.chain_id);
		s.append(&self.nonce);
		s.append(&self.max_priority_fee_per_gas);
		s.append(&self.max_fee_per_gas);
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

impl rlp::Decodable for EIP1559Transaction {
	fn decode(rlp: &Rlp) -> Result<Self, DecoderError> {
		if rlp.item_count()? != 12 {
			return Err(DecoderError::RlpIncorrectListLen);
		}

		Ok(Self {
			chain_id: rlp.val_at(0)?,
			nonce: rlp.val_at(1)?,
			max_priority_fee_per_gas: rlp.val_at(2)?,
			max_fee_per_gas: rlp.val_at(3)?,
			gas_limit: rlp.val_at(4)?,
			action: rlp.val_at(5)?,
			value: rlp.val_at(6)?,
			input: rlp.val_at(7)?,
			access_list: rlp.list_at(8)?,
			odd_y_parity: rlp.val_at(9)?,
			r: {
				let mut rarr = [0_u8; 32];
				rlp.val_at::<U256>(10)?.to_big_endian(&mut rarr);
				H256::from(rarr)
			},
			s: {
				let mut sarr = [0_u8; 32];
				rlp.val_at::<U256>(11)?.to_big_endian(&mut sarr);
				H256::from(sarr)
			},
		})
	}
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EIP1559TransactionMessage {
	pub chain_id: u64,
	pub nonce: U256,
	pub max_priority_fee_per_gas: U256,
	pub max_fee_per_gas: U256,
	pub gas_limit: U256,
	pub action: TransactionAction,
	pub value: U256,
	pub input: Bytes,
	pub access_list: AccessList,
}

impl EIP1559TransactionMessage {
	pub fn hash(&self) -> H256 {
		let encoded = rlp::encode(self);
		let mut out = vec![0; 1 + encoded.len()];
		out[0] = 2;
		out[1..].copy_from_slice(&encoded);
		H256::from_slice(Keccak256::digest(&out).as_slice())
	}
}

impl rlp::Encodable for EIP1559TransactionMessage {
	fn rlp_append(&self, s: &mut RlpStream) {
		s.begin_list(9);
		s.append(&self.chain_id);
		s.append(&self.nonce);
		s.append(&self.max_priority_fee_per_gas);
		s.append(&self.max_fee_per_gas);
		s.append(&self.gas_limit);
		s.append(&self.action);
		s.append(&self.value);
		s.append(&self.input);
		s.append_list(&self.access_list);
	}
}

impl From<EIP1559Transaction> for EIP1559TransactionMessage {
	fn from(t: EIP1559Transaction) -> Self {
		t.to_message()
	}
}
