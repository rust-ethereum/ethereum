use alloc::vec::Vec;

use ethereum_types::{Address, H256, U256};
use rlp::{DecoderError, Rlp, RlpStream};
use sha3::{Digest, Keccak256};

use super::rlp_len::{rlp_h256_as_u256_len, rlp_list_len, RlpEncodableLen};
use super::signature;
use crate::Bytes;

pub use super::legacy::TransactionAction;

#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(
	feature = "with-scale",
	derive(
		scale_info::TypeInfo,
		scale_codec::Encode,
		scale_codec::Decode,
		scale_codec::DecodeWithMemTracking
	)
)]
#[cfg_attr(feature = "with-serde", derive(serde::Serialize, serde::Deserialize))]
pub struct MalleableTransactionSignature {
	pub odd_y_parity: bool,
	pub r: H256,
	pub s: H256,
}

#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(
	feature = "with-scale",
	derive(
		scale_info::TypeInfo,
		scale_codec::Encode,
		scale_codec::DecodeWithMemTracking
	)
)]
#[cfg_attr(feature = "with-serde", derive(serde::Serialize))]
pub struct TransactionSignature {
	odd_y_parity: bool,
	r: H256,
	s: H256,
}

impl TransactionSignature {
	#[must_use]
	pub fn new(odd_y_parity: bool, r: H256, s: H256) -> Option<Self> {
		let is_valid = signature::is_valid_signature_component(&r)
			&& signature::is_valid_signature_component(&s);

		if is_valid {
			Some(Self { odd_y_parity, r, s })
		} else {
			None
		}
	}

	#[must_use]
	pub fn odd_y_parity(&self) -> bool {
		self.odd_y_parity
	}

	#[must_use]
	pub fn r(&self) -> &H256 {
		&self.r
	}

	#[must_use]
	pub fn s(&self) -> &H256 {
		&self.s
	}

	#[must_use]
	pub fn is_low_s(&self) -> bool {
		signature::is_low_s(&self.s)
	}
}

#[cfg(feature = "with-scale")]
impl scale_codec::Decode for TransactionSignature {
	fn decode<I: scale_codec::Input>(value: &mut I) -> Result<Self, scale_codec::Error> {
		let unchecked = MalleableTransactionSignature::decode(value)?;
		match Self::new(unchecked.odd_y_parity, unchecked.r, unchecked.s) {
			Some(signature) => Ok(signature),
			None => Err(scale_codec::Error::from("Invalid signature")),
		}
	}
}

#[cfg(feature = "with-serde")]
impl<'de> serde::Deserialize<'de> for TransactionSignature {
	fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
	where
		D: serde::de::Deserializer<'de>,
	{
		let unchecked = MalleableTransactionSignature::deserialize(deserializer)?;
		TransactionSignature::new(unchecked.odd_y_parity, unchecked.r, unchecked.s)
			.ok_or(serde::de::Error::custom("invalid signature"))
	}
}

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

impl AccessListItem {
	/// Non-allocating RLP-encoded length.
	///
	/// Layout: `RLP_LIST(address‖RLP_LIST(storage_keys…))`
	///  * address (H160) is always 21 bytes (1-byte prefix + 20 data).
	///  * each storage key (H256) is always 33 bytes (1-byte prefix + 32 data).
	pub fn rlp_len(&self) -> usize {
		let payload = self.address.rlp_len() + self.storage_keys.rlp_len();
		rlp_list_len(payload)
	}
}

impl RlpEncodableLen for [AccessListItem] {
	fn rlp_len(&self) -> usize {
		let items_len: usize = self.iter().map(|item| item.rlp_len()).sum();
		rlp_list_len(items_len)
	}
}

pub type AccessList = Vec<AccessListItem>;

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
pub struct EIP2930Transaction {
	pub chain_id: u64,
	pub nonce: U256,
	pub gas_price: U256,
	pub gas_limit: U256,
	pub action: TransactionAction,
	pub value: U256,
	pub input: Bytes,
	pub access_list: AccessList,
	pub signature: TransactionSignature,
}

impl EIP2930Transaction {
	pub fn hash(&self) -> H256 {
		let encoded = rlp::encode(self);
		let mut out = alloc::vec![0; 1 + encoded.len()];
		out[0] = 1;
		out[1..].copy_from_slice(&encoded);
		H256::from_slice(Keccak256::digest(&out).as_ref())
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

	/// Non-allocating RLP-encoded length of this signed transaction.
	pub fn rlp_len(&self) -> usize {
		let payload = self.chain_id.rlp_len()
			+ self.nonce.rlp_len()
			+ self.gas_price.rlp_len()
			+ self.gas_limit.rlp_len()
			+ self.action.rlp_len()
			+ self.value.rlp_len()
			+ self.input.rlp_len()
			+ self.access_list.rlp_len()
			+ self.signature.odd_y_parity().rlp_len()
			+ rlp_h256_as_u256_len(self.signature.r())
			+ rlp_h256_as_u256_len(self.signature.s());
		rlp_list_len(payload)
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
		s.append(&self.signature.odd_y_parity());
		s.append(&U256::from_big_endian(&self.signature.r()[..]));
		s.append(&U256::from_big_endian(&self.signature.s()[..]));
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
			signature: {
				let odd_y_parity = rlp.val_at(8)?;
				let r = H256::from(rlp.val_at::<U256>(9)?.to_big_endian());
				let s = H256::from(rlp.val_at::<U256>(10)?.to_big_endian());
				TransactionSignature::new(odd_y_parity, r, s)
					.ok_or(DecoderError::Custom("Invalid transaction signature format"))?
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
		H256::from_slice(Keccak256::digest(&out).as_ref())
	}

	/// Returns the RLP-encoded length of this unsigned message without
	/// allocating.
	pub fn encoded_len(&self) -> usize {
		let payload = self.chain_id.rlp_len()
			+ self.nonce.rlp_len()
			+ self.gas_price.rlp_len()
			+ self.gas_limit.rlp_len()
			+ self.action.rlp_len()
			+ self.value.rlp_len()
			+ self.input.rlp_len()
			+ self.access_list.rlp_len();
		rlp_list_len(payload)
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
