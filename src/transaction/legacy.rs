use core::ops::Deref;

use ethereum_types::{H160, H256, U256};
use rlp::{DecoderError, Rlp, RlpStream};
use sha3::{Digest, Keccak256};

use crate::Bytes;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg_attr(
	feature = "with-codec",
	derive(codec::Encode, codec::Decode, scale_info::TypeInfo)
)]
#[cfg_attr(feature = "with-serde", derive(serde::Serialize, serde::Deserialize))]
pub enum TransactionAction {
	Call(H160),
	Create,
}

impl rlp::Encodable for TransactionAction {
	fn rlp_append(&self, s: &mut RlpStream) {
		match self {
			Self::Call(address) => {
				s.encoder().encode_value(&address[..]);
			}
			Self::Create => s.encoder().encode_value(&[]),
		}
	}
}

impl rlp::Decodable for TransactionAction {
	fn decode(rlp: &Rlp) -> Result<Self, DecoderError> {
		if rlp.is_empty() {
			if rlp.is_data() {
				Ok(TransactionAction::Create)
			} else {
				Err(DecoderError::RlpExpectedToBeData)
			}
		} else {
			Ok(TransactionAction::Call(rlp.as_val()?))
		}
	}
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg_attr(
	feature = "with-codec",
	derive(codec::Encode, codec::Decode, scale_info::TypeInfo)
)]
#[cfg_attr(feature = "with-serde", derive(serde::Serialize, serde::Deserialize))]
pub struct TransactionRecoveryId(pub u64);

impl Deref for TransactionRecoveryId {
	type Target = u64;

	fn deref(&self) -> &u64 {
		&self.0
	}
}

impl TransactionRecoveryId {
	pub fn standard(self) -> u8 {
		if self.0 == 27 || self.0 == 28 || self.0 > 36 {
			((self.0 - 1) % 2) as u8
		} else {
			4
		}
	}

	pub fn chain_id(self) -> Option<u64> {
		if self.0 > 36 {
			Some((self.0 - 35) / 2)
		} else {
			None
		}
	}
}

#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "with-codec", derive(scale_info::TypeInfo))]
#[cfg_attr(feature = "with-serde", derive(serde::Serialize, serde::Deserialize))]
pub struct TransactionSignature {
	v: TransactionRecoveryId,
	r: H256,
	s: H256,
}

impl TransactionSignature {
	#[must_use]
	pub fn new(v: u64, r: H256, s: H256) -> Option<Self> {
		const LOWER: H256 = H256([
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x01,
		]);
		const UPPER: H256 = H256([
			0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
			0xff, 0xfe, 0xba, 0xae, 0xdc, 0xe6, 0xaf, 0x48, 0xa0, 0x3b, 0xbf, 0xd2, 0x5e, 0x8c,
			0xd0, 0x36, 0x41, 0x41,
		]);

		let v = TransactionRecoveryId(v);
		let is_valid = v.standard() <= 1 && r < UPPER && r >= LOWER && s < UPPER && s >= LOWER;

		if is_valid {
			Some(Self { v, r, s })
		} else {
			None
		}
	}

	#[must_use]
	pub fn v(&self) -> u64 {
		self.v.0
	}

	#[must_use]
	pub fn standard_v(&self) -> u8 {
		self.v.standard()
	}

	#[must_use]
	pub fn chain_id(&self) -> Option<u64> {
		self.v.chain_id()
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
		const LOWER: H256 = H256([
			0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
			0xff, 0xff, 0x5d, 0x57, 0x6e, 0x73, 0x57, 0xa4, 0x50, 0x1d, 0xdf, 0xe9, 0x2f, 0x46,
			0x68, 0x1b, 0x20, 0xa0,
		]);

		self.s <= LOWER
	}
}

#[cfg(feature = "codec")]
impl codec::Encode for TransactionSignature {
	fn size_hint(&self) -> usize {
		codec::Encode::size_hint(&(self.v.0, self.r, self.s))
	}

	fn using_encoded<R, F: FnOnce(&[u8]) -> R>(&self, f: F) -> R {
		codec::Encode::using_encoded(&(self.v.0, self.r, self.s), f)
	}
}

#[cfg(feature = "codec")]
impl codec::Decode for TransactionSignature {
	fn decode<I: codec::Input>(value: &mut I) -> Result<Self, codec::Error> {
		let (v, r, s) = codec::Decode::decode(value)?;
		match Self::new(v, r, s) {
			Some(signature) => Ok(signature),
			None => Err(codec::Error::from("Invalid signature")),
		}
	}
}

#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(
	feature = "with-codec",
	derive(codec::Encode, codec::Decode, scale_info::TypeInfo)
)]
#[cfg_attr(feature = "with-serde", derive(serde::Serialize, serde::Deserialize))]
pub struct LegacyTransaction {
	pub nonce: U256,
	pub gas_price: U256,
	pub gas_limit: U256,
	pub action: TransactionAction,
	pub value: U256,
	pub input: Bytes,
	pub signature: TransactionSignature,
}

impl LegacyTransaction {
	pub fn hash(&self) -> H256 {
		H256::from_slice(Keccak256::digest(&rlp::encode(self)).as_slice())
	}

	pub fn to_message(self) -> LegacyTransactionMessage {
		LegacyTransactionMessage {
			nonce: self.nonce,
			gas_price: self.gas_price,
			gas_limit: self.gas_limit,
			action: self.action,
			value: self.value,
			input: self.input,
			chain_id: self.signature.chain_id(),
		}
	}
}

impl rlp::Encodable for LegacyTransaction {
	fn rlp_append(&self, s: &mut RlpStream) {
		s.begin_list(9);
		s.append(&self.nonce);
		s.append(&self.gas_price);
		s.append(&self.gas_limit);
		s.append(&self.action);
		s.append(&self.value);
		s.append(&self.input);
		s.append(&self.signature.v.0);
		s.append(&U256::from_big_endian(&self.signature.r[..]));
		s.append(&U256::from_big_endian(&self.signature.s[..]));
	}
}

impl rlp::Decodable for LegacyTransaction {
	fn decode(rlp: &Rlp) -> Result<Self, DecoderError> {
		if rlp.item_count()? != 9 {
			return Err(DecoderError::RlpIncorrectListLen);
		}

		let v = rlp.val_at(6)?;
		let r = {
			let mut rarr = [0_u8; 32];
			rlp.val_at::<U256>(7)?.to_big_endian(&mut rarr);
			H256::from(rarr)
		};
		let s = {
			let mut sarr = [0_u8; 32];
			rlp.val_at::<U256>(8)?.to_big_endian(&mut sarr);
			H256::from(sarr)
		};
		let signature = TransactionSignature::new(v, r, s)
			.ok_or(DecoderError::Custom("Invalid transaction signature format"))?;

		Ok(Self {
			nonce: rlp.val_at(0)?,
			gas_price: rlp.val_at(1)?,
			gas_limit: rlp.val_at(2)?,
			action: rlp.val_at(3)?,
			value: rlp.val_at(4)?,
			input: rlp.val_at(5)?,
			signature,
		})
	}
}

#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(
	feature = "with-codec",
	derive(codec::Encode, codec::Decode, scale_info::TypeInfo)
)]
pub struct LegacyTransactionMessage {
	pub nonce: U256,
	pub gas_price: U256,
	pub gas_limit: U256,
	pub action: TransactionAction,
	pub value: U256,
	pub input: Bytes,
	pub chain_id: Option<u64>,
}

impl LegacyTransactionMessage {
	pub fn hash(&self) -> H256 {
		H256::from_slice(Keccak256::digest(&rlp::encode(self)).as_slice())
	}
}

impl rlp::Encodable for LegacyTransactionMessage {
	fn rlp_append(&self, s: &mut RlpStream) {
		if let Some(chain_id) = self.chain_id {
			s.begin_list(9);
			s.append(&self.nonce);
			s.append(&self.gas_price);
			s.append(&self.gas_limit);
			s.append(&self.action);
			s.append(&self.value);
			s.append(&self.input);
			s.append(&chain_id);
			s.append(&0_u8);
			s.append(&0_u8);
		} else {
			s.begin_list(6);
			s.append(&self.nonce);
			s.append(&self.gas_price);
			s.append(&self.gas_limit);
			s.append(&self.action);
			s.append(&self.value);
			s.append(&self.input);
		}
	}
}

impl From<LegacyTransaction> for LegacyTransactionMessage {
	fn from(t: LegacyTransaction) -> Self {
		t.to_message()
	}
}
