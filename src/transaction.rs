use crate::Bytes;
use core::ops::Deref;
use ethereum_types::{H160, H256, U256};
use rlp::{Decodable, DecoderError, Encodable, Rlp, RlpStream};
use sha3::{Digest, Keccak256};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "with-codec", derive(codec::Encode, codec::Decode))]
#[cfg_attr(feature = "with-serde", derive(serde::Serialize, serde::Deserialize))]
pub enum TransactionAction {
	Call(H160),
	Create,
}

impl Encodable for TransactionAction {
	fn rlp_append(&self, s: &mut RlpStream) {
		match self {
			Self::Call(address) => {
				s.encoder().encode_value(&address[..]);
			}
			Self::Create => s.encoder().encode_value(&[]),
		}
	}
}

impl Decodable for TransactionAction {
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
#[cfg_attr(feature = "with-codec", derive(codec::Encode, codec::Decode))]
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
#[cfg_attr(feature = "with-codec", derive(codec::Encode, codec::Decode))]
pub struct TransactionMessage {
	pub nonce: U256,
	pub gas_price: U256,
	pub gas_limit: U256,
	pub action: TransactionAction,
	pub value: U256,
	pub input: Bytes,
	pub chain_id: Option<u64>,
}

impl Encodable for TransactionMessage {
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

impl TransactionMessage {
	#[must_use]
	pub fn hash(&self) -> H256 {
		H256::from_slice(Keccak256::digest(&rlp::encode(self)).as_slice())
	}
}

impl From<Transaction> for TransactionMessage {
	fn from(t: Transaction) -> TransactionMessage {
		TransactionMessage {
			nonce: t.nonce,
			gas_price: t.gas_price,
			gas_limit: t.gas_limit,
			action: t.action,
			value: t.value,
			input: t.input,
			chain_id: t.signature.chain_id(),
		}
	}
}

#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "with-codec", derive(codec::Encode, codec::Decode))]
#[cfg_attr(feature = "with-serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Transaction {
	pub nonce: U256,
	pub gas_price: U256,
	pub gas_limit: U256,
	pub action: TransactionAction,
	pub value: U256,
	pub input: Bytes,
	pub signature: TransactionSignature,
}

impl Encodable for Transaction {
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

impl Decodable for Transaction {
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

#[cfg(test)]
mod tests {
	use super::*;
	use hex_literal::hex;

	#[test]
	fn can_decode_raw_transaction() {
		let bytes = hex!("f901e48080831000008080b90196608060405234801561001057600080fd5b50336000806101000a81548173ffffffffffffffffffffffffffffffffffffffff021916908373ffffffffffffffffffffffffffffffffffffffff1602179055507fc68045c3c562488255b55aa2c4c7849de001859ff0d8a36a75c2d5ed80100fb660405180806020018281038252600d8152602001807f48656c6c6f2c20776f726c64210000000000000000000000000000000000000081525060200191505060405180910390a160cf806100c76000396000f3fe6080604052348015600f57600080fd5b506004361060285760003560e01c80638da5cb5b14602d575b600080fd5b60336075565b604051808273ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200191505060405180910390f35b6000809054906101000a900473ffffffffffffffffffffffffffffffffffffffff168156fea265627a7a72315820fae816ad954005c42bea7bc7cb5b19f7fd5d3a250715ca2023275c9ca7ce644064736f6c634300050f003278a04cab43609092a99cf095d458b61b47189d1bbab64baed10a0fd7b7d2de2eb960a011ab1bcda76dfed5e733219beb83789f9887b2a7b2e61759c7c90f7d40403201");

		assert!(rlp::decode::<Transaction>(&bytes[..]).is_ok());
	}
}
