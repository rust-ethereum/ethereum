use crate::Bytes;
use alloc::vec::Vec;
use core::ops::Deref;
use ethereum_types::{Address, H160, H256, U256};
use rlp::{Decodable, DecoderError, Encodable, Rlp, RlpStream};
use sha3::{Digest, Keccak256};

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
pub struct AccessListItem {
	pub address: Address,
	pub slots: Vec<H256>,
}

impl Encodable for AccessListItem {
	fn rlp_append(&self, s: &mut RlpStream) {
		s.begin_list(2);
		s.append(&self.address);
		s.append_list(&self.slots);
	}
}

impl Decodable for AccessListItem {
	fn decode(rlp: &Rlp) -> Result<Self, DecoderError> {
		Ok(Self {
			address: rlp.val_at(0)?,
			slots: rlp.list_at(1)?,
		})
	}
}

pub type AccessList = Vec<AccessListItem>;

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

impl From<LegacyTransaction> for LegacyTransactionMessage {
	fn from(t: TransactionV0) -> Self {
		Self {
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

impl Encodable for LegacyTransactionMessage {
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

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EIP2930TransactionMessage {
	pub chain_id: u64,
	pub nonce: U256,
	pub gas_price: U256,
	pub gas_limit: U256,
	pub action: TransactionAction,
	pub value: U256,
	pub input: Bytes,
	pub access_list: Vec<AccessListItem>,
}

impl From<EIP2930Transaction> for EIP2930TransactionMessage {
	fn from(t: EIP2930Transaction) -> Self {
		Self {
			chain_id: t.chain_id,
			nonce: t.nonce,
			gas_price: t.gas_price,
			gas_limit: t.gas_limit,
			action: t.action,
			value: t.value,
			input: t.input,
			access_list: t.access_list,
		}
	}
}

impl Encodable for EIP2930TransactionMessage {
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

impl EIP2930TransactionMessage {
	pub fn hash(&self) -> H256 {
		H256::from_slice(Keccak256::digest(&rlp::encode(self)).as_slice())
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
	pub access_list: Vec<AccessListItem>,
}

impl From<EIP1559Transaction> for EIP1559TransactionMessage {
	fn from(t: EIP1559Transaction) -> Self {
		Self {
			chain_id: t.chain_id,
			nonce: t.nonce,
			max_priority_fee_per_gas: t.max_priority_fee_per_gas,
			max_fee_per_gas: t.max_fee_per_gas,
			gas_limit: t.gas_limit,
			action: t.action,
			value: t.value,
			input: t.input,
			access_list: t.access_list,
		}
	}
}

impl Encodable for EIP1559TransactionMessage {
	fn rlp_append(&self, s: &mut RlpStream) {
		s.begin_list(8);
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

impl EIP1559TransactionMessage {
	pub fn hash(&self) -> H256 {
		H256::from_slice(Keccak256::digest(&rlp::encode(self)).as_slice())
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

impl Encodable for LegacyTransaction {
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

impl Decodable for LegacyTransaction {
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

impl Encodable for EIP2930Transaction {
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

impl Decodable for EIP2930Transaction {
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

impl Encodable for EIP1559Transaction {
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

impl Decodable for EIP1559Transaction {
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

pub type TransactionV0 = LegacyTransaction;

#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "with-codec", derive(codec::Encode, codec::Decode))]
#[cfg_attr(feature = "with-serde", derive(serde::Serialize, serde::Deserialize))]
pub enum TransactionV1 {
	/// Legacy transaction type
	Legacy(LegacyTransaction),
	/// EIP-2930 transaction
	EIP2930(EIP2930Transaction),
}

impl Encodable for TransactionV1 {
	fn rlp_append(&self, s: &mut RlpStream) {
		match self {
			Self::Legacy(tx) => tx.rlp_append(s),
			Self::EIP2930(tx) => enveloped(1, tx, s),
		}
	}
}

impl Decodable for TransactionV1 {
	fn decode(rlp: &Rlp) -> Result<Self, DecoderError> {
		let slice = rlp.data()?;

		let first = *slice.get(0).ok_or(DecoderError::Custom("empty slice"))?;

		if rlp.is_list() {
			return Ok(Self::Legacy(rlp.as_val()?));
		}

		let s = slice.get(1..).ok_or(DecoderError::Custom("no tx body"))?;

		if first == 0x01 {
			return rlp::decode(s).map(Self::EIP2930);
		}

		Err(DecoderError::Custom("invalid tx type"))
	}
}

#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(
	feature = "with-codec",
	derive(codec::Encode, codec::Decode, scale_info::TypeInfo)
)]
#[cfg_attr(feature = "with-serde", derive(serde::Serialize, serde::Deserialize))]
pub enum TransactionV2 {
	/// Legacy transaction type
	Legacy(LegacyTransaction),
	/// EIP-2930 transaction
	EIP2930(EIP2930Transaction),
	/// EIP-1559 transaction
	EIP1559(EIP1559Transaction),
}

impl Encodable for TransactionV2 {
	fn rlp_append(&self, s: &mut RlpStream) {
		match self {
			Self::Legacy(tx) => tx.rlp_append(s),
			Self::EIP2930(tx) => enveloped(1, tx, s),
			Self::EIP1559(tx) => enveloped(2, tx, s),
		}
	}
}

impl Decodable for TransactionV2 {
	fn decode(rlp: &Rlp) -> Result<Self, DecoderError> {
		let slice = rlp.data()?;

		let first = *slice.get(0).ok_or(DecoderError::Custom("empty slice"))?;

		if rlp.is_list() {
			return Ok(Self::Legacy(rlp.as_val()?));
		}

		let s = slice.get(1..).ok_or(DecoderError::Custom("no tx body"))?;

		if first == 0x01 {
			return rlp::decode(s).map(Self::EIP2930);
		}

		if first == 0x02 {
			return rlp::decode(s).map(Self::EIP1559);
		}

		Err(DecoderError::Custom("invalid tx type"))
	}
}

fn enveloped<T: Encodable>(id: u8, v: &T, s: &mut RlpStream) {
	let encoded = rlp::encode(v);
	let mut out = alloc::vec![0; 1 + encoded.len()];
	out[0] = id;
	out[1..].copy_from_slice(&encoded);
	out.rlp_append(s)
}

#[cfg(test)]
mod tests {
	use super::*;
	use hex_literal::hex;

	#[test]
	fn can_decode_raw_transaction() {
		let bytes = hex!("f901e48080831000008080b90196608060405234801561001057600080fd5b50336000806101000a81548173ffffffffffffffffffffffffffffffffffffffff021916908373ffffffffffffffffffffffffffffffffffffffff1602179055507fc68045c3c562488255b55aa2c4c7849de001859ff0d8a36a75c2d5ed80100fb660405180806020018281038252600d8152602001807f48656c6c6f2c20776f726c64210000000000000000000000000000000000000081525060200191505060405180910390a160cf806100c76000396000f3fe6080604052348015600f57600080fd5b506004361060285760003560e01c80638da5cb5b14602d575b600080fd5b60336075565b604051808273ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200191505060405180910390f35b6000809054906101000a900473ffffffffffffffffffffffffffffffffffffffff168156fea265627a7a72315820fae816ad954005c42bea7bc7cb5b19f7fd5d3a250715ca2023275c9ca7ce644064736f6c634300050f003278a04cab43609092a99cf095d458b61b47189d1bbab64baed10a0fd7b7d2de2eb960a011ab1bcda76dfed5e733219beb83789f9887b2a7b2e61759c7c90f7d40403201");

		rlp::decode::<TransactionV0>(&bytes).unwrap();
		rlp::decode::<TransactionV1>(&bytes).unwrap();
		rlp::decode::<TransactionV2>(&bytes).unwrap();
	}

	#[test]
	fn transaction_v0() {
		let tx = TransactionV0 {
			nonce: 12.into(),
			gas_price: 20_000_000_000_u64.into(),
			gas_limit: 21000.into(),
			action: TransactionAction::Call(
				hex!("727fc6a68321b754475c668a6abfb6e9e71c169a").into(),
			),
			value: U256::from(10) * 1_000_000_000 * 1_000_000_000,
			input: hex!("a9059cbb000000000213ed0f886efd100b67c7e4ec0a85a7d20dc971600000000000000000000015af1d78b58c4000").into(),
			signature: TransactionSignature::new(38, hex!("be67e0a07db67da8d446f76add590e54b6e92cb6b8f9835aeb67540579a27717").into(), hex!("2d690516512020171c1ec870f6ff45398cc8609250326be89915fb538e7bd718").into()).unwrap(),
		};

		assert_eq!(tx, rlp::decode::<TransactionV0>(&rlp::encode(&tx)).unwrap());
	}

	#[test]
	fn transaction_v1() {
		let tx = TransactionV1::EIP2930(EIP2930Transaction {
			chain_id: 5,
			nonce: 7.into(),
			gas_price: 30_000_000_000_u64.into(),
			gas_limit: 5_748_100_u64.into(),
			action: TransactionAction::Call(
				hex!("811a752c8cd697e3cb27279c330ed1ada745a8d7").into(),
			),
			value: U256::from(2) * 1_000_000_000 * 1_000_000_000,
			input: hex!("6ebaf477f83e051589c1188bcc6ddccd").into(),
			access_list: vec![
				AccessListItem {
					address: hex!("de0b295669a9fd93d5f28d9ec85e40f4cb697bae").into(),
					slots: vec![
						hex!("0000000000000000000000000000000000000000000000000000000000000003")
							.into(),
						hex!("0000000000000000000000000000000000000000000000000000000000000007")
							.into(),
					],
				},
				AccessListItem {
					address: hex!("bb9bc244d798123fde783fcc1c72d3bb8c189413").into(),
					slots: vec![],
				},
			],
			odd_y_parity: false,
			r: hex!("36b241b061a36a32ab7fe86c7aa9eb592dd59018cd0443adc0903590c16b02b0").into(),
			s: hex!("5edcc541b4741c5cc6dd347c5ed9577ef293a62787b4510465fadbfe39ee4094").into(),
		});

		assert_eq!(tx, rlp::decode::<TransactionV1>(&rlp::encode(&tx)).unwrap());
	}

	#[test]
	fn transaction_v2() {
		let tx = TransactionV2::EIP1559(EIP1559Transaction {
			chain_id: 5,
			nonce: 7.into(),
			max_priority_fee_per_gas: 10_000_000_000_u64.into(),
			max_fee_per_gas: 30_000_000_000_u64.into(),
			gas_limit: 5_748_100_u64.into(),
			action: TransactionAction::Call(
				hex!("811a752c8cd697e3cb27279c330ed1ada745a8d7").into(),
			),
			value: U256::from(2) * 1_000_000_000 * 1_000_000_000,
			input: hex!("6ebaf477f83e051589c1188bcc6ddccd").into(),
			access_list: vec![
				AccessListItem {
					address: hex!("de0b295669a9fd93d5f28d9ec85e40f4cb697bae").into(),
					slots: vec![
						hex!("0000000000000000000000000000000000000000000000000000000000000003")
							.into(),
						hex!("0000000000000000000000000000000000000000000000000000000000000007")
							.into(),
					],
				},
				AccessListItem {
					address: hex!("bb9bc244d798123fde783fcc1c72d3bb8c189413").into(),
					slots: vec![],
				},
			],
			odd_y_parity: false,
			r: hex!("36b241b061a36a32ab7fe86c7aa9eb592dd59018cd0443adc0903590c16b02b0").into(),
			s: hex!("5edcc541b4741c5cc6dd347c5ed9577ef293a62787b4510465fadbfe39ee4094").into(),
		});

		assert_eq!(tx, rlp::decode::<TransactionV2>(&rlp::encode(&tx)).unwrap());
	}
}
