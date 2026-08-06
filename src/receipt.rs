use alloc::vec::Vec;

use bytes::BytesMut;
use ethereum_types::{Bloom, H256, U256};
use rlp::{Decodable, DecoderError, Rlp};

use crate::{
	enveloped::{decode_rlp_exact, EnvelopedDecodable, EnvelopedDecoderError, EnvelopedEncodable},
	log::Log,
};

#[derive(Clone, Debug, PartialEq, Eq)]
#[derive(rlp::RlpEncodable, rlp::RlpDecodable)]
#[cfg_attr(
	feature = "with-scale",
	derive(scale_codec::Encode, scale_codec::Decode, scale_info::TypeInfo)
)]
#[cfg_attr(feature = "with-serde", derive(serde::Serialize, serde::Deserialize))]
pub struct FrontierReceiptData {
	pub state_root: H256,
	pub used_gas: U256,
	pub logs_bloom: Bloom,
	pub logs: Vec<Log>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
#[derive(rlp::RlpEncodable, rlp::RlpDecodable)]
#[cfg_attr(
	feature = "with-scale",
	derive(scale_codec::Encode, scale_codec::Decode, scale_info::TypeInfo)
)]
#[cfg_attr(feature = "with-serde", derive(serde::Serialize, serde::Deserialize))]
pub struct EIP658ReceiptData {
	pub status_code: u8,
	pub used_gas: U256,
	pub logs_bloom: Bloom,
	pub logs: Vec<Log>,
}

pub type EIP2930ReceiptData = EIP658ReceiptData;

pub type EIP1559ReceiptData = EIP658ReceiptData;

pub type EIP4844ReceiptData = EIP658ReceiptData;

pub type EIP7702ReceiptData = EIP658ReceiptData;

pub type ReceiptV0 = FrontierReceiptData;

impl EnvelopedEncodable for ReceiptV0 {
	fn type_id(&self) -> Option<u8> {
		None
	}
	fn encode_payload(&self) -> BytesMut {
		rlp::encode(self)
	}
}

impl EnvelopedDecodable for ReceiptV0 {
	type PayloadDecoderError = DecoderError;

	fn decode(bytes: &[u8]) -> Result<Self, EnvelopedDecoderError<Self::PayloadDecoderError>> {
		Ok(rlp::decode(bytes)?)
	}
}

pub type ReceiptV1 = EIP658ReceiptData;

impl EnvelopedEncodable for ReceiptV1 {
	fn type_id(&self) -> Option<u8> {
		None
	}
	fn encode_payload(&self) -> BytesMut {
		rlp::encode(self)
	}
}

impl EnvelopedDecodable for ReceiptV1 {
	type PayloadDecoderError = DecoderError;

	fn decode(bytes: &[u8]) -> Result<Self, EnvelopedDecoderError<Self::PayloadDecoderError>> {
		Ok(rlp::decode(bytes)?)
	}
}

#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(
	feature = "with-scale",
	derive(scale_codec::Encode, scale_codec::Decode, scale_info::TypeInfo)
)]
#[cfg_attr(
	feature = "with-serde",
	derive(serde::Serialize, serde::Deserialize),
	serde(untagged)
)]
pub enum ReceiptV2 {
	/// Legacy receipt type
	Legacy(EIP658ReceiptData),
	/// EIP-2930 receipt type
	EIP2930(EIP2930ReceiptData),
}

impl EnvelopedEncodable for ReceiptV2 {
	fn type_id(&self) -> Option<u8> {
		match self {
			Self::Legacy(_) => None,
			Self::EIP2930(_) => Some(1),
		}
	}

	fn encode_payload(&self) -> BytesMut {
		match self {
			Self::Legacy(r) => rlp::encode(r),
			Self::EIP2930(r) => rlp::encode(r),
		}
	}
}

impl EnvelopedDecodable for ReceiptV2 {
	type PayloadDecoderError = DecoderError;

	fn decode(bytes: &[u8]) -> Result<Self, EnvelopedDecoderError<Self::PayloadDecoderError>> {
		if bytes.is_empty() {
			return Err(EnvelopedDecoderError::UnknownTypeId);
		}

		let first = bytes[0];

		let rlp = Rlp::new(bytes);
		if rlp.is_list() {
			return Ok(Self::Legacy(Decodable::decode(&rlp)?));
		}

		let s = &bytes[1..];

		if first == 0x01 {
			return Ok(Self::EIP2930(rlp::decode(s)?));
		}

		Err(DecoderError::Custom("invalid receipt type").into())
	}
}

impl From<ReceiptV2> for EIP658ReceiptData {
	fn from(v2: ReceiptV2) -> Self {
		match v2 {
			ReceiptV2::Legacy(r) => r,
			ReceiptV2::EIP2930(r) => r,
		}
	}
}

#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(
	feature = "with-scale",
	derive(scale_codec::Encode, scale_codec::Decode, scale_info::TypeInfo)
)]
#[cfg_attr(
	feature = "with-serde",
	derive(serde::Serialize, serde::Deserialize),
	serde(untagged)
)]
pub enum ReceiptV3 {
	/// Legacy receipt type
	Legacy(EIP658ReceiptData),
	/// EIP-2930 receipt type
	EIP2930(EIP2930ReceiptData),
	/// EIP-1559 receipt type
	EIP1559(EIP1559ReceiptData),
}

impl EnvelopedEncodable for ReceiptV3 {
	fn type_id(&self) -> Option<u8> {
		match self {
			Self::Legacy(_) => None,
			Self::EIP2930(_) => Some(1),
			Self::EIP1559(_) => Some(2),
		}
	}

	fn encode_payload(&self) -> BytesMut {
		match self {
			Self::Legacy(r) => rlp::encode(r),
			Self::EIP2930(r) => rlp::encode(r),
			Self::EIP1559(r) => rlp::encode(r),
		}
	}
}

impl EnvelopedDecodable for ReceiptV3 {
	type PayloadDecoderError = DecoderError;

	fn decode(bytes: &[u8]) -> Result<Self, EnvelopedDecoderError<Self::PayloadDecoderError>> {
		if bytes.is_empty() {
			return Err(EnvelopedDecoderError::UnknownTypeId);
		}

		let first = bytes[0];

		let rlp = Rlp::new(bytes);
		if rlp.is_list() {
			return Ok(Self::Legacy(Decodable::decode(&rlp)?));
		}

		let s = &bytes[1..];

		if first == 0x01 {
			return Ok(Self::EIP2930(rlp::decode(s)?));
		}

		if first == 0x02 {
			return Ok(Self::EIP1559(rlp::decode(s)?));
		}

		Err(DecoderError::Custom("invalid receipt type").into())
	}
}

impl From<ReceiptV3> for EIP658ReceiptData {
	fn from(v3: ReceiptV3) -> Self {
		match v3 {
			ReceiptV3::Legacy(r) => r,
			ReceiptV3::EIP2930(r) => r,
			ReceiptV3::EIP1559(r) => r,
		}
	}
}

#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(
	feature = "with-scale",
	derive(scale_codec::Encode, scale_codec::Decode, scale_info::TypeInfo)
)]
#[cfg_attr(
	feature = "with-serde",
	derive(serde::Serialize, serde::Deserialize),
	serde(untagged)
)]
pub enum ReceiptV4 {
	/// Legacy receipt type
	Legacy(EIP658ReceiptData),
	/// EIP-2930 receipt type
	EIP2930(EIP2930ReceiptData),
	/// EIP-1559 receipt type
	EIP1559(EIP1559ReceiptData),
	/// EIP-7702 receipt type
	EIP7702(EIP7702ReceiptData),
}

impl EnvelopedEncodable for ReceiptV4 {
	fn type_id(&self) -> Option<u8> {
		match self {
			Self::Legacy(_) => None,
			Self::EIP2930(_) => Some(1),
			Self::EIP1559(_) => Some(2),
			Self::EIP7702(_) => Some(4),
		}
	}

	fn encode_payload(&self) -> BytesMut {
		match self {
			Self::Legacy(r) => rlp::encode(r),
			Self::EIP2930(r) => rlp::encode(r),
			Self::EIP1559(r) => rlp::encode(r),
			Self::EIP7702(r) => rlp::encode(r),
		}
	}
}

impl EnvelopedDecodable for ReceiptV4 {
	type PayloadDecoderError = DecoderError;

	fn decode(bytes: &[u8]) -> Result<Self, EnvelopedDecoderError<Self::PayloadDecoderError>> {
		if bytes.is_empty() {
			return Err(EnvelopedDecoderError::UnknownTypeId);
		}

		let first = bytes[0];

		let rlp = Rlp::new(bytes);
		if rlp.is_list() {
			return Ok(Self::Legacy(Decodable::decode(&rlp)?));
		}

		let s = &bytes[1..];

		if first == 0x01 {
			return Ok(Self::EIP2930(rlp::decode(s)?));
		}

		if first == 0x02 {
			return Ok(Self::EIP1559(rlp::decode(s)?));
		}

		if first == 0x04 {
			return Ok(Self::EIP7702(rlp::decode(s)?));
		}

		Err(DecoderError::Custom("invalid receipt type").into())
	}
}

impl From<ReceiptV4> for EIP658ReceiptData {
	fn from(v3: ReceiptV4) -> Self {
		match v3 {
			ReceiptV4::Legacy(r) => r,
			ReceiptV4::EIP2930(r) => r,
			ReceiptV4::EIP1559(r) => r,
			ReceiptV4::EIP7702(r) => r,
		}
	}
}

/// Latest versioned receipt envelope, supporting transaction types 1 through 4.
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(
	feature = "with-scale",
	derive(scale_codec::Encode, scale_codec::Decode, scale_info::TypeInfo)
)]
#[cfg_attr(
	feature = "with-serde",
	derive(serde::Serialize, serde::Deserialize),
	serde(untagged)
)]
pub enum ReceiptV5 {
	Legacy(EIP658ReceiptData),
	EIP2930(EIP2930ReceiptData),
	EIP1559(EIP1559ReceiptData),
	EIP4844(EIP4844ReceiptData),
	EIP7702(EIP7702ReceiptData),
}

impl EnvelopedEncodable for ReceiptV5 {
	fn type_id(&self) -> Option<u8> {
		match self {
			Self::Legacy(_) => None,
			Self::EIP2930(_) => Some(1),
			Self::EIP1559(_) => Some(2),
			Self::EIP4844(_) => Some(3),
			Self::EIP7702(_) => Some(4),
		}
	}

	fn encode_payload(&self) -> BytesMut {
		match self {
			Self::Legacy(receipt) => rlp::encode(receipt),
			Self::EIP2930(receipt) => rlp::encode(receipt),
			Self::EIP1559(receipt) => rlp::encode(receipt),
			Self::EIP4844(receipt) => rlp::encode(receipt),
			Self::EIP7702(receipt) => rlp::encode(receipt),
		}
	}
}

impl EnvelopedDecodable for ReceiptV5 {
	type PayloadDecoderError = DecoderError;

	fn decode(bytes: &[u8]) -> Result<Self, EnvelopedDecoderError<Self::PayloadDecoderError>> {
		if bytes.is_empty() {
			return Err(EnvelopedDecoderError::UnknownTypeId);
		}

		let rlp = Rlp::new(bytes);
		if rlp.is_list() {
			return Ok(Self::Legacy(decode_rlp_exact(bytes)?));
		}

		match bytes[0] {
			1 => Ok(Self::EIP2930(decode_rlp_exact(&bytes[1..])?)),
			2 => Ok(Self::EIP1559(decode_rlp_exact(&bytes[1..])?)),
			3 => Ok(Self::EIP4844(decode_rlp_exact(&bytes[1..])?)),
			4 => Ok(Self::EIP7702(decode_rlp_exact(&bytes[1..])?)),
			_ => Err(DecoderError::Custom("invalid receipt type").into()),
		}
	}
}

impl From<ReceiptV5> for EIP658ReceiptData {
	fn from(receipt: ReceiptV5) -> Self {
		match receipt {
			ReceiptV5::Legacy(receipt) => receipt,
			ReceiptV5::EIP2930(receipt) => receipt,
			ReceiptV5::EIP1559(receipt) => receipt,
			ReceiptV5::EIP4844(receipt) => receipt,
			ReceiptV5::EIP7702(receipt) => receipt,
		}
	}
}

#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(
	feature = "with-scale",
	derive(scale_codec::Encode, scale_codec::Decode, scale_info::TypeInfo)
)]
#[cfg_attr(
	feature = "with-serde",
	derive(serde::Serialize, serde::Deserialize),
	serde(untagged)
)]
pub enum ReceiptAny {
	/// Frontier receipt type
	Frontier(FrontierReceiptData),
	/// EIP658 receipt type
	EIP658(EIP658ReceiptData),
	/// EIP-2930 receipt type
	EIP2930(EIP2930ReceiptData),
	/// EIP-1559 receipt type
	EIP1559(EIP1559ReceiptData),
	/// EIP-4844 receipt type
	EIP4844(EIP4844ReceiptData),
	/// EIP-7702 receipt type
	EIP7702(EIP7702ReceiptData),
}

impl EnvelopedEncodable for ReceiptAny {
	fn type_id(&self) -> Option<u8> {
		match self {
			Self::Frontier(_) => None,
			Self::EIP658(_) => None,
			Self::EIP2930(_) => Some(1),
			Self::EIP1559(_) => Some(2),
			Self::EIP4844(_) => Some(3),
			Self::EIP7702(_) => Some(4),
		}
	}

	fn encode_payload(&self) -> BytesMut {
		match self {
			Self::Frontier(r) => rlp::encode(r),
			Self::EIP658(r) => rlp::encode(r),
			Self::EIP2930(r) => rlp::encode(r),
			Self::EIP1559(r) => rlp::encode(r),
			Self::EIP4844(r) => rlp::encode(r),
			Self::EIP7702(r) => rlp::encode(r),
		}
	}
}

impl EnvelopedDecodable for ReceiptAny {
	type PayloadDecoderError = DecoderError;

	fn decode(bytes: &[u8]) -> Result<Self, EnvelopedDecoderError<Self::PayloadDecoderError>> {
		if bytes.is_empty() {
			return Err(EnvelopedDecoderError::UnknownTypeId);
		}

		let first = bytes[0];

		let rlp = Rlp::new(bytes);
		if rlp.is_list() {
			if rlp.item_count()? == 4 {
				let first = rlp.at(0)?;
				if first.is_data() && first.data()?.len() <= 1 {
					return Ok(Self::Frontier(Decodable::decode(&rlp)?));
				} else {
					return Ok(Self::EIP658(Decodable::decode(&rlp)?));
				}
			}

			return Err(DecoderError::RlpIncorrectListLen.into());
		}

		let s = &bytes[1..];

		if first == 0x01 {
			return Ok(Self::EIP2930(rlp::decode(s)?));
		}

		if first == 0x02 {
			return Ok(Self::EIP1559(rlp::decode(s)?));
		}

		if first == 0x03 {
			return Ok(Self::EIP4844(rlp::decode(s)?));
		}

		if first == 0x04 {
			return Ok(Self::EIP7702(rlp::decode(s)?));
		}

		Err(DecoderError::Custom("invalid receipt type").into())
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn receipt_v5_blob_roundtrip_rejects_trailing_bytes() {
		let receipt = ReceiptV5::EIP4844(EIP658ReceiptData {
			status_code: 1,
			used_gas: U256::from(21_000),
			logs_bloom: Bloom::zero(),
			logs: Vec::new(),
		});
		let encoded = receipt.encode();
		assert_eq!(ReceiptV5::decode(&encoded).unwrap(), receipt);

		let mut trailing = encoded.to_vec();
		trailing.push(0);
		assert!(ReceiptV5::decode(&trailing).is_err());
	}
}
