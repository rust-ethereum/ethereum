use alloc::vec::Vec;

use bytes::BytesMut;
use ethereum_types::{Bloom, H256, U256};
use rlp::{Decodable, DecoderError, Rlp};

use crate::{
	enveloped::{EnvelopedDecodable, EnvelopedDecoderError, EnvelopedEncodable},
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
pub enum ReceiptAny {
	/// Frontier receipt type
	Frontier(FrontierReceiptData),
	/// EIP658 receipt type
	EIP658(EIP658ReceiptData),
	/// EIP-2930 receipt type
	EIP2930(EIP2930ReceiptData),
	/// EIP-1559 receipt type
	EIP1559(EIP1559ReceiptData),
}

impl EnvelopedEncodable for ReceiptAny {
	fn type_id(&self) -> Option<u8> {
		match self {
			Self::Frontier(_) => None,
			Self::EIP658(_) => None,
			Self::EIP2930(_) => Some(1),
			Self::EIP1559(_) => Some(2),
		}
	}

	fn encode_payload(&self) -> BytesMut {
		match self {
			Self::Frontier(r) => rlp::encode(r),
			Self::EIP658(r) => rlp::encode(r),
			Self::EIP2930(r) => rlp::encode(r),
			Self::EIP1559(r) => rlp::encode(r),
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

		Err(DecoderError::Custom("invalid receipt type").into())
	}
}
