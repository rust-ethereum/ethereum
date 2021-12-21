use crate::Log;
use crate::util::enveloped;
use alloc::vec::Vec;
use ethereum_types::{Bloom, H256, U256};
use rlp::{Rlp, DecoderError, Decodable, Encodable, RlpStream};
use rlp_derive::{RlpDecodable, RlpEncodable};

#[derive(Clone, Debug, PartialEq, Eq, RlpEncodable, RlpDecodable)]
#[cfg_attr(
	feature = "with-codec",
	derive(codec::Encode, codec::Decode, scale_info::TypeInfo)
)]
#[cfg_attr(feature = "with-serde", derive(serde::Serialize, serde::Deserialize))]
pub struct ReceiptData {
	pub state_root: H256,
	pub used_gas: U256,
	pub logs_bloom: Bloom,
	pub logs: Vec<Log>,
}

pub type ReceiptV0 = ReceiptData;

#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "with-codec", derive(codec::Encode, codec::Decode))]
#[cfg_attr(feature = "with-serde", derive(serde::Serialize, serde::Deserialize))]
pub enum ReceiptV1 {
	/// Legacy receipt type
	Legacy(ReceiptData),
	/// EIP-2930 receipt type
	EIP2930(ReceiptData),
}

impl Encodable for ReceiptV1 {
	fn rlp_append(&self, s: &mut RlpStream) {
		match self {
			Self::Legacy(r) => r.rlp_append(s),
			Self::EIP2930(r) => enveloped(1, r, s),
		}
	}
}

impl Decodable for ReceiptV1 {
	fn decode(rlp: &Rlp) -> Result<Self, DecoderError> {
		let slice = rlp.data()?;

		let first = *slice.get(0).ok_or(DecoderError::Custom("empty slice"))?;

		if rlp.is_list() {
			return Ok(Self::Legacy(rlp.as_val()?));
		}

		let s = slice.get(1..).ok_or(DecoderError::Custom("no receipt body"))?;

		if first == 0x01 {
			return rlp::decode(s).map(Self::EIP2930);
		}

		Err(DecoderError::Custom("invalid receipt type"))
	}
}

#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "with-codec", derive(codec::Encode, codec::Decode))]
#[cfg_attr(feature = "with-serde", derive(serde::Serialize, serde::Deserialize))]
pub enum ReceiptV2 {
	/// Legacy receipt type
	Legacy(ReceiptData),
	/// EIP-2930 receipt type
	EIP2930(ReceiptData),
	/// EIP-1559 receipt type
	EIP1559(ReceiptData),
}

impl Encodable for ReceiptV2 {
	fn rlp_append(&self, s: &mut RlpStream) {
		match self {
			Self::Legacy(r) => r.rlp_append(s),
			Self::EIP2930(r) => enveloped(1, r, s),
			Self::EIP1559(r) => enveloped(2, r, s),
		}
	}
}

impl Decodable for ReceiptV2 {
	fn decode(rlp: &Rlp) -> Result<Self, DecoderError> {
		let slice = rlp.data()?;

		let first = *slice.get(0).ok_or(DecoderError::Custom("empty slice"))?;

		if rlp.is_list() {
			return Ok(Self::Legacy(rlp.as_val()?));
		}

		let s = slice.get(1..).ok_or(DecoderError::Custom("no receipt body"))?;

		if first == 0x01 {
			return rlp::decode(s).map(Self::EIP2930);
		}

		if first == 0x02 {
			return rlp::decode(s).map(Self::EIP1559);
		}

		Err(DecoderError::Custom("invalid receipt type"))
	}
}
