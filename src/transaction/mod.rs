pub mod eip1559;
pub mod eip2930;
pub mod eip7702;
pub mod legacy;
mod rlp_len;
mod signature;

use bytes::BytesMut;
use ethereum_types::H256;
use rlp::{DecoderError, Rlp};

pub use self::{
	eip1559::{EIP1559Transaction, EIP1559TransactionMessage},
	eip2930::{AccessList, AccessListItem, EIP2930Transaction, EIP2930TransactionMessage},
	eip7702::{
		AuthorizationList, AuthorizationListItem, EIP7702Transaction, EIP7702TransactionMessage,
	},
	legacy::{LegacyTransaction, LegacyTransactionMessage, TransactionAction},
};
use crate::enveloped::{EnvelopedDecodable, EnvelopedDecoderError, EnvelopedEncodable};

pub type TransactionV0 = LegacyTransaction;

impl EnvelopedEncodable for TransactionV0 {
	fn type_id(&self) -> Option<u8> {
		None
	}
	fn encode_payload(&self) -> BytesMut {
		rlp::encode(self)
	}
	fn payload_len(&self) -> usize {
		self.rlp_len()
	}
}

impl EnvelopedDecodable for TransactionV0 {
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
pub enum TransactionV1 {
	/// Legacy transaction type
	Legacy(LegacyTransaction),
	/// EIP-2930 transaction
	EIP2930(EIP2930Transaction),
}

impl TransactionV1 {
	pub fn hash(&self) -> H256 {
		match self {
			TransactionV1::Legacy(t) => t.hash(),
			TransactionV1::EIP2930(t) => t.hash(),
		}
	}
}

impl EnvelopedEncodable for TransactionV1 {
	fn type_id(&self) -> Option<u8> {
		match self {
			Self::Legacy(_) => None,
			Self::EIP2930(_) => Some(1),
		}
	}

	fn encode_payload(&self) -> BytesMut {
		match self {
			Self::Legacy(tx) => rlp::encode(tx),
			Self::EIP2930(tx) => rlp::encode(tx),
		}
	}

	fn payload_len(&self) -> usize {
		match self {
			Self::Legacy(tx) => tx.rlp_len(),
			Self::EIP2930(tx) => tx.rlp_len(),
		}
	}
}

impl EnvelopedDecodable for TransactionV1 {
	type PayloadDecoderError = DecoderError;

	fn decode(bytes: &[u8]) -> Result<Self, EnvelopedDecoderError<Self::PayloadDecoderError>> {
		if bytes.is_empty() {
			return Err(EnvelopedDecoderError::UnknownTypeId);
		}

		let first = bytes[0];

		let rlp = Rlp::new(bytes);
		if rlp.is_list() {
			return Ok(Self::Legacy(rlp.as_val()?));
		}

		let s = &bytes[1..];

		if first == 0x01 {
			return Ok(Self::EIP2930(rlp::decode(s)?));
		}

		Err(DecoderError::Custom("invalid tx type").into())
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
#[cfg_attr(
	feature = "with-serde",
	derive(serde::Serialize, serde::Deserialize),
	serde(untagged)
)]
pub enum TransactionV2 {
	/// Legacy transaction type
	Legacy(LegacyTransaction),
	/// EIP-2930 transaction
	EIP2930(EIP2930Transaction),
	/// EIP-1559 transaction
	EIP1559(EIP1559Transaction),
}

impl TransactionV2 {
	pub fn hash(&self) -> H256 {
		match self {
			TransactionV2::Legacy(t) => t.hash(),
			TransactionV2::EIP2930(t) => t.hash(),
			TransactionV2::EIP1559(t) => t.hash(),
		}
	}
}

impl EnvelopedEncodable for TransactionV2 {
	fn type_id(&self) -> Option<u8> {
		match self {
			Self::Legacy(_) => None,
			Self::EIP2930(_) => Some(1),
			Self::EIP1559(_) => Some(2),
		}
	}

	fn encode_payload(&self) -> BytesMut {
		match self {
			Self::Legacy(tx) => rlp::encode(tx),
			Self::EIP2930(tx) => rlp::encode(tx),
			Self::EIP1559(tx) => rlp::encode(tx),
		}
	}

	fn payload_len(&self) -> usize {
		match self {
			Self::Legacy(tx) => tx.rlp_len(),
			Self::EIP2930(tx) => tx.rlp_len(),
			Self::EIP1559(tx) => tx.rlp_len(),
		}
	}
}

impl EnvelopedDecodable for TransactionV2 {
	type PayloadDecoderError = DecoderError;

	fn decode(bytes: &[u8]) -> Result<Self, EnvelopedDecoderError<Self::PayloadDecoderError>> {
		if bytes.is_empty() {
			return Err(EnvelopedDecoderError::UnknownTypeId);
		}

		let first = bytes[0];

		let rlp = Rlp::new(bytes);
		if rlp.is_list() {
			return Ok(Self::Legacy(rlp.as_val()?));
		}

		let s = &bytes[1..];

		if first == 0x01 {
			return Ok(Self::EIP2930(rlp::decode(s)?));
		}

		if first == 0x02 {
			return Ok(Self::EIP1559(rlp::decode(s)?));
		}

		Err(DecoderError::Custom("invalid tx type").into())
	}
}

impl From<LegacyTransaction> for TransactionV1 {
	fn from(t: LegacyTransaction) -> Self {
		TransactionV1::Legacy(t)
	}
}

impl From<LegacyTransaction> for TransactionV2 {
	fn from(t: LegacyTransaction) -> Self {
		TransactionV2::Legacy(t)
	}
}

impl From<TransactionV1> for TransactionV2 {
	fn from(t: TransactionV1) -> Self {
		match t {
			TransactionV1::Legacy(t) => TransactionV2::Legacy(t),
			TransactionV1::EIP2930(t) => TransactionV2::EIP2930(t),
		}
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
#[cfg_attr(
	feature = "with-serde",
	derive(serde::Serialize, serde::Deserialize),
	serde(untagged)
)]
pub enum TransactionV3 {
	/// Legacy transaction type
	Legacy(LegacyTransaction),
	/// EIP-2930 transaction
	EIP2930(EIP2930Transaction),
	/// EIP-1559 transaction
	EIP1559(EIP1559Transaction),
	/// EIP-7702 transaction
	EIP7702(EIP7702Transaction),
}

impl TransactionV3 {
	pub fn hash(&self) -> H256 {
		match self {
			TransactionV3::Legacy(t) => t.hash(),
			TransactionV3::EIP2930(t) => t.hash(),
			TransactionV3::EIP1559(t) => t.hash(),
			TransactionV3::EIP7702(t) => t.hash(),
		}
	}
}

impl EnvelopedEncodable for TransactionV3 {
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
			Self::Legacy(tx) => rlp::encode(tx),
			Self::EIP2930(tx) => rlp::encode(tx),
			Self::EIP1559(tx) => rlp::encode(tx),
			Self::EIP7702(tx) => rlp::encode(tx),
		}
	}

	fn payload_len(&self) -> usize {
		match self {
			Self::Legacy(tx) => tx.rlp_len(),
			Self::EIP2930(tx) => tx.rlp_len(),
			Self::EIP1559(tx) => tx.rlp_len(),
			Self::EIP7702(tx) => tx.rlp_len(),
		}
	}
}

impl EnvelopedDecodable for TransactionV3 {
	type PayloadDecoderError = DecoderError;

	fn decode(bytes: &[u8]) -> Result<Self, EnvelopedDecoderError<Self::PayloadDecoderError>> {
		if bytes.is_empty() {
			return Err(EnvelopedDecoderError::UnknownTypeId);
		}

		let first = bytes[0];

		let rlp = Rlp::new(bytes);
		if rlp.is_list() {
			return Ok(Self::Legacy(rlp.as_val()?));
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

		Err(DecoderError::Custom("invalid tx type").into())
	}
}

impl From<LegacyTransaction> for TransactionV3 {
	fn from(t: LegacyTransaction) -> Self {
		TransactionV3::Legacy(t)
	}
}

impl From<TransactionV1> for TransactionV3 {
	fn from(t: TransactionV1) -> Self {
		match t {
			TransactionV1::Legacy(t) => TransactionV3::Legacy(t),
			TransactionV1::EIP2930(t) => TransactionV3::EIP2930(t),
		}
	}
}

impl From<TransactionV2> for TransactionV3 {
	fn from(t: TransactionV2) -> Self {
		match t {
			TransactionV2::Legacy(t) => TransactionV3::Legacy(t),
			TransactionV2::EIP2930(t) => TransactionV3::EIP2930(t),
			TransactionV2::EIP1559(t) => TransactionV3::EIP1559(t),
		}
	}
}

pub type TransactionAny = TransactionV3;

#[cfg(test)]
mod tests {
	use super::{
		eip2930::{self, AccessListItem},
		eip7702::AuthorizationListItem,
		legacy::{self, TransactionAction},
		EIP1559Transaction, EIP2930Transaction, EIP7702Transaction, EnvelopedDecodable,
		TransactionV0, TransactionV1, TransactionV2, TransactionV3,
	};
	use crate::enveloped::*;
	use ethereum_types::U256;
	use hex_literal::hex;

	#[test]
	fn can_decode_raw_transaction() {
		let bytes = hex!("f901e48080831000008080b90196608060405234801561001057600080fd5b50336000806101000a81548173ffffffffffffffffffffffffffffffffffffffff021916908373ffffffffffffffffffffffffffffffffffffffff1602179055507fc68045c3c562488255b55aa2c4c7849de001859ff0d8a36a75c2d5ed80100fb660405180806020018281038252600d8152602001807f48656c6c6f2c20776f726c64210000000000000000000000000000000000000081525060200191505060405180910390a160cf806100c76000396000f3fe6080604052348015600f57600080fd5b506004361060285760003560e01c80638da5cb5b14602d575b600080fd5b60336075565b604051808273ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200191505060405180910390f35b6000809054906101000a900473ffffffffffffffffffffffffffffffffffffffff168156fea265627a7a72315820fae816ad954005c42bea7bc7cb5b19f7fd5d3a250715ca2023275c9ca7ce644064736f6c634300050f003278a04cab43609092a99cf095d458b61b47189d1bbab64baed10a0fd7b7d2de2eb960a011ab1bcda76dfed5e733219beb83789f9887b2a7b2e61759c7c90f7d40403201");

		<TransactionV0 as EnvelopedDecodable>::decode(&bytes).unwrap();
		<TransactionV1 as EnvelopedDecodable>::decode(&bytes).unwrap();
		<TransactionV2 as EnvelopedDecodable>::decode(&bytes).unwrap();
		<TransactionV3 as EnvelopedDecodable>::decode(&bytes).unwrap();
	}

	fn make_legacy_tx() -> TransactionV0 {
		TransactionV0 {
			nonce: 12.into(),
			gas_price: 20_000_000_000_u64.into(),
			gas_limit: 21000.into(),
			action: TransactionAction::Call(
				hex!("727fc6a68321b754475c668a6abfb6e9e71c169a").into(),
			),
			value: U256::from(10) * 1_000_000_000 * 1_000_000_000,
			input: hex!("a9059cbb000000000213ed0f886efd100b67c7e4ec0a85a7d20dc971600000000000000000000015af1d78b58c4000").into(),
			signature: legacy::TransactionSignature::new(38, hex!("be67e0a07db67da8d446f76add590e54b6e92cb6b8f9835aeb67540579a27717").into(), hex!("2d690516512020171c1ec870f6ff45398cc8609250326be89915fb538e7bd718").into()).unwrap(),
		}
	}

	fn make_eip2930_tx() -> EIP2930Transaction {
		EIP2930Transaction {
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
					storage_keys: vec![
						hex!("0000000000000000000000000000000000000000000000000000000000000003")
							.into(),
						hex!("0000000000000000000000000000000000000000000000000000000000000007")
							.into(),
					],
				},
				AccessListItem {
					address: hex!("bb9bc244d798123fde783fcc1c72d3bb8c189413").into(),
					storage_keys: vec![],
				},
			],
			signature: eip2930::TransactionSignature::new(
				false,
				hex!("36b241b061a36a32ab7fe86c7aa9eb592dd59018cd0443adc0903590c16b02b0").into(),
				hex!("5edcc541b4741c5cc6dd347c5ed9577ef293a62787b4510465fadbfe39ee4094").into(),
			)
			.unwrap(),
		}
	}

	fn make_eip1559_tx() -> EIP1559Transaction {
		EIP1559Transaction {
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
					storage_keys: vec![
						hex!("0000000000000000000000000000000000000000000000000000000000000003")
							.into(),
						hex!("0000000000000000000000000000000000000000000000000000000000000007")
							.into(),
					],
				},
				AccessListItem {
					address: hex!("bb9bc244d798123fde783fcc1c72d3bb8c189413").into(),
					storage_keys: vec![],
				},
			],
			signature: eip2930::TransactionSignature::new(
				false,
				hex!("36b241b061a36a32ab7fe86c7aa9eb592dd59018cd0443adc0903590c16b02b0").into(),
				hex!("5edcc541b4741c5cc6dd347c5ed9577ef293a62787b4510465fadbfe39ee4094").into(),
			)
			.unwrap(),
		}
	}

	fn make_eip7702_tx() -> EIP7702Transaction {
		EIP7702Transaction {
			chain_id: 5,
			nonce: 7.into(),
			max_priority_fee_per_gas: 10_000_000_000_u64.into(),
			max_fee_per_gas: 30_000_000_000_u64.into(),
			gas_limit: 5_748_100_u64.into(),
			destination: TransactionAction::Call(
				hex!("811a752c8cd697e3cb27279c330ed1ada745a8d7").into(),
			),
			value: U256::from(2) * 1_000_000_000 * 1_000_000_000,
			data: hex!("6ebaf477f83e051589c1188bcc6ddccd").into(),
			access_list: vec![AccessListItem {
				address: hex!("de0b295669a9fd93d5f28d9ec85e40f4cb697bae").into(),
				storage_keys: vec![hex!(
					"0000000000000000000000000000000000000000000000000000000000000003"
				)
				.into()],
			}],
			authorization_list: vec![AuthorizationListItem {
				chain_id: 5,
				address: hex!("de0b295669a9fd93d5f28d9ec85e40f4cb697bae").into(),
				nonce: 1.into(),
				signature: eip2930::MalleableTransactionSignature {
					odd_y_parity: false,
					r: hex!("36b241b061a36a32ab7fe86c7aa9eb592dd59018cd0443adc0903590c16b02b0")
						.into(),
					s: hex!("5edcc541b4741c5cc6dd347c5ed9577ef293a62787b4510465fadbfe39ee4094")
						.into(),
				},
			}],
			signature: eip2930::TransactionSignature::new(
				false,
				hex!("36b241b061a36a32ab7fe86c7aa9eb592dd59018cd0443adc0903590c16b02b0").into(),
				hex!("5edcc541b4741c5cc6dd347c5ed9577ef293a62787b4510465fadbfe39ee4094").into(),
			)
			.unwrap(),
		}
	}

	#[test]
	fn transaction_v0() {
		let tx = make_legacy_tx();

		assert_eq!(
			tx,
			<TransactionV0 as EnvelopedDecodable>::decode(&tx.encode()).unwrap()
		);
	}

	#[test]
	fn transaction_v1() {
		let tx = TransactionV1::EIP2930(make_eip2930_tx());

		assert_eq!(
			tx,
			<TransactionV1 as EnvelopedDecodable>::decode(&tx.encode()).unwrap()
		);
	}

	#[test]
	fn transaction_v2() {
		let tx = TransactionV2::EIP1559(make_eip1559_tx());

		assert_eq!(
			tx,
			<TransactionV2 as EnvelopedDecodable>::decode(&tx.encode()).unwrap()
		);
	}

	#[test]
	fn transaction_v3() {
		let tx = TransactionV3::EIP7702(make_eip7702_tx());

		assert_eq!(
			tx,
			<TransactionV3 as EnvelopedDecodable>::decode(&tx.encode()).unwrap()
		);
	}

	#[test]
	fn encoded_len_matches_encode_for_legacy() {
		let tx = make_legacy_tx();
		assert_eq!(tx.encoded_len(), tx.encode().len());
	}

	#[test]
	fn encoded_len_matches_encode_for_eip2930() {
		let tx = TransactionV1::EIP2930(make_eip2930_tx());
		assert_eq!(tx.encoded_len(), tx.encode().len());
	}

	#[test]
	fn encoded_len_matches_encode_for_eip1559() {
		let tx = TransactionV2::EIP1559(make_eip1559_tx());
		assert_eq!(tx.encoded_len(), tx.encode().len());
	}

	#[test]
	fn encoded_len_matches_encode_for_eip7702() {
		let tx = TransactionV3::EIP7702(make_eip7702_tx());
		assert_eq!(tx.encoded_len(), tx.encode().len());
	}

	#[test]
	fn payload_len_equals_encoded_len_for_legacy() {
		let tx = make_legacy_tx();
		// Legacy has no type byte, so encoded_len == payload_len
		assert_eq!(tx.type_id(), None);
		assert_eq!(tx.encoded_len(), tx.payload_len());
	}

	#[test]
	fn payload_len_plus_type_byte_equals_encoded_len_for_typed_txs() {
		let eip2930 = TransactionV1::EIP2930(make_eip2930_tx());
		assert_eq!(eip2930.encoded_len(), 1 + eip2930.payload_len());

		let eip1559 = TransactionV2::EIP1559(make_eip1559_tx());
		assert_eq!(eip1559.encoded_len(), 1 + eip1559.payload_len());

		let eip7702 = TransactionV3::EIP7702(make_eip7702_tx());
		assert_eq!(eip7702.encoded_len(), 1 + eip7702.payload_len());
	}

	#[test]
	fn transaction_message_encoded_len() {
		let legacy_msg = make_legacy_tx().to_message();
		assert_eq!(legacy_msg.encoded_len(), rlp::encode(&legacy_msg).len());

		let eip2930_msg = make_eip2930_tx().to_message();
		assert_eq!(eip2930_msg.encoded_len(), rlp::encode(&eip2930_msg).len());

		let eip1559_msg = make_eip1559_tx().to_message();
		assert_eq!(eip1559_msg.encoded_len(), rlp::encode(&eip1559_msg).len());

		let eip7702_msg = make_eip7702_tx().to_message();
		assert_eq!(eip7702_msg.encoded_len(), rlp::encode(&eip7702_msg).len());
	}

	#[test]
	fn payload_len_matches_encode_payload() {
		let legacy = make_legacy_tx();
		assert_eq!(legacy.payload_len(), legacy.encode_payload().len());

		let eip2930 = TransactionV1::EIP2930(make_eip2930_tx());
		assert_eq!(eip2930.payload_len(), eip2930.encode_payload().len());

		let eip1559 = TransactionV2::EIP1559(make_eip1559_tx());
		assert_eq!(eip1559.payload_len(), eip1559.encode_payload().len());

		let eip7702 = TransactionV3::EIP7702(make_eip7702_tx());
		assert_eq!(eip7702.payload_len(), eip7702.encode_payload().len());
	}

	#[test]
	fn encoded_len_grows_with_larger_input() {
		let mut tx = make_legacy_tx();
		let small_len = tx.encoded_len();

		tx.input = vec![0xab; 1024].into();
		let large_len = tx.encoded_len();
		assert!(
			large_len > small_len,
			"larger input should increase encoded_len"
		);
		assert_eq!(large_len, tx.encode().len());
	}

	#[test]
	fn encoded_len_grows_with_larger_access_list() {
		let mut tx = make_eip1559_tx();
		let small_len = TransactionV2::EIP1559(tx.clone()).encoded_len();

		tx.access_list.extend((0..10).map(|i| AccessListItem {
			address: hex!("de0b295669a9fd93d5f28d9ec85e40f4cb697bae").into(),
			storage_keys: vec![
				ethereum_types::H256::from_low_u64_be(i),
				ethereum_types::H256::from_low_u64_be(i + 100),
			],
		}));
		let large = TransactionV2::EIP1559(tx);
		let large_len = large.encoded_len();
		assert!(
			large_len > small_len,
			"larger access_list should increase encoded_len"
		);
		assert_eq!(large_len, large.encode().len());
	}

	#[test]
	fn encoded_len_grows_with_larger_authorization_list() {
		let mut tx = make_eip7702_tx();
		let small_len = TransactionV3::EIP7702(tx.clone()).encoded_len();

		tx.authorization_list
			.extend((0..5).map(|i| {
				AuthorizationListItem {
					chain_id: 5,
					address: hex!("de0b295669a9fd93d5f28d9ec85e40f4cb697bae").into(),
					nonce: (i + 10).into(),
					signature: eip2930::MalleableTransactionSignature {
						odd_y_parity: false,
						r: hex!("36b241b061a36a32ab7fe86c7aa9eb592dd59018cd0443adc0903590c16b02b0")
							.into(),
						s: hex!("5edcc541b4741c5cc6dd347c5ed9577ef293a62787b4510465fadbfe39ee4094")
							.into(),
					},
				}
			}));
		let large = TransactionV3::EIP7702(tx);
		let large_len = large.encoded_len();
		assert!(
			large_len > small_len,
			"larger authorization_list should increase encoded_len"
		);
		assert_eq!(large_len, large.encode().len());
	}

	#[test]
	fn large_payload_encoded_len_matches() {
		// ~128KB data field, matching reth's DEFAULT_MAX_TX_INPUT_BYTES
		let large_data: Vec<u8> = vec![0xff; 128 * 1024];

		let mut legacy = make_legacy_tx();
		legacy.input = large_data.clone().into();
		assert_eq!(legacy.encoded_len(), legacy.encode().len());
		assert_eq!(legacy.payload_len(), legacy.encode_payload().len());

		let mut eip1559 = make_eip1559_tx();
		eip1559.input = large_data.clone().into();
		let eip1559_v2 = TransactionV2::EIP1559(eip1559);
		assert_eq!(eip1559_v2.encoded_len(), eip1559_v2.encode().len());
		assert_eq!(eip1559_v2.payload_len(), eip1559_v2.encode_payload().len());

		let mut eip7702 = make_eip7702_tx();
		eip7702.data = large_data.into();
		let eip7702_v3 = TransactionV3::EIP7702(eip7702);
		assert_eq!(eip7702_v3.encoded_len(), eip7702_v3.encode().len());
		assert_eq!(eip7702_v3.payload_len(), eip7702_v3.encode_payload().len());
	}

	#[test]
	fn encoded_len_is_nonzero() {
		assert!(make_legacy_tx().encoded_len() > 0);
		assert!(TransactionV1::EIP2930(make_eip2930_tx()).encoded_len() > 0);
		assert!(TransactionV2::EIP1559(make_eip1559_tx()).encoded_len() > 0);
		assert!(TransactionV3::EIP7702(make_eip7702_tx()).encoded_len() > 0);
	}

	#[test]
	fn v3_encoded_len_for_all_variants() {
		let legacy = TransactionV3::Legacy(make_legacy_tx());
		assert_eq!(legacy.encoded_len(), legacy.encode().len());
		assert_eq!(legacy.type_id(), None);

		let eip2930 = TransactionV3::EIP2930(make_eip2930_tx());
		assert_eq!(eip2930.encoded_len(), eip2930.encode().len());
		assert_eq!(eip2930.type_id(), Some(1));

		let eip1559 = TransactionV3::EIP1559(make_eip1559_tx());
		assert_eq!(eip1559.encoded_len(), eip1559.encode().len());
		assert_eq!(eip1559.type_id(), Some(2));

		let eip7702 = TransactionV3::EIP7702(make_eip7702_tx());
		assert_eq!(eip7702.encoded_len(), eip7702.encode().len());
		assert_eq!(eip7702.type_id(), Some(4));
	}

	#[test]
	fn roundtrip_preserves_encoded_len() {
		// Legacy
		let legacy = make_legacy_tx();
		let encoded = legacy.encode();
		let decoded = <TransactionV0 as EnvelopedDecodable>::decode(&encoded).unwrap();
		assert_eq!(decoded.encoded_len(), encoded.len());

		// EIP-2930
		let eip2930 = TransactionV1::EIP2930(make_eip2930_tx());
		let encoded = eip2930.encode();
		let decoded = <TransactionV1 as EnvelopedDecodable>::decode(&encoded).unwrap();
		assert_eq!(decoded.encoded_len(), encoded.len());

		// EIP-1559
		let eip1559 = TransactionV2::EIP1559(make_eip1559_tx());
		let encoded = eip1559.encode();
		let decoded = <TransactionV2 as EnvelopedDecodable>::decode(&encoded).unwrap();
		assert_eq!(decoded.encoded_len(), encoded.len());

		// EIP-7702
		let eip7702 = TransactionV3::EIP7702(make_eip7702_tx());
		let encoded = eip7702.encode();
		let decoded = <TransactionV3 as EnvelopedDecodable>::decode(&encoded).unwrap();
		assert_eq!(decoded.encoded_len(), encoded.len());
	}

	#[test]
	fn message_encoded_len_less_than_signed_tx() {
		// Unsigned messages should be smaller than signed transactions
		// because they lack signature fields (v, r, s).
		let legacy = make_legacy_tx();
		let legacy_signed_len = legacy.encoded_len();
		assert!(legacy.to_message().encoded_len() < legacy_signed_len);

		let eip2930 = make_eip2930_tx();
		let eip2930_signed_len = rlp::encode(&eip2930).len();
		assert!(eip2930.to_message().encoded_len() < eip2930_signed_len);

		let eip1559 = make_eip1559_tx();
		let eip1559_signed_len = rlp::encode(&eip1559).len();
		assert!(eip1559.to_message().encoded_len() < eip1559_signed_len);

		let eip7702 = make_eip7702_tx();
		let eip7702_signed_len = rlp::encode(&eip7702).len();
		assert!(eip7702.to_message().encoded_len() < eip7702_signed_len);
	}
}
