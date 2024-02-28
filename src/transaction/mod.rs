mod eip1559;
mod eip2930;
mod legacy;

use bytes::BytesMut;
use ethereum_types::H256;
use rlp::{DecoderError, Rlp};

pub use self::{
	eip1559::{EIP1559Transaction, EIP1559TransactionMessage},
	eip2930::{AccessList, AccessListItem, EIP2930Transaction, EIP2930TransactionMessage},
	legacy::{
		LegacyTransaction, LegacyTransactionMessage, TransactionAction, TransactionRecoveryId,
		TransactionSignature,
	},
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
	derive(scale_codec::Encode, scale_codec::Decode, scale_info::TypeInfo)
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

pub type TransactionAny = TransactionV2;

#[cfg(test)]
mod tests {
	use super::*;
	use ethereum_types::U256;
	use hex_literal::hex;

	#[test]
	fn can_decode_raw_transaction() {
		let bytes = hex!("f901e48080831000008080b90196608060405234801561001057600080fd5b50336000806101000a81548173ffffffffffffffffffffffffffffffffffffffff021916908373ffffffffffffffffffffffffffffffffffffffff1602179055507fc68045c3c562488255b55aa2c4c7849de001859ff0d8a36a75c2d5ed80100fb660405180806020018281038252600d8152602001807f48656c6c6f2c20776f726c64210000000000000000000000000000000000000081525060200191505060405180910390a160cf806100c76000396000f3fe6080604052348015600f57600080fd5b506004361060285760003560e01c80638da5cb5b14602d575b600080fd5b60336075565b604051808273ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200191505060405180910390f35b6000809054906101000a900473ffffffffffffffffffffffffffffffffffffffff168156fea265627a7a72315820fae816ad954005c42bea7bc7cb5b19f7fd5d3a250715ca2023275c9ca7ce644064736f6c634300050f003278a04cab43609092a99cf095d458b61b47189d1bbab64baed10a0fd7b7d2de2eb960a011ab1bcda76dfed5e733219beb83789f9887b2a7b2e61759c7c90f7d40403201");

		<TransactionV0 as EnvelopedDecodable>::decode(&bytes).unwrap();
		<TransactionV1 as EnvelopedDecodable>::decode(&bytes).unwrap();
		<TransactionV2 as EnvelopedDecodable>::decode(&bytes).unwrap();
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

		assert_eq!(
			tx,
			<TransactionV0 as EnvelopedDecodable>::decode(&tx.encode()).unwrap()
		);
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
			odd_y_parity: false,
			r: hex!("36b241b061a36a32ab7fe86c7aa9eb592dd59018cd0443adc0903590c16b02b0").into(),
			s: hex!("5edcc541b4741c5cc6dd347c5ed9577ef293a62787b4510465fadbfe39ee4094").into(),
		});

		assert_eq!(
			tx,
			<TransactionV1 as EnvelopedDecodable>::decode(&tx.encode()).unwrap()
		);
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
			odd_y_parity: false,
			r: hex!("36b241b061a36a32ab7fe86c7aa9eb592dd59018cd0443adc0903590c16b02b0").into(),
			s: hex!("5edcc541b4741c5cc6dd347c5ed9577ef293a62787b4510465fadbfe39ee4094").into(),
		});

		assert_eq!(
			tx,
			<TransactionV2 as EnvelopedDecodable>::decode(&tx.encode()).unwrap()
		);
	}
}
