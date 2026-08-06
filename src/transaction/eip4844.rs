use alloc::vec::Vec;

use ethereum_types::{Address, H256, U256};
use rlp::{DecoderError, Rlp, RlpStream};
use sha3::{Digest, Keccak256};

use crate::Bytes;

pub use super::eip2930::{AccessList, TransactionSignature};
use super::{recovery, TransactionRecoveryError};

/// EIP-4844 blob-carrying transaction type.
pub const BLOB_TX_TYPE: u8 = 0x03;

/// An EIP-4844 blob-carrying transaction as included in an execution payload.
///
/// This type represents the transaction payload only. Blob sidecars are part of
/// the networking representation and are intentionally not included here.
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
pub struct EIP4844Transaction {
	pub chain_id: u64,
	pub nonce: U256,
	pub max_priority_fee_per_gas: U256,
	pub max_fee_per_gas: U256,
	pub gas_limit: U256,
	/// The recipient. EIP-4844 transactions cannot create contracts.
	pub destination: Address,
	pub value: U256,
	pub data: Bytes,
	pub access_list: AccessList,
	pub max_fee_per_blob_gas: U256,
	pub blob_versioned_hashes: Vec<H256>,
	pub signature: TransactionSignature,
}

impl EIP4844Transaction {
	/// Return the EIP-2718 transaction hash.
	#[must_use]
	pub fn hash(&self) -> H256 {
		typed_hash(self)
	}

	/// Return the hash signed by the transaction sender.
	#[must_use]
	pub fn signing_hash(&self) -> H256 {
		EIP4844TransactionMessage::from(self).hash()
	}

	/// Discard the signature and return the transaction's signing message.
	#[must_use]
	pub fn to_message(self) -> EIP4844TransactionMessage {
		EIP4844TransactionMessage {
			chain_id: self.chain_id,
			nonce: self.nonce,
			max_priority_fee_per_gas: self.max_priority_fee_per_gas,
			max_fee_per_gas: self.max_fee_per_gas,
			gas_limit: self.gas_limit,
			destination: self.destination,
			value: self.value,
			data: self.data,
			access_list: self.access_list,
			max_fee_per_blob_gas: self.max_fee_per_blob_gas,
			blob_versioned_hashes: self.blob_versioned_hashes,
		}
	}

	/// Recover the account that signed this transaction.
	pub fn recover_signer(&self) -> Result<Address, TransactionRecoveryError> {
		recovery::recover_address(
			self.signing_hash(),
			u8::from(self.signature.odd_y_parity()),
			self.signature.r(),
			self.signature.s(),
		)
	}
}

impl rlp::Encodable for EIP4844Transaction {
	fn rlp_append(&self, s: &mut RlpStream) {
		s.begin_list(14);
		s.append(&self.chain_id);
		s.append(&self.nonce);
		s.append(&self.max_priority_fee_per_gas);
		s.append(&self.max_fee_per_gas);
		s.append(&self.gas_limit);
		s.append(&self.destination);
		s.append(&self.value);
		s.append(&self.data);
		s.append_list(&self.access_list);
		s.append(&self.max_fee_per_blob_gas);
		s.append_list(&self.blob_versioned_hashes);
		s.append(&self.signature.odd_y_parity());
		s.append(&U256::from_big_endian(&self.signature.r()[..]));
		s.append(&U256::from_big_endian(&self.signature.s()[..]));
	}
}

impl rlp::Decodable for EIP4844Transaction {
	fn decode(rlp: &Rlp) -> Result<Self, DecoderError> {
		if rlp.item_count()? != 14 {
			return Err(DecoderError::RlpIncorrectListLen);
		}

		Ok(Self {
			chain_id: rlp.val_at(0)?,
			nonce: rlp.val_at(1)?,
			max_priority_fee_per_gas: rlp.val_at(2)?,
			max_fee_per_gas: rlp.val_at(3)?,
			gas_limit: rlp.val_at(4)?,
			destination: rlp.val_at(5)?,
			value: rlp.val_at(6)?,
			data: rlp.val_at(7)?,
			access_list: rlp.list_at(8)?,
			max_fee_per_blob_gas: rlp.val_at(9)?,
			blob_versioned_hashes: rlp.list_at(10)?,
			signature: {
				let odd_y_parity = rlp.val_at(11)?;
				let r = H256::from(rlp.val_at::<U256>(12)?.to_big_endian());
				let s = H256::from(rlp.val_at::<U256>(13)?.to_big_endian());
				TransactionSignature::new(odd_y_parity, r, s)
					.ok_or(DecoderError::Custom("Invalid transaction signature format"))?
			},
		})
	}
}

/// The unsigned signing payload for an EIP-4844 transaction.
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
pub struct EIP4844TransactionMessage {
	pub chain_id: u64,
	pub nonce: U256,
	pub max_priority_fee_per_gas: U256,
	pub max_fee_per_gas: U256,
	pub gas_limit: U256,
	pub destination: Address,
	pub value: U256,
	pub data: Bytes,
	pub access_list: AccessList,
	pub max_fee_per_blob_gas: U256,
	pub blob_versioned_hashes: Vec<H256>,
}

impl EIP4844TransactionMessage {
	/// Return the EIP-4844 signing hash, `keccak256(0x03 || rlp(message))`.
	#[must_use]
	pub fn hash(&self) -> H256 {
		typed_hash(self)
	}
}

impl rlp::Encodable for EIP4844TransactionMessage {
	fn rlp_append(&self, s: &mut RlpStream) {
		s.begin_list(11);
		s.append(&self.chain_id);
		s.append(&self.nonce);
		s.append(&self.max_priority_fee_per_gas);
		s.append(&self.max_fee_per_gas);
		s.append(&self.gas_limit);
		s.append(&self.destination);
		s.append(&self.value);
		s.append(&self.data);
		s.append_list(&self.access_list);
		s.append(&self.max_fee_per_blob_gas);
		s.append_list(&self.blob_versioned_hashes);
	}
}

impl rlp::Decodable for EIP4844TransactionMessage {
	fn decode(rlp: &Rlp) -> Result<Self, DecoderError> {
		if rlp.item_count()? != 11 {
			return Err(DecoderError::RlpIncorrectListLen);
		}

		Ok(Self {
			chain_id: rlp.val_at(0)?,
			nonce: rlp.val_at(1)?,
			max_priority_fee_per_gas: rlp.val_at(2)?,
			max_fee_per_gas: rlp.val_at(3)?,
			gas_limit: rlp.val_at(4)?,
			destination: rlp.val_at(5)?,
			value: rlp.val_at(6)?,
			data: rlp.val_at(7)?,
			access_list: rlp.list_at(8)?,
			max_fee_per_blob_gas: rlp.val_at(9)?,
			blob_versioned_hashes: rlp.list_at(10)?,
		})
	}
}

impl From<EIP4844Transaction> for EIP4844TransactionMessage {
	fn from(transaction: EIP4844Transaction) -> Self {
		transaction.to_message()
	}
}

impl From<&EIP4844Transaction> for EIP4844TransactionMessage {
	fn from(transaction: &EIP4844Transaction) -> Self {
		Self {
			chain_id: transaction.chain_id,
			nonce: transaction.nonce,
			max_priority_fee_per_gas: transaction.max_priority_fee_per_gas,
			max_fee_per_gas: transaction.max_fee_per_gas,
			gas_limit: transaction.gas_limit,
			destination: transaction.destination,
			value: transaction.value,
			data: transaction.data.clone(),
			access_list: transaction.access_list.clone(),
			max_fee_per_blob_gas: transaction.max_fee_per_blob_gas,
			blob_versioned_hashes: transaction.blob_versioned_hashes.clone(),
		}
	}
}

fn typed_hash(value: &impl rlp::Encodable) -> H256 {
	let encoded = rlp::encode(value);
	let mut hasher = Keccak256::new();
	hasher.update([BLOB_TX_TYPE]);
	hasher.update(encoded);
	H256::from_slice(hasher.finalize().as_ref())
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::{EnvelopedDecodable, EnvelopedEncodable, TransactionV4};
	use hex_literal::hex;

	// From EELS tests@v20.0.1, test_blob_gas_subtraction_tx.
	const RAW_TRANSACTION: &[u8] = &hex!(
		"03f901880180800e8307a12094db6f2c51eaba85193c1d44db097e4c3a118327418080f85bf859940000000000000000000000000000000000000064f842a00000000000000000000000000000000000000000000000000000000000000064a000000000000000000000000000000000000000000000000000000000000000c801f8c6a00100000000000000000000000000000000000000000000000000000000000000a00100000000000000000000000000000000000000000000000000000000000001a00100000000000000000000000000000000000000000000000000000000000002a00100000000000000000000000000000000000000000000000000000000000003a00100000000000000000000000000000000000000000000000000000000000004a0010000000000000000000000000000000000000000000000000000000000000580a01d86838b59ff95c7ffb95327eb90b532ee30b6b5b84998cf5a416bf3cd77a5d3a01bd0423015558e5bded3b48ff886d08cc84167aa8f8ff45ea34f1dcb417845c0"
	);

	fn fixture_transaction() -> EIP4844Transaction {
		assert_eq!(RAW_TRANSACTION[0], BLOB_TX_TYPE);
		rlp::decode(&RAW_TRANSACTION[1..]).expect("valid EELS EIP-4844 transaction")
	}

	#[test]
	fn eels_vector_decodes_hashes_and_roundtrips() {
		let transaction = fixture_transaction();

		assert_eq!(transaction.chain_id, 1);
		assert_eq!(transaction.nonce, U256::zero());
		assert_eq!(transaction.max_fee_per_gas, U256::from(14));
		assert_eq!(transaction.gas_limit, U256::from(500_000));
		assert_eq!(
			transaction.destination,
			Address::from_slice(&hex!("db6f2c51eaba85193c1d44db097e4c3a11832741"))
		);
		assert_eq!(transaction.access_list.len(), 1);
		assert_eq!(transaction.blob_versioned_hashes.len(), 6);
		assert_eq!(
			transaction.hash(),
			H256::from(hex!(
				"bf4c3f33cc0fa6681e5f41442c0601eb2c0894127646835bc08048bf68d445f5"
			))
		);
		assert_eq!(rlp::encode(&transaction).as_ref(), &RAW_TRANSACTION[1..]);

		let decoded: EIP4844Transaction =
			rlp::decode(&rlp::encode(&transaction)).expect("transaction roundtrip");
		assert_eq!(decoded, transaction);

		let envelope = TransactionV4::decode(RAW_TRANSACTION).expect("type-3 envelope");
		assert_eq!(envelope, TransactionV4::EIP4844(transaction));
		assert_eq!(envelope.encode().as_ref(), RAW_TRANSACTION);
	}

	#[test]
	fn signing_message_roundtrips_and_recovers_fixture_sender() {
		let transaction = fixture_transaction();
		let message = EIP4844TransactionMessage::from(&transaction);
		let decoded: EIP4844TransactionMessage =
			rlp::decode(&rlp::encode(&message)).expect("message roundtrip");
		assert_eq!(decoded, message);
		assert_eq!(transaction.signing_hash(), message.hash());

		assert_eq!(
			transaction
				.recover_signer()
				.expect("recover fixture signer"),
			Address::from_slice(&hex!("4a89611e30f5a3141694240f9529815a7fa7cc34"))
		);
	}

	#[test]
	fn high_s_signature_recovers_the_same_signer() {
		let mut transaction = fixture_transaction();
		let curve_order = U256::from_big_endian(&hex!(
			"fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141"
		));
		let original_s = U256::from_big_endian(transaction.signature.s().as_bytes());
		let high_s = H256::from((curve_order - original_s).to_big_endian());
		transaction.signature = TransactionSignature::new(
			!transaction.signature.odd_y_parity(),
			*transaction.signature.r(),
			high_s,
		)
		.expect("malleated signature remains in range");

		assert!(!transaction.signature.is_low_s());
		assert_eq!(
			transaction.recover_signer().expect("recover high-S signer"),
			Address::from_slice(&hex!("4a89611e30f5a3141694240f9529815a7fa7cc34"))
		);
	}

	#[test]
	fn rejects_contract_creation_destination_and_invalid_signature() {
		let transaction = fixture_transaction();
		let mut stream = RlpStream::new_list(14);
		stream.append(&transaction.chain_id);
		stream.append(&transaction.nonce);
		stream.append(&transaction.max_priority_fee_per_gas);
		stream.append(&transaction.max_fee_per_gas);
		stream.append(&transaction.gas_limit);
		stream.append_empty_data();
		stream.append(&transaction.value);
		stream.append(&transaction.data);
		stream.append_list(&transaction.access_list);
		stream.append(&transaction.max_fee_per_blob_gas);
		stream.append_list(&transaction.blob_versioned_hashes);
		stream.append(&transaction.signature.odd_y_parity());
		stream.append(&U256::zero());
		stream.append(&U256::zero());

		assert!(rlp::decode::<EIP4844Transaction>(&stream.out()).is_err());
	}
}
