use alloc::vec::Vec;

use ethereum_types::{Address, H256, U256};
use rlp::{DecoderError, Rlp, RlpStream};
use sha3::{Digest, Keccak256};

use crate::Bytes;

pub use super::eip2930::{
	AccessList, MalleableTransactionSignature, TransactionAction, TransactionSignature,
};
use super::{recovery, TransactionRecoveryError};

/// Error type for EIP-7702 authorization signature recovery
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "with-serde", derive(serde::Serialize, serde::Deserialize))]
pub enum AuthorizationError {
	/// Invalid signature format
	InvalidSignature,
	/// Invalid recovery ID
	InvalidRecoveryId,
	/// Signature recovery failed
	RecoveryFailed,
	/// Invalid public key format
	InvalidPublicKey,
}

/// EIP-7702 transaction type as defined in the specification
pub const SET_CODE_TX_TYPE: u8 = 0x04;

/// EIP-7702 authorization message magic prefix
pub const AUTHORIZATION_MAGIC: u8 = 0x05;

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
pub struct AuthorizationListItem {
	pub chain_id: u64,
	pub address: Address,
	pub nonce: U256,
	pub signature: MalleableTransactionSignature,
}

impl rlp::Encodable for AuthorizationListItem {
	fn rlp_append(&self, s: &mut RlpStream) {
		s.begin_list(6);
		s.append(&self.chain_id);
		s.append(&self.address);
		s.append(&self.nonce);
		s.append(&self.signature.odd_y_parity);
		s.append(&U256::from_big_endian(&self.signature.r[..]));
		s.append(&U256::from_big_endian(&self.signature.s[..]));
	}
}

impl rlp::Decodable for AuthorizationListItem {
	fn decode(rlp: &Rlp) -> Result<Self, DecoderError> {
		if rlp.item_count()? != 6 {
			return Err(DecoderError::RlpIncorrectListLen);
		}

		Ok(Self {
			chain_id: rlp.val_at(0)?,
			address: rlp.val_at(1)?,
			nonce: rlp.val_at(2)?,
			signature: {
				let odd_y_parity = rlp.val_at(3)?;
				let r = H256::from(rlp.val_at::<U256>(4)?.to_big_endian());
				let s = H256::from(rlp.val_at::<U256>(5)?.to_big_endian());
				MalleableTransactionSignature { odd_y_parity, r, s }
			},
		})
	}
}

impl AuthorizationListItem {
	/// Check and get the signature.
	///
	/// This checks that the signature is not malleable, but does not otherwise check or recover
	/// the public key.
	pub fn signature(&self) -> Option<TransactionSignature> {
		TransactionSignature::new(
			self.signature.odd_y_parity,
			self.signature.r,
			self.signature.s,
		)
	}

	/// Recover the authorizing address from the authorization signature according to EIP-7702
	pub fn authorizing_address(&self) -> Result<Address, AuthorizationError> {
		// Create the authorization message hash according to EIP-7702
		let message_hash = self.authorization_message_hash();

		let sigv = self
			.signature()
			.ok_or(AuthorizationError::InvalidSignature)?;

		recovery::recover_address(
			message_hash,
			u8::from(sigv.odd_y_parity()),
			sigv.r(),
			sigv.s(),
		)
		.map_err(|error| match error {
			TransactionRecoveryError::InvalidSignature => AuthorizationError::InvalidSignature,
			TransactionRecoveryError::InvalidRecoveryId => AuthorizationError::InvalidRecoveryId,
			TransactionRecoveryError::RecoveryFailed => AuthorizationError::RecoveryFailed,
			TransactionRecoveryError::InvalidPublicKey => AuthorizationError::InvalidPublicKey,
		})
	}

	/// Create the authorization message hash according to EIP-7702
	pub fn authorization_message_hash(&self) -> H256 {
		// EIP-7702 authorization message format:
		// MAGIC || rlp([chain_id, address, nonce])
		let mut message = alloc::vec![AUTHORIZATION_MAGIC];

		// RLP encode the authorization tuple
		let mut rlp_stream = RlpStream::new_list(3);
		rlp_stream.append(&self.chain_id);
		rlp_stream.append(&self.address);
		rlp_stream.append(&self.nonce);
		message.extend_from_slice(&rlp_stream.out());

		// Return keccak256 hash of the complete message
		H256::from_slice(Keccak256::digest(&message).as_ref())
	}
}

pub type AuthorizationList = Vec<AuthorizationListItem>;

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
pub struct EIP7702Transaction {
	pub chain_id: u64,
	pub nonce: U256,
	pub max_priority_fee_per_gas: U256,
	pub max_fee_per_gas: U256,
	pub gas_limit: U256,
	pub destination: TransactionAction,
	pub value: U256,
	pub data: Bytes,
	pub access_list: AccessList,
	pub authorization_list: AuthorizationList,
	pub signature: TransactionSignature,
}

impl EIP7702Transaction {
	pub fn hash(&self) -> H256 {
		let encoded = rlp::encode(self);
		let mut out = alloc::vec![0; 1 + encoded.len()];
		out[0] = SET_CODE_TX_TYPE;
		out[1..].copy_from_slice(&encoded);
		H256::from_slice(Keccak256::digest(&out).as_ref())
	}

	pub fn to_message(self) -> EIP7702TransactionMessage {
		EIP7702TransactionMessage {
			chain_id: self.chain_id,
			nonce: self.nonce,
			max_priority_fee_per_gas: self.max_priority_fee_per_gas,
			max_fee_per_gas: self.max_fee_per_gas,
			gas_limit: self.gas_limit,
			destination: self.destination,
			value: self.value,
			data: self.data,
			access_list: self.access_list,
			authorization_list: self.authorization_list,
		}
	}

	/// Hash of the unsigned transaction payload covered by the signature.
	pub fn signing_hash(&self) -> H256 {
		self.clone().to_message().hash()
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

impl rlp::Encodable for EIP7702Transaction {
	fn rlp_append(&self, s: &mut RlpStream) {
		s.begin_list(13);
		s.append(&self.chain_id);
		s.append(&self.nonce);
		s.append(&self.max_priority_fee_per_gas);
		s.append(&self.max_fee_per_gas);
		s.append(&self.gas_limit);
		s.append(&self.destination);
		s.append(&self.value);
		s.append(&self.data);
		s.append_list(&self.access_list);
		s.append_list(&self.authorization_list);
		s.append(&self.signature.odd_y_parity());
		s.append(&U256::from_big_endian(&self.signature.r()[..]));
		s.append(&U256::from_big_endian(&self.signature.s()[..]));
	}
}

impl rlp::Decodable for EIP7702Transaction {
	fn decode(rlp: &Rlp) -> Result<Self, DecoderError> {
		if rlp.item_count()? != 13 {
			return Err(DecoderError::RlpIncorrectListLen);
		}

		let destination = rlp.val_at(5)?;
		if destination == TransactionAction::Create {
			return Err(DecoderError::Custom(
				"EIP-7702 transactions cannot create contracts",
			));
		}

		Ok(Self {
			chain_id: rlp.val_at(0)?,
			nonce: rlp.val_at(1)?,
			max_priority_fee_per_gas: rlp.val_at(2)?,
			max_fee_per_gas: rlp.val_at(3)?,
			gas_limit: rlp.val_at(4)?,
			destination,
			value: rlp.val_at(6)?,
			data: rlp.val_at(7)?,
			access_list: rlp.list_at(8)?,
			authorization_list: rlp.list_at(9)?,
			signature: {
				let odd_y_parity = rlp.val_at(10)?;
				let r = H256::from(rlp.val_at::<U256>(11)?.to_big_endian());
				let s = H256::from(rlp.val_at::<U256>(12)?.to_big_endian());
				TransactionSignature::new(odd_y_parity, r, s)
					.ok_or(DecoderError::Custom("Invalid transaction signature format"))?
			},
		})
	}
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EIP7702TransactionMessage {
	pub chain_id: u64,
	pub nonce: U256,
	pub max_priority_fee_per_gas: U256,
	pub max_fee_per_gas: U256,
	pub gas_limit: U256,
	pub destination: TransactionAction,
	pub value: U256,
	pub data: Bytes,
	pub access_list: AccessList,
	pub authorization_list: AuthorizationList,
}

impl EIP7702TransactionMessage {
	pub fn hash(&self) -> H256 {
		let encoded = rlp::encode(self);
		let mut out = alloc::vec![0; 1 + encoded.len()];
		out[0] = SET_CODE_TX_TYPE;
		out[1..].copy_from_slice(&encoded);
		H256::from_slice(Keccak256::digest(&out).as_ref())
	}
}

impl rlp::Encodable for EIP7702TransactionMessage {
	fn rlp_append(&self, s: &mut RlpStream) {
		s.begin_list(10);
		s.append(&self.chain_id);
		s.append(&self.nonce);
		s.append(&self.max_priority_fee_per_gas);
		s.append(&self.max_fee_per_gas);
		s.append(&self.gas_limit);
		s.append(&self.destination);
		s.append(&self.value);
		s.append(&self.data);
		s.append_list(&self.access_list);
		s.append_list(&self.authorization_list);
	}
}

impl From<EIP7702Transaction> for EIP7702TransactionMessage {
	fn from(t: EIP7702Transaction) -> Self {
		t.to_message()
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use ethereum_types::{Address, H256, U256};

	#[test]
	fn test_authorizing_address_with_real_signature() {
		use k256::ecdsa::SigningKey;
		use k256::elliptic_curve::SecretKey;

		// Use a fixed test private key for deterministic testing
		let private_key_bytes = [
			0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
			0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c,
			0x1d, 0x1e, 0x1f, 0x20,
		];

		let secret_key =
			SecretKey::from_bytes(&private_key_bytes.into()).expect("Invalid private key");
		let signing_key = SigningKey::from(secret_key);
		let verifying_key = signing_key.verifying_key();

		// Create authorization data
		let chain_id = 1u64;
		let address = Address::from_slice(&[0x42u8; 20]);
		let nonce = U256::zero();

		// Create the EIP-7702 authorization message hash
		let mut message = alloc::vec![AUTHORIZATION_MAGIC];
		let mut rlp_stream = RlpStream::new_list(3);
		rlp_stream.append(&chain_id);
		rlp_stream.append(&address);
		rlp_stream.append(&nonce);
		message.extend_from_slice(&rlp_stream.out());
		let message_hash = H256::from_slice(Keccak256::digest(&message).as_ref());

		// Sign the message hash
		let (signature, recovery_id) = signing_key
			.sign_prehash_recoverable(message_hash.as_bytes())
			.expect("Failed to sign message");

		// Extract signature components
		let signature_bytes = signature.to_bytes();
		let r = H256::from_slice(&signature_bytes[0..32]);
		let s = H256::from_slice(&signature_bytes[32..64]);
		let y_parity = recovery_id.is_y_odd();

		// Create AuthorizationListItem with real signature
		let auth_item = AuthorizationListItem {
			chain_id,
			address,
			nonce,
			signature: MalleableTransactionSignature {
				odd_y_parity: y_parity,
				r,
				s,
			},
		};

		// Recover the authorizing address
		let recovered_address = auth_item
			.authorizing_address()
			.expect("Failed to recover authorizing address");

		// Convert the original verifying key to an Ethereum address for comparison
		let encoded_key = verifying_key.to_encoded_point(false);
		let encoded_key = encoded_key.as_bytes();
		let key_hash = Keccak256::digest(&encoded_key[1..]);
		let expected_address = Address::from_slice(&key_hash[12..]);

		// Verify that the recovered address matches the original signer
		assert_eq!(recovered_address, expected_address);
		assert_ne!(recovered_address, Address::zero());

		// For deterministic testing, verify specific expected values
		// This ensures the implementation is working correctly with known inputs
		assert_eq!(
			expected_address,
			Address::from_slice(&hex_literal::hex!(
				"6370ef2f4db3611d657b90667de398a2cc2a370c"
			))
		);
	}

	#[test]
	fn test_authorizing_address_error_handling() {
		// Test with invalid signature components (zero values are invalid in ECDSA)
		assert!(TransactionSignature::new(
			false,
			H256::zero(), // Invalid r value (r cannot be zero)
			H256::zero(), // Invalid s value (s cannot be zero)
		)
		.is_none());

		// Test with values that are too high (greater than secp256k1 curve order)
		// secp256k1 curve order is FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
		assert!(TransactionSignature::new(
			false,
			// Use maximum possible values which exceed the curve order
			H256::from_slice(&[0xFF; 32]),
			H256::from_slice(&[0xFF; 32]),
		)
		.is_none());
	}

	#[test]
	fn checked_rlp_decode_rejects_contract_creation() {
		let signature =
			TransactionSignature::new(false, H256::from_low_u64_be(1), H256::from_low_u64_be(1))
				.unwrap();
		let transaction = EIP7702Transaction {
			chain_id: 1,
			nonce: U256::zero(),
			max_priority_fee_per_gas: U256::one(),
			max_fee_per_gas: U256::from(2),
			gas_limit: U256::from(21_000),
			destination: TransactionAction::Create,
			value: U256::zero(),
			data: Vec::new(),
			access_list: Vec::new(),
			authorization_list: Vec::new(),
			signature,
		};

		assert_eq!(
			rlp::decode::<EIP7702Transaction>(&rlp::encode(&transaction)),
			Err(DecoderError::Custom(
				"EIP-7702 transactions cannot create contracts"
			))
		);
	}
}
