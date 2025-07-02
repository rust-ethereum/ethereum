use alloc::vec::Vec;

use ethereum_types::{Address, H256, U256};
use k256::ecdsa::{RecoveryId, Signature, VerifyingKey};
use rlp::{DecoderError, Rlp, RlpStream};
use sha3::{Digest, Keccak256};

use crate::Bytes;

pub use super::eip2930::{
	AccessList, MalleableTransactionSignature, TransactionAction, TransactionSignature,
};

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

		// Create signature from r and s components
		let mut signature_bytes = [0u8; 64];
		signature_bytes[0..32].copy_from_slice(&sigv.r()[..]);
		signature_bytes[32..64].copy_from_slice(&sigv.s()[..]);

		// Create the signature and recovery ID
		let signature = Signature::from_bytes(&signature_bytes.into())
			.map_err(|_| AuthorizationError::InvalidSignature)?;

		let recovery_id = RecoveryId::try_from(if sigv.odd_y_parity() { 1u8 } else { 0u8 })
			.map_err(|_| AuthorizationError::InvalidRecoveryId)?;

		// Recover the verifying key using VerifyingKey::recover_from_prehash
		// message_hash is already a 32-byte Keccak256 hash, so we use recover_from_prehash
		let verifying_key =
			VerifyingKey::recover_from_prehash(message_hash.as_bytes(), &signature, recovery_id)
				.map_err(|_| AuthorizationError::RecoveryFailed)?;

		// Convert public key to Ethereum address
		Self::verifying_key_to_address(&verifying_key)
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
		H256::from_slice(Keccak256::digest(&message).as_slice())
	}

	/// Convert VerifyingKey to Ethereum address
	fn verifying_key_to_address(
		verifying_key: &VerifyingKey,
	) -> Result<Address, AuthorizationError> {
		// Convert public key to bytes (uncompressed format, skip the 0x04 prefix)
		let pubkey_point = verifying_key.to_encoded_point(false);
		let pubkey_bytes = pubkey_point.as_bytes();

		// pubkey_bytes is 65 bytes: [0x04, x_coord (32 bytes), y_coord (32 bytes)]
		// We want just the x and y coordinates (64 bytes total)
		if pubkey_bytes.len() >= 65 && pubkey_bytes[0] == 0x04 {
			let pubkey_coords = &pubkey_bytes[1..65];
			// Ethereum address is the last 20 bytes of keccak256(pubkey)
			let hash = Keccak256::digest(pubkey_coords);
			Ok(Address::from_slice(&hash[12..]))
		} else {
			Err(AuthorizationError::InvalidPublicKey)
		}
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
		H256::from_slice(Keccak256::digest(&out).as_slice())
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
		H256::from_slice(Keccak256::digest(&out).as_slice())
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
		let message_hash = H256::from_slice(Keccak256::digest(&message).as_slice());

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
		let expected_address = AuthorizationListItem::verifying_key_to_address(&verifying_key)
			.expect("Failed to convert verifying key to address");

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
}
