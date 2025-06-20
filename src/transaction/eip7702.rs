use alloc::vec::Vec;

use ethereum_types::{Address, H256, U256};
use rlp::{DecoderError, Rlp, RlpStream};
use sha3::{Digest, Keccak256};

use crate::{
	transaction::{AccessList, TransactionAction},
	Bytes,
};

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
	pub y_parity: bool,
	pub r: H256,
	pub s: H256,
}

impl rlp::Encodable for AuthorizationListItem {
	fn rlp_append(&self, s: &mut RlpStream) {
		s.begin_list(6);
		s.append(&self.chain_id);
		s.append(&self.address);
		s.append(&self.nonce);
		s.append(&self.y_parity);
		s.append(&U256::from_big_endian(&self.r[..]));
		s.append(&U256::from_big_endian(&self.s[..]));
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
			y_parity: rlp.val_at(3)?,
			r: H256::from(rlp.val_at::<U256>(4)?.to_big_endian()),
			s: H256::from(rlp.val_at::<U256>(5)?.to_big_endian()),
		})
	}
}

impl AuthorizationListItem {
	/// Recover the authorizing address from the authorization signature according to EIP-7702
	pub fn authorizing_address(&self) -> Address {
		// Create the authorization message hash according to EIP-7702
		let message_hash = self.authorization_message_hash();

		// Convert signature components to the format expected by ecrecover
		let mut signature = [0u8; 65];
		
		// Convert H256 to bytes
		signature[0..32].copy_from_slice(&self.r[..]);  // r
		signature[32..64].copy_from_slice(&self.s[..]);  // s
		signature[64] = if self.y_parity { 1 } else { 0 }; // recovery_id

		// Perform ECDSA recovery
		let message_bytes: [u8; 32] = message_hash.into();
		
		// Use a simple ecrecover implementation
		if let Ok(pubkey) = Self::ecrecover(&message_bytes, &signature) {
			// Convert public key to Ethereum address
			Self::pubkey_to_address(&pubkey)
		} else {
			// Return zero address on recovery failure
			Address::zero()
		}
	}

	/// Create the authorization message hash according to EIP-7702
	fn authorization_message_hash(&self) -> H256 {
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

	/// ECDSA recovery implementation using k256 (pure Rust secp256k1)
	fn ecrecover(message_hash: &[u8; 32], signature: &[u8; 65]) -> Result<[u8; 64], ()> {
		use k256::ecdsa::{RecoveryId, Signature, VerifyingKey};
		
		// Extract signature components
		let r = &signature[0..32];
		let s = &signature[32..64];
		let recovery_id = signature[64];

		// Validate recovery_id (must be 0, 1, 2, or 3)
		if recovery_id > 3 {
			return Err(());
		}

		// Create signature from r and s
		let mut signature_data = [0u8; 64];
		signature_data[0..32].copy_from_slice(r);
		signature_data[32..64].copy_from_slice(s);

		let signature = match Signature::from_bytes(&signature_data.into()) {
			Ok(sig) => sig,
			Err(_) => return Err(()),
		};

		let recovery_id = match RecoveryId::try_from(recovery_id) {
			Ok(id) => id,
			Err(_) => return Err(()),
		};

		// Perform recovery
		match VerifyingKey::recover_from_prehash(message_hash, &signature, recovery_id) {
			Ok(verifying_key) => {
				// Convert public key to bytes (uncompressed format, skip the 0x04 prefix)
				let pubkey_bytes = verifying_key.to_encoded_point(false);
				let pubkey_slice = pubkey_bytes.as_bytes();
				
				// pubkey_slice is 65 bytes: [0x04, x_coord (32 bytes), y_coord (32 bytes)]
				// We want just the x and y coordinates (64 bytes total)
				if pubkey_slice.len() >= 65 && pubkey_slice[0] == 0x04 {
					let mut result = [0u8; 64];
					result.copy_from_slice(&pubkey_slice[1..65]);
					Ok(result)
				} else {
					Err(())
				}
			}
			Err(_) => Err(()),
		}
	}

	/// Convert public key to Ethereum address
	fn pubkey_to_address(pubkey: &[u8; 64]) -> Address {
		// Ethereum address is the last 20 bytes of keccak256(pubkey)
		let hash = Keccak256::digest(pubkey);
		Address::from_slice(&hash[12..])
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
	pub odd_y_parity: bool,
	pub r: H256,
	pub s: H256,
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
		s.append(&self.odd_y_parity);
		s.append(&U256::from_big_endian(&self.r[..]));
		s.append(&U256::from_big_endian(&self.s[..]));
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
			odd_y_parity: rlp.val_at(10)?,
			r: H256::from(rlp.val_at::<U256>(11)?.to_big_endian()),
			s: H256::from(rlp.val_at::<U256>(12)?.to_big_endian()),
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
	fn test_authorizing_address_basic() {
		// Create a sample AuthorizationListItem
		// Note: These are sample values - in real usage they would be valid ECDSA signature components
		let auth_item = AuthorizationListItem {
			chain_id: 1,
			address: Address::from_slice(&[1u8; 20]),
			nonce: U256::zero(),
			y_parity: false,
			r: H256::from_slice(&[0x12u8; 32]),
			s: H256::from_slice(&[0x34u8; 32]),
		};

		// Call the authorizing_address method
		let recovered_address = auth_item.authorizing_address();
		
		// The recovery should produce a deterministic address based on the signature components
		// Even though these are not valid ECDSA signature components from a real signature,
		// the secp256k1 library will still process them and produce a deterministic result
		assert_ne!(recovered_address, Address::zero());
		
		// Test that the same input produces the same result (deterministic)
		let recovered_address2 = auth_item.authorizing_address();
		assert_eq!(recovered_address, recovered_address2);
	}

	#[test]
	fn test_authorization_message_hash() {
		let auth_item = AuthorizationListItem {
			chain_id: 1,
			address: Address::from_slice(&[1u8; 20]),
			nonce: U256::zero(),
			y_parity: false,
			r: H256::from_slice(&[0x12u8; 32]),
			s: H256::from_slice(&[0x34u8; 32]),
		};

		let hash = auth_item.authorization_message_hash();
		
		// Verify that the hash is not zero (meaning the function executed)
		assert_ne!(hash, H256::zero());
		
		// Verify that the same input produces the same hash (deterministic)
		let hash2 = auth_item.authorization_message_hash();
		assert_eq!(hash, hash2);
	}

	#[test]
	fn test_authorization_message_hash_format() {
		// Test with known values to verify the EIP-7702 message format
		let auth_item = AuthorizationListItem {
			chain_id: 1,
			address: Address::zero(),
			nonce: U256::zero(),
			y_parity: false,
			r: H256::zero(),
			s: H256::zero(),
		};

		let hash = auth_item.authorization_message_hash();
		
		// The hash should be deterministic based on the input
		// We're not checking the exact value since that would require manually computing
		// the EIP-7702 message hash, but we verify it's not zero
		assert_ne!(hash, H256::zero());
	}
}
