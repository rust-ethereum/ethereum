use core::fmt;

use ethereum_types::{Address, H256};
use k256::ecdsa::{RecoveryId, Signature, VerifyingKey};
use sha3::{Digest, Keccak256};

/// Error returned when recovering an Ethereum transaction signer.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TransactionRecoveryError {
	/// The signature components cannot be represented by secp256k1.
	InvalidSignature,
	/// The recovery identifier is not supported by secp256k1.
	InvalidRecoveryId,
	/// Public-key recovery failed.
	RecoveryFailed,
	/// The recovered public key did not use the expected uncompressed format.
	InvalidPublicKey,
}

impl fmt::Display for TransactionRecoveryError {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		match self {
			Self::InvalidSignature => f.write_str("invalid transaction signature"),
			Self::InvalidRecoveryId => f.write_str("invalid transaction recovery id"),
			Self::RecoveryFailed => f.write_str("transaction signer recovery failed"),
			Self::InvalidPublicKey => f.write_str("invalid recovered public key"),
		}
	}
}

#[cfg(feature = "std")]
impl std::error::Error for TransactionRecoveryError {}

pub(crate) fn recover_address(
	message_hash: H256,
	y_parity: u8,
	r: &H256,
	s: &H256,
) -> Result<Address, TransactionRecoveryError> {
	let mut signature_bytes = [0u8; 64];
	signature_bytes[..32].copy_from_slice(r.as_bytes());
	signature_bytes[32..].copy_from_slice(s.as_bytes());

	let mut signature = Signature::from_slice(&signature_bytes)
		.map_err(|_| TransactionRecoveryError::InvalidSignature)?;
	let mut recovery_id =
		RecoveryId::from_byte(y_parity).ok_or(TransactionRecoveryError::InvalidRecoveryId)?;

	// `k256` deliberately rejects high-S signatures during recovery. Ethereum only
	// makes low-S a fork-level transaction-validity rule, however, so older valid
	// transactions still need to be recoverable. Normalizing `s` preserves the
	// signature when the recovery parity is flipped as well.
	if let Some(normalized) = signature.normalize_s() {
		signature = normalized;
		recovery_id = RecoveryId::new(!recovery_id.is_y_odd(), recovery_id.is_x_reduced());
	}
	let verifying_key =
		VerifyingKey::recover_from_prehash(message_hash.as_bytes(), &signature, recovery_id)
			.map_err(|_| TransactionRecoveryError::RecoveryFailed)?;
	let encoded = verifying_key.to_encoded_point(false);
	let encoded = encoded.as_bytes();
	if encoded.len() != 65 || encoded[0] != 0x04 {
		return Err(TransactionRecoveryError::InvalidPublicKey);
	}

	let digest = Keccak256::digest(&encoded[1..]);
	Ok(Address::from_slice(&digest[12..]))
}
