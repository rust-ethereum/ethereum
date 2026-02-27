//! Non-allocating RLP length computation helpers.
//!
//! Mirrors alloy-rlp's `Encodable::length()` via an extension trait
//! [`RlpEncodableLen`].  Since parity's `rlp::Encodable` does not carry a
//! `length()` method, we bolt one on for every type that appears inside an
//! Ethereum transaction.

use ethereum_types::{H160, H256, U256};

// ---------------------------------------------------------------------------
// Extension trait
// ---------------------------------------------------------------------------

/// Non-allocating RLP-encoded length, analogous to
/// `alloy_rlp::Encodable::length()`.
pub(crate) trait RlpEncodableLen {
	/// Exact number of bytes this value occupies when RLP-encoded.
	fn rlp_len(&self) -> usize;
}

// ---------------------------------------------------------------------------
// Standalone helpers (list framing, special encodings)
// ---------------------------------------------------------------------------

/// Number of bytes required to RLP-encode a length value (used in long
/// string / list headers).
#[inline]
fn length_of_length(len: usize) -> usize {
	if len < 0x100 {
		1
	} else if len < 0x1_0000 {
		2
	} else if len < 0x100_0000 {
		3
	} else {
		// Sufficient for any practical RLP payload (up to 4 GB).
		4
	}
}

/// Total RLP-encoded length of a *list* whose item payloads occupy
/// `payload_len` bytes in total.
#[inline]
pub(crate) fn rlp_list_len(payload_len: usize) -> usize {
	rlp_list_header_len(payload_len) + payload_len
}

/// Length of just the RLP list header for a given payload size.
#[inline]
pub(crate) fn rlp_list_header_len(payload_len: usize) -> usize {
	if payload_len <= 55 {
		1
	} else {
		1 + length_of_length(payload_len)
	}
}

/// RLP-encoded length of an [`H256`] that is serialised as a big-endian
/// [`U256`] (leading zero bytes stripped).
///
/// This is the encoding used for ECDSA signature `r` and `s` components,
/// which are stored as `H256` but RLP-encoded via
/// `U256::from_big_endian(…)`.
#[inline]
pub(crate) fn rlp_h256_as_u256_len(h: &H256) -> usize {
	let bytes = h.as_bytes();
	let start = bytes.iter().position(|b| *b != 0).unwrap_or(32);
	let trimmed_len = 32 - start;

	if trimmed_len == 0 || (trimmed_len == 1 && bytes[start] < 0x80) {
		1 // zero (0x80) or single byte < 128 (encodes directly)
	} else {
		1 + trimmed_len
	}
}

// ---------------------------------------------------------------------------
// Trait impls — primitive / foreign types
// ---------------------------------------------------------------------------

impl RlpEncodableLen for U256 {
	/// `U256` is serialised as a big-endian byte string with leading zeros
	/// stripped, so the encoded size depends on the numeric magnitude.
	#[inline]
	fn rlp_len(&self) -> usize {
		if self.is_zero() {
			return 1; // 0x80 (empty string)
		}
		let byte_len = self.bits().div_ceil(8);
		// A single byte < 0x80 is its own RLP encoding (no prefix).
		if byte_len == 1 && self.low_u64() < 0x80 {
			1
		} else {
			1 + byte_len // length-prefix byte + data
		}
	}
}

impl RlpEncodableLen for u64 {
	#[inline]
	fn rlp_len(&self) -> usize {
		if *self == 0 {
			return 1; // 0x80
		}
		let byte_len = 8 - (*self).leading_zeros() as usize / 8;
		if byte_len == 1 && *self < 0x80 {
			1
		} else {
			1 + byte_len
		}
	}
}

impl RlpEncodableLen for bool {
	/// `bool` is encoded as `u8` (`false → 0x80`, `true → 0x01`); always 1
	/// byte.
	#[inline]
	fn rlp_len(&self) -> usize {
		1
	}
}

impl RlpEncodableLen for [u8] {
	/// Byte-string encoding.
	#[inline]
	fn rlp_len(&self) -> usize {
		match self.len() {
			0 => 1,
			1 if self[0] < 0x80 => 1,
			len @ 1..=55 => 1 + len,
			len => 1 + length_of_length(len) + len,
		}
	}
}

impl RlpEncodableLen for H160 {
	/// Fixed 20-byte hash → always `1 + 20 = 21` bytes.
	#[inline]
	fn rlp_len(&self) -> usize {
		1 + 20
	}
}

impl RlpEncodableLen for H256 {
	/// Fixed 32-byte hash → always `1 + 32 = 33` bytes.
	#[inline]
	fn rlp_len(&self) -> usize {
		1 + 32
	}
}

impl RlpEncodableLen for [H256] {
	/// RLP list of fixed 32-byte hashes (e.g. storage keys).
	#[inline]
	fn rlp_len(&self) -> usize {
		rlp_list_len(self.len() * 33)
	}
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
	use super::*;
	use ethereum_types::{H256, U256};

	// --- primitive sanity checks ---

	#[test]
	fn u256_len_zero() {
		assert_eq!(U256::zero().rlp_len(), 1);
		assert_eq!(rlp::encode(&U256::zero()).len(), 1);
	}

	#[test]
	fn u256_len_one() {
		let v = U256::from(1);
		assert_eq!(v.rlp_len(), rlp::encode(&v).len());
	}

	#[test]
	fn u256_len_boundary_0x7f() {
		let v = U256::from(0x7fu64);
		assert_eq!(v.rlp_len(), 1);
		assert_eq!(rlp::encode(&v).len(), 1);
	}

	#[test]
	fn u256_len_boundary_0x80() {
		let v = U256::from(0x80u64);
		assert_eq!(v.rlp_len(), 2);
		assert_eq!(rlp::encode(&v).len(), 2);
	}

	#[test]
	fn u256_len_large() {
		let v = U256::MAX;
		assert_eq!(v.rlp_len(), rlp::encode(&v).len());
	}

	#[test]
	fn u64_len_zero() {
		assert_eq!(0u64.rlp_len(), 1);
		assert_eq!(rlp::encode(&0u64).len(), 1);
	}

	#[test]
	fn u64_len_small() {
		for v in [1u64, 0x7f, 0x80, 0xff, 0x100, u64::MAX] {
			assert_eq!(v.rlp_len(), rlp::encode(&v).len(), "mismatch for {v}");
		}
	}

	#[test]
	fn h256_as_u256_len_zero() {
		assert_eq!(rlp_h256_as_u256_len(&H256::zero()), 1);
	}

	#[test]
	fn h256_as_u256_len_matches_u256() {
		let h = H256::from_slice(&hex_literal::hex!(
			"36b241b061a36a32ab7fe86c7aa9eb592dd59018cd0443adc0903590c16b02b0"
		));
		let u = U256::from_big_endian(h.as_bytes());
		assert_eq!(rlp_h256_as_u256_len(&h), rlp::encode(&u).len());
	}

	#[test]
	fn bytes_len_empty() {
		let v: Vec<u8> = vec![];
		assert_eq!(v.rlp_len(), rlp::encode(&v).len());
	}

	#[test]
	fn bytes_len_single_low() {
		let v = vec![0x42u8];
		assert_eq!(v.rlp_len(), 1);
		assert_eq!(rlp::encode(&v).len(), 1);
	}

	#[test]
	fn bytes_len_single_high() {
		let v = vec![0x80u8];
		assert_eq!(v.rlp_len(), 2);
		assert_eq!(rlp::encode(&v).len(), 2);
	}

	#[test]
	fn bytes_len_short() {
		let v = vec![0xab; 55];
		assert_eq!(v.rlp_len(), rlp::encode(&v).len());
	}

	#[test]
	fn bytes_len_long() {
		let v = vec![0xab; 56];
		assert_eq!(v.rlp_len(), rlp::encode(&v).len());
	}

	#[test]
	fn bytes_len_very_long() {
		let v = vec![0xff; 128 * 1024];
		assert_eq!(v.rlp_len(), rlp::encode(&v).len());
	}

	#[test]
	fn list_len_empty() {
		// Empty list encodes as 0xc0 → 1 byte
		assert_eq!(rlp_list_len(0), 1);
	}

	#[test]
	fn list_len_short() {
		assert_eq!(rlp_list_len(55), 1 + 55);
	}

	#[test]
	fn list_len_long() {
		// 56-byte payload needs 1-byte length → header = 2 bytes
		assert_eq!(rlp_list_len(56), 2 + 56);
	}
}
