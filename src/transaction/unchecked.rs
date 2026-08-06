//! Structurally decoded transaction types.
//!
//! The ordinary transaction decoders in this crate validate signatures while decoding.  That is
//! the safest default for application code, but it prevents callers such as consensus test
//! runners from distinguishing malformed signatures from malformed RLP.  The types in this
//! module only validate the RLP shape and canonical integer encoding.  Use the provided
//! [`TryFrom`] implementations to obtain the corresponding checked transaction types.

use alloc::vec::Vec;
use core::fmt;

use bytes::BytesMut;
use ethereum_types::{Address, H256, U256};
use rlp::{DecoderError, PayloadInfo, Rlp, RlpStream};

use super::{
	eip1559::EIP1559Transaction,
	eip2930::{AccessList, MalleableTransactionSignature, TransactionSignature},
	eip4844::EIP4844Transaction,
	eip7702::{AuthorizationListItem, EIP7702Transaction},
	legacy::{self, LegacyTransaction, TransactionAction},
	signature,
};
use crate::{
	enveloped::{EnvelopedDecodable, EnvelopedDecoderError, EnvelopedEncodable},
	Bytes,
};

const ACCESS_LIST_TX_TYPE: u8 = 0x01;
const DYNAMIC_FEE_TX_TYPE: u8 = 0x02;
const BLOB_TX_TYPE: u8 = 0x03;
const SET_CODE_TX_TYPE: u8 = 0x04;

/// An unchecked legacy ECDSA signature.
///
/// All three values retain their full RLP integer range. In particular, `v` is not restricted to
/// a recovery ID and `r` and `s` are not restricted to the secp256k1 scalar range.
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
pub struct UncheckedLegacyTransactionSignature {
	pub v: U256,
	pub r: U256,
	pub s: U256,
}

/// An unchecked typed-transaction ECDSA signature.
///
/// `odd_y_parity` is an integer rather than a `bool`, allowing a structurally valid transaction
/// with a parity other than zero or one to be inspected after decoding.
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
pub struct UncheckedTransactionSignature {
	pub odd_y_parity: U256,
	pub r: U256,
	pub s: U256,
}

/// Error returned while converting an unchecked signature to a checked signature.
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
pub enum SignatureConversionError {
	/// The legacy `v` value cannot represent a valid legacy recovery ID.
	InvalidLegacyV(U256),
	/// Typed-transaction parity is not zero or one.
	InvalidParity(U256),
	/// The `r` value is zero or is not below the secp256k1 curve order.
	InvalidR(U256),
	/// The `s` value is zero or is not below the secp256k1 curve order.
	InvalidS(U256),
}

impl fmt::Display for SignatureConversionError {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		match self {
			Self::InvalidLegacyV(v) => write!(f, "invalid legacy transaction v value: {v}"),
			Self::InvalidParity(parity) => {
				write!(f, "invalid typed transaction y parity: {parity}")
			}
			Self::InvalidR(r) => write!(f, "invalid transaction signature r value: {r}"),
			Self::InvalidS(s) => write!(f, "invalid transaction signature s value: {s}"),
		}
	}
}

#[cfg(feature = "std")]
impl std::error::Error for SignatureConversionError {}

/// Error returned while converting an unchecked EIP-7702 authorization.
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
pub enum AuthorizationConversionError {
	/// The authorization chain ID cannot be represented by the checked type.
	ChainIdOverflow(U256),
	/// The authorization signature is invalid.
	Signature(SignatureConversionError),
}

impl fmt::Display for AuthorizationConversionError {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		match self {
			Self::ChainIdOverflow(chain_id) => {
				write!(f, "authorization chain ID does not fit in u64: {chain_id}")
			}
			Self::Signature(error) => write!(f, "invalid authorization signature: {error}"),
		}
	}
}

#[cfg(feature = "std")]
impl std::error::Error for AuthorizationConversionError {}

/// Error returned while converting an unchecked transaction to a checked transaction.
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
pub enum TransactionConversionError {
	/// The transaction chain ID cannot be represented by the checked type.
	ChainIdOverflow(U256),
	/// The transaction signature is invalid.
	Signature(SignatureConversionError),
	/// EIP-4844 transactions must call an address and cannot create a contract.
	EIP4844ContractCreation,
	/// EIP-7702 transactions must call an address and cannot create a contract.
	EIP7702ContractCreation,
	/// The EIP-7702 authorization at `index` is invalid.
	InvalidAuthorization {
		index: u64,
		error: AuthorizationConversionError,
	},
}

impl fmt::Display for TransactionConversionError {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		match self {
			Self::ChainIdOverflow(chain_id) => {
				write!(f, "transaction chain ID does not fit in u64: {chain_id}")
			}
			Self::Signature(error) => write!(f, "invalid transaction signature: {error}"),
			Self::EIP4844ContractCreation => {
				f.write_str("EIP-4844 transactions cannot create contracts")
			}
			Self::EIP7702ContractCreation => {
				f.write_str("EIP-7702 transactions cannot create contracts")
			}
			Self::InvalidAuthorization { index, error } => {
				write!(
					f,
					"invalid EIP-7702 authorization at index {index}: {error}"
				)
			}
		}
	}
}

#[cfg(feature = "std")]
impl std::error::Error for TransactionConversionError {}

impl From<SignatureConversionError> for TransactionConversionError {
	fn from(error: SignatureConversionError) -> Self {
		Self::Signature(error)
	}
}

fn checked_chain_id(chain_id: U256) -> Result<u64, TransactionConversionError> {
	if chain_id > U256::from(u64::MAX) {
		return Err(TransactionConversionError::ChainIdOverflow(chain_id));
	}

	Ok(chain_id.low_u64())
}

fn checked_authorization_chain_id(chain_id: U256) -> Result<u64, AuthorizationConversionError> {
	if chain_id > U256::from(u64::MAX) {
		return Err(AuthorizationConversionError::ChainIdOverflow(chain_id));
	}

	Ok(chain_id.low_u64())
}

fn checked_r(r: U256) -> Result<H256, SignatureConversionError> {
	let value = H256::from(r.to_big_endian());
	if !signature::is_valid_signature_component(&value) {
		return Err(SignatureConversionError::InvalidR(r));
	}
	Ok(value)
}

fn checked_s(s: U256) -> Result<H256, SignatureConversionError> {
	let value = H256::from(s.to_big_endian());
	if !signature::is_valid_signature_component(&value) {
		return Err(SignatureConversionError::InvalidS(s));
	}
	Ok(value)
}

impl TryFrom<UncheckedLegacyTransactionSignature> for legacy::TransactionSignature {
	type Error = SignatureConversionError;

	fn try_from(signature: UncheckedLegacyTransactionSignature) -> Result<Self, Self::Error> {
		if signature.v > U256::from(u64::MAX) {
			return Err(SignatureConversionError::InvalidLegacyV(signature.v));
		}

		let v = signature.v.low_u64();
		let r = checked_r(signature.r)?;
		let s = checked_s(signature.s)?;
		Self::new(v, r, s).ok_or(SignatureConversionError::InvalidLegacyV(signature.v))
	}
}

impl TryFrom<UncheckedTransactionSignature> for TransactionSignature {
	type Error = SignatureConversionError;

	fn try_from(signature: UncheckedTransactionSignature) -> Result<Self, Self::Error> {
		let odd_y_parity = match signature.odd_y_parity {
			value if value.is_zero() => false,
			value if value == U256::one() => true,
			value => return Err(SignatureConversionError::InvalidParity(value)),
		};
		let r = checked_r(signature.r)?;
		let s = checked_s(signature.s)?;

		// The checks above are identical to those performed by `TransactionSignature::new`.
		Ok(Self::new(odd_y_parity, r, s).expect("validated transaction signature"))
	}
}

impl TryFrom<UncheckedTransactionSignature> for MalleableTransactionSignature {
	type Error = SignatureConversionError;

	fn try_from(signature: UncheckedTransactionSignature) -> Result<Self, Self::Error> {
		let checked = TransactionSignature::try_from(signature)?;
		Ok(Self {
			odd_y_parity: checked.odd_y_parity(),
			r: *checked.r(),
			s: *checked.s(),
		})
	}
}

/// A structurally decoded legacy transaction.
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
pub struct UncheckedLegacyTransaction {
	pub nonce: U256,
	pub gas_price: U256,
	pub gas_limit: U256,
	pub action: TransactionAction,
	pub value: U256,
	pub input: Bytes,
	pub signature: UncheckedLegacyTransactionSignature,
}

impl rlp::Encodable for UncheckedLegacyTransaction {
	fn rlp_append(&self, stream: &mut RlpStream) {
		stream.begin_list(9);
		stream.append(&self.nonce);
		stream.append(&self.gas_price);
		stream.append(&self.gas_limit);
		stream.append(&self.action);
		stream.append(&self.value);
		stream.append(&self.input);
		stream.append(&self.signature.v);
		stream.append(&self.signature.r);
		stream.append(&self.signature.s);
	}
}

impl rlp::Decodable for UncheckedLegacyTransaction {
	fn decode(rlp: &Rlp) -> Result<Self, DecoderError> {
		if rlp.item_count()? != 9 {
			return Err(DecoderError::RlpIncorrectListLen);
		}

		Ok(Self {
			nonce: rlp.val_at(0)?,
			gas_price: rlp.val_at(1)?,
			gas_limit: rlp.val_at(2)?,
			action: rlp.val_at(3)?,
			value: rlp.val_at(4)?,
			input: rlp.val_at(5)?,
			signature: UncheckedLegacyTransactionSignature {
				v: rlp.val_at(6)?,
				r: rlp.val_at(7)?,
				s: rlp.val_at(8)?,
			},
		})
	}
}

impl TryFrom<UncheckedLegacyTransaction> for LegacyTransaction {
	type Error = TransactionConversionError;

	fn try_from(transaction: UncheckedLegacyTransaction) -> Result<Self, Self::Error> {
		Ok(Self {
			nonce: transaction.nonce,
			gas_price: transaction.gas_price,
			gas_limit: transaction.gas_limit,
			action: transaction.action,
			value: transaction.value,
			input: transaction.input,
			signature: transaction.signature.try_into()?,
		})
	}
}

/// A structurally decoded EIP-2930 transaction.
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
pub struct UncheckedEIP2930Transaction {
	pub chain_id: U256,
	pub nonce: U256,
	pub gas_price: U256,
	pub gas_limit: U256,
	pub action: TransactionAction,
	pub value: U256,
	pub input: Bytes,
	pub access_list: AccessList,
	pub signature: UncheckedTransactionSignature,
}

impl rlp::Encodable for UncheckedEIP2930Transaction {
	fn rlp_append(&self, stream: &mut RlpStream) {
		stream.begin_list(11);
		stream.append(&self.chain_id);
		stream.append(&self.nonce);
		stream.append(&self.gas_price);
		stream.append(&self.gas_limit);
		stream.append(&self.action);
		stream.append(&self.value);
		stream.append(&self.input);
		stream.append_list(&self.access_list);
		stream.append(&self.signature.odd_y_parity);
		stream.append(&self.signature.r);
		stream.append(&self.signature.s);
	}
}

impl rlp::Decodable for UncheckedEIP2930Transaction {
	fn decode(rlp: &Rlp) -> Result<Self, DecoderError> {
		if rlp.item_count()? != 11 {
			return Err(DecoderError::RlpIncorrectListLen);
		}

		Ok(Self {
			chain_id: rlp.val_at(0)?,
			nonce: rlp.val_at(1)?,
			gas_price: rlp.val_at(2)?,
			gas_limit: rlp.val_at(3)?,
			action: rlp.val_at(4)?,
			value: rlp.val_at(5)?,
			input: rlp.val_at(6)?,
			access_list: rlp.list_at(7)?,
			signature: UncheckedTransactionSignature {
				odd_y_parity: rlp.val_at(8)?,
				r: rlp.val_at(9)?,
				s: rlp.val_at(10)?,
			},
		})
	}
}

impl TryFrom<UncheckedEIP2930Transaction> for super::eip2930::EIP2930Transaction {
	type Error = TransactionConversionError;

	fn try_from(transaction: UncheckedEIP2930Transaction) -> Result<Self, Self::Error> {
		Ok(Self {
			chain_id: checked_chain_id(transaction.chain_id)?,
			nonce: transaction.nonce,
			gas_price: transaction.gas_price,
			gas_limit: transaction.gas_limit,
			action: transaction.action,
			value: transaction.value,
			input: transaction.input,
			access_list: transaction.access_list,
			signature: transaction.signature.try_into()?,
		})
	}
}

/// A structurally decoded EIP-1559 transaction.
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
pub struct UncheckedEIP1559Transaction {
	pub chain_id: U256,
	pub nonce: U256,
	pub max_priority_fee_per_gas: U256,
	pub max_fee_per_gas: U256,
	pub gas_limit: U256,
	pub action: TransactionAction,
	pub value: U256,
	pub input: Bytes,
	pub access_list: AccessList,
	pub signature: UncheckedTransactionSignature,
}

impl rlp::Encodable for UncheckedEIP1559Transaction {
	fn rlp_append(&self, stream: &mut RlpStream) {
		stream.begin_list(12);
		stream.append(&self.chain_id);
		stream.append(&self.nonce);
		stream.append(&self.max_priority_fee_per_gas);
		stream.append(&self.max_fee_per_gas);
		stream.append(&self.gas_limit);
		stream.append(&self.action);
		stream.append(&self.value);
		stream.append(&self.input);
		stream.append_list(&self.access_list);
		stream.append(&self.signature.odd_y_parity);
		stream.append(&self.signature.r);
		stream.append(&self.signature.s);
	}
}

impl rlp::Decodable for UncheckedEIP1559Transaction {
	fn decode(rlp: &Rlp) -> Result<Self, DecoderError> {
		if rlp.item_count()? != 12 {
			return Err(DecoderError::RlpIncorrectListLen);
		}

		Ok(Self {
			chain_id: rlp.val_at(0)?,
			nonce: rlp.val_at(1)?,
			max_priority_fee_per_gas: rlp.val_at(2)?,
			max_fee_per_gas: rlp.val_at(3)?,
			gas_limit: rlp.val_at(4)?,
			action: rlp.val_at(5)?,
			value: rlp.val_at(6)?,
			input: rlp.val_at(7)?,
			access_list: rlp.list_at(8)?,
			signature: UncheckedTransactionSignature {
				odd_y_parity: rlp.val_at(9)?,
				r: rlp.val_at(10)?,
				s: rlp.val_at(11)?,
			},
		})
	}
}

impl TryFrom<UncheckedEIP1559Transaction> for EIP1559Transaction {
	type Error = TransactionConversionError;

	fn try_from(transaction: UncheckedEIP1559Transaction) -> Result<Self, Self::Error> {
		Ok(Self {
			chain_id: checked_chain_id(transaction.chain_id)?,
			nonce: transaction.nonce,
			max_priority_fee_per_gas: transaction.max_priority_fee_per_gas,
			max_fee_per_gas: transaction.max_fee_per_gas,
			gas_limit: transaction.gas_limit,
			action: transaction.action,
			value: transaction.value,
			input: transaction.input,
			access_list: transaction.access_list,
			signature: transaction.signature.try_into()?,
		})
	}
}

/// A structurally decoded EIP-4844 transaction.
///
/// `destination` intentionally uses [`TransactionAction`], rather than [`Address`], so an invalid
/// blob contract-creation transaction can be decoded and reported by the caller.
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
pub struct UncheckedEIP4844Transaction {
	pub chain_id: U256,
	pub nonce: U256,
	pub max_priority_fee_per_gas: U256,
	pub max_fee_per_gas: U256,
	pub gas_limit: U256,
	pub destination: TransactionAction,
	pub value: U256,
	pub data: Bytes,
	pub access_list: AccessList,
	pub max_fee_per_blob_gas: U256,
	pub blob_versioned_hashes: Vec<H256>,
	pub signature: UncheckedTransactionSignature,
}

impl rlp::Encodable for UncheckedEIP4844Transaction {
	fn rlp_append(&self, stream: &mut RlpStream) {
		stream.begin_list(14);
		stream.append(&self.chain_id);
		stream.append(&self.nonce);
		stream.append(&self.max_priority_fee_per_gas);
		stream.append(&self.max_fee_per_gas);
		stream.append(&self.gas_limit);
		stream.append(&self.destination);
		stream.append(&self.value);
		stream.append(&self.data);
		stream.append_list(&self.access_list);
		stream.append(&self.max_fee_per_blob_gas);
		stream.append_list(&self.blob_versioned_hashes);
		stream.append(&self.signature.odd_y_parity);
		stream.append(&self.signature.r);
		stream.append(&self.signature.s);
	}
}

impl rlp::Decodable for UncheckedEIP4844Transaction {
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
			signature: UncheckedTransactionSignature {
				odd_y_parity: rlp.val_at(11)?,
				r: rlp.val_at(12)?,
				s: rlp.val_at(13)?,
			},
		})
	}
}

impl TryFrom<UncheckedEIP4844Transaction> for EIP4844Transaction {
	type Error = TransactionConversionError;

	fn try_from(transaction: UncheckedEIP4844Transaction) -> Result<Self, Self::Error> {
		let destination = match transaction.destination {
			TransactionAction::Call(address) => address,
			TransactionAction::Create => {
				return Err(TransactionConversionError::EIP4844ContractCreation)
			}
		};

		Ok(Self {
			chain_id: checked_chain_id(transaction.chain_id)?,
			nonce: transaction.nonce,
			max_priority_fee_per_gas: transaction.max_priority_fee_per_gas,
			max_fee_per_gas: transaction.max_fee_per_gas,
			gas_limit: transaction.gas_limit,
			destination,
			value: transaction.value,
			data: transaction.data,
			access_list: transaction.access_list,
			max_fee_per_blob_gas: transaction.max_fee_per_blob_gas,
			blob_versioned_hashes: transaction.blob_versioned_hashes,
			signature: transaction.signature.try_into()?,
		})
	}
}

/// A structurally decoded EIP-7702 authorization-list item.
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
pub struct UncheckedAuthorizationListItem {
	pub chain_id: U256,
	pub address: Address,
	pub nonce: U256,
	pub signature: UncheckedTransactionSignature,
}

impl rlp::Encodable for UncheckedAuthorizationListItem {
	fn rlp_append(&self, stream: &mut RlpStream) {
		stream.begin_list(6);
		stream.append(&self.chain_id);
		stream.append(&self.address);
		stream.append(&self.nonce);
		stream.append(&self.signature.odd_y_parity);
		stream.append(&self.signature.r);
		stream.append(&self.signature.s);
	}
}

impl rlp::Decodable for UncheckedAuthorizationListItem {
	fn decode(rlp: &Rlp) -> Result<Self, DecoderError> {
		if rlp.item_count()? != 6 {
			return Err(DecoderError::RlpIncorrectListLen);
		}

		Ok(Self {
			chain_id: rlp.val_at(0)?,
			address: rlp.val_at(1)?,
			nonce: rlp.val_at(2)?,
			signature: UncheckedTransactionSignature {
				odd_y_parity: rlp.val_at(3)?,
				r: rlp.val_at(4)?,
				s: rlp.val_at(5)?,
			},
		})
	}
}

impl TryFrom<UncheckedAuthorizationListItem> for AuthorizationListItem {
	type Error = AuthorizationConversionError;

	fn try_from(authorization: UncheckedAuthorizationListItem) -> Result<Self, Self::Error> {
		Ok(Self {
			chain_id: checked_authorization_chain_id(authorization.chain_id)?,
			address: authorization.address,
			nonce: authorization.nonce,
			signature: authorization
				.signature
				.try_into()
				.map_err(AuthorizationConversionError::Signature)?,
		})
	}
}

/// A structurally decoded EIP-7702 transaction.
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
pub struct UncheckedEIP7702Transaction {
	pub chain_id: U256,
	pub nonce: U256,
	pub max_priority_fee_per_gas: U256,
	pub max_fee_per_gas: U256,
	pub gas_limit: U256,
	pub destination: TransactionAction,
	pub value: U256,
	pub data: Bytes,
	pub access_list: AccessList,
	pub authorization_list: Vec<UncheckedAuthorizationListItem>,
	pub signature: UncheckedTransactionSignature,
}

impl rlp::Encodable for UncheckedEIP7702Transaction {
	fn rlp_append(&self, stream: &mut RlpStream) {
		stream.begin_list(13);
		stream.append(&self.chain_id);
		stream.append(&self.nonce);
		stream.append(&self.max_priority_fee_per_gas);
		stream.append(&self.max_fee_per_gas);
		stream.append(&self.gas_limit);
		stream.append(&self.destination);
		stream.append(&self.value);
		stream.append(&self.data);
		stream.append_list(&self.access_list);
		stream.append_list(&self.authorization_list);
		stream.append(&self.signature.odd_y_parity);
		stream.append(&self.signature.r);
		stream.append(&self.signature.s);
	}
}

impl rlp::Decodable for UncheckedEIP7702Transaction {
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
			signature: UncheckedTransactionSignature {
				odd_y_parity: rlp.val_at(10)?,
				r: rlp.val_at(11)?,
				s: rlp.val_at(12)?,
			},
		})
	}
}

impl TryFrom<UncheckedEIP7702Transaction> for EIP7702Transaction {
	type Error = TransactionConversionError;

	fn try_from(transaction: UncheckedEIP7702Transaction) -> Result<Self, Self::Error> {
		if transaction.destination == TransactionAction::Create {
			return Err(TransactionConversionError::EIP7702ContractCreation);
		}

		let mut authorization_list = Vec::with_capacity(transaction.authorization_list.len());
		for (index, authorization) in transaction.authorization_list.into_iter().enumerate() {
			authorization_list.push(authorization.try_into().map_err(|error| {
				TransactionConversionError::InvalidAuthorization {
					index: index as u64,
					error,
				}
			})?);
		}

		Ok(Self {
			chain_id: checked_chain_id(transaction.chain_id)?,
			nonce: transaction.nonce,
			max_priority_fee_per_gas: transaction.max_priority_fee_per_gas,
			max_fee_per_gas: transaction.max_fee_per_gas,
			gas_limit: transaction.gas_limit,
			destination: transaction.destination,
			value: transaction.value,
			data: transaction.data,
			access_list: transaction.access_list,
			authorization_list,
			signature: transaction.signature.try_into()?,
		})
	}
}

fn decode_exact<T: rlp::Decodable>(bytes: &[u8]) -> Result<T, DecoderError> {
	let payload_info = PayloadInfo::from(bytes)?;
	match payload_info.total().cmp(&bytes.len()) {
		core::cmp::Ordering::Less => Err(DecoderError::RlpIsTooBig),
		core::cmp::Ordering::Greater => Err(DecoderError::RlpIsTooShort),
		core::cmp::Ordering::Equal => rlp::decode(bytes),
	}
}

/// A structurally decoded EIP-2718 transaction envelope.
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
pub enum UncheckedTransactionEnvelope {
	Legacy(UncheckedLegacyTransaction),
	EIP2930(UncheckedEIP2930Transaction),
	EIP1559(UncheckedEIP1559Transaction),
	EIP4844(UncheckedEIP4844Transaction),
	EIP7702(UncheckedEIP7702Transaction),
}

impl EnvelopedEncodable for UncheckedTransactionEnvelope {
	fn type_id(&self) -> Option<u8> {
		match self {
			Self::Legacy(_) => None,
			Self::EIP2930(_) => Some(ACCESS_LIST_TX_TYPE),
			Self::EIP1559(_) => Some(DYNAMIC_FEE_TX_TYPE),
			Self::EIP4844(_) => Some(BLOB_TX_TYPE),
			Self::EIP7702(_) => Some(SET_CODE_TX_TYPE),
		}
	}

	fn encode_payload(&self) -> BytesMut {
		match self {
			Self::Legacy(transaction) => rlp::encode(transaction),
			Self::EIP2930(transaction) => rlp::encode(transaction),
			Self::EIP1559(transaction) => rlp::encode(transaction),
			Self::EIP4844(transaction) => rlp::encode(transaction),
			Self::EIP7702(transaction) => rlp::encode(transaction),
		}
	}
}

impl EnvelopedDecodable for UncheckedTransactionEnvelope {
	type PayloadDecoderError = DecoderError;

	fn decode(bytes: &[u8]) -> Result<Self, EnvelopedDecoderError<Self::PayloadDecoderError>> {
		let Some((&type_id, payload)) = bytes.split_first() else {
			return Err(EnvelopedDecoderError::UnknownTypeId);
		};

		if Rlp::new(bytes).is_list() {
			return Ok(Self::Legacy(decode_exact(bytes)?));
		}

		match type_id {
			ACCESS_LIST_TX_TYPE => Ok(Self::EIP2930(decode_exact(payload)?)),
			DYNAMIC_FEE_TX_TYPE => Ok(Self::EIP1559(decode_exact(payload)?)),
			BLOB_TX_TYPE => Ok(Self::EIP4844(decode_exact(payload)?)),
			SET_CODE_TX_TYPE => Ok(Self::EIP7702(decode_exact(payload)?)),
			_ => Err(EnvelopedDecoderError::UnknownTypeId),
		}
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::enveloped::{EnvelopedDecodable, EnvelopedEncodable};

	fn signature() -> UncheckedTransactionSignature {
		UncheckedTransactionSignature {
			odd_y_parity: U256::zero(),
			r: U256::one(),
			s: U256::one(),
		}
	}

	fn eip1559(signature: UncheckedTransactionSignature) -> UncheckedEIP1559Transaction {
		UncheckedEIP1559Transaction {
			chain_id: U256::one(),
			nonce: U256::zero(),
			max_priority_fee_per_gas: U256::one(),
			max_fee_per_gas: U256::from(2),
			gas_limit: U256::from(21_000),
			action: TransactionAction::Call(Address::repeat_byte(0x11)),
			value: U256::zero(),
			input: Vec::new(),
			access_list: Vec::new(),
			signature,
		}
	}

	#[test]
	fn invalid_typed_parity_round_trips() {
		let transaction =
			UncheckedTransactionEnvelope::EIP1559(eip1559(UncheckedTransactionSignature {
				odd_y_parity: U256::from(2),
				..signature()
			}));
		let encoded = transaction.encode();
		let decoded = UncheckedTransactionEnvelope::decode(&encoded).unwrap();
		assert_eq!(decoded, transaction);

		let UncheckedTransactionEnvelope::EIP1559(transaction) = decoded else {
			panic!("wrong transaction variant")
		};
		assert_eq!(
			EIP1559Transaction::try_from(transaction),
			Err(TransactionConversionError::Signature(
				SignatureConversionError::InvalidParity(U256::from(2))
			))
		);
	}

	#[test]
	fn invalid_signature_components_remain_decodable() {
		let transaction =
			UncheckedTransactionEnvelope::EIP1559(eip1559(UncheckedTransactionSignature {
				r: U256::zero(),
				..signature()
			}));
		let decoded = UncheckedTransactionEnvelope::decode(&transaction.encode()).unwrap();
		let UncheckedTransactionEnvelope::EIP1559(transaction) = decoded else {
			panic!("wrong transaction variant")
		};
		assert_eq!(
			EIP1559Transaction::try_from(transaction),
			Err(TransactionConversionError::Signature(
				SignatureConversionError::InvalidR(U256::zero())
			))
		);
	}

	#[test]
	fn high_s_converts_and_remains_malleable() {
		let high_s = U256::from_big_endian(&hex_literal::hex!(
			"7fffffffffffffffffffffffffffffff5d576e7357a4501ddfe92f46681b20a1"
		));
		let checked = TransactionSignature::try_from(UncheckedTransactionSignature {
			s: high_s,
			..signature()
		})
		.unwrap();
		assert!(!checked.is_low_s());
	}

	#[test]
	fn invalid_legacy_v_has_a_precise_error() {
		let error = legacy::TransactionSignature::try_from(UncheckedLegacyTransactionSignature {
			v: U256::from(29),
			r: U256::one(),
			s: U256::one(),
		})
		.unwrap_err();
		assert_eq!(
			error,
			SignatureConversionError::InvalidLegacyV(U256::from(29))
		);
	}

	#[test]
	fn envelope_rejects_trailing_bytes() {
		let legacy = UncheckedTransactionEnvelope::Legacy(UncheckedLegacyTransaction {
			nonce: U256::zero(),
			gas_price: U256::one(),
			gas_limit: U256::from(21_000),
			action: TransactionAction::Call(Address::repeat_byte(0x11)),
			value: U256::zero(),
			input: Vec::new(),
			signature: UncheckedLegacyTransactionSignature {
				v: U256::from(27),
				r: U256::one(),
				s: U256::one(),
			},
		});
		let mut encoded = legacy.encode();
		encoded.extend_from_slice(&[0]);
		assert_eq!(
			UncheckedTransactionEnvelope::decode(&encoded),
			Err(EnvelopedDecoderError::Payload(DecoderError::RlpIsTooBig))
		);

		let typed = UncheckedTransactionEnvelope::EIP1559(eip1559(signature()));
		let mut encoded = typed.encode();
		encoded.extend_from_slice(&[0]);
		assert_eq!(
			UncheckedTransactionEnvelope::decode(&encoded),
			Err(EnvelopedDecoderError::Payload(DecoderError::RlpIsTooBig))
		);
	}

	#[test]
	fn blob_contract_creation_is_preserved_until_conversion() {
		let transaction = UncheckedEIP4844Transaction {
			chain_id: U256::one(),
			nonce: U256::zero(),
			max_priority_fee_per_gas: U256::one(),
			max_fee_per_gas: U256::from(2),
			gas_limit: U256::from(21_000),
			destination: TransactionAction::Create,
			value: U256::zero(),
			data: Vec::new(),
			access_list: Vec::new(),
			max_fee_per_blob_gas: U256::one(),
			blob_versioned_hashes: Vec::new(),
			signature: signature(),
		};
		let envelope = UncheckedTransactionEnvelope::EIP4844(transaction);
		let decoded = UncheckedTransactionEnvelope::decode(&envelope.encode()).unwrap();
		let UncheckedTransactionEnvelope::EIP4844(transaction) = decoded else {
			panic!("wrong transaction variant")
		};
		assert_eq!(
			EIP4844Transaction::try_from(transaction),
			Err(TransactionConversionError::EIP4844ContractCreation)
		);
	}

	#[test]
	fn invalid_authorization_reports_its_index() {
		let transaction = UncheckedEIP7702Transaction {
			chain_id: U256::one(),
			nonce: U256::zero(),
			max_priority_fee_per_gas: U256::one(),
			max_fee_per_gas: U256::from(2),
			gas_limit: U256::from(21_000),
			destination: TransactionAction::Call(Address::repeat_byte(0x11)),
			value: U256::zero(),
			data: Vec::new(),
			access_list: Vec::new(),
			authorization_list: alloc::vec![
				UncheckedAuthorizationListItem {
					chain_id: U256::one(),
					address: Address::repeat_byte(0x22),
					nonce: U256::zero(),
					signature: signature(),
				},
				UncheckedAuthorizationListItem {
					chain_id: U256::one(),
					address: Address::repeat_byte(0x33),
					nonce: U256::one(),
					signature: UncheckedTransactionSignature {
						odd_y_parity: U256::from(3),
						..signature()
					},
				},
			],
			signature: signature(),
		};

		assert_eq!(
			EIP7702Transaction::try_from(transaction),
			Err(TransactionConversionError::InvalidAuthorization {
				index: 1,
				error: AuthorizationConversionError::Signature(
					SignatureConversionError::InvalidParity(U256::from(3))
				),
			})
		);
	}

	#[test]
	fn eip7702_contract_creation_has_a_precise_error() {
		let transaction = UncheckedEIP7702Transaction {
			chain_id: U256::one(),
			nonce: U256::zero(),
			max_priority_fee_per_gas: U256::one(),
			max_fee_per_gas: U256::from(2),
			gas_limit: U256::from(21_000),
			destination: TransactionAction::Create,
			value: U256::zero(),
			data: Vec::new(),
			access_list: Vec::new(),
			authorization_list: Vec::new(),
			signature: signature(),
		};

		let error = EIP7702Transaction::try_from(transaction).unwrap_err();
		assert_eq!(error, TransactionConversionError::EIP7702ContractCreation);
		assert_eq!(
			error.to_string(),
			"EIP-7702 transactions cannot create contracts"
		);
	}

	#[test]
	fn oversized_chain_id_is_not_truncated() {
		let mut transaction = eip1559(signature());
		transaction.chain_id = U256::from(u64::MAX) + U256::one();
		assert_eq!(
			EIP1559Transaction::try_from(transaction),
			Err(TransactionConversionError::ChainIdOverflow(
				U256::from(u64::MAX) + U256::one()
			))
		);
	}
}
