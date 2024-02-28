use ethereum_types::{H256, U256};

#[derive(Clone, Debug, PartialEq, Eq)]
#[derive(rlp::RlpEncodable, rlp::RlpDecodable)]
#[cfg_attr(
	feature = "with-scale",
	derive(scale_codec::Encode, scale_codec::Decode, scale_info::TypeInfo)
)]
#[cfg_attr(feature = "with-serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Account {
	pub nonce: U256,
	pub balance: U256,
	pub storage_root: H256,
	pub code_hash: H256,
}
