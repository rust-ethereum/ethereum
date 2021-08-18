use crate::Log;
use alloc::vec::Vec;
use ethereum_types::{Bloom, U256};
use rlp_derive::{RlpDecodable, RlpEncodable};

#[derive(Clone, Debug, PartialEq, Eq, RlpEncodable, RlpDecodable)]
#[cfg_attr(feature = "with-codec", derive(codec::Encode, codec::Decode))]
#[cfg_attr(feature = "with-serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Receipt {
	pub state_root: U256,
	pub used_gas: U256,
	pub logs_bloom: Bloom,
	pub logs: Vec<Log>,
}
