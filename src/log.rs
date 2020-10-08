use alloc::vec::Vec;
use ethereum_types::{H160, H256};
use rlp_derive::{RlpDecodable, RlpEncodable};

#[derive(Clone, Debug, PartialEq, Eq, RlpEncodable, RlpDecodable)]
#[cfg_attr(feature = "codec", derive(codec::Encode, codec::Decode))]
pub struct Log {
	pub address: H160,
	pub topics: Vec<H256>,
	pub data: Vec<u8>,
}
