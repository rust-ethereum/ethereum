use alloc::vec::Vec;
use ethereum_types::{H256, U256, Bloom};
use rlp_derive::{RlpEncodable, RlpDecodable};
use crate::Log;

#[derive(Clone, Debug, PartialEq, Eq, RlpEncodable, RlpDecodable)]
#[cfg_attr(feature = "codec", derive(codec::Encode, codec::Decode))]
pub struct Receipt {
    pub state_root: H256,
    pub used_gas: U256,
    pub logs_bloom: Bloom,
    pub logs: Vec<Log>,
}
