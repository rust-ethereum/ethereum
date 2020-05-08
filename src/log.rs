use alloc::vec::Vec;
use rlp_derive::{RlpEncodable, RlpDecodable};
use ethereum_types::{H160, H256};

#[derive(Clone, Debug, PartialEq, Eq, RlpEncodable, RlpDecodable)]
pub struct Log {
    pub address: H160,
    pub topics: Vec<H256>,
    pub data: Vec<u8>,
}
