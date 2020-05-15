use rlp_derive::{RlpEncodable, RlpDecodable};
use ethereum_types::{H160, H256, H64, U256, Bloom};

#[derive(Clone, Debug, PartialEq, Eq, RlpEncodable, RlpDecodable)]
#[cfg_attr(feature = "codec", derive(codec::Encode, codec::Decode))]
pub struct Header {
    pub parent_hash: H256,
    pub ommers_hash: H256,
    pub beneficiary: H160,
    pub state_root: H256,
    pub transactions_root: H256,
    pub receipts_root: H256,
    pub logs_bloom: Bloom,
    pub difficulty: U256,
    pub number: U256,
    pub gas_limit: U256,
    pub gas_used: U256,
    pub timestamp: u64,
    pub extra_data: H256,
    pub mix_hash: H256,
    pub nonce: H64,
}
