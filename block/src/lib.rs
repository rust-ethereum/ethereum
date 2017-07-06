extern crate etcommon_bigint as bigint;
extern crate etcommon_util as util;
extern crate etcommon_rlp as rlp;

use bigint::{Address, LogsBloom, Gas, H256, U256, B256};

pub struct BlockHeader {
    pub parent_hash: H256,
    pub ommers_hash: H256,
    pub beneficiary: Address,
    pub state_root: H256,
    pub transactions_root: H256,
    pub receipts_root: H256,
    pub logs_bloom: LogsBloom,
    pub difficulty: U256,
    pub number: U256,
    pub gas_limit: Gas,
    pub gas_used: Gas,
    pub timestamp: u64,
    pub extra_data: B256,
    pub mix_hash: H256,
    pub nonce: u64,
}
