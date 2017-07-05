extern crate etcommon_bigint as bigint;

mod bytes;

use bytes::B256;
use bigint::{H256, H160, H2048, U256};

pub type LogsBloom = H2048;
pub type Address = H160;
pub type Gas = U256;

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
