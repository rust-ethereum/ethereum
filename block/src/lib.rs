extern crate etcommon_bigint as bigint;

use bigint::U256;

pub struct BlockHeader {
    pub parent_hash: U256,
    pub ommers_hash: U256,

}