extern crate bigint;
extern crate rlp;
extern crate bloom;
extern crate secp256k1;
extern crate sha3;
extern crate blockchain;
extern crate trie;
extern crate trie_memory;
extern crate block_core;
#[cfg(test)] extern crate hexutil;
#[cfg(test)] extern crate rand;

mod header;
mod transaction;
mod block;
mod receipt;
mod address;

pub use block_core::*;
pub use transaction::*;
pub use header::{TotalHeader, Header, HeaderHash};
pub use block::{Block, transactions_root, receipts_root, ommers_hash};
pub use receipt::Receipt;
pub use address::FromKey;

use bigint::H256;

pub trait RlpHash {
    fn rlp_hash(&self) -> H256;
}
