#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

mod account;
mod block;
mod header;
mod log;
mod receipt;
mod transaction;
pub mod util;

// Alias for `Vec<u8>`. This type alias is necessary for rlp-derive to work correctly.
type Bytes = alloc::vec::Vec<u8>;

pub use account::Account;
pub use block::*;
pub use header::{Header, PartialHeader};
pub use log::Log;
pub use receipt::Receipt;
pub use transaction::*;
