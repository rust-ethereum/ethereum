#![cfg_attr(not(feature = "std"), no_std)]

#[cfg(not(feature = "std"))]
extern crate alloc;

mod account;
mod block;
mod enveloped;
mod header;
mod log;
mod receipt;
mod transaction;
pub mod util;

// Alias for `Vec<u8>`. This type alias is necessary for rlp-derive to work correctly.
#[cfg(not(feature = "std"))]
type Bytes = alloc::vec::Vec<u8>;
#[cfg(feature = "std")]
type Bytes = Vec<u8>;

pub use crate::account::Account;
pub use crate::block::*;
pub use crate::enveloped::*;
pub use crate::header::{Header, PartialHeader};
pub use crate::log::Log;
pub use crate::receipt::*;
pub use crate::transaction::*;
