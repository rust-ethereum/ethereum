#![cfg_attr(asm_available, feature(asm))]

extern crate etcommon_rlp as rlp;
extern crate etcommon_util as util;
extern crate rand;
extern crate libc;
extern crate byteorder;
#[macro_use] extern crate heapsize;

mod m256;
mod mi256;
mod uint;
mod hash;

pub use self::uint::{U128, U256, U512};
pub use self::m256::M256;
pub use self::mi256::MI256;
pub use self::hash::{H32, H64, H128, H160, H256, H264, H512, H520, H1024, H2048};

#[derive(Eq, PartialEq, Debug, Copy, Clone, Hash)]
/// Sign of an integer.
pub enum Sign {
    Minus,
    NoSign,
    Plus,
}
