extern crate etcommon_bigint as bigint;
extern crate secp256k1;
#[macro_use]
extern crate lazy_static;
extern crate sha3;
extern crate digest;

use bigint::H256;
use digest::Digest;

lazy_static! {
	pub static ref SECP256K1: secp256k1::Secp256k1 = secp256k1::Secp256k1::new();
}

pub fn keccak256(data: &[u8]) -> H256 {
    use sha3::Keccak256;

    let mut hasher = Keccak256::new();
    hasher.input(data);
    let out = hasher.result().to_vec();

    H256::from(out.as_slice())
}
