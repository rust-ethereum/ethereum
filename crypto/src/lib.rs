extern crate secp256k1;
#[macro_use]
extern crate lazy_static;

lazy_static! {
	pub static ref SECP256K1: secp256k1::Secp256k1 = secp256k1::Secp256k1::new();
}
