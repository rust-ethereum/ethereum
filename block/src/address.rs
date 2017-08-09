use secp256k1::{SECP256K1, Error};
use secp256k1::key::{PublicKey, SecretKey};
use bigint::{H256, Address};
use sha3::{Digest, Keccak256};

pub trait FromKey: Sized {
    fn from_public_key(key: &PublicKey) -> Self;
    fn from_secret_key(key: &SecretKey) -> Result<Self, Error>;
}

impl FromKey for Address {
    fn from_public_key(key: &PublicKey) -> Self {
        let hash = H256::from(
            Keccak256::digest(&key.serialize_vec(&SECP256K1, false)[1..]).as_slice());
        Address::from(hash)
    }

    fn from_secret_key(key: &SecretKey) -> Result<Self, Error> {
        let public_key = PublicKey::from_secret_key(&SECP256K1, key)?;
        Ok(Self::from_public_key(&public_key))
    }
}
