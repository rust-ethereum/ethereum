//! Log bloom implementation for Ethereum

extern crate bigint;
extern crate rlp;
#[cfg(test)]
extern crate hexutil;
extern crate sha3;

use std::ops::BitOr;
use bigint::H2048;
use sha3::{Digest, Keccak256};
use rlp::{Encodable, Decodable, RlpStream, DecoderError, UntrustedRlp};

/// A log bloom for Ethereum
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LogsBloom(H2048);

impl From<H2048> for LogsBloom {
    fn from(val: H2048) -> LogsBloom {
        LogsBloom(val)
    }
}

impl Into<H2048> for LogsBloom {
    fn into(self) -> H2048 {
        self.0
    }
}

impl Encodable for LogsBloom {
    fn rlp_append(&self, s: &mut RlpStream) {
        self.0.rlp_append(s);
    }
}

impl Decodable for LogsBloom {
    fn decode(rlp: &UntrustedRlp) -> Result<Self, DecoderError> {
        Ok(LogsBloom(H2048::decode(rlp)?))
    }
}

impl Default for LogsBloom {
    fn default() -> LogsBloom {
        LogsBloom(H2048::zero())
    }
}

impl BitOr for LogsBloom {
    type Output = LogsBloom;

    fn bitor(self, other: LogsBloom) -> LogsBloom {
        LogsBloom(self.0 | other.0)
    }
}

fn single_set(arr: &[u8]) -> H2048 {
    let mut r = H2048::zero();
    let h = Keccak256::digest(arr);
    for i in [0usize, 2usize, 4usize].iter() {
        let m = (((h[*i] as usize) << 8) + (h[*i + 1] as usize)) % 2048;
        r[m / 8] = r[m / 8] | (1 << (m % 8));
    }
    r
}

impl LogsBloom {
    /// Create a new log bloom
    pub fn new() -> LogsBloom {
        LogsBloom::default()
    }

    /// Set respective bits in the bloom with the array
    pub fn set(&mut self, arr: &[u8]) {
        self.0 = self.0 | single_set(arr);
    }

    /// Check that an array is in the bloom
    pub fn check(&self, arr: &[u8]) -> bool {
        let s = single_set(arr);
        self.0 & s == s
    }
}

#[cfg(test)]
mod tests {
    use super::LogsBloom;
    use bigint::H2048;
    use hexutil::read_hex;

    #[test]
    fn test_bloom() {
        let mut bloom = LogsBloom::new();
        bloom.set(&read_hex("0f572e5295c57f15886f9b263e2f6d2d6c7b5ec6").unwrap());
        assert!(bloom.check(&read_hex("0f572e5295c57f15886f9b263e2f6d2d6c7b5ec6").unwrap()));

        let h: H2048 = bloom.into();
        for i in [1323usize, 431usize, 1319usize].iter() {
            let v = 1 << (i % 8);
            assert!(h[i / 8] & v == v);
        }
    }
}
