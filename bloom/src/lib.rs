//! Log bloom implementation for Ethereum

extern crate etcommon_bigint as bigint;
extern crate etcommon_crypto as crypto;
extern crate etcommon_util;

use bigint::H2048;
use crypto::keccak256;

/// A log bloom for Ethereum
pub struct Bloom(H2048);

impl From<H2048> for Bloom {
    fn from(val: H2048) -> Bloom {
        Bloom(val)
    }
}

impl Into<H2048> for Bloom {
    fn into(self) -> H2048 {
        self.0
    }
}

impl Default for Bloom {
    fn default() -> Bloom {
        Bloom(H2048::zero())
    }
}

fn single_set(arr: &[u8]) -> H2048 {
    let mut r = H2048::zero();
    let h = keccak256(arr);
    for i in [0usize, 2usize, 4usize].iter() {
        let m = (((h[*i] as usize) << 8) + (h[*i + 1] as usize)) % 2048;
        r[m / 8] = r[m / 8] | (1 << (m % 8));
    }
    r
}

impl Bloom {
    /// Create a new log bloom
    pub fn new() -> Bloom {
        Bloom::default()
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
    use super::Bloom;
    use bigint::H2048;
    use etcommon_util::read_hex;

    #[test]
    fn test_bloom() {
        let mut bloom = Bloom::new();
        bloom.set(&read_hex("0f572e5295c57f15886f9b263e2f6d2d6c7b5ec6").unwrap());
        assert!(bloom.check(&read_hex("0f572e5295c57f15886f9b263e2f6d2d6c7b5ec6").unwrap()));

        let h: H2048 = bloom.into();
        for i in [1323usize, 431usize, 1319usize].iter() {
            let v = 1 << (i % 8);
            assert!(h[i / 8] & v == v);
        }
    }
}
