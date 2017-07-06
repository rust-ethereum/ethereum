/// Maximum 256-bit byte-array that does not require heap allocation.
pub struct B256(usize, [u8; 32]);
