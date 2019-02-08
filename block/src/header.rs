use rlp::{self, Encodable, Decodable, RlpStream, DecoderError, UntrustedRlp};
use bigint::{Address, Gas, H256, U256, B256, H64};
use bloom::LogsBloom;
use std::cmp::Ordering;
use sha3::{Keccak256, Digest};
use super::RlpHash;

pub use blockchain::chain::HeaderHash;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TotalHeader(pub Header, U256);

impl TotalHeader {
    pub fn from_genesis(header: Header) -> TotalHeader {
        let diff = header.difficulty;
        TotalHeader(header, diff)
    }

    pub fn from_parent(header: Header, parent: &TotalHeader) -> TotalHeader {
        let diff = header.difficulty + parent.1;
        TotalHeader(header, diff)
    }

    pub fn total_difficulty(&self) -> U256 {
        self.1
    }
}

impl HeaderHash<H256> for TotalHeader {
    fn parent_hash(&self) -> Option<H256> {
        self.0.parent_hash()
    }

    fn header_hash(&self) -> H256 {
        self.0.header_hash()
    }
}

impl Into<Header> for TotalHeader {
    fn into(self) -> Header {
        self.0
    }
}

impl Ord for TotalHeader {
    fn cmp(&self, other: &TotalHeader) -> Ordering {
        self.1.cmp(&other.1)
    }
}

impl PartialOrd for TotalHeader {
    fn partial_cmp(&self, other: &TotalHeader) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Header {
    pub parent_hash: H256,
    pub ommers_hash: H256,
    pub beneficiary: Address,
    pub state_root: H256,
    pub transactions_root: H256,
    pub receipts_root: H256,
    pub logs_bloom: LogsBloom,
    pub difficulty: U256,
    pub number: U256,
    pub gas_limit: Gas,
    pub gas_used: Gas,
    pub timestamp: u64,
    pub extra_data: B256,
    pub mix_hash: H256,
    pub nonce: H64,
}

impl HeaderHash<H256> for Header {
    fn parent_hash(&self) -> Option<H256> {
        if self.number == U256::zero() {
            None
        } else {
            Some(self.parent_hash)
        }
    }

    fn header_hash(&self) -> H256 {
        H256::from(Keccak256::digest(&rlp::encode(self).to_vec()).as_slice())
    }
}

impl Header {
    pub fn partial_rlp_append(&self, s: &mut RlpStream) {
        s.begin_list(13);
        s.append(&self.parent_hash);
        s.append(&self.ommers_hash);
        s.append(&self.beneficiary);
        s.append(&self.state_root);
        s.append(&self.transactions_root);
        s.append(&self.receipts_root);
        s.append(&self.logs_bloom);
        s.append(&self.difficulty);
        s.append(&self.number);
        s.append(&self.gas_limit);
        s.append(&self.gas_used);
        s.append(&self.timestamp);
        s.append(&self.extra_data);
    }

    pub fn partial_hash(&self) -> H256 {
        let mut stream = RlpStream::new();
        self.partial_rlp_append(&mut stream);
        H256::from(Keccak256::digest(&stream.drain()).as_slice())
    }
}

impl Encodable for Header {
    fn rlp_append(&self, s: &mut RlpStream) {
        s.begin_list(15);
        s.append(&self.parent_hash);
        s.append(&self.ommers_hash);
        s.append(&self.beneficiary);
        s.append(&self.state_root);
        s.append(&self.transactions_root);
        s.append(&self.receipts_root);
        s.append(&self.logs_bloom);
        s.append(&self.difficulty);
        s.append(&self.number);
        s.append(&self.gas_limit);
        s.append(&self.gas_used);
        s.append(&self.timestamp);
        s.append(&self.extra_data);
        s.append(&self.mix_hash);
        s.append(&self.nonce);
    }
}

impl Decodable for Header {
    fn decode(rlp: &UntrustedRlp) -> Result<Self, DecoderError> {
        Ok(Self {
            parent_hash: rlp.val_at(0)?,
            ommers_hash: rlp.val_at(1)?,
            beneficiary: rlp.val_at(2)?,
            state_root: rlp.val_at(3)?,
            transactions_root: rlp.val_at(4)?,
            receipts_root: rlp.val_at(5)?,
            logs_bloom: rlp.val_at(6)?,
            difficulty: rlp.val_at(7)?,
            number: rlp.val_at(8)?,
            gas_limit: rlp.val_at(9)?,
            gas_used: rlp.val_at(10)?,
            timestamp: rlp.val_at(11)?,
            extra_data: rlp.val_at(12)?,
            mix_hash: rlp.val_at(13)?,
            nonce: rlp.val_at(14)?,
        })
    }
}

impl RlpHash for Header {
    fn rlp_hash(&self) -> H256 {
        H256::from(Keccak256::digest(&rlp::encode(self)).as_slice())
    }
}

#[cfg(test)]
mod tests {
    use rlp::{encode, decode, Rlp};
    use hexutil::read_hex;
    use bigint::{U256, H256, Address, Gas};
    use bloom::LogsBloom;
    use header::Header;
    use std::str::FromStr;

    #[test]
    fn block_0_rlp() {
        let raw = read_hex("f90219f90214a00000000000000000000000000000000000000000000000000000000000000000a01dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347940000000000000000000000000000000000000000a0d7f8974fb5ac78d9ac099b9ad5018bedc2ce0a72dad1827a1709da30580f0544a056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421a056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421b9010000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000850400000000808213888080a011bbe8db4e347b4e8c937c1c8370e4b5ed33adb3db69cbdb7a38e1e50b1b82faa00000000000000000000000000000000000000000000000000000000000000000880000000000000042c0c0").unwrap();
        let block_raw = Rlp::new(&raw);
        let block: Header = block_raw.val_at(0);
        assert_eq!(block.number, U256::from(0u64));

        let encoded = encode(&block).to_vec();
        let encoded_ref: &[u8] = encoded.as_ref();
        assert_eq!(encoded_ref, block_raw.at(0).as_raw());
    }

    #[test]
    fn block_1_rlp() {
        let raw = read_hex("f90216f90211a0d4e56740f876aef8c010b86a40d5f56745a118d0906a34e69aec8c0db1cb8fa3a01dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d493479405a56e2d52c817161883f50c441c3228cfe54d9fa0d67e4d450343046425ae4271474353857ab860dbc0a1dde64b41b5cd3a532bf3a056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421a056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421b90100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000008503ff80000001821388808455ba422499476574682f76312e302e302f6c696e75782f676f312e342e32a0969b900de27b6ac6a67742365dd65f55a0526c41fd18e1b16f1a1215c2e66f5988539bd4979fef1ec4c0c0").unwrap();
        let block_raw = Rlp::new(&raw);
        let block: Header = block_raw.val_at(0);
        assert_eq!(block.parent_hash, H256::from_str("d4e56740f876aef8c010b86a40d5f56745a118d0906a34e69aec8c0db1cb8fa3").unwrap());
        assert_eq!(block.ommers_hash, H256::from_str("1dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347").unwrap());
        assert_eq!(block.beneficiary, Address::from_str("05a56e2d52c817161883f50c441c3228cfe54d9f").unwrap());
        assert_eq!(block.state_root, H256::from_str("d67e4d450343046425ae4271474353857ab860dbc0a1dde64b41b5cd3a532bf3").unwrap());
        assert_eq!(block.transactions_root, H256::from_str("56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421").unwrap());
        assert_eq!(block.logs_bloom, LogsBloom::default());
        assert_eq!(block.difficulty, U256::from(17171480576u64));
        assert_eq!(block.number, U256::from(1u64));
        assert_eq!(block.gas_limit, Gas::from(5000u64));
        assert_eq!(block.gas_used, Gas::zero());
        assert_eq!(block.timestamp, 1438269988u64);
        assert_eq!(block, decode(&encode(&block).to_vec()));

        let encoded = encode(&block).to_vec();
        let encoded_ref: &[u8] = encoded.as_ref();
        assert_eq!(encoded_ref, block_raw.at(0).as_raw());
    }
}
