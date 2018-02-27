use rlp::{self, Encodable, Decodable, RlpStream, DecoderError, UntrustedRlp};
use bigint::{Address, Gas, H256, U256, B256, H64, H2048};
use bloom::LogsBloom;
use trie_memory::FixedMemoryTrieMut;
use sha3::{Keccak256, Digest};
use std::collections::HashMap;
use super::{Header, Transaction, Receipt, SignaturePatch};

pub fn transactions_root(transactions: &[Transaction]) -> H256 {
    let mut trie = FixedMemoryTrieMut::default();
    for (i, transaction) in transactions.iter().enumerate() {
        trie.insert(&U256::from(i), transaction);
    }
    trie.root()
}

pub fn receipts_root(receipts: &[Receipt]) -> H256 {
    let mut trie = FixedMemoryTrieMut::default();
    for (i, receipt) in receipts.iter().enumerate() {
        trie.insert(&U256::from(i), receipt);
    }
    trie.root()
}

pub fn ommers_hash(ommers: &[Header]) -> H256 {
    let encoded = rlp::encode_list(ommers).to_vec();
    let hash = H256::from(Keccak256::digest(&encoded).as_slice());
    hash
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Block {
    pub header: Header,
    pub transactions: Vec<Transaction>,
    pub ommers: Vec<Header>,
}

impl Block {
    pub fn is_basic_valid(&self) -> bool {
        if transactions_root(&self.transactions) != self.header.transactions_root {
            return false;
        }

        if ommers_hash(&self.ommers) != self.header.ommers_hash {
            return false;
        }

        return true;
    }
}

impl Encodable for Block {
    fn rlp_append(&self, s: &mut RlpStream) {
        s.begin_list(3);
        s.append(&self.header);
        s.append_list(&self.transactions);
        s.append_list(&self.ommers);
    }
}

impl Decodable for Block {
    fn decode(rlp: &UntrustedRlp) -> Result<Self, DecoderError> {
        Ok(Self {
            header: rlp.val_at(0)?,
            transactions: rlp.list_at(1)?,
            ommers: rlp.list_at(2)?,
        })
    }
}

#[cfg(test)]
mod tests {
    use rlp::{encode, decode, Rlp};
    use hexutil::read_hex;
    use bigint::{U256, H256, Address, Gas};
    use bloom::LogsBloom;
    use block::Block;
    use TransactionAction;
    use transaction::GlobalSignaturePatch;
    use std::str::FromStr;

    #[test]
    fn block_53165_rlp() {
        let raw = read_hex("f9050df901ffa037ecbfd908ece3c54fa5b9f8e1b4a6089139da1dc4b5013a46c5818304de47b3a05cd40176209a61f3b26f3b5b491f177b93a3c33c595d0be75c26c97bdb60e7a294a50ec0d39fa913e62f1bae7074e6f36caa71855ba0a1b07a1f98248efee3d2111fcf9dcb2c1ad9f961a192e02571c0b55e7539b427a0f739c0f6d17bcad52552bfe3a4950885222ae694750135a75f452efc033d425da0b61bbed645e5b6366521a5c3bddb98d788067dc7a0f1515bfe4bdad0fb63b188b901000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000086016f2c8a34da82cfad8320f4018307a1208455c5e86b80a05fca8f6fce90e5f92549824d7b7d456cefafb92f223f97d60efee8e62522b9778870cee9238ebd5c31f8ecf8ea04850d9afee4208307a12094dc884e349103eaee4aef913d532cb5db2745f48b80b884de6f24bb0000000000000000000000008674c218f0351a62c3ba78c34fd2182a93da94e20000000000000000000000000000000000000000000000000000000000000040000000000000000000000000000000000000000000000000000000000000000568656c6c6f0000000000000000000000000000000000000000000000000000001ba04f2dfebd7c0f712119678fdd5ce6abc357a91df2284edafa5dc1c7503bb2d5c6a023b85af577d777b5cc5af8a4ece80bf45ae9f0be7b8e166a91271deb938b72aff9021af90217a059c53a8471fdc848352699052890b6156753a94743cfb4dc3f921df67e16978aa01dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d4934794f2d2aff1320476cb8c6b607199d23175cc595693a0bf6464bc0efe71b06723bf303cc661322eff513b247e714537d6593472ae76bea056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421a056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421b901000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000086016f2c8ff18c82cfab8320f404808455c5e84b9b476574682f76312e302e312f77696e646f77732f676f312e342e32a0fc0a1197dee6cf57a6d8afeaa1d070462638d484e1f71266b114b9cc5d5a5b0e88f48a42a38b85ccf0").unwrap();
        let block: Block = decode(&raw);
        assert_eq!(block.header.parent_hash, H256::from_str("37ecbfd908ece3c54fa5b9f8e1b4a6089139da1dc4b5013a46c5818304de47b3").unwrap());
        assert_eq!(block.transactions[0].action, TransactionAction::Call(Address::from_str("0xdc884e349103eaee4aef913d532cb5db2745f48b").unwrap()));
        assert_eq!(block.transactions[0].gas_limit, Gas::from(500000u64));
        assert_eq!(block.transactions[0].value, U256::zero());
        assert_eq!(block.ommers[0].parent_hash, H256::from_str("59c53a8471fdc848352699052890b6156753a94743cfb4dc3f921df67e16978a").unwrap());
        assert_eq!(block.ommers[0].beneficiary, Address::from_str("f2d2aff1320476cb8c6b607199d23175cc595693").unwrap());
        assert_eq!(block, decode(&encode(&block).to_vec()));

        let encoded = encode(&block).to_vec();
        assert_eq!(encoded, raw);
    }
}
