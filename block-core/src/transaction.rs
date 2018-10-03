use rlp::{UntrustedRlp, DecoderError, RlpStream, Encodable, Decodable};
use bigint::{Address, U256, M256, H256};
use sha3::{Digest, Keccak256};

#[cfg(not(feature = "std"))] use alloc::vec::Vec;
#[cfg(not(feature = "std"))] use alloc::rc::Rc;
#[cfg(feature = "std")] use std::rc::Rc;

// Use transaction action so we can keep most of the common fields
// without creating a large enum.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TransactionAction {
    Call(Address),
    Create,
    Create2(H256, Rc<Vec<u8>>),
}

impl TransactionAction {
    pub fn address(&self, caller: Address, nonce: U256) -> Address {
        match self {
            &TransactionAction::Call(address) => address,
            &TransactionAction::Create => {
                let mut rlp = RlpStream::new_list(2);
                rlp.append(&caller);
                rlp.append(&nonce);

                Address::from(M256::from(Keccak256::digest(rlp.out().as_slice()).as_slice()))
            },
            &TransactionAction::Create2(salt, ref code) => {
                let mut digest = Keccak256::new();
                digest.input(&[0xff]);
                digest.input(&caller);
                digest.input(&salt);
                digest.input(code);
                let hash = digest.result();
                Address::from(M256::from(&hash[12..]))
            }
        }
    }
}

const CREATE2_TAG: u8 = 0xc2;

impl Encodable for TransactionAction {
    fn rlp_append(&self, s: &mut RlpStream) {
        match self {
            &TransactionAction::Call(address) => {
                s.encoder().encode_value(&address);
            },
            &TransactionAction::Create => {
                s.encoder().encode_value(&[])
            },
            &TransactionAction::Create2(salt, ref code) => {
                s.begin_list(3)
                    .append(&CREATE2_TAG)
                    .append(&salt)
                    .append(code.as_ref());
            }
        }
    }
}

impl Decodable for TransactionAction {
    fn decode(rlp: &UntrustedRlp) -> Result<Self, DecoderError> {
        let action = if rlp.is_empty() {
            TransactionAction::Create
        } else if let Ok(CREATE2_TAG) = rlp.val_at(0) {
            let (salt, code) = (rlp.val_at(1)?, rlp.val_at(2)?);
            TransactionAction::Create2(salt, Rc::new(code))
        } else {
            TransactionAction::Call(rlp.as_val()?)
        };

        Ok(action)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rlp;

    #[test]
    fn rlp_roundtrip_call() {
        let address = Address::from(M256::from(0xDEADBEEFDEADBEEFDEADBEEF_u64));
        let action = TransactionAction::Call(address);
        let encoded = rlp::encode(&action);
        let decoded: TransactionAction = rlp::decode(&encoded);
        assert_eq!(action, decoded);
    }

    #[test]
    fn rlp_roundtrip_create() {
        let action = TransactionAction::Create;
        let encoded = rlp::encode(&action);
        let decoded: TransactionAction = rlp::decode(&encoded);
        assert_eq!(action, decoded);
    }

    #[test]
    fn rlp_roundtrip_create2() {
        let salt = H256::from(M256::from(0xDEADBEEF));
        let code = Rc::new(vec![1, 2, 3, 4, 5, 6, 7, 8, 9]);
        let action = TransactionAction::Create2(salt, code);
        let encoded = rlp::encode(&action);
        let decoded: TransactionAction = rlp::decode(&encoded);
        assert_eq!(action, decoded);
    }
}
