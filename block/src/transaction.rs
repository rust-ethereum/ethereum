use secp256k1::{Message, Error, RecoverableSignature, RecoveryId, SECP256K1};
use secp256k1::key::{PublicKey, SecretKey};
use rlp::{self, Encodable, Decodable, RlpStream, DecoderError, UntrustedRlp};
use bigint::{Address, Gas, H256, U256, B256};
use sha3::{Digest, Keccak256};
use address::FromKey;

const ECDSA_SIGNATURE_BYTES: usize = 65;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TransactionSignature {
    pub v: u8,
    pub r: H256,
    pub s: H256,
}

impl TransactionSignature {
    pub fn standard_v(&self) -> u8 {
        let v = self.v;
        if v == 27 || v == 28 || v > 36 {
            ((v - 1) % 2) as u8
        } else {
            4
        }
    }

    pub fn into_recoverable_signature(self) -> Result<RecoverableSignature, Error> {
        let mut sig = [0u8; 64];
        sig[0..32].copy_from_slice(&self.r);
        sig[32..64].copy_from_slice(&self.s);

        RecoverableSignature::from_compact(&SECP256K1, &sig, RecoveryId::from_i32(self.standard_v() as i32)?)
    }
}

// Use transaction action so we can keep most of the common fields
// without creating a large enum.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TransactionAction {
    Call(Address),
    Create,
}

impl Encodable for TransactionAction {
    fn rlp_append(&self, s: &mut RlpStream) {
        match self {
            &TransactionAction::Call(address) => {
                s.encoder().encode_value(&address);
            },
            &TransactionAction::Create => {
                s.encoder().encode_value(&[])
            },
        }
    }
}

impl Decodable for TransactionAction {
    fn decode(rlp: &UntrustedRlp) -> Result<Self, DecoderError> {
        Ok(if rlp.is_empty() {
            TransactionAction::Create
        } else {
            TransactionAction::Call(rlp.as_val()?)
        })
    }
}

pub struct UnsignedTransaction {
    pub nonce: U256,
    pub gas_price: Gas,
    pub gas_limit: Gas,
    pub action: TransactionAction,
    pub value: U256,
    pub input: Vec<u8>,
    pub network_id: Option<u8>,
}

impl UnsignedTransaction {
    pub fn sign(self, key: &SecretKey) -> Transaction {
        let hash = H256::from(Keccak256::digest(&rlp::encode(&self).to_vec()).as_slice());
        // hash is always MESSAGE_SIZE bytes.
        let msg = Message::from_slice(&hash).unwrap();

        // SecretKey and Message are always valid.
        let s = SECP256K1.sign_recoverable(&msg, key).unwrap();
        let (rid, sig) = s.serialize_compact(&SECP256K1);

        let sig = TransactionSignature {
            v: (rid.to_i32() + if let Some(n) = self.network_id { (35 + n * 2) as i32 } else { 27 }) as u8,
            r: H256::from(&sig[0..32]),
            s: H256::from(&sig[32..64]),
        };

        Transaction {
            nonce: self.nonce,
            gas_price: self.gas_price,
            gas_limit: self.gas_limit,
            action: self.action,
            value: self.value,
            input: self.input,
            signature: sig,
        }
    }
}

impl Encodable for UnsignedTransaction {
    fn rlp_append(&self, s: &mut RlpStream) {
        s.begin_list(if self.network_id.is_some() { 9 } else { 6 });
        s.append(&self.nonce);
        s.append(&self.gas_price);
        s.append(&self.gas_limit);
        s.append(&self.action);
        s.append(&self.value);
        s.append(&self.input);

        if let Some(network_id) = self.network_id {
            s.append(&network_id);
            s.append(&0u8);
            s.append(&0u8);
        }
    }
}

impl From<Transaction> for UnsignedTransaction {
    fn from(val: Transaction) -> UnsignedTransaction {
        UnsignedTransaction {
            network_id: val.network_id(),
            nonce: val.nonce,
            gas_price: val.gas_price,
            gas_limit: val.gas_limit,
            action: val.action,
            value: val.value,
            input: val.input,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Transaction {
    pub nonce: U256,
    pub gas_price: Gas,
    pub gas_limit: Gas,
    pub action: TransactionAction,
    pub value: U256,
    pub signature: TransactionSignature,
    pub input: Vec<u8>, // The input data, either data or init, depending on TransactionAction.
}

impl Transaction {
    pub fn caller(&self) -> Result<Address, Error> {
        let hash = H256::from(Keccak256::digest(&rlp::encode(&UnsignedTransaction::from(self.clone())).to_vec()).as_slice());
        let sig = self.signature.clone().into_recoverable_signature()?;
        let public_key = SECP256K1.recover(&Message::from_slice(&hash).unwrap(), &sig)?;

        Ok(Address::from_public_key(&public_key))
    }

    pub fn network_id(&self) -> Option<u8> {
        if self.signature.v > 36 {
            Some((self.signature.v - 35) / 2)
        } else {
            None
        }
    }
}

impl Encodable for Transaction {
    fn rlp_append(&self, s: &mut RlpStream) {
        s.begin_list(9);
        s.append(&self.nonce);
        s.append(&self.gas_price);
        s.append(&self.gas_limit);
        s.append(&self.action);
        s.append(&self.value);
        s.append(&self.input);
        s.append(&self.signature.v);
        s.append(&self.signature.r);
        s.append(&self.signature.s);
    }
}

impl Decodable for Transaction {
    fn decode(rlp: &UntrustedRlp) -> Result<Self, DecoderError> {
        Ok(Self {
            nonce: rlp.val_at(0)?,
            gas_price: rlp.val_at(1)?,
            gas_limit: rlp.val_at(2)?,
            action: rlp.val_at(3)?,
            value: rlp.val_at(4)?,
            input: rlp.val_at(5)?,
            signature: TransactionSignature {
                v: rlp.val_at(6)?,
                r: rlp.val_at(7)?,
                s: rlp.val_at(8)?,
            },
        })
    }
}

#[cfg(test)]
mod tests {
    use secp256k1::{Message, Error, RecoverableSignature, RecoveryId, SECP256K1};
    use secp256k1::key::{PublicKey, SecretKey};
    use rlp::{self, Encodable, Decodable, RlpStream, DecoderError, UntrustedRlp};
    use bigint::{Address, Gas, H256, U256, B256};
    use sha3::{Digest, Keccak256};
    use address::FromKey;
    use rand::os::OsRng;
    use super::{Transaction, UnsignedTransaction, TransactionAction};

    #[test]
    pub fn should_recover_address() {
        let mut rng = OsRng::new().unwrap();
        let secret_key = SecretKey::new(&SECP256K1, &mut rng);
        let address = Address::from_secret_key(&secret_key);

        let unsigned = UnsignedTransaction {
            nonce: U256::zero(),
            gas_price: Gas::zero(),
            gas_limit: Gas::zero(),
            action: TransactionAction::Create,
            value: U256::zero(),
            input: Vec::new(),
            network_id: Some(61),
        };
        let signed = unsigned.sign(&secret_key);

        assert_eq!(signed.network_id(), Some(61));
        assert_eq!(signed.caller(), address);
    }
}
