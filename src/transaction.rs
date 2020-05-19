use core::ops::Deref;
use alloc::vec::Vec;
use rlp::{Rlp, DecoderError, RlpStream, Encodable, Decodable};
use ethereum_types::{H160, U256, H256};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "codec", derive(codec::Encode, codec::Decode))]
pub enum TransactionAction {
    Call(H160),
    Create,
}

impl Encodable for TransactionAction {
    fn rlp_append(&self, s: &mut RlpStream) {
        match self {
            &TransactionAction::Call(address) => {
                s.encoder().encode_value(&address[..]);
            },
            &TransactionAction::Create => {
                s.encoder().encode_value(&[])
            },
        }
    }
}

impl Decodable for TransactionAction {
    fn decode(rlp: &Rlp) -> Result<Self, DecoderError> {
        let action = if rlp.is_empty() {
            TransactionAction::Create
        } else {
            TransactionAction::Call(rlp.as_val()?)
        };

        Ok(action)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "codec", derive(codec::Encode, codec::Decode))]
pub struct TransactionRecoveryId(pub u64);

impl Deref for TransactionRecoveryId {
	type Target = u64;

	fn deref(&self) -> &u64 {
		&self.0
	}
}

impl TransactionRecoveryId {
	pub fn standard(&self) -> u8 {
		if self.0 == 27 || self.0 == 28 || self.0 > 36 {
			((self.0 - 1) % 2) as u8
		} else {
			4
		}
	}

	pub fn chain_id(&self) -> Option<u64> {
		if self.0 > 36 {
			Some((self.0 - 35) / 2)
		} else {
			None
		}
	}
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TransactionSignature {
    v: TransactionRecoveryId,
    r: H256,
    s: H256,
}

impl TransactionSignature {
	pub fn new(v: u64, r: H256, s: H256) -> Option<Self> {
		const LOWER: H256 = H256([0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
								  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
								  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
								  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01]);
		const UPPER: H256 = H256([0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
								  0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe,
								  0xba, 0xae, 0xdc, 0xe6, 0xaf, 0x48, 0xa0, 0x3b,
								  0xbf, 0xd2, 0x5e, 0x8c, 0xd0, 0x36, 0x41, 0x41]);

		let v = TransactionRecoveryId(v);
		let is_valid = v.standard() <= 1 &&
			r < UPPER && r >= LOWER &&
			s < UPPER && s >= LOWER;

		if is_valid {
			Some(Self { v, r, s })
		} else {
			None
		}
	}

	pub fn v(&self) -> u64 {
		self.v.0
	}

	pub fn standard_v(&self) -> u8 {
		self.v.standard()
	}

	pub fn chain_id(&self) -> Option<u64> {
		self.v.chain_id()
	}

	pub fn r(&self) -> &H256 {
		&self.r
	}

	pub fn s(&self) -> &H256 {
		&self.s
	}
}

#[cfg(feature = "codec")]
impl codec::Encode for TransactionSignature {
	fn size_hint(&self) -> usize {
		codec::Encode::size_hint(&(self.v.0, self.r, self.s))
	}

	fn using_encoded<R, F: FnOnce(&[u8]) -> R>(&self, f: F) -> R {
		codec::Encode::using_encoded(&(self.v.0, self.r, self.s), f)
	}
}

#[cfg(feature = "codec")]
impl codec::Decode for TransactionSignature {
	fn decode<I: codec::Input>(value: &mut I) -> Result<Self, codec::Error> {
		let (v, r, s) = codec::Decode::decode(value)?;
		match Self::new(v, r, s) {
			Some(signature) => Ok(signature),
			None => Err(codec::Error::from("Invalid signature")),
		}
	}
}

#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "codec", derive(codec::Encode, codec::Decode))]
pub struct Transaction {
    pub nonce: U256,
    pub gas_price: U256,
    pub gas_limit: U256,
    pub action: TransactionAction,
    pub value: U256,
    pub signature: TransactionSignature,
    pub input: Vec<u8>,
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
        s.append(&self.signature.v.0);
        s.append(&self.signature.r);
        s.append(&self.signature.s);
    }
}

impl Decodable for Transaction {
    fn decode(rlp: &Rlp) -> Result<Self, DecoderError> {
		let v = rlp.val_at(6)?;
		let r = rlp.val_at(7)?;
		let s = rlp.val_at(8)?;
		let signature = TransactionSignature::new(v, r, s)
			.ok_or(DecoderError::Custom("Invalid transaction signature format"))?;

        Ok(Self {
            nonce: rlp.val_at(0)?,
            gas_price: rlp.val_at(1)?,
            gas_limit: rlp.val_at(2)?,
            action: rlp.val_at(3)?,
            value: rlp.val_at(4)?,
            input: rlp.val_at(5)?,
            signature: signature,
        })
    }
}
