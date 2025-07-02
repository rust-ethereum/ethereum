use alloc::vec::Vec;

use ethereum_types::H256;
use rlp::{DecoderError, Rlp, RlpStream};
use sha3::{Digest, Keccak256};

use crate::{
	enveloped::{EnvelopedDecodable, EnvelopedEncodable},
	header::{Header, PartialHeader},
	transaction::{TransactionAny, TransactionV0, TransactionV1, TransactionV2, TransactionV3},
	util::ordered_trie_root,
};

#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(
	feature = "with-scale",
	derive(scale_codec::Encode, scale_codec::Decode, scale_info::TypeInfo)
)]
#[cfg_attr(feature = "with-serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Block<T> {
	pub header: Header,
	pub transactions: Vec<T>,
	pub ommers: Vec<Header>,
}

impl<T: EnvelopedEncodable> rlp::Encodable for Block<T> {
	fn rlp_append(&self, s: &mut RlpStream) {
		s.begin_list(3);
		s.append(&self.header);
		s.append_list::<Vec<u8>, _>(
			&self
				.transactions
				.iter()
				.map(|tx| EnvelopedEncodable::encode(tx).to_vec())
				.collect::<Vec<_>>(),
		);
		s.append_list(&self.ommers);
	}
}

impl<T: EnvelopedDecodable> rlp::Decodable for Block<T> {
	fn decode(rlp: &Rlp) -> Result<Self, DecoderError> {
		Ok(Self {
			header: rlp.val_at(0)?,
			transactions: rlp
				.list_at::<Vec<u8>>(1)?
				.into_iter()
				.map(|raw_tx| {
					EnvelopedDecodable::decode(&raw_tx)
						.map_err(|_| DecoderError::Custom("decode enveloped transaction failed"))
				})
				.collect::<Result<Vec<_>, _>>()?,
			ommers: rlp.list_at(2)?,
		})
	}
}

impl<T: EnvelopedEncodable> Block<T> {
	pub fn new(partial_header: PartialHeader, transactions: Vec<T>, ommers: Vec<Header>) -> Self {
		let ommers_hash =
			H256::from_slice(Keccak256::digest(&rlp::encode_list(&ommers)[..]).as_slice());
		let transactions_root = ordered_trie_root(
			transactions
				.iter()
				.map(|r| EnvelopedEncodable::encode(r).freeze()),
		);

		Self {
			header: Header::new(partial_header, ommers_hash, transactions_root),
			transactions,
			ommers,
		}
	}
}

pub type BlockV0 = Block<TransactionV0>;
pub type BlockV1 = Block<TransactionV1>;
pub type BlockV2 = Block<TransactionV2>;
pub type BlockV3 = Block<TransactionV3>;
pub type BlockAny = Block<TransactionAny>;

impl<T> From<BlockV0> for Block<T>
where
	T: From<TransactionV0> + From<TransactionV1>,
{
	fn from(t: BlockV0) -> Self {
		Self {
			header: t.header,
			transactions: t.transactions.into_iter().map(|t| t.into()).collect(),
			ommers: t.ommers,
		}
	}
}

impl From<BlockV1> for BlockV2 {
	fn from(t: BlockV1) -> Self {
		Self {
			header: t.header,
			transactions: t.transactions.into_iter().map(|t| t.into()).collect(),
			ommers: t.ommers,
		}
	}
}

impl From<BlockV2> for BlockV3 {
	fn from(t: BlockV2) -> Self {
		Self {
			header: t.header,
			transactions: t.transactions.into_iter().map(|t| t.into()).collect(),
			ommers: t.ommers,
		}
	}
}

impl From<BlockV1> for BlockV3 {
	fn from(t: BlockV1) -> Self {
		Self {
			header: t.header,
			transactions: t.transactions.into_iter().map(|t| t.into()).collect(),
			ommers: t.ommers,
		}
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::transaction::{
		eip2930, eip7702::AuthorizationListItem, legacy::TransactionAction, EIP7702Transaction,
		TransactionV3,
	};
	use ethereum_types::{H160, H256, U256};

	const ONE: H256 = H256([
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
		0, 1,
	]);

	#[test]
	fn block_v3_with_eip7702_transaction() {
		// Create an EIP-7702 transaction
		let eip7702_tx = TransactionV3::EIP7702(EIP7702Transaction {
			chain_id: 1,
			nonce: U256::from(1),
			max_priority_fee_per_gas: U256::from(1_000_000_000),
			max_fee_per_gas: U256::from(2_000_000_000),
			gas_limit: U256::from(21000),
			destination: TransactionAction::Call(H160::zero()),
			value: U256::zero(),
			data: vec![],
			access_list: vec![],
			authorization_list: vec![AuthorizationListItem {
				chain_id: 1,
				address: H160::zero(),
				nonce: U256::zero(),
				signature: eip2930::MalleableTransactionSignature {
					odd_y_parity: false,
					r: ONE,
					s: ONE,
				},
			}],
			signature: eip2930::TransactionSignature::new(false, ONE, ONE).unwrap(),
		});

		// Create a block with the EIP-7702 transaction
		let partial_header = PartialHeader {
			parent_hash: H256::zero(),
			beneficiary: H160::zero(),
			state_root: H256::zero(),
			receipts_root: H256::zero(),
			logs_bloom: ethereum_types::Bloom::zero(),
			difficulty: U256::zero(),
			number: U256::zero(),
			gas_limit: U256::from(1_000_000),
			gas_used: U256::zero(),
			timestamp: 0,
			extra_data: vec![],
			mix_hash: H256::zero(),
			nonce: ethereum_types::H64::zero(),
		};

		let block = BlockV3::new(partial_header, vec![eip7702_tx.clone()], vec![]);

		// Verify the block can be encoded and decoded
		let encoded = rlp::encode(&block);
		let decoded: BlockV3 = rlp::decode(&encoded).unwrap();

		assert_eq!(block, decoded);
		assert_eq!(decoded.transactions.len(), 1);

		// Verify the transaction is preserved correctly
		match &decoded.transactions[0] {
			TransactionV3::EIP7702(tx) => {
				assert_eq!(tx.chain_id, 1);
				assert_eq!(tx.authorization_list.len(), 1);
			}
			_ => panic!("Expected EIP7702 transaction"),
		}
	}

	#[test]
	fn block_v2_to_v3_conversion() {
		use crate::transaction::{EIP1559Transaction, TransactionV2};

		// Create a BlockV2 with EIP1559 transaction
		let eip1559_tx = TransactionV2::EIP1559(EIP1559Transaction {
			chain_id: 1,
			nonce: U256::from(1),
			max_priority_fee_per_gas: U256::from(1_000_000_000),
			max_fee_per_gas: U256::from(2_000_000_000),
			gas_limit: U256::from(21000),
			action: TransactionAction::Call(H160::zero()),
			value: U256::zero(),
			input: vec![],
			access_list: vec![],
			signature: eip2930::TransactionSignature::new(false, ONE, ONE).unwrap(),
		});

		let partial_header = PartialHeader {
			parent_hash: H256::zero(),
			beneficiary: H160::zero(),
			state_root: H256::zero(),
			receipts_root: H256::zero(),
			logs_bloom: ethereum_types::Bloom::zero(),
			difficulty: U256::zero(),
			number: U256::zero(),
			gas_limit: U256::from(1_000_000),
			gas_used: U256::zero(),
			timestamp: 0,
			extra_data: vec![],
			mix_hash: H256::zero(),
			nonce: ethereum_types::H64::zero(),
		};

		let block_v2 = BlockV2::new(partial_header, vec![eip1559_tx], vec![]);
		let block_v3: BlockV3 = block_v2.into();

		// Verify conversion worked
		assert_eq!(block_v3.transactions.len(), 1);
		match &block_v3.transactions[0] {
			TransactionV3::EIP1559(_) => {} // Expected
			_ => panic!("Expected EIP1559 transaction in V3"),
		}
	}
}
