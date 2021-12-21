use crate::Log;
use alloc::vec::Vec;
use ethereum_types::{Bloom, H256, U256, U64};
use rlp_derive::{RlpDecodable, RlpEncodable};

#[derive(Clone, Debug, PartialEq, Eq, RlpEncodable, RlpDecodable)]
#[cfg_attr(
	feature = "with-codec",
	derive(codec::Encode, codec::Decode, scale_info::TypeInfo)
)]
#[cfg_attr(feature = "with-serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Receipt {
	pub state_root: H256,
	pub used_gas: U256,
	pub logs_bloom: Bloom,
	pub logs: Vec<Log>,
}

pub struct EncodeableReceipt<'a> {
	pub transaction_type: u8,
	pub status: U64,
	pub cumulative_gas_used: U256,
	pub bloom: Bloom,
	pub logs: &'a Vec<Log>,
}

impl<'a> rlp::Encodable for EncodeableReceipt<'a> {
	fn rlp_append(&self, s: &mut rlp::RlpStream) {
		if self.transaction_type == 0 {
			// Legacy
			s.begin_list(4);
			s.append(&self.status);
			s.append(&self.cumulative_gas_used);
			s.append(&self.bloom);
			s.append_list(self.logs);
		} else {
			// Typed transactions are prepended with the envelope byte
			s.begin_list(5);
			s.append(&self.transaction_type);
			s.append(&self.status);
			s.append(&self.cumulative_gas_used);
			s.append(&self.bloom);
			s.append_list(self.logs);
		}
	}
}
