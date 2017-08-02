use rlp::{Encodable, Decodable, RlpStream, DecoderError, UntrustedRlp};
use bigint::{Address, Gas, H256, U256, B256, H64};
use bloom::LogsBloom;

use super::Log;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Receipt {
    pub state_root: H256,
    pub used_gas: Gas,
    pub logs_bloom: LogsBloom,
    pub logs: Vec<Log>,
}

impl Encodable for Receipt {
    fn rlp_append(&self, s: &mut RlpStream) {
        s.begin_list(4);
        s.append(&self.state_root);
        s.append(&self.used_gas);
        s.append(&self.logs_bloom);
        s.append_list(&self.logs);
    }
}

impl Decodable for Receipt {
    fn decode(rlp: &UntrustedRlp) -> Result<Self, DecoderError> {
        Ok(Self {
            state_root: rlp.val_at(0)?,
            used_gas: rlp.val_at(1)?,
            logs_bloom: rlp.val_at(2)?,
            logs: rlp.list_at(3)?,
        })
    }
}
