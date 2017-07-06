use rlp::{Encodable, Decodable, RlpStream, DecoderError, UntrustedRlp};

/// Maximum 256-bit byte-array that does not require heap allocation.
pub struct B256(usize, [u8; 32]);

impl Encodable for B256 {
    fn rlp_append(&self, s: &mut RlpStream) {
        s.encoder().encode_value(&self.1[0..self.0])
    }
}

impl Decodable for B256 {
    fn decode(rlp: &UntrustedRlp) -> Result<Self, DecoderError> {
        rlp.decoder().decode_value(|bytes| {
            if bytes.len() > 32 {
                Err(DecoderError::Custom("More than 32 bytes"))
            } else {
                let mut ret = B256(0, [0u8; 32]);
                ret.0 = bytes.len();
                for i in 0..bytes.len() {
                    ret.1[i] = bytes[i];
                }
                Ok(ret)
            }
        })
    }
}
