use bytes::BytesMut;

/// DecoderError for typed transactions.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum EnvelopedDecoderError<T> {
	UnknownTypeId,
	Payload(T),
}

impl<T> From<T> for EnvelopedDecoderError<T> {
	fn from(e: T) -> Self {
		Self::Payload(e)
	}
}

/// Encodable typed transactions.
pub trait EnvelopedEncodable {
	/// Convert self to an owned vector.
	fn encode(&self) -> BytesMut {
		let type_id = self.type_id();

		let mut out = BytesMut::new();
		if let Some(type_id) = type_id {
			assert!(type_id <= 0x7f);
			out.extend_from_slice(&[type_id]);
		}

		out.extend_from_slice(&self.encode_payload()[..]);
		out
	}

	/// Returns the length of the encoded transaction.
	///
	/// This is the EIP-2718 encoded length: type_id (1 byte for typed txs) + RLP payload.
	/// Matches geth's `tx.Size()` and reth/alloy's `encoded_length()`.
	fn encoded_len(&self) -> usize {
		let type_id_len = if self.type_id().is_some() { 1 } else { 0 };
		type_id_len + self.payload_len()
	}

	/// Type Id of the transaction.
	fn type_id(&self) -> Option<u8>;

	/// Encode inner payload.
	fn encode_payload(&self) -> BytesMut;

	/// Returns the length of the RLP-encoded payload without the type byte.
	fn payload_len(&self) -> usize {
		self.encode_payload().len()
	}
}

/// Decodable typed transactions.
pub trait EnvelopedDecodable: Sized {
	/// Inner payload decoder error.
	type PayloadDecoderError;

	/// Decode raw bytes to a Self type.
	fn decode(bytes: &[u8]) -> Result<Self, EnvelopedDecoderError<Self::PayloadDecoderError>>;
}
