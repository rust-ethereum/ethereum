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

	/// Type Id of the transaction.
	fn type_id(&self) -> Option<u8>;

	/// Encode inner payload.
	fn encode_payload(&self) -> BytesMut;
}

/// Decodable typed transactions.
pub trait EnvelopedDecodable: Sized {
	/// Inner payload decoder error.
	type PayloadDecoderError;

	/// Decode raw bytes to a Self type.
	fn decode(bytes: &[u8]) -> Result<Self, EnvelopedDecoderError<Self::PayloadDecoderError>>;
}
