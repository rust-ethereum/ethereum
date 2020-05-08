use alloc::vec::Vec;
use rlp_derive::{RlpEncodable, RlpDecodable};
use crate::{Header, Transaction};

#[derive(Clone, Debug, PartialEq, Eq, RlpEncodable, RlpDecodable)]
pub struct Block {
    pub header: Header,
    pub transactions: Vec<Transaction>,
    pub ommers: Vec<Header>,
}
