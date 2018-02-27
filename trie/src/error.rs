use bigint::H256;

#[derive(Debug)]
pub enum Error {
    Require(H256),
}
