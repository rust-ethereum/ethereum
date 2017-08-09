pub extern crate bigint;
pub extern crate rlp;
pub extern crate hexutil;
pub extern crate block;
pub extern crate bloom;
pub extern crate trie;

extern crate blockchain;

use bigint::H256;
use block::{Block, Receipt, Transaction};
use trie::MemoryTrie;
use std::marker::PhantomData;

pub struct EthereumDefinition<C, T> {
    consensus: PhantomData<C>,
    transition_rule: PhantomData<T>
}

impl<C: blockchain::Consensus<Block=Block, Extra=Receipt>,
     T: blockchain::TransitionRule<Transaction=Transaction, Extra=Receipt, WorldState=MemoryTrie>>
    blockchain::Definition
    for EthereumDefinition<C, T>
{
    type Transaction = Transaction;
    type Extra = Receipt;
    type Hash = H256;
    type WorldState = MemoryTrie;
    type Block = Block;
    type TransitionRule = T;
    type Consensus = C;
}
