extern crate blockchain;
extern crate etcommon;
extern crate sputnikvm;
extern crate secp256k1;
extern crate rand;
extern crate sha3;

use etcommon::EthereumDefinition;
use etcommon::block::{Receipt, Block, UnsignedTransaction, Transaction, TransactionAction, Log, FromKey, Header, Account};
use etcommon::trie::{empty_trie_hash, MemoryTrie};
use etcommon::bigint::{H256, M256, U256, H64, B256, Gas, Address};
use etcommon::bloom::LogsBloom;
use etcommon::rlp;
use sputnikvm::vm::{self, VM};
use secp256k1::SECP256K1;
use secp256k1::key::{PublicKey, SecretKey};
use std::time::Duration;
use std::thread;
use std::collections::HashMap;
use std::str::FromStr;
use rand::os::OsRng;
use sha3::{Keccak256, Digest};

pub struct EthereumTransitionRule;

impl blockchain::TransitionRule for EthereumTransitionRule {
    type Block = Block;
    type Transaction = Transaction;
    type Extra = Receipt;
    type WorldState = MemoryTrie;

    fn transit(
        current_block: &Block,
        transaction: &Transaction,
        state: &MemoryTrie
    ) -> (MemoryTrie, Receipt) {
        let mut state = state.clone();
        let transaction_cloned = transaction.clone();

        let transaction = match transaction.action.clone() {
            TransactionAction::Create => {
                vm::Transaction::ContractCreation {
                    caller: transaction_cloned.caller().unwrap(),
                    gas_price: transaction_cloned.gas_price,
                    gas_limit: transaction_cloned.gas_limit,
                    value: transaction_cloned.value,
                    init: transaction_cloned.input,
                }
            },
            TransactionAction::Call(addr) => {
                vm::Transaction::MessageCall {
                    address: addr,
                    caller: transaction_cloned.caller().unwrap(),
                    gas_price: transaction_cloned.gas_price,
                    gas_limit: transaction_cloned.gas_limit,
                    value: transaction_cloned.value,
                    data: transaction_cloned.input,
                }
            },
        };

        let header = vm::BlockHeader {
            coinbase: current_block.header.beneficiary,
            timestamp: M256::from(current_block.header.timestamp),
            number: M256::from(current_block.header.number),
            difficulty: M256::from(current_block.header.difficulty),
            gas_limit: current_block.header.gas_limit,
        };

        let mut vm = vm::SeqTransactionVM::new(transaction, header, &vm::EIP160_PATCH);

        loop {
            match vm.fire() {
                Ok(()) => break,
                Err(vm::errors::RequireError::Account(addr)) => {
                    println!("Requiring account {:?}", addr);

                    let account_rlp = state.get(addr.as_ref());
                    if account_rlp.is_none() {
                        vm.commit_account(vm::AccountCommitment::Nonexist(addr)).unwrap();;
                    } else {
                        let account_rlp = account_rlp.unwrap();
                        let account: Account = rlp::decode(&account_rlp);
                        let code = state.get(account.code_hash.as_ref());

                        vm.commit_account(vm::AccountCommitment::Full {
                            nonce: account.nonce.into(),
                            address: addr,
                            balance: account.balance,
                            code: code.unwrap_or(Vec::new()),
                        }).unwrap();
                    }
                },
                Err(vm::errors::RequireError::AccountCode(addr)) => {
                    println!("Requiring account code {:?}", addr);

                    let account_rlp = state.get(addr.as_ref());
                    if account_rlp.is_none() {
                        vm.commit_account(vm::AccountCommitment::Nonexist(addr)).unwrap();;
                    } else {
                        let account_rlp = account_rlp.unwrap();
                        let account: Account = rlp::decode(&account_rlp);
                        let code = state.get(account.code_hash.as_ref());

                        vm.commit_account(vm::AccountCommitment::Code {
                            address: addr,
                            code: code.unwrap_or(Vec::new()),
                        }).unwrap();
                    }
                },
                Err(vm::errors::RequireError::AccountStorage(addr, index)) => {
                    println!("Requiring account storage {:?}", addr);

                    let account_rlp = state.get(addr.as_ref());
                    if account_rlp.is_none() {
                        vm.commit_account(vm::AccountCommitment::Nonexist(addr)).unwrap();;
                    } else {
                        let account_rlp = account_rlp.unwrap();
                        let account: Account = rlp::decode(&account_rlp);
                        let mut storage = state.clone();
                        storage.set_root(account.storage_root);

                        let mut key_raw = Vec::new();
                        let key: U256 = index.into();
                        key.to_big_endian(&mut key_raw);
                        vm.commit_account(vm::AccountCommitment::Storage {
                            address: addr,
                            index: index,
                            value: M256::from(storage.get(key_raw.as_ref()).unwrap_or(Vec::new()).as_ref()),
                        }).unwrap();
                    }
                },
                _ => unimplemented!(),
            }
        }

        let mut state = state.clone();
        for account in vm.accounts() {
            match account.clone() {
                vm::Account::Full {
                    nonce, address, balance, changing_storage, code
                } => {
                    let storage: HashMap<M256, M256> = changing_storage.into();
                    let state_root = state.root();
                    let account_rlp = state.get(address.as_ref()).unwrap();
                    let mut account: Account = rlp::decode(&account_rlp);

                    state.set_root(account.storage_root);
                    for (key, value) in storage {
                        let mut key_raw = Vec::new();
                        let mut value_raw = Vec::new();
                        let key: U256 = key.into();
                        let value: U256 = value.into();
                        key.to_big_endian(&mut key_raw);
                        value.to_big_endian(&mut value_raw);
                        state.insert(key_raw, value_raw);
                    }
                    account.storage_root = state.root();
                    account.nonce = nonce.into();
                    account.balance = balance;
                    let account_rlp = rlp::encode(&account).to_vec();
                    state.set_root(state_root);
                    state.insert(address.as_ref().into(), account_rlp);
                },
                vm::Account::IncreaseBalance(address, value) => {
                    let state_root = state.root();
                    let account_rlp = state.get(address.as_ref()).unwrap();
                    let mut account: Account = rlp::decode(&account_rlp);
                    account.balance = account.balance + value;
                    let account_rlp = rlp::encode(&account).to_vec();
                    state.set_root(state_root);
                    state.insert(address.as_ref().into(), account_rlp);
                },
                vm::Account::DecreaseBalance(address, value) => {
                    let state_root = state.root();
                    let account_rlp = state.get(address.as_ref()).unwrap();
                    let mut account: Account = rlp::decode(&account_rlp);
                    account.balance = account.balance - value;
                    let account_rlp = rlp::encode(&account).to_vec();
                    state.set_root(state_root);
                    state.insert(address.as_ref().into(), account_rlp);
                },
                vm::Account::Create {
                    nonce, address, balance, storage, code, exists
                } => {
                    if !exists {
                        state.remove(address.as_ref());
                    } else {
                        let storage: HashMap<M256, M256> = storage.into();
                        let state_root = state.root();
                        let code_hash = H256::from(Keccak256::digest(code.as_ref()).as_slice());
                        let mut account: Account = Account {
                            balance: balance,
                            nonce: nonce.into(),
                            code_hash: code_hash,
                            storage_root: empty_trie_hash(),
                        };

                        state.insert(code_hash.as_ref().into(), code);

                        state.set_root(account.storage_root);
                        for (key, value) in storage {
                            let mut key_raw = Vec::new();
                            let mut value_raw = Vec::new();
                            let key: U256 = key.into();
                            let value: U256 = value.into();
                            key.to_big_endian(&mut key_raw);
                            value.to_big_endian(&mut value_raw);
                            state.insert(key_raw, value_raw);
                        }
                        account.storage_root = state.root();
                        account.nonce = nonce.into();
                        account.balance = balance;
                        let account_rlp = rlp::encode(&account).to_vec();
                        state.set_root(state_root);
                        state.insert(address.as_ref().into(), account_rlp);
                    }
                }
            }
        }

        let logs: Vec<Log> = vm.logs().into();
        let used_gas = vm.real_used_gas();
        let mut logs_bloom = LogsBloom::new();
        for log in logs.clone() {
            logs_bloom.set(&log.address);
            for topic in log.topics {
                logs_bloom.set(&topic)
            }
        }

        let receipt = Receipt {
            used_gas, logs, logs_bloom, state_root: state.root(),
        };

        (state, receipt)
    }
}

fn main() {
    let mut rng = OsRng::new().unwrap();
    let secret_key = SecretKey::new(&SECP256K1, &mut rng);
    let address = Address::from_secret_key(&secret_key).unwrap();
    println!("address: {:?}", address);
    let mut state = MemoryTrie::empty(HashMap::new());

    state.insert(address.as_ref().into(), rlp::encode(&Account {
        nonce: U256::zero(),
        balance: U256::from_str("0x10000000000000000000000000000").unwrap(),
        storage_root: empty_trie_hash(),
        code_hash: H256::from(Keccak256::digest(&[]).as_slice()),
    }).to_vec());

    let mut blockchain: blockchain::Blockchain<EthereumDefinition<blockchain::FakeConsensus<Block, Receipt>, EthereumTransitionRule>> = blockchain::Blockchain::new(Block {
        header: Header {
            parent_hash: H256::default(),
            ommers_hash: empty_trie_hash(),
            beneficiary: Address::default(),
            state_root: empty_trie_hash(),
            transactions_root: empty_trie_hash(),
            receipts_root: empty_trie_hash(),
            logs_bloom: LogsBloom::new(),
            difficulty: U256::zero(),
            number: U256::zero(),
            gas_limit: Gas::zero(),
            gas_used: Gas::zero(),
            timestamp: 0,
            extra_data: B256::default(),
            mix_hash: H256::default(),
            nonce: H64::default(),
        },
        transactions: Vec::new(),
        ommers: Vec::new(),
    }, state);

    loop {
        let unsigned = UnsignedTransaction {
            nonce: U256::zero(),
            gas_price: Gas::zero(),
            gas_limit: Gas::from_str("0x100000000").unwrap(),
            action: TransactionAction::Create,
            value: U256::zero(),
            input: Vec::new(),
            network_id: Some(61),
        };
        let signed = unsigned.sign(&secret_key);
        blockchain.mine(&[signed]);
        println!("Mined one block, {:?}", blockchain.current_block());

        thread::sleep(Duration::from_millis(1000));
    }
}
