#[macro_use]
extern crate serde_derive;

extern crate serde;
extern crate serde_json;
extern crate bigint;
extern crate trie;
extern crate trie_memory;
extern crate block;
extern crate sha3;
extern crate rlp;
extern crate rand;

use bigint::{Address, H256, M256, U256};
use trie_memory::{FixedSecureMemoryTrieMut, MemoryTrieMut, TrieMut};
use block::Account;
use sha3::{Digest, Keccak256};
use rand::Rng;

use std::str::FromStr;
use std::collections::HashMap;

fn build_db(map: &HashMap<Address, Account>) -> MemoryTrieMut {
    let mut db: HashMap<Vec<u8>, Vec<u8>> = HashMap::new();

    for (key, value) in map {
        db.insert(Keccak256::digest(key.as_ref()).as_slice().into(), rlp::encode(value).to_vec());
    }

    MemoryTrieMut::build(&db)
}

#[test]
pub fn test_genesis_root() {
    #[derive(Serialize, Deserialize, Debug)]
    struct JSONAccount {
        balance: String,
    }

    type StorageTrieMut = FixedSecureMemoryTrieMut<H256, M256>;

    let genesis_accounts: HashMap<String, JSONAccount> =
        serde_json::from_str(include_str!("../res/genesis.json")).unwrap();

    let mut accounts: Vec<(&String, &JSONAccount)> = genesis_accounts.iter().collect();
    let mut account_trie: FixedSecureMemoryTrieMut<Address, Account> = Default::default();
    let mut account_db: HashMap<Address, Account> = HashMap::new();
    let mut addresses: Vec<Address> = Vec::new();

    for (key, value) in accounts {
        let address = Address::from_str(key).unwrap();
        let balance = U256::from_dec_str(&value.balance).unwrap();

        let account = Account {
            nonce: U256::zero(),
            balance: balance,
            storage_root: StorageTrieMut::default().root(),
            code_hash: H256::from(Keccak256::digest(&[]).as_slice()),
        };

        account_trie.insert(&address, &account);
        account_db.insert(address, account);
        addresses.push(address);
    }

    let db_full = build_db(&account_db);
    assert_eq!(account_trie.root(), H256::from_str("0xd7f8974fb5ac78d9ac099b9ad5018bedc2ce0a72dad1827a1709da30580f0544").unwrap());
    assert_eq!(db_full.root(), H256::from_str("0xd7f8974fb5ac78d9ac099b9ad5018bedc2ce0a72dad1827a1709da30580f0544").unwrap());

    let db_full_raw: HashMap<H256, Vec<u8>> = db_full.into();
    let trie_full_raw: HashMap<H256, Vec<u8>> = account_trie.clone().to_trie().into();
    assert_eq!(db_full_raw, trie_full_raw);

    for _ in 0..(addresses.len() / 2) {
        let i = rand::thread_rng().gen_range(0, addresses.len());

        let addr = addresses[i];
        addresses.swap_remove(i);

        account_trie.delete(&addr);
        account_db.remove(&addr);
    }

    let db_half = build_db(&account_db);

    let db_half_raw: HashMap<H256, Vec<u8>> = db_half.into();
    let trie_half_raw: HashMap<H256, Vec<u8>> = account_trie.clone().to_trie().into();
    assert_eq!(db_half_raw, trie_half_raw);

    for addr in addresses {
        account_trie.delete(&addr);
    }
    assert_eq!(account_trie.root(), MemoryTrieMut::default().root());

    let trie_empty_raw: HashMap<H256, Vec<u8>> = account_trie.clone().to_trie().into();
    assert_eq!(trie_empty_raw.len(), 0);
}
