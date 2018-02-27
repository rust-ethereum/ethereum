use merkle::{MerkleValue, MerkleNode};
use merkle::nibble::NibbleVec;
use {DatabaseHandle, Error};

use rlp::Rlp;

pub fn get_by_value<'a, D: DatabaseHandle>(
    merkle: MerkleValue<'a>, nibble: NibbleVec, database: &'a D
) -> Result<Option<&'a [u8]>, Error> {
    match merkle {
        MerkleValue::Empty => Ok(None),
        MerkleValue::Full(subnode) => {
            get_by_node(subnode.as_ref().clone(), nibble, database)
        },
        MerkleValue::Hash(h) => {
            let subnode = MerkleNode::decode(&Rlp::new(database.get_with_error(h)?));
            get_by_node(subnode, nibble, database)
        },
    }
}

pub fn get_by_node<'a, D: DatabaseHandle>(
    node: MerkleNode<'a>, nibble: NibbleVec, database: &'a D
) -> Result<Option<&'a [u8]>, Error> {
    match node {
        MerkleNode::Leaf(node_nibble, node_value) => {
            if node_nibble == nibble {
                Ok(Some(node_value))
            } else {
                Ok(None)
            }
        },
        MerkleNode::Extension(node_nibble, node_value) => {
            if nibble.starts_with(&node_nibble) {
                get_by_value(node_value, nibble[node_nibble.len()..].into(), database)
            } else {
                Ok(None)
            }
        },
        MerkleNode::Branch(node_nodes, node_additional) => {
            if nibble.len() == 0 {
                Ok(node_additional)
            } else {
                let ni: usize = nibble[0].into();
                get_by_value(node_nodes[ni].clone(), nibble[1..].into(), database)
            }
        },
    }
}
