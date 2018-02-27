use merkle::{MerkleValue, MerkleNode};
use merkle::nibble::{NibbleVec, Nibble};
use {Change, DatabaseHandle, Error};

use rlp::Rlp;

fn find_and_remove_child<'a, D: DatabaseHandle>(
    merkle: MerkleValue<'a>, database: &'a D
) -> Result<(MerkleNode<'a>, Change), Error> {
    let mut change = Change::default();

    let node = match merkle {
        MerkleValue::Empty => panic!(),
        MerkleValue::Full(ref sub_node) => sub_node.as_ref().clone(),
        MerkleValue::Hash(h) => {
            let sub_node = MerkleNode::decode(&Rlp::new(database.get_with_error(h)?));
            change.remove_raw(h);
            sub_node
        },
    };

    Ok((node, change))
}

fn collapse_extension<'a>(
    node_nibble: NibbleVec, subnode: MerkleNode<'a>
) -> (MerkleNode<'a>, Change) {
    let mut change = Change::default();

    let node = match subnode {
        MerkleNode::Leaf(mut sub_nibble, sub_value) => {
            let mut new_sub_nibble = node_nibble.clone();
            new_sub_nibble.append(&mut sub_nibble);
            MerkleNode::Leaf(new_sub_nibble, sub_value)
        },
        MerkleNode::Extension(mut sub_nibble, sub_value) => {
            debug_assert!(sub_value != MerkleValue::Empty);

            let mut new_sub_nibble = node_nibble.clone();
            new_sub_nibble.append(&mut sub_nibble);
            MerkleNode::Extension(new_sub_nibble, sub_value)
        },
        branch => {
            let subvalue = change.add_value(&branch);
            MerkleNode::Extension(node_nibble, subvalue)
        },
    };

    (node, change)
}

fn nonempty_node_count<'a, 'b>(
    nodes: &'b [MerkleValue<'a>; 16], additional: &'b Option<&'a [u8]>
) -> usize {
    additional.iter().count() +
        nodes.iter().filter(|v| v != &&MerkleValue::Empty).count()
}

fn collapse_branch<'a, D: DatabaseHandle>(
    node_nodes: [MerkleValue<'a>; 16], node_additional: Option<&'a [u8]>,
    database: &'a D
) -> Result<(MerkleNode<'a>, Change), Error> {
    let mut change = Change::default();

    let value_count = nonempty_node_count(&node_nodes, &node_additional);

    let node = match value_count {
        0 => panic!(),
        1 if node_additional.is_some() =>
            MerkleNode::Leaf(NibbleVec::new(), node_additional.unwrap()),
        1 /* value in node_nodes */ => {
            let (subindex, subvalue) = node_nodes.iter().enumerate()
                .filter(|&(_, v)| v != &MerkleValue::Empty).next()
                .map(|(i, v)| (i, v.clone())).unwrap();
            let subnibble: Nibble = subindex.into();

            let (subnode, subchange) = find_and_remove_child(subvalue, database)?;
            change.merge(&subchange);

            match subnode {
                MerkleNode::Leaf(mut leaf_nibble, leaf_value) => {
                    leaf_nibble.insert(0, subnibble);
                    MerkleNode::Leaf(leaf_nibble, leaf_value)
                },
                MerkleNode::Extension(mut ext_nibble, ext_value) => {
                    debug_assert!(ext_value != MerkleValue::Empty);

                    ext_nibble.insert(0, subnibble);
                    MerkleNode::Extension(ext_nibble, ext_value)
                },
                branch => {
                    let subvalue = change.add_value(&branch);
                    MerkleNode::Extension(vec![subnibble], subvalue)
                },
            }
        },
        _ /* value_count > 1 */ =>
            MerkleNode::Branch(node_nodes, node_additional),
    };

    Ok((node, change))
}

pub fn delete_by_child<'a, D: DatabaseHandle>(
    merkle: MerkleValue<'a>, nibble: NibbleVec, database: &'a D
) -> Result<(Option<MerkleNode<'a>>, Change), Error> {
    let mut change = Change::default();

    let new = match merkle {
        MerkleValue::Empty => {
            None
        },
        MerkleValue::Full(ref sub_node) => {
            let (new_node, subchange) = delete_by_node(
                sub_node.as_ref().clone(), nibble, database)?;
            change.merge(&subchange);
            match new_node {
                Some(new_node) => Some(new_node),
                None => None,
            }
        },
        MerkleValue::Hash(h) => {
            let sub_node = MerkleNode::decode(&Rlp::new(database.get_with_error(h)?));
            change.remove_raw(h);
            let (new_node, subchange) = delete_by_node(
                sub_node, nibble, database)?;
            change.merge(&subchange);
            match new_node {
                Some(new_node) => Some(new_node),
                None => None,
            }
        },
    };

    Ok((new, change))
}

pub fn delete_by_node<'a, D: DatabaseHandle>(
    node: MerkleNode<'a>, nibble: NibbleVec, database: &'a D
) -> Result<(Option<MerkleNode<'a>>, Change), Error> {
    let mut change = Change::default();

    let new = match node {
        MerkleNode::Leaf(node_nibble, node_value) => {
            if node_nibble == nibble {
                None
            } else {
                Some(MerkleNode::Leaf(node_nibble, node_value))
            }
        },
        MerkleNode::Extension(node_nibble, node_value) => {
            if nibble.starts_with(&node_nibble) {
                let (subnode, subchange) = delete_by_child(
                    node_value, nibble[node_nibble.len()..].into(),
                    database)?;
                change.merge(&subchange);

                match subnode {
                    Some(subnode) => {
                        let (new, subchange) = collapse_extension(node_nibble, subnode);
                        change.merge(&subchange);

                        Some(new)
                    },
                    None => None,
                }
            } else {
                Some(MerkleNode::Extension(node_nibble, node_value))
            }
        },
        MerkleNode::Branch(mut node_nodes, mut node_additional) => {
            let needs_collapse;

            if nibble.len() == 0 {
                node_additional = None;
                needs_collapse = true;
            } else {
                let ni: usize = nibble[0].into();
                let (new_subnode, subchange) = delete_by_child(
                    node_nodes[ni].clone(), nibble[1..].into(),
                    database)?;
                change.merge(&subchange);

                match new_subnode {
                    Some(new_subnode) => {
                        let new_subvalue = change.add_value(&new_subnode);

                        node_nodes[ni] = new_subvalue;
                        needs_collapse = false;
                    },
                    None => {
                        node_nodes[ni] = MerkleValue::Empty;
                        needs_collapse = true;
                    },
                }
            }

            if needs_collapse {
                let value_count = nonempty_node_count(&node_nodes, &node_additional);
                if value_count > 0 {
                    let (new, subchange) = collapse_branch(node_nodes, node_additional, database)?;
                    change.merge(&subchange);

                    Some(new)
                } else {
                    None
                }
            } else {
                Some(MerkleNode::Branch(node_nodes, node_additional))
            }
        },
    };

    Ok((new, change))
}
