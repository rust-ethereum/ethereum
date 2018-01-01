fn find_and_remove_child<'a, D: DatabaseHandle>(
    merkle: MerkleValue<'a>, database: &'a D
) -> (MerkleNode<'a>, Change) {
    let mut change = Change::default();

    let node = match merkle {
        MerkleValue::Empty => panic!(),
        MerkleValue::Full(ref sub_node) => sub_node.clone(),
        MerkleValue::Hash(h) => {
            let sub_node = MerkleNode::decode(&Rlp::new(database.get(h)));
            change.remove_raw(h);
            sub_node
        },
    };

    (node, change)
}

fn collapse_and_remove_child<'a, D: DatabaseHandle>(
    merkle: MerkleValue<'a>, database: &'a D
) -> (MerkleNode<'a>, Change) {
    let mut change = Change::default();

    let (child, subchange) = find_and_remove_child(merkle, database);
    change.merge(&subchange);

    let new_child = match child {
        MerkleNode::Extension(sub_nibble, sub_value) => {
            let (new, subchange) = collapse_extension(sub_nibble, sub_value, database);
            change.merge(&subchange);
            new
        },
        MerkleNode::Branch(node_nodes, node_additional) => {
            let (new, subchange) = collapse_branch(node_nodes, node_additional, database);
            change.merge(&subchange);
            new
        },
        leaf => leaf,
    };

    (new_child, change)
}

fn collapse_extension<'a, D: DatabaseHandle>(
    node_nibble: NibbleVec, node_value: MerkleValue<'a>, database: &'a D
) -> (MerkleNode<'a>, Change) {
    let mut change = Change::default();

    let (subnode, subchange) = collapse_and_remove_child(node_value, database);
    change.merge(&subchange);

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
            let subvalue = change.add_value(branch);
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
) -> (MerkleNode<'a>, Change) {
    let mut change = Change::default();

    let value_count = nonempty_node_count(node_nodes, node_additional);

    let node = match value_count {
        0 => panic!(),
        1 if node_additional.is_some() =>
            MerkleNode::Leaf(NibbleVec::new(), node_additional.unwrap()),
        1 /* value in node_nodes */ => {
            let (subindex, subvalue) = node_nodes.iter().enumerate()
                .filter(|&(_, v)| v != &MerkleValue::Empty).next()
                .map(|(i, v)| (i, v.clone())).unwrap();
            let subnibble: Nibble = subindex.into();

            let (subnode, subchange) = collapse_and_remove_child(subvalue, database);
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
                    let subvalue = change.add_value(branch);
                    MerkleNode::Extension(subnibble, subvalue)
                },
            }
        },
        _ /* value_count > 1 */ =>
            MerkleNode::Branch(node_nodes, node_additional),
    };

    (node, change)
}

pub fn delete_by_value<'a, D: DatabaseHandle>(
    merkle: MerkleValue<'a>, nibble: NibbleVec, database: &'a D
) -> (MerkleValue<'a>, Change) {
    let mut change = Change::default();

    let new = match merkle {
        MerkleValue::Empty => {
            MerkleValue::Empty
        },
        MerkleValue::Full(ref sub_node) => {
            let (new_node, subchange) = delete_by_node(
                sub_node.as_ref().clone(), nibble, database);
            change.merge(&subchange);
            match new_node {
                Some(new_node) => change.add_value(&new_node),
                None => MerkleValue::Empty,
            }
        },
        MerkleValue::Hash(h) => {
            let sub_node = MerkleNode::decode(&Rlp::new(database.get(h)));
            change.remove_raw(h);
            let (new_node, subchange) = delete_by_node(
                sub_node, nibble, database);
            change.merge(&subchange);
            match new_node {
                Some(new_node) => change.add_value(&new_node),
                None => MerkleValue::Empty,
            }
        },
    };

    (new, change)
}

pub fn delete_by_node<'a, D: DatabaseHandle>(
    node: MerkleNode<'a>, nibble: NibbleVec, database: &'a D
) -> (Option<MerkleNode<'a>>, Change) {
    let mut change = Change::default();

    let new = match node {
        MerkleNode::Leaf(ref node_nibble, ref node_value) => {
            if node_nibble == &nibble {
                None
            } else {
                Some(MerkleNode::Leaf(node_nibble.clone(), node_value.clone()))
            }
        },
        MerkleNode::Extension(ref node_nibble, ref node_value) => {
            if nibble.starts_with(node_nibble) {
                let (subvalue, subchange) = delete_by_value(
                    node_value.clone(), nibble[node_nibble.len()..].into(),
                    database);
                change.merge(&subchange);

                match subvalue {
                    MerkleValue::Empty => None,
                }
            }
        },
    }
}
