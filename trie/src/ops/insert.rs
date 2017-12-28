fn value_and_leaf_branch<'a>(
    anibble: NibbleVec, avalue: MerkleValue<'a>, bnibble: NibbleVec, bvalue: &'a [u8]
) -> (MerkleNode<'a>, Change) {
    debug_assert!(anibble.len() > 0);

    let mut change = Change::default();
    let mut additional = None;
    let mut nodes = empty_nodes!();

    let ai: usize = anibble[0].into();
    let asub = anibble[1..].into();

    if asub.len() > 0 {
        let ext_value = change.add_value(MerkleNode::Extension(asub, avalue));
        nodes[ai] = ext_value;
    } else {
        nodes[ai] = avalue;
    }

    if bnibble.len() == 0 {
        additional = Some(bvalue);
    } else {
        let bi: usize = bnibble[0].into();
        debug_assert!(ai != bi);

        let bsub = bnibble[1..].into();
        let bvalue = change.add_value(MerkleNode::Leaf(bsub, bvalue));

        nodes[bi] = bvalue;
    }

    (MerkleNode::Branch(nodes, additional), change)
}

fn two_leaf_branch<'a>(
    anibble: NibbleVec, avalue: &'a [u8], bnibble: NibbleVec, bvalue: &'a [u8]
) -> (MerkleNode<'a>, Change) {
    debug_assert!(!anibble.starts_with(bnibble));
    debug_assert!(!bnibble.starts_with(anibble));

    let mut change = Change::default();
    let mut additional = None;
    let mut nodes = empty_nodes!();

    if anibble.len() == 0 {
        additional = Some(avalue);
    } else {
        let ai: usize = anibble[0].into();
        let asub: NibbleVec = anibble[1..].into();
        let avalue = change.add_value(MerkleNode::Leaf(asub, avalue));
        nodes[ai] = avalue;
    }

    if bnibble.len() == 0 {
        additional = Some(bvalue);
    } else {
        let bi: usize = bnibble[0].into();
        let bsub: NibbleVec = bnibble[1..].into();
        let bvalue = change.add_value(MerkleNode::Leaf(bsub, bvalue));
        nodes[bi] = bvalue;
    }

    (MerkleNode::Branch(nodes, additional), change)
}

pub fn insert_by_value<'a, D: DatabaseHandle>(
    merkle: MerkleValue<'a>, nibble: NibbleVec, value: &'a [u8], database: &'a D
) -> (MerkleValue<'a>, Change) {
    let mut change = Change::default();

    let new = match merkle {
        MerkleValue::Empty => {
            change.add_value(MerkleNode::Leaf(nibble, value))
        },
        MerkleValue::Full(ref sub_node) => {
            let (new_node, subchange) = Self::insert_by_node(
                sub_node, nibble, value, database);
            change.merge(&subchange);
            change.add_value(new_node)
        },
        MerkleValue::Hash(h) => {
            let sub_node = database.get(h);
            change.remove_node(sub_node);
            let (new_node, subchange) = Self::insert_by_node(
                sub_node, nibble, value, database);
            change.merge(&subchange);
            change.add_value(new_node)
        },
    };

    (new, change)
}

pub fn insert_by_node<'a, D: DatabaseHandle>(
    node: MerkleNode<'a>, nibble: NibbleVec, value: &'a [u8], database: &'a D
) -> (MerkleNode<'a>, Change) {
    let mut change = Change::default();

    let new = match node {
        MerkleNode::Leaf(ref node_nibble, ref node_value) => {
            debug_assert!(node_nibble.len() > 0);

            let (common, nibble_sub, node_nibble_sub) =
                nibble::common_with_sub(&nibble, &node_nibble);

            let (branch, subchange) = two_leaf_branch(node_nibble_sub, node_value,
                                                      nibble_sub, value);
            change.merge(&subchange);
            if common.len() > 0 {
                MerkleNode::Extension(common, branch)
            } else {
                branch
            }
        },
        MerkleNode::Extension(ref node_nibble, ref node_value) => {
            if nibble.starts_with(node_nibble) {
                let (subvalue, subchange) = insert_by_value(
                    node_value.clone(),
                    nibble.split_at(node_nibble.len()).1.into(),
                    value);
                change.merge(&subchange);

                MerkleNode::Extension(node_nibble.clone(), subvalue)
            } else {
                let (common, nibble_sub, node_nibble_sub) =
                    nibble::common_with_sub(&nibble, &node_nibble);

                let (branch, subchange) = value_and_leaf_branch(node_nibble_sub, node_value,
                                                                nibble_sub, value);
                change.merge(&subchange);
                if common.len() > 0 {
                    MerkleNode::Extension(common, branch)
                } else {
                    branch
                }
            }
        },
        MerkleNode::Branch(ref node_nodes, ref node_additional) => {
            unimplemented!();
        },
    };

    (new, change)
}

pub fn insert_by_empty<'a, D: DatabaseHandle>(
    nibble: NibbleVec, value: &'a [u8], database: &'a D
) -> (MerkleNode<'a>, Change) {
    let mut change = Change::default();

    let new = MerkleNode::Leaf(nibble, value);
    (new, change)
}
