pub fn insert_by_value<'a, D: DatabaseHandle>(
    merkle: MerkleValue<'a>, nibble: NibbleVec, value: &'a [u8], database: &'a D
) -> (MerkleValue<'a>, Change) {
    let mut change = Change::default();

    let new = match merkle {
        MerkleValue::Empty => {
            unimplemented!();
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
            if nibble.starts_with(node_nibble) {
                match nibble.len().cmp(node_nibble.len()) {
                    Ordering::Less => {
                        unimplemented!();
                    },
                    Ordering::Equal => {
                        // When new nibble is the same as the old
                        // nibble, then we only need to replace the
                        // value.

                        MerkleNode::Leaf(nibble, value)
                    },
                    Ordering::Greater => {
                        unimplemented!();
                    },
                }
            } else {
                unimplemented!();
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
                unimplemented!();
            }
        },
        MerkleNode::Branch(ref node_nodes, ref node_additional) => {
            unimplemented!();
        },
    };

    (new, change)
}
