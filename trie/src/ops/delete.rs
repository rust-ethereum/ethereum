pub fn remove_by_value<'a, D: DatabaseHandle>(
    merkle: MerkleValue<'a>, nibble: NibbleVec, database: &'a D
) -> (MerkleValue<'a>, Change) {
    let mut change = Change::default();

    let new = match merkle {
        MerkleValue::Empty => {
            MerkleValue::Empty
        },
        MerkleValue::Full(ref sub_node) => {
            let (new_node, subchange) = remove_by_node(
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
            let (new_node, subchange) = insert_by_node(
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
