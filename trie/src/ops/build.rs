use merkle::{MerkleValue, MerkleNode};
use merkle::nibble::{self, NibbleVec, Nibble};
use Change;

use std::collections::HashMap;

fn make_submap<'a, 'b: 'a, T: Iterator<Item=(&'a NibbleVec, &'a &'b [u8])>>(
    common_len: usize, map: T
) -> HashMap<NibbleVec, &'b [u8]> {
    let mut submap = HashMap::new();
    for (key, value) in map {
        submap.insert(key[common_len..].into(), value.clone());
    }
    submap
}

pub fn build_value<'a>(node: MerkleNode<'a>) -> (MerkleValue<'a>, Change) {
    let mut change = Change::default();
    let value = change.add_value(&node);

    (value, change)
}

pub fn build_node<'a>(map: &HashMap<NibbleVec, &'a [u8]>) -> (MerkleNode<'a>, Change) {
    let mut change = Change::default();

    assert!(map.len() > 0);
    if map.len() == 1 {
        let key = map.keys().next().unwrap();
        return (MerkleNode::Leaf(key.clone(), map.get(key).unwrap().clone()), change);
    }

    debug_assert!(map.len() > 1);
    let common = nibble::common_all(map.keys().map(|v| v.as_ref()));

    if common.len() > 0 {
        let submap = make_submap(common.len(), map.iter());
        debug_assert!(submap.len() > 0);

        let (node, subchange) = build_node(&submap);
        change.merge(&subchange);

        let (value, subchange) = build_value(node);
        change.merge(&subchange);

        (MerkleNode::Extension(common.into(), value), change)
    } else {
        let mut nodes = empty_nodes!();

        for i in 0..16 {
            let nibble: Nibble = i.into();

            let submap = make_submap(1, map.iter().filter(|&(key, _value)| {
                key.len() > 0 && key[0] == nibble
            }));

            if submap.len() > 0 {
                let (node, subchange) = build_node(&submap);
                change.merge(&subchange);

                let (value, subchange) = build_value(node);
                change.merge(&subchange);

                nodes[i] = value;
            }
        }

        let additional = map.iter()
            .filter(|&(key, _value)| key.len() == 0).next()
            .map(|(_key, value)| value.clone());

        (MerkleNode::Branch(nodes, additional), change)
    }
}
