pub enum MerkleNode<'a> {
    Blank,
    Leaf(LeafNibbleSlice<'a>, &'a [u8]),
    Extension(ExtensionNibbleSlice<'a>, MerkleValue<'a>),
    Branch([MerkleValue<'a>; 16], Option<&'a [u8]>),
}

impl<'a> MerkleNode<'a> {
    pub fn decode(rlp: &Rlp<'a>) -> Self {

    }
}

impl<'a> Encodable for MerkleNode {

}

pub enum MerkleValue<'a> {
    Empty,
    Full(MerkleNode<'a>),
    Hash(H256),
}

impl<'a> MerkleValue<'a> {
    pub fn decode(rlp: &Rlp<'a>) -> Self {

    }
}

impl<'a> Encodable for MerkleValue {
    fn rlp_append(&self, s: &mut RlpStream) {
        match self {
            &MerkleValue::Empty => {
                s.append_list(0);
            },
            &MerkleValue::Full(ref node) => {

            }
        }
    }
}
