use super::nibble::{self, NibbleVec, NibbleType};

use rlp::{self, RlpStream, Encodable, Rlp, Prototype};
use bigint::H256;
use std::borrow::Borrow;

/// Represents a merkle node.
#[derive(Debug, PartialEq, Eq)]
pub enum MerkleNode<'a> {
    Leaf(NibbleVec, &'a [u8]),
    Extension(NibbleVec, MerkleValue<'a>),
    Branch([MerkleValue<'a>; 16], Option<&'a [u8]>),
}

impl<'a> MerkleNode<'a> {
    /// Given a RLP, decode it to a merkle node.
    pub fn decode(rlp: &Rlp<'a>) -> Self {
        match rlp.prototype() {
            Prototype::List(2) => {
                let (nibble, typ) = nibble::decode(&rlp.at(0));
                match typ {
                    NibbleType::Leaf => {
                        MerkleNode::Leaf(nibble, rlp.at(1).data())
                    },
                    NibbleType::Extension => {
                        MerkleNode::Extension(nibble, MerkleValue::decode(&rlp.at(1)))
                    },
                }
            },
            Prototype::List(17) => {
                let mut nodes = [MerkleValue::Empty, MerkleValue::Empty,
                                 MerkleValue::Empty, MerkleValue::Empty,
                                 MerkleValue::Empty, MerkleValue::Empty,
                                 MerkleValue::Empty, MerkleValue::Empty,
                                 MerkleValue::Empty, MerkleValue::Empty,
                                 MerkleValue::Empty, MerkleValue::Empty,
                                 MerkleValue::Empty, MerkleValue::Empty,
                                 MerkleValue::Empty, MerkleValue::Empty];
                for i in 0..16 {
                    nodes[i] = MerkleValue::decode(&rlp.at(i));
                }
                let value = if rlp.at(16).is_empty() {
                    None
                } else {
                    Some(rlp.at(16).data())
                };
                MerkleNode::Branch(nodes, value)
            },
            _ => panic!(),
        }
    }

    /// Whether the node can be inlined to a merkle value.
    pub fn inlinable(&self) -> bool {
        rlp::encode(self).to_vec().len() < 32
    }
}

impl<'a> Clone for MerkleNode<'a> {
    fn clone(&self) -> MerkleNode<'a> {
        match self {
            &MerkleNode::Leaf(ref nibble, ref value) => {
                MerkleNode::Leaf(nibble.clone(), value.clone())
            },
            &MerkleNode::Extension(ref nibble, ref value) => {
                MerkleNode::Extension(nibble.clone(), value.clone())
            },
            &MerkleNode::Branch(ref nodes, ref additional) => {
                let mut cloned_nodes = [MerkleValue::Empty, MerkleValue::Empty,
                                        MerkleValue::Empty, MerkleValue::Empty,
                                        MerkleValue::Empty, MerkleValue::Empty,
                                        MerkleValue::Empty, MerkleValue::Empty,
                                        MerkleValue::Empty, MerkleValue::Empty,
                                        MerkleValue::Empty, MerkleValue::Empty,
                                        MerkleValue::Empty, MerkleValue::Empty,
                                        MerkleValue::Empty, MerkleValue::Empty];
                for i in 0..16 {
                    cloned_nodes[i] = nodes[i].clone();
                }
                MerkleNode::Branch(cloned_nodes, additional.clone())
            },
        }
    }
}

impl<'a> Encodable for MerkleNode<'a> {
    fn rlp_append(&self, s: &mut RlpStream) {
        match self {
            &MerkleNode::Leaf(ref nibble, ref value) => {
                s.begin_list(2);
                nibble::encode(nibble, NibbleType::Leaf, s);
                value.rlp_append(s);
            },
            &MerkleNode::Extension(ref nibble, ref value) => {
                s.begin_list(2);
                nibble::encode(nibble, NibbleType::Extension, s);
                value.rlp_append(s);
            },
            &MerkleNode::Branch(ref nodes, ref value) => {
                s.begin_list(17);
                for i in 0..16 {
                    nodes[i].rlp_append(s);
                }
                match value {
                    &Some(ref value) => { value.rlp_append(s); },
                    &None => { s.append_empty_data(); },
                }
            }
        }
    }
}

/// Represents a merkle value.
#[derive(Debug, Eq, PartialEq, Clone)]
pub enum MerkleValue<'a> {
    Empty,
    Full(Box<MerkleNode<'a>>),
    Hash(H256),
}

impl<'a> MerkleValue<'a> {
    /// Given a RLP, decode it to a merkle value.
    pub fn decode(rlp: &Rlp<'a>) -> Self {
        if rlp.is_empty() {
            return MerkleValue::Empty;
        }

        if rlp.size() == 32 {
            return MerkleValue::Hash(rlp.as_val());
        }

        if rlp.size() < 32 {
            return MerkleValue::Full(Box::new(MerkleNode::decode(rlp)));
        }

        panic!();
    }
}

impl<'a> Encodable for MerkleValue<'a> {
    fn rlp_append(&self, s: &mut RlpStream) {
        match self {
            &MerkleValue::Empty => {
                s.append_empty_data();
            },
            &MerkleValue::Full(ref node) => {
                debug_assert!(node.inlinable());
                let node: &MerkleNode = node.borrow();
                s.append(node);
            },
            &MerkleValue::Hash(ref hash) => {
                s.append(hash);
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use hexutil::read_hex;
    use rlp::{self, Rlp};
    use merkle::nibble;
    use super::MerkleNode;

    #[test]
    fn encode_decode() {
        let key = [6, 7, 8, 9, 10, 11, 12, 13, 14, 15];
        let val = [1, 2, 3, 4, 5];
        let node = MerkleNode::Leaf(nibble::from_key(&key), &val);
        let rlp_raw = rlp::encode(&node);
        let decoded_node: MerkleNode = MerkleNode::decode(&Rlp::new(&rlp_raw));
        assert_eq!(node, decoded_node);
    }

    #[test]
    fn decode_genesis_state() {
        let buffer: Vec<u8> = read_hex("f90211a090dcaf88c40c7bbc95a912cbdde67c175767b31173df9ee4b0d733bfdd511c43a0babe369f6b12092f49181ae04ca173fb68d1a5456f18d20fa32cba73954052bda0473ecf8a7e36a829e75039a3b055e51b8332cbf03324ab4af2066bbd6fbf0021a0bbda34753d7aa6c38e603f360244e8f59611921d9e1f128372fec0d586d4f9e0a04e44caecff45c9891f74f6a2156735886eedf6f1a733628ebc802ec79d844648a0a5f3f2f7542148c973977c8a1e154c4300fec92f755f7846f1b734d3ab1d90e7a0e823850f50bf72baae9d1733a36a444ab65d0a6faaba404f0583ce0ca4dad92da0f7a00cbe7d4b30b11faea3ae61b7f1f2b315b61d9f6bd68bfe587ad0eeceb721a07117ef9fc932f1a88e908eaead8565c19b5645dc9e5b1b6e841c5edbdfd71681a069eb2de283f32c11f859d7bcf93da23990d3e662935ed4d6b39ce3673ec84472a0203d26456312bbc4da5cd293b75b840fc5045e493d6f904d180823ec22bfed8ea09287b5c21f2254af4e64fca76acc5cd87399c7f1ede818db4326c98ce2dc2208a06fc2d754e304c48ce6a517753c62b1a9c1d5925b89707486d7fc08919e0a94eca07b1c54f15e299bd58bdfef9741538c7828b5d7d11a489f9c20d052b3471df475a051f9dd3739a927c89e357580a4c97b40234aa01ed3d5e0390dc982a7975880a0a089d613f26159af43616fd9455bb461f4869bfede26f2130835ed067a8b967bfb80").unwrap();

        let decoded_node: MerkleNode = MerkleNode::decode(&Rlp::new(&buffer));
        println!("{:?}", decoded_node);

        let buffer: Vec<u8> = read_hex("f90211a0e45a9e85cab1b6eb18b30df2c6acc448bbac6a30d81646823b31223e16e5063ea033bd7171d556b981f6849064eb09412b24fedc0812127db936067043f53db1b9a0ca56945f074da4f15587404593faf3a50d17ea0e21a418ad6ec99bdf4bf3f914a0da23e9004f782df128eea1adff77952dc85f91b7f7ca4893aac5f21d24c3a1c9a0ba5ec61fa780ee02af19db99677c37560fc4f0df5c278d9dfa2837f30f72bc6ba08310ad91625c2e3429a74066b7e2e0c958325e4e7fa3ec486b73b7c8300cfef7a0732e5c103bf4d5adfef83773026809d9405539b67e93293a02342e83ad2fb766a030d14ff0c2aab57d1fbaf498ab14519b4e9d94f149a3dc15f0eec5adf8df25e1a038f4db0ccaf2e3ecefec2c38e903dfc52033806102d36fd2b9aa21ef56811155a05a43bd92e55aa78df60e70b6b53b6366c4080fd6a5bdd7b533b46aff4a75f6f2a0a0c410aa59efe416b1213166fab680ce330bd46c3ebf877ff14609ee6a383600a02f41e918786e557293068b1eda9b3f9f86ed4e65a6a5363ee3262109f6e08b17a001f42a40f02f6f24bb97b09c4d3934e8b03be7cfbb902acc1c8fd67a7a5abacea00acbdce2787a6ea177209bd13bfc9d0779d7e2b5249e0211a2974164e14312f5a0dadbe113e4132e0c0c3cd4867e0a2044d0e5a3d44b350677ed42fc9244d004d4a0aa7441fefc17d76aedfcaf692fe71014b94c1547b6d129562b34fc5995ca0d1a80").unwrap();

        let decoded_node: MerkleNode = MerkleNode::decode(&Rlp::new(&buffer));
        println!("{:?}", decoded_node);

        let buffer: Vec<u8> = read_hex("f90211a0321ce3dbefd6bbfe3eb0ec01e69c8c02defaecee55c35537fb17cfdaa61fea01a0c9070d92ac06f82c774d835ceb0b8f9d5babaaba72780ddcfc61899169c1429fa0cf8a4080cfae61e14f66c4dbbaa0e030e1ae628a1c5d567d2a218ed518a11f1ba059bbb3d53d72247af6b96b293057b1bd4b3e33e16a43bb987ac5b39b66c0df88a021836f56fd3379012136afb8bac3fa129009a53ac690092f726e58f7e3744303a06e4756bcdc63adb15284916232daf199220135dbd4e6c301c34aeb87d01794a9a036ed834810103f7fea46a26c02268c55e1c3643704cba91051b7067fdf2a64c4a00b9124a8a02b8b0032563e77ec01d099890c56436ba6fd130510945d9d2ef349a07ef214478b630bc0da414808b3ccc35f283adafd729751bbfb2d3b1636691e90a0a92ceb11375bc0db2c7d8bf277b0759e509ff551b9f3690c747cef59a3344636a07527bb8c0749ec0984759716c16ff8a822b76e79910291599a0870c7b30b39f5a0970e4426ce35ea36a11a3951fa77e6af6e710cb2db92362e1d767af5fd942c13a0f84d7a19f192fbe04f0da9b912e354885cb2c40db429c40238ceb5f2f6038788a01f7b133e84b9424c37aa4b271f9656bb0087a540bc8e4dec719c68ec5b7293c7a012f648db1a3f1e4d83ffdc1bd6e8acd5b6da0003a64c0d291352e53b31beec44a077b20fce59bf2808791cb69d2082fa1a955445762949443d5ab7840e826c3d0c80").unwrap();

        let decoded_node: MerkleNode = MerkleNode::decode(&Rlp::new(&buffer));
        println!("{:?}", decoded_node);

        let buffer: Vec<u8> = read_hex("f891808080a069185a88d266c54bc344b5bc4e093d5a847bd97906497450983dba2d9b072051a0bcb5ffb5c6c3e43ef07550fa30af86d66b4015ee3f64aaf70cd0bf8fcc60a9c6a00e8b349222a19a50a7004fee229e44ac51a221138b57d16ab47394799e0fa93880a00870b212fc31ec828b7ca920135c60e43a882ae0ac4db260cb5b310e13c963e6808080808080808080").unwrap();

        let decoded_node: MerkleNode = MerkleNode::decode(&Rlp::new(&buffer));
        println!("{:?}", decoded_node);

        let buffer: Vec<u8> = read_hex("f8719f2088c5ba62b0e7342687d94b0e03b772aa4ab7c08f13fe3fa9f9d0a3153e05b84ff84d8089194608686316bd8000a056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421a0c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470").unwrap();

        let decoded_node: MerkleNode = MerkleNode::decode(&Rlp::new(&buffer));
        println!("{:?}", decoded_node);

        let buffer: Vec<u8> = read_hex("f8518080a07c91f9c7e481ccd6b98f04de0b387d09310628d5bb41e9c2dadd57fb7c97d51c80808080808080a095c578616ce6c2990245aa5c8731e5df9ae9c6d7032bf667b874ced7740816ce808080808080").unwrap();

        let decoded_node: MerkleNode = MerkleNode::decode(&Rlp::new(&buffer));
        println!("{:?}", decoded_node);

        let buffer: Vec<u8> = read_hex("e98080a07c91f9c7e481ccd6b98f04de0b387d09310628d5bb41e9c2dadd57fb7c97d51c80808080808080a095c578616ce6c2990245aa5c8731e5df9ae9c6d7032bf667b874ced7740816ce808080808080").unwrap();

        let decoded_node: MerkleNode = MerkleNode::decode(&Rlp::new(&buffer));
        println!("{:?}", decoded_node);

        let buffer: Vec<u8> = read_hex("f8719e304188718653cd7e50f3fd51a820db66112517ca190c637e7cdd80782d56b850f84e808a152d02c7e14af6800000a056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421a0c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470").unwrap();

        let decoded_node: MerkleNode = MerkleNode::decode(&Rlp::new(&buffer));
        println!("{:?}", decoded_node);

        let buffer: Vec<u8> = read_hex("f8709e3390953f116afb00f89fbedb2f8e77297e4e7e1749e2ef0e32e17808e4adb84ff84d80896c6b935b8bbd400000a056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421a0c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470").unwrap();

        let decoded_node: MerkleNode = MerkleNode::decode(&Rlp::new(&buffer));
        println!("{:?}", decoded_node);
    }
}
