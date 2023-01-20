/// Tests `MerkleTree::root()`.
///
/// Identical leaves to keep the number of Merkle root sane.
macro_rules! test_tree_root {
    ($mod:ident, $hasher:ty, $single_leaf_hash:expr, $merkle_root_in_depth:expr) => {
        mod $mod {
            use std::collections::HashMap;
            use std::iter;

            use hex_literal::hex;
            use merkle_lite::MerkleTree;

            #[test]
            fn tree_root() {
                let merkle_root_in_depth: HashMap<_, _> =
                    $merkle_root_in_depth.into_iter().collect();

                for leaf_len in 1..129 {
                    // Create a Merkle tree.
                    let tree: MerkleTree<$hasher> =
                        iter::repeat($single_leaf_hash).take(leaf_len).collect();

                    // Tests the Merkle root.
                    let root = tree.root().unwrap();
                    let depth = tree.depth();
                    assert_eq!(
                        root, merkle_root_in_depth[&depth],
                        "leaf_len={leaf_len}, tree_depth={depth}, tree_root={root:02x?}",
                    );
                }
            }
        }
    };
}

test_tree_root!(
    sha2_256,
    sha2::Sha256,
    [0xab_u8; 32],
    [
        (1, [0xab_u8; 32]),
        (
            2,
            hex!("ec65c8798ecf95902413c40f7b9e6d4b0068885f5f324aba1f9ba1c8e14aea61"),
        ),
        (
            3,
            hex!("582d4fc79f5ea22ea3f81072bf24e12409881b49978f718486781b8e29bfbb61"),
        ),
        (
            4,
            hex!("8621f76f2a5d27ddccdf5aeaa39b7b35a2e625c029a2b2a5bcc8f02525fce2be"),
        ),
        (
            5,
            hex!("2632549cdae005145bc70225e86d402c112242712c3917b2a3fb2255ad9c159c"),
        ),
        (
            6,
            hex!("138002e52084766c3cd6c159cc68f05257394fecd04e4879431dd2df91bc4fe0"),
        ),
        (
            7,
            hex!("1aa696eb97aa5e89b87afba58c118776e0b80c54bd782569a85189351d619116"),
        ),
        (
            8,
            hex!("1c1b786d9394587956b9cd5762ee3f2c000b39e2613ebf8aabc054407a877e80"),
        ),
    ]
);
test_tree_root!(
    sha3_256,
    sha3::Sha3_256,
    [0xab_u8; 32],
    [
        (1, [0xab_u8; 32]),
        (
            2,
            hex!("699fc94ff1ec83f1abf531030e324003e7758298281645245f7c698425a5e0e7"),
        ),
        (
            3,
            hex!("a2422433244a1da24b3c4db126dcc593666f98365403e6aaf07fae011c824f09"),
        ),
        (
            4,
            hex!("ec46a8dbc7fb0da5753b11f3ff04ee6b7a2a979b168025d40394a0ff4cf2df59"),
        ),
        (
            5,
            hex!("34fac4b8781d0b811746ec45623606f43df1a8b9009f89c5564e68025a6fd604"),
        ),
        (
            6,
            hex!("b8b1810f54c4048913090d78983712bd54cd4bae4e236be1f294122388abef6b"),
        ),
        (
            7,
            hex!("4a011043594c8c029ec6141932c555b99c464ab75734027aeb968ed87fd5275c"),
        ),
        (
            8,
            hex!("90029acbe3254c63bc9dd4a8f1e4b8e27b4445bb5e5a5897af9251ec744f6f68"),
        ),
    ]
);
