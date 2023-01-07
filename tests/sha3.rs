use std::collections::HashMap;
use std::iter;

use hex_literal::hex;
use merkle_lite::MerkleTree;
use sha3::Sha3_256;

#[test]
fn tree_leaf_len_single() {
    let leaves = [[0u8; 32]];

    let tree: MerkleTree<Sha3_256> = leaves.iter().collect();
    assert_eq!(tree.leaf_len(), 1);
}

#[test]
fn tree_leaf_len_even() {
    for i in (0..100).step_by(2) {
        let leaves: Vec<_> = iter::repeat([0u8; 32]).take(i).collect();

        let tree: MerkleTree<Sha3_256> = leaves.iter().collect();
        assert_eq!(tree.leaf_len(), leaves.len());
    }
}

#[test]
fn tree_leaf_len_odd() {
    for i in (3..100).step_by(2) {
        let leaves: Vec<_> = iter::repeat([0u8; 32]).take(i).collect();

        // The last leaf is copied over to make the even leaves.
        let tree: MerkleTree<Sha3_256> = leaves.iter().collect();
        assert_eq!(tree.leaf_len(), leaves.len() + 1);
    }
}

#[test]
fn tree_root() {
    let merkle_root: HashMap<usize, [u8; 32]> = [
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
        (
            9,
            hex!("1489ad5e85ce2b6cbccfd2f25f8d63d115ff80199afbc4ec4f6fc2484bf8d690"),
        ),
        (
            10,
            hex!("c795494aa662dd012c5de6c52f0ab28ee9135fe846074d62bb7807cf98742fd9"),
        ),
    ]
    .into_iter()
    .collect();
    let leaf = [0xab_u8; 32];

    for tree_depth in 2..=10 {
        // try all the possible leaf length for the tree depth.
        let leaf_len_range = ((0b1 << (tree_depth - 2)) + 1)..((0b1 << (tree_depth - 1)) + 1);

        for leaf_len in leaf_len_range {
            let tree: MerkleTree<Sha3_256> = iter::repeat(leaf).take(leaf_len).collect();
            println!("{:02x?}", tree.root());
            assert_eq!(
                tree.root(),
                merkle_root[&tree_depth],
                "tree_depth={tree_depth}, leaf_len={leaf_len}",
            );
        }
    }
}

#[test]
fn tree_get_leaves_mut() {
    let merkle_root: HashMap<usize, [u8; 32]> = [
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
        (
            9,
            hex!("1489ad5e85ce2b6cbccfd2f25f8d63d115ff80199afbc4ec4f6fc2484bf8d690"),
        ),
        (
            10,
            hex!("c795494aa662dd012c5de6c52f0ab28ee9135fe846074d62bb7807cf98742fd9"),
        ),
    ]
    .into_iter()
    .collect();
    let leaf = [0xab_u8; 32];

    for tree_depth in 2..=10 {
        // try all the possible leaf length for the tree depth.
        let leaf_len_range = ((0b1 << (tree_depth - 2)) + 1)..((0b1 << (tree_depth - 1)) + 1);

        for leaf_len in leaf_len_range {
            let mut tree: MerkleTree<Sha3_256> = iter::repeat([0u8; 32]).take(leaf_len).collect();
            {
                let actual_leaf_len = tree.leaf_len();
                let mut leaves = tree.get_leaves_mut();
                (0..actual_leaf_len).for_each(|i| {
                    leaves[i] = leaf.into();
                });
            }
            assert_eq!(
                tree.root(),
                merkle_root[&tree_depth],
                "tree_depth={tree_depth}, leaf_len={leaf_len}",
            );
        }
    }
}
