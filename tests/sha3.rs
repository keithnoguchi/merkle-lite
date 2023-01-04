use std::iter;

use merkle_lite::MerkleTree;
use sha3::Sha3_256;

#[test]
fn tree_leaf_len_single() {
    let leaves = [[0u8; 32]];

    let tree = MerkleTree::<Sha3_256>::from_iter(leaves.iter());
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

        let tree: MerkleTree<Sha3_256> = leaves.iter().collect();
        assert_eq!(tree.leaf_len(), leaves.len() + 1);
    }
}
