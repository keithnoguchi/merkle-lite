/// Tests `MerkleTree::leaf_len()`.
macro_rules! test_tree_leaf_len {
    ($mod:ident, $hash_size:ty, $hasher:ty) => {
        mod $mod {
            use std::iter;

            use digest::generic_array::GenericArray;
            use digest::typenum;

            use merkle_lite::MerkleTree;

            #[test]
            fn tree_leaf_len() {
                for leaf_len in 0..200 {
                    let tree: MerkleTree<$hasher> =
                        iter::repeat(GenericArray::<u8, $hash_size>::default())
                            .take(leaf_len)
                            .collect();

                    assert_eq!(tree.leaf_len(), leaf_len);
                }
            }
        }
    };
}

test_tree_leaf_len!(sha3_256, typenum::U32, sha3::Sha3_256);
