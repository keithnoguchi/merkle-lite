/// Tests `MerkleTree::depth()`.
macro_rules! test_tree_leaf_len {
    ($mod:ident, $hash_size:ty, $hasher:ty) => {
        mod $mod {
            use std::iter;

            use digest::generic_array::GenericArray;
            use digest::typenum;

            use merkle_lite::MerkleTree;

            #[test]
            fn tree_depth() {
                vec![
                    (0, 0),
                    (1, 1),
                    (2, 2),
                    (3, 3),
                    (4, 3),
                    (5, 4),
                    (6, 4),
                    (7, 4),
                    (8, 4),
                    (9, 5),
                ]
                .into_iter()
                .for_each(|(leaf_len, tree_depth)| {
                    let tree: MerkleTree<$hasher> =
                        iter::repeat(GenericArray::<u8, $hash_size>::default())
                            .take(leaf_len)
                            .collect();

                    assert_eq!(tree.depth(), tree_depth, "leaf_len={leaf_len}");
                });
            }
        }
    };
}

test_tree_leaf_len!(sha3_256, typenum::U32, sha3::Sha3_256);
