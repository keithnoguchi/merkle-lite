/// Tests `MerkleTree::len()`.
macro_rules! test_tree_leaf_len {
    ($mod:ident, $hash_size:ty, $hasher:ty) => {
        mod $mod {
            use std::iter;

            use digest::generic_array::GenericArray;
            use digest::typenum;

            use merkle_lite::MerkleTree;

            #[test]
            fn tree_len() {
                vec![
                    (0, 0),
                    (1, 1),
                    (2, 2 + 1),
                    (3, 3 + 2 + 1),
                    (4, 4 + 2 + 1),
                    (5, 5 + 3 + 2 + 1),
                    (6, 6 + 3 + 2 + 1),
                    (7, 7 + 4 + 2 + 1),
                    (8, 8 + 4 + 2 + 1),
                    (9, 9 + 5 + 3 + 2 + 1),
                ]
                .into_iter()
                .for_each(|(leaf_len, tree_len)| {
                    let tree: MerkleTree<$hasher> =
                        iter::repeat(GenericArray::<u8, $hash_size>::default())
                            .take(leaf_len)
                            .collect();

                    assert_eq!(tree.len(), tree_len, "leaf_len={leaf_len}");
                });
            }
        }
    };
}

test_tree_leaf_len!(sha2_224, typenum::U28, sha2::Sha224);
