/// Tests `MerkleTree::leaf_len()`.
macro_rules! test_tree_leaf_len {
    ($mod:ident, $hash_size:ty, $hasher:ty) => {
        mod $mod {
            use std::iter;

            use digest::generic_array::GenericArray;
            use digest::typenum;

            use merkle_lite::MerkleTree;

            #[test]
            fn tree_leaf_len_even() {
                for leaf_len in (0..200) {
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

test_tree_leaf_len!(sha2_224, typenum::U28, sha2::Sha224);
test_tree_leaf_len!(sha2_256, typenum::U32, sha2::Sha256);
test_tree_leaf_len!(sha2_384, typenum::U48, sha2::Sha384);
test_tree_leaf_len!(sha2_512, typenum::U64, sha2::Sha512);
test_tree_leaf_len!(sha3_224, typenum::U28, sha3::Sha3_224);
test_tree_leaf_len!(sha3_256, typenum::U32, sha3::Sha3_256);
test_tree_leaf_len!(sha3_384, typenum::U48, sha3::Sha3_384);
test_tree_leaf_len!(sha3_512, typenum::U64, sha3::Sha3_512);
