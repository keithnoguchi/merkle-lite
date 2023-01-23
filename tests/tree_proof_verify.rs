/// Tests `MerkleTree::proof()` and MerkleProof::verify()`.
macro_rules! test_tree_proof_verify {
    ($mod:ident, $hash_size:ty, $hasher:ty, $leaf_len:expr, $leaf_indices:expr) => {
        mod $mod {
            use std::iter;

            use digest::generic_array::GenericArray;
            use digest::typenum;
            use rand_core::RngCore;

            use merkle_lite::MerkleTree;

            #[test]
            fn tree_proof_verify() {
                // Create a Merkle tree.
                let tree: MerkleTree<$hasher> =
                    iter::repeat(GenericArray::<u8, $hash_size>::default())
                        .take($leaf_len)
                        .map(|mut leaf| {
                            rand_core::OsRng.fill_bytes(&mut leaf);
                            leaf
                        })
                        .collect();

                // Tests the Merkle root.
                let tree_leaves = tree.get_leaves();
                let leaf_indices: Vec<_> = $leaf_indices.into_iter().flatten().collect();
                let leaf_hash: Vec<_> = leaf_indices
                    .iter()
                    .map(|index| (*index, tree_leaves[*index]))
                    .collect();
                assert_eq!(
                    tree.proof(&leaf_indices)
                        .expect("proof")
                        .verify(&leaf_hash)
                        .expect("verify")
                        .as_ref(),
                    tree.root().expect("root"),
                );
            }
        }
    };
}

test_tree_proof_verify!(sha2_256_0001_0, typenum::U32, sha2::Sha256, 1, [0..1]);
test_tree_proof_verify!(sha3_256_0001_0, typenum::U32, sha3::Sha3_256, 1, [0..1]);
test_tree_proof_verify!(sha2_256_0002_0, typenum::U32, sha2::Sha256, 2, [0..1]);
test_tree_proof_verify!(sha3_256_0002_0, typenum::U32, sha3::Sha3_256, 2, [0..1]);
test_tree_proof_verify!(sha2_256_0002_1, typenum::U32, sha2::Sha256, 2, [1..2]);
test_tree_proof_verify!(sha3_256_0002_1, typenum::U32, sha3::Sha3_256, 2, [1..2]);
test_tree_proof_verify!(sha2_256_0002_0_1, typenum::U32, sha2::Sha256, 2, [0..2]);
test_tree_proof_verify!(sha3_256_0002_0_1, typenum::U32, sha3::Sha3_256, 2, [0..2]);
test_tree_proof_verify!(sha2_256_0003_0, typenum::U32, sha2::Sha256, 3, [0..1]);
test_tree_proof_verify!(sha3_256_0003_0, typenum::U32, sha3::Sha3_256, 3, [0..1]);
test_tree_proof_verify!(sha2_256_0003_1, typenum::U32, sha2::Sha256, 3, [1..2]);
test_tree_proof_verify!(sha3_256_0003_1, typenum::U32, sha3::Sha3_256, 3, [1..2]);
test_tree_proof_verify!(sha2_256_0003_2, typenum::U32, sha2::Sha256, 3, [2..3]);
test_tree_proof_verify!(sha3_256_0003_2, typenum::U32, sha3::Sha3_256, 3, [2..3]);
test_tree_proof_verify!(sha2_256_0003_0_1, typenum::U32, sha2::Sha256, 3, [0..2]);
test_tree_proof_verify!(sha3_256_0003_0_1, typenum::U32, sha3::Sha3_256, 3, [0..2]);
test_tree_proof_verify!(sha2_256_0003_1_2, typenum::U32, sha2::Sha256, 3, [1..3]);
test_tree_proof_verify!(sha3_256_0003_1_2, typenum::U32, sha3::Sha3_256, 3, [1..3]);
test_tree_proof_verify!(
    sha2_256_0003_0_2,
    typenum::U32,
    sha2::Sha256,
    3,
    [0..1, 2..3]
);
test_tree_proof_verify!(
    sha3_256_0003_0_2,
    typenum::U32,
    sha3::Sha3_256,
    3,
    [0..1, 2..3]
);
test_tree_proof_verify!(sha2_256_0003_0_1_2, typenum::U32, sha2::Sha256, 3, [0..3]);
test_tree_proof_verify!(sha3_256_0003_0_1_2, typenum::U32, sha3::Sha3_256, 3, [0..3]);
test_tree_proof_verify!(sha2_256_0004_0, typenum::U32, sha2::Sha256, 4, [0..1]);
test_tree_proof_verify!(sha3_256_0004_0, typenum::U32, sha3::Sha3_256, 4, [0..1]);
test_tree_proof_verify!(sha2_256_0004_1, typenum::U32, sha2::Sha256, 4, [1..2]);
test_tree_proof_verify!(sha3_256_0004_1, typenum::U32, sha3::Sha3_256, 4, [1..2]);
test_tree_proof_verify!(sha2_256_0004_2, typenum::U32, sha2::Sha256, 4, [2..3]);
test_tree_proof_verify!(sha3_256_0004_2, typenum::U32, sha3::Sha3_256, 4, [2..3]);
test_tree_proof_verify!(sha2_256_0004_3, typenum::U32, sha2::Sha256, 4, [3..4]);
test_tree_proof_verify!(sha3_256_0004_3, typenum::U32, sha3::Sha3_256, 4, [3..4]);
test_tree_proof_verify!(sha2_256_0004_0_1, typenum::U32, sha2::Sha256, 4, [0..2]);
test_tree_proof_verify!(sha3_256_0004_0_1, typenum::U32, sha3::Sha3_256, 4, [0..2]);
test_tree_proof_verify!(sha2_256_0004_1_2, typenum::U32, sha2::Sha256, 4, [1..3]);
test_tree_proof_verify!(sha3_256_0004_1_2, typenum::U32, sha3::Sha3_256, 4, [1..3]);
test_tree_proof_verify!(sha2_256_0004_2_3, typenum::U32, sha2::Sha256, 4, [2..4]);
test_tree_proof_verify!(sha3_256_0004_2_3, typenum::U32, sha3::Sha3_256, 4, [2..4]);
test_tree_proof_verify!(
    sha2_256_0004_0_2,
    typenum::U32,
    sha2::Sha256,
    4,
    [0..1, 2..3]
);
test_tree_proof_verify!(
    sha3_256_0004_0_2,
    typenum::U32,
    sha3::Sha3_256,
    4,
    [0..1, 2..3]
);
test_tree_proof_verify!(
    sha2_256_0004_1_3,
    typenum::U32,
    sha2::Sha256,
    4,
    [1..2, 3..4]
);
test_tree_proof_verify!(
    sha3_256_0004_1_3,
    typenum::U32,
    sha3::Sha3_256,
    4,
    [1..2, 3..4]
);
test_tree_proof_verify!(sha2_256_0004_0_1_2, typenum::U32, sha2::Sha256, 4, [0..3]);
test_tree_proof_verify!(sha3_256_0004_0_1_2, typenum::U32, sha3::Sha3_256, 4, [0..3]);
test_tree_proof_verify!(sha2_256_0004_1_2_3, typenum::U32, sha2::Sha256, 4, [1..4]);
test_tree_proof_verify!(sha3_256_0004_1_2_3, typenum::U32, sha3::Sha3_256, 4, [1..4]);
test_tree_proof_verify!(sha2_256_0004_0_1_2_3, typenum::U32, sha2::Sha256, 4, [0..4]);
test_tree_proof_verify!(
    sha3_256_0004_0_1_2_3,
    typenum::U32,
    sha3::Sha3_256,
    4,
    [0..4]
);
test_tree_proof_verify!(sha2_256_0005_0, typenum::U32, sha2::Sha256, 5, [0..1]);
test_tree_proof_verify!(sha3_256_0005_0, typenum::U32, sha3::Sha3_256, 5, [0..1]);
test_tree_proof_verify!(sha2_256_0005_1, typenum::U32, sha2::Sha256, 5, [1..2]);
test_tree_proof_verify!(sha3_256_0005_1, typenum::U32, sha3::Sha3_256, 5, [1..2]);
test_tree_proof_verify!(sha2_256_0005_2, typenum::U32, sha2::Sha256, 5, [2..3]);
test_tree_proof_verify!(sha3_256_0005_2, typenum::U32, sha3::Sha3_256, 5, [2..3]);
test_tree_proof_verify!(sha2_256_0005_3, typenum::U32, sha2::Sha256, 5, [3..4]);
test_tree_proof_verify!(sha3_256_0005_3, typenum::U32, sha3::Sha3_256, 5, [3..4]);
test_tree_proof_verify!(sha2_256_0005_4, typenum::U32, sha2::Sha256, 5, [4..5]);
test_tree_proof_verify!(sha3_256_0005_4, typenum::U32, sha3::Sha3_256, 5, [4..5]);
test_tree_proof_verify!(sha2_256_0005_0_1, typenum::U32, sha2::Sha256, 5, [0..2]);
test_tree_proof_verify!(sha3_256_0005_0_1, typenum::U32, sha3::Sha3_256, 5, [0..2]);
test_tree_proof_verify!(sha2_256_0005_1_2, typenum::U32, sha2::Sha256, 5, [1..3]);
test_tree_proof_verify!(sha3_256_0005_1_2, typenum::U32, sha3::Sha3_256, 5, [1..3]);
test_tree_proof_verify!(sha2_256_0005_2_3, typenum::U32, sha2::Sha256, 5, [2..4]);
test_tree_proof_verify!(sha3_256_0005_2_3, typenum::U32, sha3::Sha3_256, 5, [2..4]);
test_tree_proof_verify!(sha2_256_0005_3_4, typenum::U32, sha2::Sha256, 5, [3..5]);
test_tree_proof_verify!(sha3_256_0005_3_4, typenum::U32, sha3::Sha3_256, 5, [3..5]);
test_tree_proof_verify!(
    sha2_256_0005_0_2,
    typenum::U32,
    sha2::Sha256,
    5,
    [0..1, 2..3]
);
test_tree_proof_verify!(
    sha3_256_0005_0_2,
    typenum::U32,
    sha3::Sha3_256,
    5,
    [0..1, 2..3]
);
test_tree_proof_verify!(
    sha2_256_0005_1_3,
    typenum::U32,
    sha2::Sha256,
    5,
    [1..2, 3..4]
);
test_tree_proof_verify!(
    sha3_256_0005_1_3,
    typenum::U32,
    sha3::Sha3_256,
    5,
    [1..2, 3..4]
);
test_tree_proof_verify!(
    sha2_256_0005_2_4,
    typenum::U32,
    sha2::Sha256,
    5,
    [2..3, 4..5]
);
test_tree_proof_verify!(
    sha3_256_0005_2_4,
    typenum::U32,
    sha3::Sha3_256,
    5,
    [2..3, 4..5]
);
test_tree_proof_verify!(sha2_256_0005_0_1_2, typenum::U32, sha2::Sha256, 5, [0..3]);
test_tree_proof_verify!(sha3_256_0005_0_1_2, typenum::U32, sha3::Sha3_256, 5, [0..3]);
test_tree_proof_verify!(sha2_256_0005_1_2_3, typenum::U32, sha2::Sha256, 5, [1..4]);
test_tree_proof_verify!(sha3_256_0005_1_2_3, typenum::U32, sha3::Sha3_256, 5, [1..4]);
test_tree_proof_verify!(sha2_256_0005_2_3_4, typenum::U32, sha2::Sha256, 5, [2..5]);
test_tree_proof_verify!(sha3_256_0005_2_3_4, typenum::U32, sha3::Sha3_256, 5, [2..5]);
test_tree_proof_verify!(
    sha2_256_0005_0_2_3,
    typenum::U32,
    sha2::Sha256,
    5,
    [0..1, 2..4]
);
test_tree_proof_verify!(
    sha3_256_0005_0_2_3,
    typenum::U32,
    sha3::Sha3_256,
    5,
    [0..1, 2..4]
);
test_tree_proof_verify!(
    sha2_256_0005_0_3_4,
    typenum::U32,
    sha2::Sha256,
    5,
    [0..1, 3..5]
);
test_tree_proof_verify!(
    sha3_256_0005_0_3_4,
    typenum::U32,
    sha3::Sha3_256,
    5,
    [0..1, 3..5]
);
test_tree_proof_verify!(
    sha2_256_0005_1_3_4,
    typenum::U32,
    sha2::Sha256,
    5,
    [1..2, 3..5]
);
test_tree_proof_verify!(
    sha3_256_0005_1_3_4,
    typenum::U32,
    sha3::Sha3_256,
    5,
    [1..2, 3..5]
);
test_tree_proof_verify!(sha2_256_0005_0_1_2_3, typenum::U32, sha2::Sha256, 5, [0..4]);
test_tree_proof_verify!(
    sha3_256_0005_0_1_2_3,
    typenum::U32,
    sha3::Sha3_256,
    5,
    [0..4]
);
test_tree_proof_verify!(
    sha2_256_0005_0_1_3_4,
    typenum::U32,
    sha2::Sha256,
    5,
    [0..2, 3..5]
);
test_tree_proof_verify!(
    sha3_256_0005_0_1_3_4,
    typenum::U32,
    sha3::Sha3_256,
    5,
    [0..2, 3..5]
);
test_tree_proof_verify!(
    sha2_256_0005_0_2_3_4,
    typenum::U32,
    sha2::Sha256,
    5,
    [0..1, 2..5]
);
test_tree_proof_verify!(
    sha3_256_0005_0_2_3_4,
    typenum::U32,
    sha3::Sha3_256,
    5,
    [0..1, 2..5]
);
test_tree_proof_verify!(sha2_256_0005_1_2_3_4, typenum::U32, sha2::Sha256, 5, [1..5]);
test_tree_proof_verify!(
    sha3_256_0005_1_2_3_4,
    typenum::U32,
    sha3::Sha3_256,
    5,
    [1..5]
);
test_tree_proof_verify!(
    sha2_256_0005_0_1_2_3_4,
    typenum::U32,
    sha2::Sha256,
    5,
    [0..5]
);
test_tree_proof_verify!(
    sha3_256_0005_0_1_2_3_4,
    typenum::U32,
    sha3::Sha3_256,
    5,
    [0..5]
);

test_tree_proof_verify!(sha2_256_1000_0, typenum::U32, sha2::Sha256, 1000, [0..1]);
test_tree_proof_verify!(sha3_256_1000_0, typenum::U32, sha3::Sha3_256, 1000, [0..1]);
test_tree_proof_verify!(sha2_256_1001_0, typenum::U32, sha2::Sha256, 1001, [0..1]);
test_tree_proof_verify!(sha3_256_1001_0, typenum::U32, sha3::Sha3_256, 1001, [0..1]);
test_tree_proof_verify!(
    sha2_256_1000_999,
    typenum::U32,
    sha2::Sha256,
    1000,
    [999..1000]
);
test_tree_proof_verify!(
    sha3_256_1000_999,
    typenum::U32,
    sha3::Sha3_256,
    1000,
    [999..1000]
);
test_tree_proof_verify!(
    sha2_256_1001_1000,
    typenum::U32,
    sha2::Sha256,
    1001,
    [1000..1001]
);
test_tree_proof_verify!(
    sha3_256_1001_1000,
    typenum::U32,
    sha3::Sha3_256,
    1001,
    [1000..1001]
);
test_tree_proof_verify!(
    sha2_256_1000_0_999,
    typenum::U32,
    sha2::Sha256,
    1000,
    [0..1, 999..1000]
);
test_tree_proof_verify!(
    sha3_256_1000_0_999,
    typenum::U32,
    sha3::Sha3_256,
    1000,
    [0..1, 999..1000]
);
test_tree_proof_verify!(
    sha2_256_1001_0_999,
    typenum::U32,
    sha2::Sha256,
    1001,
    [0..1, 999..1000]
);
test_tree_proof_verify!(
    sha3_256_1001_0_999,
    typenum::U32,
    sha3::Sha3_256,
    1001,
    [0..1, 999..1000]
);
test_tree_proof_verify!(
    sha2_256_1001_0_1000,
    typenum::U32,
    sha2::Sha256,
    1001,
    [0..1, 1000..1001]
);
test_tree_proof_verify!(
    sha3_256_1001_0_1000,
    typenum::U32,
    sha3::Sha3_256,
    1001,
    [0..1, 1000..1001]
);
