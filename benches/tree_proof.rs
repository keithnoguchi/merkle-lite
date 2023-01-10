//! [`MerkleTree::proof`] Benchmark
//!
//! [`merkletree::proof`]: https://docs.rs/merkle-lite/latest/merkle_lite/struct.MerkleTree.html#method.proof
#[macro_use]
extern crate bencher;

use bencher::Bencher;

use digest::generic_array::{ArrayLength, GenericArray};
use digest::{typenum, Digest, OutputSizeUser};
use merkle_lite::MerkleTree;

const NR_LEAVES: usize = 100_000;
const PROOF_LEAF_INDICES: [std::ops::Range<usize>; 5] =
    [0..2, 101..109, 90_098..90_102, 8_928..8_929, 35..36];

benchmark_main!(sha2, sha3);

// With [SHA2] hash functions.
//
// [sha2]: https://crates.io/crates/sha3
benchmark_group!(
    sha2,
    tree_proof::<typenum::U28, sha2::Sha224>,
    tree_proof::<typenum::U32, sha2::Sha256>,
    tree_proof::<typenum::U48, sha2::Sha384>,
    tree_proof::<typenum::U64, sha2::Sha512>,
);

// With [SHA3] hash functions.
//
// [sha3]: https://crates.io/crates/sha3
benchmark_group!(
    sha3,
    tree_proof::<typenum::U28, sha3::Sha3_224>,
    tree_proof::<typenum::U32, sha3::Sha3_256>,
    tree_proof::<typenum::U48, sha3::Sha3_384>,
    tree_proof::<typenum::U64, sha3::Sha3_512>,
);

fn tree_proof<N, B>(b: &mut Bencher)
where
    N: ArrayLength<u8>,
    B: Digest,
    <N as ArrayLength<u8>>::ArrayType: Copy,
    <<B as OutputSizeUser>::OutputSize as ArrayLength<u8>>::ArrayType: Copy,
{
    let leaves = [GenericArray::<u8, N>::default(); NR_LEAVES];
    let proof_leaf_indices: Vec<_> = PROOF_LEAF_INDICES.into_iter().flatten().collect();

    // compose the Merkle tree from the leaves.
    let tree = MerkleTree::<B>::from_iter(leaves.iter());

    b.iter(|| {
        // get the Merkle proof.
        let _proof = tree.proof(&proof_leaf_indices).unwrap();
    })
}
