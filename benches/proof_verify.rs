//! [`MerkleProof::verify`] Benchmark
//!
//! [`merkleproof::verify`]: https://docs.rs/merkle-lite/latest/merkle_lite/struct.MerkleProof.html#method.verify
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
    proof_verify::<typenum::U28, sha2::Sha224>,
    proof_verify::<typenum::U32, sha2::Sha256>,
    proof_verify::<typenum::U48, sha2::Sha384>,
    proof_verify::<typenum::U64, sha2::Sha512>,
);

// With [SHA3] hash functions.
//
// [sha3]: https://crates.io/crates/sha3
benchmark_group!(
    sha3,
    proof_verify::<typenum::U28, sha3::Sha3_224>,
    proof_verify::<typenum::U32, sha3::Sha3_256>,
    proof_verify::<typenum::U48, sha3::Sha3_384>,
    proof_verify::<typenum::U64, sha3::Sha3_512>,
);

fn proof_verify<N, B>(b: &mut Bencher)
where
    N: ArrayLength<u8>,
    B: Digest,
    <N as ArrayLength<u8>>::ArrayType: Copy,
    <<B as OutputSizeUser>::OutputSize as ArrayLength<u8>>::ArrayType: Copy,
{
    let leaves = [GenericArray::<u8, N>::default(); NR_LEAVES];
    let proof_leaf_indices: Vec<_> = PROOF_LEAF_INDICES.into_iter().flatten().collect();
    let proof_leaf_hashes: Vec<_> = proof_leaf_indices
        .iter()
        .map(|index| (*index, &leaves[*index]))
        .collect();

    // compose the Merkle tree from the leaves.
    let tree = MerkleTree::<B>::from_iter(leaves.iter());

    b.iter(|| {
        // verify the Merkle root for the proof of inclusion.
        assert_eq!(
            tree.proof(&proof_leaf_indices)
                .unwrap()
                .verify(&proof_leaf_hashes)
                .unwrap()
                .as_ref(),
            tree.root().unwrap(),
        );
    })
}
