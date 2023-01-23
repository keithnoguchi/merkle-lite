//! [`MerkleTree::get_leaves_mut`] Benchmark
//!
//! [`merkletree::get_leaves_mut`]: https://docs.rs/merkle-lite/latest/merkle_lite/struct.MerkleTree.html#get_leaves_mut
#[macro_use]
extern crate bencher;

use bencher::Bencher;

use digest::generic_array::{ArrayLength, GenericArray};
use digest::{typenum, Digest, OutputSizeUser};
use merkle_lite::MerkleTree;

const NR_LEAVES: usize = 100_000;
const NR_LEAVES_CHANGE_DENSE_STEP: usize = NR_LEAVES / 100; // 100 changes total.
const NR_LEAVES_CHANGE_SPARSE_STEP: usize = NR_LEAVES / 10; //  10 changes total.

benchmark_main!(sha2, sha3);

// With [SHA2] hash functions.
//
// [sha2]: https://crates.io/crates/sha3
benchmark_group!(
    sha2,
    tree_get_leaves_mut_all::<typenum::U28, sha2::Sha224>,
    tree_get_leaves_mut_all::<typenum::U32, sha2::Sha256>,
    tree_get_leaves_mut_all::<typenum::U48, sha2::Sha384>,
    tree_get_leaves_mut_all::<typenum::U64, sha2::Sha512>,
    tree_get_leaves_mut_dense::<typenum::U28, sha2::Sha224>,
    tree_get_leaves_mut_dense::<typenum::U32, sha2::Sha256>,
    tree_get_leaves_mut_dense::<typenum::U48, sha2::Sha384>,
    tree_get_leaves_mut_dense::<typenum::U64, sha2::Sha512>,
    tree_get_leaves_mut_sparse::<typenum::U28, sha2::Sha224>,
    tree_get_leaves_mut_sparse::<typenum::U32, sha2::Sha256>,
    tree_get_leaves_mut_sparse::<typenum::U48, sha2::Sha384>,
    tree_get_leaves_mut_sparse::<typenum::U64, sha2::Sha512>,
);

// With [SHA3] hash functions.
//
// [sha3]: https://crates.io/crates/sha3
benchmark_group!(
    sha3,
    tree_get_leaves_mut_all::<typenum::U28, sha3::Sha3_224>,
    tree_get_leaves_mut_all::<typenum::U32, sha3::Sha3_256>,
    tree_get_leaves_mut_all::<typenum::U48, sha3::Sha3_384>,
    tree_get_leaves_mut_all::<typenum::U64, sha3::Sha3_512>,
    tree_get_leaves_mut_dense::<typenum::U28, sha3::Sha3_224>,
    tree_get_leaves_mut_dense::<typenum::U32, sha3::Sha3_256>,
    tree_get_leaves_mut_dense::<typenum::U48, sha3::Sha3_384>,
    tree_get_leaves_mut_dense::<typenum::U64, sha3::Sha3_512>,
    tree_get_leaves_mut_sparse::<typenum::U28, sha3::Sha3_224>,
    tree_get_leaves_mut_sparse::<typenum::U32, sha3::Sha3_256>,
    tree_get_leaves_mut_sparse::<typenum::U48, sha3::Sha3_384>,
    tree_get_leaves_mut_sparse::<typenum::U64, sha3::Sha3_512>,
);

fn tree_get_leaves_mut_all<N, B>(b: &mut Bencher)
where
    N: ArrayLength<u8>,
    B: Digest + OutputSizeUser<OutputSize = N>,
    <N as ArrayLength<u8>>::ArrayType: Copy,
    <<B as OutputSizeUser>::OutputSize as ArrayLength<u8>>::ArrayType: Copy,
{
    tree_get_leaves_mut_step::<N, B>(b, 1);
}

fn tree_get_leaves_mut_dense<N, B>(b: &mut Bencher)
where
    N: ArrayLength<u8>,
    B: Digest + OutputSizeUser<OutputSize = N>,
    <N as ArrayLength<u8>>::ArrayType: Copy,
    <<B as OutputSizeUser>::OutputSize as ArrayLength<u8>>::ArrayType: Copy,
{
    tree_get_leaves_mut_step::<N, B>(b, NR_LEAVES_CHANGE_DENSE_STEP);
}

fn tree_get_leaves_mut_sparse<N, B>(b: &mut Bencher)
where
    N: ArrayLength<u8>,
    B: Digest + OutputSizeUser<OutputSize = N>,
    <N as ArrayLength<u8>>::ArrayType: Copy,
    <<B as OutputSizeUser>::OutputSize as ArrayLength<u8>>::ArrayType: Copy,
{
    tree_get_leaves_mut_step::<N, B>(b, NR_LEAVES_CHANGE_SPARSE_STEP);
}

fn tree_get_leaves_mut_step<N, B>(b: &mut Bencher, step: usize)
where
    N: ArrayLength<u8>,
    B: Digest + OutputSizeUser<OutputSize = N>,
    <N as ArrayLength<u8>>::ArrayType: Copy,
    <<B as OutputSizeUser>::OutputSize as ArrayLength<u8>>::ArrayType: Copy,
{
    let leaves = vec![GenericArray::<u8, N>::default(); NR_LEAVES];
    let mut tree = MerkleTree::<B>::from_iter(leaves.iter());

    b.iter(|| {
        {
            // Calculates the Merkle root with the single leaf change.
            let mut leaves_mut = tree.get_leaves_mut();
            for i in (0..NR_LEAVES).step_by(step) {
                leaves_mut[i] = GenericArray::<u8, N>::default();
            }
        }
        assert_eq!(tree.leaf_len(), NR_LEAVES);
    })
}
