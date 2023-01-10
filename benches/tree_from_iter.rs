//! [`MerkleTree::from_iter`] Benchmark
//!
//! [`merkletree::from_iter`]: https://doc.rust-lang.org/nightly/core/iter/trait.FromIterator.html#tymethod.from_iter
#[macro_use]
extern crate bencher;

use bencher::Bencher;

use digest::generic_array::{ArrayLength, GenericArray};
use digest::{typenum, Digest, OutputSizeUser};
use merkle_lite::MerkleTree;

const NR_LEAVES: usize = 100_000;

benchmark_main!(sha2, sha3);

// With [SHA2] hash functions.
//
// [sha2]: https://crates.io/crates/sha3
benchmark_group!(
    sha2,
    tree_from_iter::<typenum::U28, sha2::Sha224>,
    tree_from_iter::<typenum::U32, sha2::Sha256>,
    tree_from_iter::<typenum::U48, sha2::Sha384>,
    tree_from_iter::<typenum::U64, sha2::Sha512>,
);

// With [SHA3] hash functions.
//
// [sha3]: https://crates.io/crates/sha3
benchmark_group!(
    sha3,
    tree_from_iter::<typenum::U28, sha3::Sha3_224>,
    tree_from_iter::<typenum::U32, sha3::Sha3_256>,
    tree_from_iter::<typenum::U48, sha3::Sha3_384>,
    tree_from_iter::<typenum::U64, sha3::Sha3_512>,
);

fn tree_from_iter<N, B>(b: &mut Bencher)
where
    N: ArrayLength<u8>,
    B: Digest,
    <N as ArrayLength<u8>>::ArrayType: Copy,
    <<B as OutputSizeUser>::OutputSize as ArrayLength<u8>>::ArrayType: Copy,
{
    let leaves = [GenericArray::<u8, N>::default(); NR_LEAVES];

    b.iter(|| {
        // compose the Merkle tree from the leaves.
        let _tree = MerkleTree::<B>::from_iter(leaves.iter());
    })
}
