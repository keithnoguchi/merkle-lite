//! Benchmark with [SHA3] hash functions.
//!
//! [sha3]: https://crates.io/crates/sha3
#[macro_use]
extern crate bencher;

use bencher::Bencher;

use merkle_lite::MerkleTree;
use sha3::{Sha3_224, Sha3_256, Sha3_384, Sha3_512};

const NR_LEAVES: usize = 100_000;

fn sha224(b: &mut Bencher)
{
    let leaves = [[0u8; 28]; NR_LEAVES];
    b.iter(|| {
        let _tree: MerkleTree<Sha3_224> = leaves.iter().collect();
    })
}


fn sha256(b: &mut Bencher)
{
    let leaves = [[0u8; 32]; NR_LEAVES];
    b.iter(|| {
        let _tree: MerkleTree<Sha3_256> = leaves.iter().collect();
    })
}

fn sha384(b: &mut Bencher)
{
    let leaves = [[0u8; 48]; NR_LEAVES];
    b.iter(|| {
        let _tree: MerkleTree<Sha3_384> = leaves.iter().collect();
    })
}

fn sha512(b: &mut Bencher)
{
    let leaves = [[0u8; 64]; NR_LEAVES];
    b.iter(|| {
        let _tree: MerkleTree<Sha3_512> = leaves.iter().collect();
    })
}

benchmark_group!(benches, sha224, sha256, sha384, sha512);
benchmark_main!(benches);
