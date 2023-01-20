//! A `sha3::Sha3_256` Merkle proof example.

use std::collections::HashSet;
use std::iter;
use std::str::FromStr;
use std::sync::mpsc::{channel, Sender};
use std::thread;

use digest::generic_array::{ArrayLength, GenericArray};
use digest::{Digest, OutputSizeUser};
use merkle_lite::{MerkleProof, MerkleTree};
use rand_core::RngCore;

const NR_LEAF_LEN: usize = 10_000;
const NR_LEAF_CHECK: usize = 19;

fn main() {
    let mut args = std::env::args().skip(1);
    let nr_leaf_len = args
        .next()
        .as_ref()
        .and_then(|n| usize::from_str(n).ok())
        .unwrap_or(NR_LEAF_LEN);
    let nr_leaf_check = args
        .next()
        .as_ref()
        .and_then(|n| usize::from_str(n).ok())
        .map(|n| n % nr_leaf_len)
        .unwrap_or(NR_LEAF_CHECK);

    // Random indices for the proof of inclusion check below.
    let leaf_indices: HashSet<_> = iter::repeat(fastrand::usize(..nr_leaf_len))
        .take(nr_leaf_check)
        .collect();

    // A channel to receive the Merkle proof generated by `proof_server`.
    let (tx, rx) = channel();

    // Generate the Merkle proof.
    thread::spawn(move || merkle_proof::<sha3::Sha3_256>(tx, nr_leaf_len, leaf_indices));

    // Waits for the Merkle proof generated thread above.
    let (proof, root, leaves) = rx.recv().expect("server crashed");

    // Check the proof of inclusion.
    assert_eq!(
        proof.verify(&leaves).expect("verify failed").as_ref(),
        root.as_slice(),
    );
}

/// A Merkle root and leaf hashes for the proof of inclusion.
type MerkleRoot = Vec<u8>;
type MerkleLeaves = Vec<(usize, Vec<u8>)>;

/// A Merkle proof generator.
fn merkle_proof<B>(
    tx: Sender<(MerkleProof<B>, MerkleRoot, MerkleLeaves)>,
    leaf_len: usize,
    leaf_indices: HashSet<usize>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>>
where
    B: Digest + 'static,
    <<B as OutputSizeUser>::OutputSize as ArrayLength<u8>>::ArrayType: Copy,
{
    // Composes a Merkle tree for `leaf_len` random leaves.
    let tree: MerkleTree<B> =
        iter::repeat(GenericArray::<u8, <B as OutputSizeUser>::OutputSize>::default())
            .map(|mut hash| {
                rand_core::OsRng.fill_bytes(&mut hash);
                hash
            })
            .take(leaf_len)
            .collect();

    // Gets the Merkle root and proof.
    let root = tree.root().ok_or("merkle root")?.to_vec();
    let proof = tree.proof(&leaf_indices).ok_or("merkle proof")?;

    // Gets the leaf index and the hash requested by the caller.
    let leaves: MerkleLeaves = leaf_indices
        .iter()
        .map(|index| (*index, tree.leaves().nth(*index).expect("leaf hash").into()))
        .collect();

    // Returns a result over the channel.
    tx.send((proof, root, leaves))?;

    Ok(())
}
