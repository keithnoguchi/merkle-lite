# Version 0.0.8

- Benchmark MerkleTree::proof() and MerkleProof::verify().

# Version 0.0.7

- MerkleTree::proof() method to create a MerkleProof.
- MerkleProof::verify() to verify the proof of inclusion.

# Version 0.0.6

- MerkleTree::get_leaves_mut() to update leaves and
  Merkle root.
- Fix the CI link in README.md.

# Version 0.0.5

- MerkleTree::leaves() to return the iterator to the Merkle leaves.
- Cleanup document.

# Version 0.0.4

- Fix the lone leaf handling.
- Panic section in IntoIterator impl in case of the wrong hash length.

# Version 0.0.3

- Add sha2 and sha3 benchmarks with 100,000 leaves.

# Version 0.0.2

- IntoIterator for the tree generation with the Merkle root calculation.

# Version 0.0.1

- Initial release
