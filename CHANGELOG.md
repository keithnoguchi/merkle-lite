# Version 0.0.15

- Add MerkleLeaves type to access leaves by indices.
- Add Debug implementation for the public types.

# Version 0.0.14

- Improved MerkleLeavesMut update operation with LeftNodeIndexSet.

# Version 0.0.13

- Add the Merkle proof example

# Version 0.0.12

- Make the data order from root-to-leaf to leaf-to-root
  1. It only allocates the required number of nodes
  2. It makes the level iteration much easier to make.

It also dropped leaf_capacity API, as there is
no leaf node specific capacity anymore.

# Version 0.0.11

- Fix the odd length leaf handling.

# Version 0.0.10

- Converts the existing tests into macros to cover
  multiple hashers.

# Version 0.0.9

Use NodeIndex through out the code to consolidate the node
index operation:

- Define NodeIndexRange, aka LevelRange, as Range<NodeIndex>.
- Use NodeIndexRange in MerkleProof.
- Use NodeIndexRange in MerkleTree.
- Use NodeIndex in MerkleLeavesMut.
- Add NodeIndex::index() for the array indexing.

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
