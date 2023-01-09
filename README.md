# merkle-lite

[![CI](https://github.com/keithnoguchi/merkle-lite/actions/workflows/ci.yml/badge.svg)](
https://github.com/keithnoguchi/merkle-lite/actions)
[![License](https://img.shields.io/badge/license-Apache--2.0_OR_MIT-blue.svg)](
https://github.com/keithnoguchi/merkle-lite)
[![Cargo](https://img.shields.io/crates/v/merkle-lite.svg)](
https://crates.io/crates/merkle-lite)
[![Documentation](https://docs.rs/merkle-lite/badge.svg)](
https://docs.rs/merkle-lite)

A simple, fast, and composable [Merkle Tree] for [Rust Crypto] hash functions.

## Examples

Here is how to create `MerkleTree` and the Markle Root
for the ordered array of cryptographic hashes:
```
use sha3::Sha3_256;
use hex_literal::hex;

use merkle_lite::MerkleTree;

// odd number of `sha3::Sha3_256` leaves.
let hashed_leaves = [[0xab_u8; 32]; 13];
let tree: MerkleTree<Sha3_256> = hashed_leaves.iter().collect();

// check the Merkle root.
assert_eq!(
    tree.root(),
    hex!("34fac4b8781d0b811746ec45623606f43df1a8b9009f89c5564e68025a6fd604"),
);
```

## License

Licensed under either of

 * Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)
 * MIT license ([LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT)

at your option.

#### Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in the work by you, as defined in the Apache-2.0 license, shall be
dual licensed as above, without any additional terms or conditions.

[merkle tree]: https://en.wikipedia.org/wiki/Merkle_tree
[rust crypto]: https://github.com/RustCrypto
