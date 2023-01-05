# merkle-lite

![CI](https://github.com/keithnoguchi/merkle-lite/actions/workflows/ci.yml/badge.svg)
[![License](https://img.shields.io/badge/license-Apache--2.0_OR_MIT-blue.svg)](
https://github.com/keithnoguchi/merkle-lite)
[![Cargo](https://img.shields.io/crates/v/merkle-lite.svg)](
https://crates.io/crates/merkle-lite)
[![Documentation](https://docs.rs/merkle-lite/badge.svg)](
https://docs.rs/merkle-lite)

A simple and fast generic binary [Merkle Tree] for [Rust Crypto]
hash functions.

The goal of [`MerkleTree`] is simple yet fast implementation
of [Merkle Tree] by supporting the standard Rust traits, e.g.
[`FromIterator`].

This also makes [`MerkleTree`] work with other data types ergonomically.

## Examples

Here is how to create [`MerkleTree`] from the array of leaves.

Thanks to [`FromIterator`],  you just call `collect()` on the array iterator:
```
use hex_literal::hex;
use sha3::Sha3_256;

use merkle_lite::MerkleTree;

// 16 identical leaves for the demonstration purpose.
let leaves = [[0xab_u8; 32]; 16];
let tree: MerkleTree<Sha3_256> = leaves.iter().collect();

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
[`merkletree`]: https://docs.rs/merkle-lite/latest/merkle_lite/struct.MerkleTree.html
[`fromiterator`]: https://doc.rust-lang.org/std/iter/trait.FromIterator.html
