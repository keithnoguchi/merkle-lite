//! Generic Binary Merkle Tree
//!
//! A simple and fast generic binary [Merkle Tree] for [Rust Crypto]
//! hash functions.
//!
//! The goal of [`MerkleTree`] is simple yet fast implementation
//! of [Merkle Tree] by supporting the standard Rust traits, e.g.
//! [`FromIterator`].
//!
//! This also makes [`MerkleTree`] work with other data types ergonomically.
//!
//! # Examples
//!
//! Here is how to create [`MerkleTree`] for the array of leaf hash.
//!
//! Thanks to [`FromIterator`], all you have to do is just call `collect()`
//! on the leaf array iterator:
//! ```
//! use sha3::Sha3_256;
//! use hex_literal::hex;
//!
//! use merkle_lite::MerkleTree;
//!
//! // 16 identical leaves for the demonstration purpose.
//! let leaves = [[0xab_u8; 32]; 16];
//! let tree: MerkleTree<Sha3_256> = leaves.iter().collect();
//!
//! assert_eq!(
//!     tree.root(),
//!     hex!("34fac4b8781d0b811746ec45623606f43df1a8b9009f89c5564e68025a6fd604"),
//! );
//! ```
//! [merkle tree]: https://en.wikipedia.org/wiki/Merkle_tree
//! [rust crypto]: https://github.com/RustCrypto
//! [`merkletree`]: struct.MerkleTree.html
//! [`fromiterator`]: https://doc.rust-lang.org/std/iter/trait.FromIterator.html
#![no_std]
#![forbid(unsafe_code, missing_docs, missing_debug_implementations)]
extern crate alloc;

use alloc::{vec, vec::Vec};
use core::mem;
use core::ops::Range;

use digest::block_buffer;
use digest::generic_array::ArrayLength;
use digest::{Digest, OutputSizeUser};

type Buffer<B> = <<B as OutputSizeUser>::OutputSize as ArrayLength<u8>>::ArrayType;

/// Generic Binary Merkle Tree
///
/// # Examples
///
/// Basic usage:
/// ```
/// use sha3::Sha3_256;
/// use hex_literal::hex;
///
/// use merkle_lite::MerkleTree;
///
/// // 16 identical leaves for the demonstration purpose.
/// let leaves = [[0xab_u8; 32]; 16];
/// let tree: MerkleTree<Sha3_256> = leaves.iter().collect();
///
/// assert_eq!(
///     tree.root(),
///     hex!("34fac4b8781d0b811746ec45623606f43df1a8b9009f89c5564e68025a6fd604"),
/// );
/// ```
#[derive(Clone, Debug)]
pub struct MerkleTree<B>
where
    B: Digest,
    Buffer<B>: Copy,
{
    /// represents the range of the valid leaves in `data`.
    leaf_range: Range<usize>,

    /// points to the contiguous memory of the array of hash.
    data: Vec<Node<B>>,
}

impl<A, B> FromIterator<A> for MerkleTree<B>
where
    A: AsRef<[u8]>,
    B: Digest,
    Buffer<B>: Copy,
{
    /// Conversion from an `Iterator`.
    ///
    /// # Panics
    ///
    /// May panic in case the length of iterator item is not the valid
    /// hash length.
    fn from_iter<T: IntoIterator<Item = A>>(iter: T) -> Self {
        let iter = iter.into_iter();
        let (leaf_len, _) = iter.size_hint();

        // prep the leaf nodes.
        let mut tree = Self::with_leaf_len(leaf_len);
        iter.for_each(|data| {
            assert!(
                data.as_ref().len() == <B as Digest>::output_size(),
                "invalid hash length"
            );
            let node = Node::try_from(data.as_ref()).unwrap();
            tree.push(node);
        });

        // nothing to do in case of the lone leaf.
        if tree.leaf_len() == 1 {
            return tree;
        }

        // make it even leaves.
        if tree.leaf_len() & 0b1 == 0b1 {
            tree.push(tree.data[tree.leaf_range.end - 1].clone());
        }

        // calculate the Merkle root.
        for _ in tree.merkle_root_iter(tree.leaf_range.clone()) {}

        tree
    }
}

impl<B> MerkleTree<B>
where
    B: Digest,
    Buffer<B>: Copy,
{
    /// Returns the number of node in the tree.
    ///
    /// # Examples
    ///
    /// Basic usage:
    /// ```
    /// use merkle_lite::MerkleTree;
    /// use sha3::Sha3_256;
    ///
    /// let leaves = [[0u8; 32]; 2];
    /// let tree: MerkleTree<Sha3_256> = leaves.into_iter().collect();
    ///
    /// assert_eq!(tree.len(), 3);
    /// ```
    pub fn len(&self) -> usize {
        self.data.len()
    }

    /// Returns `true` if the tree is empty.
    ///
    /// # Examples
    ///
    /// Basic usage:
    /// ```
    /// use merkle_lite::MerkleTree;
    /// use sha3::Sha3_256;
    ///
    /// // zero length leaf.
    /// let leaves = [[0u8; 32]; 0];
    /// let tree: MerkleTree<Sha3_256> = leaves.iter().collect();
    ///
    /// assert!(tree.is_empty());
    /// ```
    pub fn is_empty(&self) -> bool {
        self.data.len() == 0
    }

    /// Returns the total number of tree node without reallocating.
    pub fn capacity(&self) -> usize {
        self.data.capacity()
    }

    /// Returns the length of the Merkle tree leaves.
    ///
    /// # Examples
    ///
    /// Basic usage:
    /// ```
    /// use merkle_lite::MerkleTree;
    /// use sha3::Sha3_256;
    ///
    /// let leaves = [[0u8; 32]; 100];
    /// let tree: MerkleTree<Sha3_256> = leaves.into_iter().collect();
    ///
    /// assert_eq!(tree.leaf_len(), 100);
    /// ```
    pub const fn leaf_len(&self) -> usize {
        self.leaf_range.end - self.leaf_range.start
    }

    /// Returns the total number of leaf node without reallocating.
    pub fn leaf_capacity(&self) -> usize {
        self.data.capacity() - self.leaf_range.start
    }

    /// Returns the Merkle root.
    ///
    /// # Examples
    ///
    /// Basic usage:
    /// ```
    /// use sha3::Sha3_256;
    /// use hex_literal::hex;
    ///
    /// use merkle_lite::MerkleTree;
    ///
    /// // identical leaves for the demonstration purpose.
    /// let leaves = [[0xab_u8; 32]; 14];
    /// let tree: MerkleTree<Sha3_256> = leaves.iter().collect();
    ///
    /// assert_eq!(
    ///     tree.root(),
    ///     hex!("34fac4b8781d0b811746ec45623606f43df1a8b9009f89c5564e68025a6fd604"),
    /// );
    /// ```
    ///
    /// # Panics
    ///
    /// May panic in case the tree is empty.
    pub fn root(&self) -> &[u8] {
        self.data[0].as_ref()
    }

    /// Returns the leaves iterator of the Merkle tree.
    ///
    /// # Examples
    ///
    /// ```
    /// use std::iter;
    /// use sha3::Sha3_256;
    ///
    /// use merkle_lite::MerkleTree;
    ///
    /// // create a sequencial leaf for the demonstration purpose.
    /// let leaves = iter::repeat(0x1_u8)
    ///     .enumerate()
    ///     .map(|(i, byte)| [byte * i as u8; 32])
    ///     .take(18);
    ///
    /// // create a Merkle tree.
    /// let tree: MerkleTree<Sha3_256> = leaves.clone().collect();
    ///
    /// // test leaves.
    /// assert_eq!(tree.leaf_len(), 18);
    /// assert_eq!(tree.leaves().count(), 18);
    /// for (got, want) in tree.leaves().zip(leaves) {
    ///     assert_eq!(got, want);
    /// }
    /// ```
    pub fn leaves(&self) -> impl Iterator<Item = &[u8]> {
        self.data[self.leaf_range.clone()]
            .iter()
            .map(|n| n.as_ref())
    }

    fn with_leaf_len(leaf_len: usize) -> Self {
        let capacity = match leaf_len.count_ones() {
            0 => 0,
            1 => {
                // power of two leaves.
                //
                // The following equasion will give us the entire
                // tree size, as `leaf_len - 1` represents the
                // size of the base tree.
                2 * leaf_len - 1
            }
            _ => {
                // get the base power of two of the leaf_len, and then
                // calculate the tree capacity in addition to the actual
                // leaf length.
                let base = 1 << (usize::BITS - leaf_len.leading_zeros() - 1);
                (2 * base - 1) + leaf_len
            }
        };
        let start = capacity - leaf_len;
        Self {
            data: vec![Node::default(); capacity],
            leaf_range: start..start,
        }
    }

    #[inline]
    fn push(&mut self, node: Node<B>) {
        if self.leaf_range.end < self.data.len() {
            self.data[self.leaf_range.end] = node;
        } else {
            self.data.push(node);
        }
        self.leaf_range.end += 1;
    }

    #[inline]
    fn merkle_root_iter(&mut self, child_range: Range<usize>) -> MerkleRootIter<B> {
        MerkleRootIter {
            data: &mut self.data[..child_range.end],
            child_range,
        }
    }
}

/// Merkle root calculation iterator.
///
/// It iteratively calculates parent digests to generate the Merkle root.
struct MerkleRootIter<'a, B>
where
    B: Digest,
    Buffer<B>: Copy,
{
    /// represents the range of the child node in `data`.
    child_range: Range<usize>,

    /// borrowed reference to the `MerkleTree::data`.
    data: &'a mut [Node<B>],
}

impl<'a, B> Iterator for MerkleRootIter<'a, B>
where
    B: Digest,
    Buffer<B>: Copy,
{
    type Item = Range<usize>;

    fn next(&mut self) -> Option<Self::Item> {
        // Calculated the merkle root.
        if self.data.len() <= 1 {
            return None;
        }

        // Calculates the parent digests.
        let Range { start, end } = self.child_range;
        let parent_range = (start - 1) >> 1..(end - 1) >> 1;
        let (parents, children) = mem::take(&mut self.data).split_at_mut(start);
        for (i, pair) in children.chunks(2).enumerate() {
            let mut hasher = B::new();
            for child in pair {
                hasher.update(child);
            }
            parents[parent_range.start + i] = Node::from(hasher.finalize());
        }

        // adjust the start and the end for the next iteration.
        let Range { start, end } = parent_range;
        let next_start = if start != 0 && start & 1 == 0 {
            start - 1
        } else {
            start
        };
        let next_end = if end & 1 == 0 {
            // copy the sibling's digest in case of it's not set yet.
            if parents[end].0.is_none() {
                parents[end] = parents[end - 1].clone();
            }
            end + 1
        } else {
            end
        };
        self.child_range = next_start..next_end;
        self.data = &mut parents[..next_end];

        Some(parent_range)
    }
}

/// Tree node.
///
/// It abstructs the [`digest::Output`] value.
///
/// [`digest::Output`]: https://docs.rs/digest/latest/digest/type.Output.html
#[derive(Copy, Debug)]
struct Node<B>(Option<digest::Output<B>>)
where
    B: OutputSizeUser,
    Buffer<B>: Copy;

impl<B> Clone for Node<B>
where
    B: OutputSizeUser,
    Buffer<B>: Copy,
{
    fn clone(&self) -> Self {
        Self(self.0)
    }
}

impl<B> Default for Node<B>
where
    B: OutputSizeUser,
    Buffer<B>: Copy,
{
    fn default() -> Self {
        Self(None)
    }
}

impl<B> AsRef<[u8]> for Node<B>
where
    B: OutputSizeUser,
    Buffer<B>: Copy,
{
    fn as_ref(&self) -> &[u8] {
        debug_assert!(self.0.is_some(), "uninitialized node");
        self.0.as_ref().unwrap()
    }
}

impl<B> From<digest::Output<B>> for Node<B>
where
    B: OutputSizeUser,
    Buffer<B>: Copy,
{
    fn from(inner: digest::Output<B>) -> Self {
        Self(Some(inner))
    }
}

impl<B> TryFrom<&[u8]> for Node<B>
where
    B: OutputSizeUser,
    Buffer<B>: Copy,
{
    type Error = block_buffer::Error;

    fn try_from(from: &[u8]) -> Result<Self, Self::Error> {
        if from.len() != B::output_size() {
            return Err(block_buffer::Error);
        }
        Ok(Self(Some(digest::Output::<B>::clone_from_slice(from))))
    }
}
