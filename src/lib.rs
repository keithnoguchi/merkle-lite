//! A binary Merkle tree and proof.
//!
//! [merkle tree and proof]: https://en.wikipedia.org/wiki/Merkle_tree
//! [rust crypto]: https://github.com/RustCrypto
//!
//! A simple, fast, and composable binary [Merkle tree and proof] for
//! [Rust Crypto] hash functions.
//!
//! # Examples
//!
//! [`merkletree`]: struct.MerkleTree.html
//! [`merkleproof`]: struct.MerkleProof.html
//!
//! Here is how to compose [`MerkleTree`] and [`MerkleProof`] for the
//! proof of inclusion verification:
//!
//! ```
//! use rand_core::RngCore;
//! use sha3::Sha3_256;
//!
//! use merkle_lite::MerkleTree;
//!
//! // Composes MerkleTree from the 100 random leaves.
//! let tree: MerkleTree<Sha3_256> = std::iter::repeat([0u8; 32])
//!     .map(|mut leaf| {
//!         rand_core::OsRng.fill_bytes(&mut leaf);
//!         leaf
//!     })
//!     .take(100)
//!     .collect();
//!
//! // Verifies the proof of inclusion, e.g. 12th and 98th leaves.
//! assert_eq!(
//!     tree.proof(&[12, 98])
//!         .unwrap()
//!         .verify(&[
//!             (98, tree.leaves().nth(98).unwrap()),
//!             (12, tree.leaves().nth(12).unwrap()),
//!         ])
//!         .unwrap()
//!         .as_ref(),
//!     tree.root(),
//! );
//! ```

#![no_std]
#![forbid(unsafe_code, missing_docs, missing_debug_implementations)]

extern crate alloc;

use core::fmt::Debug;
use core::mem;
use core::ops::{Add, AddAssign, Index, IndexMut, Sub};

use alloc::collections::{BTreeMap, BTreeSet};
use alloc::{vec, vec::Vec};

use digest::block_buffer;
use digest::generic_array::ArrayLength;
use digest::{Digest, OutputSizeUser};

type Buffer<B> = <<B as OutputSizeUser>::OutputSize as ArrayLength<u8>>::ArrayType;

/// A binary Merkle tree.
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
    /// Provides the range of the leaf node in `data`.
    leaf_range: NodeIndexRange,

    /// Points to the contiguous memory of array of `data`, e.g. hash value.
    data: Vec<NodeData<B>>,
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
            let data = NodeData::try_from(data.as_ref()).unwrap();
            tree.push(data);
        });

        // nothing to do in case of the zero or single leaf tree.
        if tree.leaf_range.len() <= 1 {
            return tree;
        }

        // make it even leaves.
        if tree.leaf_range.is_odd_len() {
            tree.push(tree.data[tree.leaf_range.end().index() - 1].clone());
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
        self.leaf_range.len()
    }

    /// Returns the total number of leaf node without reallocating.
    pub fn leaf_capacity(&self) -> usize {
        self.data.capacity() - self.leaf_range.start().index()
    }

    /// Returns the Merkle tree depth.
    ///
    /// # Examples
    ///
    /// Basic usage:
    /// ```
    /// use digest::generic_array::GenericArray;
    /// use digest::typenum::U32;
    ///
    /// use sha3::Sha3_256;
    ///
    /// use merkle_lite::MerkleTree;
    ///
    /// let leaves = [GenericArray::<u8, U32>::default(); 14];
    /// let tree: MerkleTree<Sha3_256> = leaves.iter().collect();
    ///
    /// assert_eq!(tree.depth(), 5);
    /// ```
    pub const fn depth(&self) -> usize {
        (usize::BITS - self.leaf_range.end().index().leading_zeros()) as usize
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
        self.data[self.leaf_range.as_range_usize()]
            .iter()
            .map(|n| n.as_ref())
    }

    /// Get the mutable Merkle tree leaves.
    ///
    /// Please note that updating the Merkle tree through this
    /// `MerkleLeavesMut` is inefficient because it re-calculate
    /// the Merkle root once `MerkleLeavesMut` drops.
    ///
    /// # Example
    ///
    /// Updating the Merkle root with the new hash values.
    ///
    /// ```
    /// use sha3::Sha3_256;
    /// use hex_literal::hex;
    ///
    /// use merkle_lite::MerkleTree;
    ///
    /// // create tree with the dummy leaves first.
    /// let leaves = [[0u8; 32]; 14];
    /// let mut tree: MerkleTree<Sha3_256> = leaves.iter().collect();
    /// {
    ///     let leaf_len = tree.leaf_len();
    ///     let mut leaves = tree.get_leaves_mut();
    ///
    ///     // sets the leaves with the new hash and update
    ///     // the Merkle root when it drops.
    ///     (0..leaf_len).for_each(|i| {
    ///         leaves[i] = [0xab_u8; 32].into();
    ///     });
    /// }
    /// assert_eq!(
    ///     tree.root(),
    ///     hex!("34fac4b8781d0b811746ec45623606f43df1a8b9009f89c5564e68025a6fd604"),
    /// );
    /// ```
    pub fn get_leaves_mut(&mut self) -> MerkleLeavesMut<B> {
        MerkleLeavesMut {
            mutated_set: BTreeSet::default(),
            tree: self,
        }
    }

    /// Returns a [`MerkleProof`] for the specified leaf indices.
    ///
    /// # Examples
    ///
    /// ```
    /// use rand_core::RngCore;
    /// use sha3::Sha3_256;
    ///
    /// use merkle_lite::MerkleTree;
    ///
    /// // 100 random leaves.
    /// let leaves: Vec<_> = std::iter::repeat([0u8; 32])
    ///     .map(|mut leaf| {
    ///         rand_core::OsRng.fill_bytes(&mut leaf);
    ///         leaf
    ///     })
    ///     .take(100)
    ///     .collect();
    ///
    /// // A Merkle tree composed from the leaves.
    /// let tree: MerkleTree<Sha3_256> = leaves.iter().collect();
    ///
    /// // A proof of inclusion for an arbitrary number of leaves
    /// // specified by the 0-indexed ordered indices.
    /// let proof = tree.proof(&[12, 98]).unwrap();
    ///
    /// // verify the merkle proof of inclusion by comparing the
    /// // result to the Merkle root.
    /// let inclusion = [(98, &leaves[98]), (12, &leaves[12])];
    /// assert_eq!(
    ///     proof.verify(&inclusion).unwrap().as_ref(),
    ///     tree.root(),
    /// );
    /// ```
    pub fn proof<'a, I>(&self, leaf_indices: I) -> Option<MerkleProof<B>>
    where
        I: IntoIterator<Item = &'a usize>,
    {
        // sanity check of the leaf indices.
        let leaf_indices: BTreeSet<_> = leaf_indices
            .into_iter()
            .map(|index| self.leaf_range.start() + *index)
            .filter(|index| self.leaf_range.0.contains(index))
            .collect();

        // no valid leaf indices.
        if leaf_indices.is_empty() {
            return None;
        }

        // get the lemmas for each level all the way to the root.
        let mut proof = MerkleProof {
            leaf_range: self.leaf_range.clone(),
            leaf_indices: leaf_indices.clone(),
            lemmas: Vec::new(),
        };
        for lemmas in self.merkle_lemmas_iter(leaf_indices) {
            proof.lemmas.push(lemmas);
        }

        Some(proof)
    }

    fn with_leaf_len(leaf_len: usize) -> Self {
        let total_len = match leaf_len.count_ones() {
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
        let start = total_len - leaf_len;
        Self {
            data: vec![NodeData::default(); total_len],
            leaf_range: NodeIndexRange::from(start..start),
        }
    }

    #[inline]
    fn push(&mut self, data: NodeData<B>) {
        if self.leaf_range.end().index() < self.data.len() {
            self.data[self.leaf_range.end().index()] = data;
        } else {
            self.data.push(data);
        }
        *self.leaf_range.end_mut() += 1;
    }

    fn merkle_root_iter(&mut self, updated_leaf_range: NodeIndexRange) -> MerkleRootIter<B> {
        MerkleRootIter {
            data: &mut self.data[..updated_leaf_range.end().index()],
            level_range: self.leaf_range.clone(),
            updated_range: updated_leaf_range,
        }
    }

    fn merkle_lemmas_iter(&self, leaf_indices: BTreeSet<NodeIndex>) -> MerkleLemmasIter<B> {
        MerkleLemmasIter {
            data: &self.data,
            level_indices: leaf_indices,
        }
    }
}

/// Mutable Merkle tree leaves.
///
/// It accumulates the changes and triggers the Merkle root calculation
/// when it drops.
///
/// Please refer to [`MerkleRoot::get_leaves_mut()`] for more detail.
///
/// [`merkleroot::get_leaves_mut()`]: struct.MerkleTree.html#method.get_leaves_mut
#[derive(Debug)]
pub struct MerkleLeavesMut<'a, B>
where
    B: Digest,
    Buffer<B>: Copy,
{
    /// mutated leaves.
    mutated_set: BTreeSet<NodeIndex>,

    /// mutable reference to the tree for the merkle root calculation.
    tree: &'a mut MerkleTree<B>,
}

impl<'a, B> Index<usize> for MerkleLeavesMut<'a, B>
where
    B: Digest,
    Buffer<B>: Copy,
{
    type Output = digest::Output<B>;

    fn index(&self, index: usize) -> &Self::Output {
        let index = self.tree.leaf_range.start().index() + index;
        self.tree.data[index].0.as_ref().unwrap()
    }
}

impl<'a, B> IndexMut<usize> for MerkleLeavesMut<'a, B>
where
    B: Digest,
    Buffer<B>: Copy,
{
    fn index_mut(&mut self, index: usize) -> &mut Self::Output {
        let index = self.tree.leaf_range.start().index() + index;
        self.mutated_set.insert(NodeIndex(index));
        self.tree.data[index].0.as_mut().unwrap()
    }
}

impl<'a, B> Drop for MerkleLeavesMut<'a, B>
where
    B: Digest,
    Buffer<B>: Copy,
{
    /// Calculates the Merkle root in case there is a change in the leaves.
    fn drop(&mut self) {
        // do nothing in case of no change.
        if self.mutated_set.is_empty() {
            return;
        }
        // get the range of the change set.
        let start = match self.mutated_set.first() {
            Some(&start) if !start.is_root() && start.is_even() => start - 1,
            Some(&start) => start,
            None => return,
        };
        let end = match self.mutated_set.last() {
            Some(&end) if end.is_even() => end + 1,
            Some(&end) => end,
            None => return,
        };
        // calculate the Merkle root.
        for _ in self.tree.merkle_root_iter(NodeIndexRange(start..end)) {}
    }
}

/// A Merkle proof.
///
/// A Merkle proof of the inclusion.
///
/// Please refer to [`MerkleRoot::proof()`] for more detail.
///
/// [`merkleroot::proof()`]: struct.MerkleTree.html#method.proof
#[derive(Clone, Debug)]
pub struct MerkleProof<B>
where
    B: OutputSizeUser,
    Buffer<B>: Copy,
{
    /// the range of the Merkle tree leaves.
    leaf_range: NodeIndexRange,

    /// the indices of the Merkle proof verification.
    leaf_indices: BTreeSet<NodeIndex>,

    /// Merkle proof lemmas.
    ///
    /// It's indexed starting from the leaf level to the top.
    /// The last entry of the vector, e.g. lemmans[lemmas.len() - 1],
    /// will be used as a Merkle root cache for the Merkle proof
    /// verification.
    lemmas: Vec<BTreeMap<NodeIndex, NodeData<B>>>,
}

impl<B> MerkleProof<B>
where
    B: Digest,
    Buffer<B>: Copy,
{
    /// Returns the Merkle root as the proof of inclusion.
    ///
    /// # Examples
    ///
    /// ```
    /// use rand_core::RngCore;
    /// use sha3::Sha3_256;
    ///
    /// use merkle_lite::MerkleTree;
    ///
    /// // 100 random leaves.
    /// let leaves: Vec<_> = std::iter::repeat([0u8; 32])
    ///     .map(|mut leaf| {
    ///         rand_core::OsRng.fill_bytes(&mut leaf);
    ///         leaf
    ///     })
    ///     .take(100)
    ///     .collect();
    ///
    /// // A Merkle tree composed from the leaves.
    /// let tree: MerkleTree<Sha3_256> = leaves.iter().collect();
    ///
    /// // A proof of inclusion for an arbitrary number of leaves
    /// // specified by the 0-indexed ordered indices.
    /// let proof = tree.proof(&[99, 98]).unwrap();
    ///
    /// // verify the merkle proof of inclusion by comparing the
    /// // result to the Merkle root.
    /// let inclusion = vec![(98, &leaves[98]), (99, &leaves[99])];
    /// assert_eq!(
    ///     proof.verify(&inclusion).unwrap().as_ref(),
    ///     tree.root(),
    /// );
    /// ```
    pub fn verify<'a, T, I>(mut self, leaves: I) -> Option<impl AsRef<[u8]>>
    where
        T: AsRef<[u8]> + 'a,
        I: IntoIterator<Item = &'a (usize, T)>,
    {
        let leaves: BTreeMap<_, _> = leaves
            .into_iter()
            .map(|(k, v)| {
                assert!(
                    v.as_ref().len() == <B as Digest>::output_size(),
                    "invalid hash length"
                );
                let index = self.leaf_range.start() + *k;
                let data = NodeData::<B>::try_from(v.as_ref()).unwrap();
                (index, data)
            })
            .collect();

        // sanity check that `leaf_indices` cover all the required
        // indices.
        let leaf_indices: BTreeSet<_> = leaves.keys().cloned().collect();
        if leaf_indices != self.leaf_indices {
            return None;
        }

        // calculate the Merkle proof root.
        for _ in Self::merkle_proof_iter(leaves, &mut self.lemmas[..]) {}

        // last entry of lemmas holds the merkle root.
        self.lemmas
            .last()
            .and_then(|lemmas| lemmas.get(&NodeIndex::ROOT))
            .and_then(|node| node.0)
    }

    fn merkle_proof_iter(
        leaf_hashes: BTreeMap<NodeIndex, NodeData<B>>,
        lemmas: &mut [BTreeMap<NodeIndex, NodeData<B>>],
    ) -> MerkleProofIter<B> {
        MerkleProofIter {
            level_hashes: leaf_hashes,
            lemmas,
        }
    }
}

/// Merkle proof iterator.
///
/// Calculate the Merkle root as for the proof of inclusion.
struct MerkleProofIter<'a, B>
where
    B: Digest,
    Buffer<B>: Copy,
{
    /// current level hashes to calculate the parent hashes.
    level_hashes: BTreeMap<NodeIndex, NodeData<B>>,

    /// lemmas for the Merkle proof calculation.
    lemmas: &'a mut [BTreeMap<NodeIndex, NodeData<B>>],
}

impl<'a, B> Iterator for MerkleProofIter<'a, B>
where
    B: Digest,
    Buffer<B>: Copy,
{
    type Item = ();

    fn next(&mut self) -> Option<Self::Item> {
        // get the next lemmas.
        let lemmas = match mem::take(&mut self.lemmas).split_first_mut() {
            None => return None,
            Some((first, remains)) => {
                self.lemmas = remains;
                first
            }
        };

        // calculate the next level hashes.
        let mut level_hashes = BTreeMap::new();
        for (index, data) in &self.level_hashes {
            let sibling_index = index.sibling().unwrap();
            let sibling = match self.level_hashes.get(&sibling_index) {
                Some(data) => data,
                None => match lemmas.get(&sibling_index) {
                    None => return None,
                    Some(data) => data,
                },
            };
            let mut hasher = B::new();
            if index.is_odd() {
                hasher.update(data);
                hasher.update(sibling);
            } else {
                hasher.update(sibling);
                hasher.update(data);
            }
            let parent_data = NodeData::<B>::from(hasher.finalize());
            let parent_index = index.parent().unwrap();

            // We got the Markle root.  Cache it in the self.lemma
            // and break the loop.
            if parent_index.is_root() {
                self.lemmas
                    .first_mut()
                    .map(|map| map.insert(parent_index, parent_data));
                break;
            } else {
                level_hashes.insert(parent_index, parent_data);
            }
        }
        self.level_hashes = level_hashes;

        Some(())
    }
}

/// Merkle proof lemmas iterator.
///
/// Get the Merkle tree lemmas for the Merkle proof.
struct MerkleLemmasIter<'a, B>
where
    B: OutputSizeUser,
    Buffer<B>: Copy,
{
    /// current level indices which requires lemma, siblings.
    level_indices: BTreeSet<NodeIndex>,

    /// borrowed reference to the `MerkleTree::data`.
    data: &'a [NodeData<B>],
}

impl<'a, B> Iterator for MerkleLemmasIter<'a, B>
where
    B: OutputSizeUser,
    Buffer<B>: Copy,
{
    type Item = BTreeMap<NodeIndex, NodeData<B>>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.level_indices.is_empty() {
            return None;
        } else if self.level_indices.get(&NodeIndex::ROOT).is_some() {
            // empty out the level indices to indicate the completion.
            self.level_indices = BTreeSet::new();

            // returns the empty BtreeMap as a place holder of
            // the Merkle Root, which will be calculated and
            // cached in the verification phase.
            return Some(BTreeMap::new());
        }

        // prepare the next level index and the level lemmas.
        let mut next_indices = BTreeSet::new();
        let mut lemmas = BTreeMap::new();
        for index in &self.level_indices {
            // first the parent for the next level indices.
            next_indices.insert(index.parent().unwrap());

            // get the sibling index.
            let sibling = index.sibling().unwrap();

            // we don't need to store the lemma in case of
            // the sibling pair is in the `level_indices`.
            if self.level_indices.contains(&sibling) {
                continue;
            }

            // store the lemma.
            lemmas.insert(sibling, self.data[sibling.0].clone());
        }

        // Update the next level indices.
        self.level_indices = next_indices;

        Some(lemmas)
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
    /// represents the range of the current level.
    level_range: NodeIndexRange,

    /// represents the range of the updated child node.
    updated_range: NodeIndexRange,

    /// borrowed reference to the `MerkleTree::data`.
    data: &'a mut [NodeData<B>],
}

impl<'a, B> Iterator for MerkleRootIter<'a, B>
where
    B: Digest,
    Buffer<B>: Copy,
{
    type Item = NodeIndexRange;

    fn next(&mut self) -> Option<Self::Item> {
        // less than 1 represents the completion of the root hash
        // and end of the iteration.
        if self.updated_range.len() <= 1 {
            return None;
        }

        // calculates the parent hash.
        let split = self.updated_range.start().index();
        let parent_range = self.updated_range.next().unwrap();
        let parent_base = parent_range.start().index();
        let (parents, children) = mem::take(&mut self.data).split_at_mut(split);
        for (i, pair) in children.chunks(2).enumerate() {
            let mut hasher = B::new();
            for child in pair {
                hasher.update(child);
            }
            parents[parent_base + i] = NodeData::from(hasher.finalize());
        }

        // adjust the next child range.
        let NodeIndexRange(core::ops::Range { start, end }) = parent_range;
        let start = if !start.is_root() && start.is_even() {
            start - 1
        } else {
            start
        };

        // make sure the updated node is even.
        self.level_range.next().unwrap();
        let end = if end.is_even() {
            if end >= self.level_range.end() {
                // Copy the last element in case it's out of
                // level range.
                parents[end.0] = parents[end.0 - 1].clone();
            }
            end + 1
        } else {
            end
        };

        // prepare the state for the next iteration.
        self.data = &mut parents[..end.0];
        self.updated_range = NodeIndexRange(start..end);

        Some(parent_range)
    }
}

/// A tree node index range.
///
/// It's an iterable value and gives the way to move the tree level
/// up to the the zero length range.
#[derive(Clone, Debug)]
struct NodeIndexRange(core::ops::Range<NodeIndex>);

impl Iterator for NodeIndexRange {
    type Item = Self;

    /// Returns the next up of the tree node index range.
    fn next(&mut self) -> Option<Self> {
        if self.is_empty() {
            return None;
        }
        self.0.start = self.0.start.parent().unwrap();
        self.0.end = self.0.end.parent().unwrap();
        Some(self.clone())
    }
}

impl From<core::ops::Range<usize>> for NodeIndexRange {
    fn from(range: core::ops::Range<usize>) -> Self {
        Self(core::ops::Range {
            start: NodeIndex(range.start),
            end: NodeIndex(range.end),
        })
    }
}

impl From<NodeIndexRange> for core::ops::Range<usize> {
    fn from(range: NodeIndexRange) -> Self {
        core::ops::Range {
            start: range.0.start.index(),
            end: range.0.end.index(),
        }
    }
}

impl NodeIndexRange {
    /// Returns the length of the range.
    #[inline]
    const fn len(&self) -> usize {
        self.0.end.index() - self.0.start.index()
    }

    /// Returns `true` if the length of the range is zero.
    #[inline]
    const fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Returns `true` if the range is odd length.
    #[inline]
    const fn is_odd_len(&self) -> bool {
        self.len() & 0b1 == 0b1
    }

    /// Returns `start` value.
    #[inline]
    const fn start(&self) -> NodeIndex {
        self.0.start
    }

    /// Returns `end` value.
    #[inline]
    const fn end(&self) -> NodeIndex {
        self.0.end
    }

    /// Returns mutable `end` value.
    #[inline]
    fn end_mut(&mut self) -> &mut NodeIndex {
        &mut self.0.end
    }

    /// Returns the `NodeIndexRange` in `Range<usize>`.
    #[inline]
    const fn as_range_usize(&self) -> core::ops::Range<usize> {
        self.0.start.0..self.0.end.0
    }
}

/// A tree node index.
#[derive(Copy, Clone, Debug, Eq, PartialEq, Ord, PartialOrd)]
struct NodeIndex(usize);

impl From<NodeIndex> for usize {
    fn from(index: NodeIndex) -> usize {
        index.0
    }
}

impl Add<usize> for NodeIndex {
    type Output = Self;

    fn add(self, rhs: usize) -> Self {
        Self(self.0 + rhs)
    }
}

impl Sub<usize> for NodeIndex {
    type Output = Self;

    fn sub(self, rhs: usize) -> Self {
        Self(self.0 - rhs)
    }
}

impl AddAssign<usize> for NodeIndex {
    fn add_assign(&mut self, rhs: usize) {
        self.0 += rhs
    }
}

impl NodeIndex {
    const ROOT: Self = Self(0);

    /// Returns `true` if it's root index.
    #[inline]
    fn is_root(&self) -> bool {
        self == &Self::ROOT
    }

    /// Returns `true` if it's an odd index.
    #[inline]
    const fn is_odd(&self) -> bool {
        (self.0 & 0b1) == 0b1
    }

    /// Returns `true` if it's an even index.
    #[inline]
    const fn is_even(&self) -> bool {
        !self.is_odd()
    }

    /// Returns the parent index or `None`.
    #[inline]
    fn parent(&self) -> Option<Self> {
        if self.is_root() {
            None
        } else {
            Some(Self((self.0 - 1) / 2))
        }
    }

    /// Returns the sibling index or `None`.
    #[inline]
    fn sibling(&self) -> Option<Self> {
        if self.is_root() {
            None
        } else if self.is_odd() {
            Some(Self(self.0 + 1))
        } else {
            Some(Self(self.0 - 1))
        }
    }

    /// Returns `NodeIndex` in `usize`.
    ///
    /// This is usuful as the array index.
    #[inline]
    const fn index(&self) -> usize {
        self.0
    }
}

/// A tree node data.
///
/// It abstructs the [`digest::Output`] value.
///
/// [`digest::Output`]: https://docs.rs/digest/latest/digest/type.Output.html
#[derive(Copy, Debug)]
struct NodeData<B>(Option<digest::Output<B>>)
where
    B: OutputSizeUser,
    Buffer<B>: Copy;

impl<B> Clone for NodeData<B>
where
    B: OutputSizeUser,
    Buffer<B>: Copy,
{
    fn clone(&self) -> Self {
        Self(self.0)
    }
}

impl<B> Default for NodeData<B>
where
    B: OutputSizeUser,
    Buffer<B>: Copy,
{
    fn default() -> Self {
        Self(None)
    }
}

impl<B> AsRef<[u8]> for NodeData<B>
where
    B: OutputSizeUser,
    Buffer<B>: Copy,
{
    fn as_ref(&self) -> &[u8] {
        debug_assert!(self.0.is_some(), "uninitialized node");
        self.0.as_ref().unwrap()
    }
}

impl<B> From<digest::Output<B>> for NodeData<B>
where
    B: OutputSizeUser,
    Buffer<B>: Copy,
{
    fn from(inner: digest::Output<B>) -> Self {
        Self(Some(inner))
    }
}

impl<B> TryFrom<&[u8]> for NodeData<B>
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
