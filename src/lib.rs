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
//! It's super simple to compose [MerkleTree] from the ordered array
//! of hashes and verify the proof of inclusion with [MerkleProof]:
//!
//! ```
//! use merkle_lite::MerkleTree;
//! use rand_core::RngCore;
//!
//! // Composes MerkleTree from the 50,000 random hashes.
//! let tree: MerkleTree<sha3::Sha3_256> = std::iter::repeat([0u8; 32])
//!     .map(|mut leaf| {
//!         rand_core::OsRng.fill_bytes(&mut leaf);
//!         leaf
//!     })
//!     .take(50_000)
//!     .collect();
//!
//! // Verifies the proof of inclusion for the arbitrary leaves.
//! let tree_leaves = tree.get_leaves();
//! let leaf_indices = [12, 0, 1, 1201, 13_903, 980];
//! let leaf_hashes: Vec<_> = leaf_indices
//!     .iter()
//!     .map(|index| (*index, tree_leaves[*index]))
//!     .collect();
//! assert_eq!(
//!     tree.proof(&leaf_indices)
//!         .expect("proof")
//!         .verify(&leaf_hashes)
//!         .expect("verify")
//!         .as_ref(),
//!     tree.root().expect("root"),
//! );
//! ```

#![no_std]
#![forbid(unsafe_code, missing_docs, missing_debug_implementations)]

extern crate alloc;

use core::fmt::{self, Debug};
use core::mem;
use core::ops::{Deref, DerefMut, Div, DivAssign, Index, IndexMut};

use alloc::collections::{BTreeMap, BTreeSet};
use alloc::{vec, vec::Vec};

use digest::block_buffer;
use digest::generic_array::ArrayLength;
use digest::{Digest, OutputSizeUser};

type Buffer<B> = <<B as OutputSizeUser>::OutputSize as ArrayLength<u8>>::ArrayType;

/// A Merkle tree.
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
///     tree.root().unwrap(),
///     hex!("34fac4b8781d0b811746ec45623606f43df1a8b9009f89c5564e68025a6fd604"),
/// );
/// ```
#[derive(Clone)]
pub struct MerkleTree<B>
where
    B: Digest,
    Buffer<B>: Copy,
{
    /// Provides the range of leaf node index.
    leaf_range: NodeIndexRange,

    /// Points to the contiguous memory of array of `data`, e.g. hash value.
    data: Vec<NodeData<B>>,
}

impl<B> Debug for MerkleTree<B>
where
    B: Digest,
    Buffer<B>: Copy,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MerkleTree")
            .field("leaf_range", &self.leaf_range)
            .field("tree_depth", &self.depth())
            .field("data_len", &self.data.len())
            .finish()
    }
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
            tree.push(NodeData::try_from(data.as_ref()).unwrap());
        });

        // nothing to do in case of the zero or single leaf tree.
        if tree.leaf_range.len() <= 1 {
            return tree;
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
    /// let leaves = [[0u8; 32]; 127];
    /// let tree: MerkleTree<Sha3_256> = leaves.into_iter().collect();
    ///
    /// assert_eq!(tree.leaf_len(), 127);
    /// ```
    pub const fn leaf_len(&self) -> usize {
        self.leaf_range.len()
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
    pub fn depth(&self) -> usize {
        (usize::BITS - self.data.len().leading_zeros()) as usize
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
    ///     tree.root().unwrap(),
    ///     hex!("34fac4b8781d0b811746ec45623606f43df1a8b9009f89c5564e68025a6fd604"),
    /// );
    /// ```
    pub fn root(&self) -> Option<&[u8]> {
        self.data.last().map(|node| node.as_ref())
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
            .map(|node| node.as_ref())
    }

    /// Gets the Merkle tree leaves.
    ///
    /// # Example
    ///
    /// ```
    /// use sha3::Sha3_256;
    /// use hex_literal::hex;
    ///
    /// use merkle_lite::MerkleTree;
    ///
    /// // Composes a tree from sequential leaves.
    /// let leaves: Vec<_> = [[1u8; 32]; 14]
    ///     .iter()
    ///     .enumerate()
    ///     .map(|(i, mut leaf)| leaf.map(|mut leaf| {
    ///         leaf *= i as u8;
    ///         leaf
    ///     }))
    ///     .collect();
    /// let tree: MerkleTree<Sha3_256> = leaves.iter().collect();
    ///
    /// // Gets the `MerkleLeaves` and checks each element.
    /// let tree_leaves = tree.get_leaves();
    /// for (i, leaf) in leaves.iter().enumerate() {
    ///     assert_eq!(tree_leaves[i].as_slice(), leaf);
    /// }
    /// ```
    pub fn get_leaves(&self) -> MerkleLeaves<B> {
        MerkleLeaves {
            leaves: &self.data[self.leaf_range.as_range_usize()],
        }
    }

    /// Gets the mutable Merkle tree leaves.
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
    ///     let mut tree_leaves = tree.get_leaves_mut();
    ///
    ///     // sets the leaves with the new hash and update
    ///     // the Merkle root when it drops.
    ///     (0..leaves.len()).for_each(|i| {
    ///         tree_leaves[i] = [0xab_u8; 32].into();
    ///     });
    /// }
    /// assert_eq!(
    ///     tree.root().unwrap(),
    ///     hex!("34fac4b8781d0b811746ec45623606f43df1a8b9009f89c5564e68025a6fd604"),
    /// );
    /// ```
    pub fn get_leaves_mut(&mut self) -> MerkleLeavesMut<B> {
        MerkleLeavesMut {
            changed_set: LeftNodeIndexSet::default(),
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
    /// // Composes MerkleTree for the 10 random leaves.
    /// let tree: MerkleTree<Sha3_256> = std::iter::repeat([0u8; 32])
    ///     .map(|mut leaf| {
    ///         rand_core::OsRng.fill_bytes(&mut leaf);
    ///         leaf
    ///     })
    ///     .take(10)
    ///     .collect();
    ///
    /// // Verifies the proof of inclusion for the particular leaves.
    /// let leaves = tree.get_leaves();
    /// assert_eq!(
    ///     tree.proof(&[0, 1, 9])
    ///         .unwrap()
    ///         .verify(&[
    ///             (1, leaves[1]),
    ///             (9, leaves[9]),
    ///             (0, leaves[0]),
    ///         ])
    ///         .unwrap()
    ///         .as_ref(),
    ///     tree.root().unwrap(),
    /// );
    /// ```
    pub fn proof<'a, I>(&self, leaf_indices: I) -> Option<MerkleProof<B>>
    where
        I: IntoIterator<Item = &'a usize>,
    {
        // Ignore the out of range indices.
        let leaf_indices: BTreeSet<_> = leaf_indices
            .into_iter()
            .map(|index| NodeIndex(*index))
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
        let total_len = match leaf_len {
            0 => 0,
            leaf_len if leaf_len.is_power_of_two() => {
                // The following equasion will give us the entire
                // tree size, as `leaf_len - 1` represents the
                // size of the base tree.
                2 * leaf_len - 1
            }
            _ => {
                // Counts each level length for depth's times.
                //
                // In case of the odd number of length, add one
                // for the next level.
                let mut total = 1;
                let mut level_len = leaf_len;
                while level_len > 1 {
                    total += level_len;
                    level_len = level_len / 2 + level_len % 2;
                }
                total
            }
        };
        Self {
            data: vec![NodeData::default(); total_len],
            leaf_range: NodeIndexRange::default(),
        }
    }

    fn push(&mut self, data: NodeData<B>) {
        if *self.leaf_range.end < self.data.len() {
            self.data[*self.leaf_range.end] = data;
        } else {
            self.data.push(data);
        }
        *self.leaf_range.end += 1;
    }

    fn merkle_root_iter(&mut self, changed_range: NodeIndexRange) -> MerkleRootIter<B> {
        MerkleRootIter {
            changed_range,
            level_range: self.leaf_range.clone(),
            data: &mut self.data[..],
        }
    }

    fn merkle_root_set_iter(&mut self, changed_set: LeftNodeIndexSet) -> MerkleRootSetIter<B> {
        MerkleRootSetIter {
            changed_set,
            level_range: self.leaf_range.clone(),
            data: &mut self.data[..],
        }
    }

    fn merkle_lemmas_iter(&self, leaf_indices: BTreeSet<NodeIndex>) -> MerkleLemmasIter<B> {
        MerkleLemmasIter {
            level_indices: leaf_indices,
            level_range: self.leaf_range.clone(),
            data: &self.data[..],
        }
    }
}

/// A shared reference to the Merkle leaves.
///
/// Please refer to [`MerkleRoot::get_leaves()`] for the example.
///
/// [`merkleroot::get_leaves()`]: struct.MerkleTree.html#method.get_leaves
pub struct MerkleLeaves<'a, B>
where
    B: OutputSizeUser,
    Buffer<B>: Copy,
{
    leaves: &'a [NodeData<B>],
}

impl<'a, B> Debug for MerkleLeaves<'a, B>
where
    B: OutputSizeUser,
    Buffer<B>: Copy,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MerkleLeaves")
            .field("leaf_len", &self.leaves.len())
            .finish()
    }
}

impl<'a, B> Index<usize> for MerkleLeaves<'a, B>
where
    B: OutputSizeUser,
    Buffer<B>: Copy,
{
    type Output = digest::Output<B>;

    fn index(&self, index: usize) -> &Self::Output {
        self.leaves[index].0.as_ref().unwrap()
    }
}

/// A mutable reference to the Merkle leaves.
///
/// It accumulates the changes and triggers the Merkle root calculation
/// when it drops.
///
/// Please refer to [`MerkleRoot::get_leaves_mut()`] for the example.
///
/// [`merkleroot::get_leaves_mut()`]: struct.MerkleTree.html#method.get_leaves_mut
pub struct MerkleLeavesMut<'a, B>
where
    B: Digest,
    Buffer<B>: Copy,
{
    /// A changed set of the leaf indices.
    ///
    /// It only keeps track of the left side of the index
    /// to make the parent hash calculation simpler.
    changed_set: LeftNodeIndexSet,

    /// mutable reference to the tree for the merkle root calculation.
    tree: &'a mut MerkleTree<B>,
}

impl<'a, B> Debug for MerkleLeavesMut<'a, B>
where
    B: Digest,
    Buffer<B>: Copy,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MerkleLeavesMut")
            .field("leaf_len", &self.tree.leaf_len())
            .field("changed_set_len", &self.changed_set.len())
            .finish()
    }
}

impl<'a, B> Drop for MerkleLeavesMut<'a, B>
where
    B: Digest,
    Buffer<B>: Copy,
{
    /// Calculates the Merkle root in case there is a change in the leaves.
    fn drop(&mut self) {
        // There is no change.
        if self.changed_set.is_empty() {
            return;
        }
        for _ in self.tree.merkle_root_set_iter(self.changed_set.clone()) {}
    }
}

impl<'a, B> Index<usize> for MerkleLeavesMut<'a, B>
where
    B: Digest,
    Buffer<B>: Copy,
{
    type Output = digest::Output<B>;

    fn index(&self, index: usize) -> &Self::Output {
        self.tree.data[index].0.as_ref().unwrap()
    }
}

impl<'a, B> IndexMut<usize> for MerkleLeavesMut<'a, B>
where
    B: Digest,
    Buffer<B>: Copy,
{
    fn index_mut(&mut self, index: usize) -> &mut Self::Output {
        self.changed_set
            .insert(NodeIndex(index), &self.tree.leaf_range);
        self.tree.data[index].0.as_mut().unwrap()
    }
}

/// A Merkle proof.
///
/// A Merkle proof of the inclusion.
///
/// Please refer to [`MerkleRoot::proof()`] for more detail.
///
/// [`merkleroot::proof()`]: struct.MerkleTree.html#method.proof
#[derive(Clone)]
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

impl<B> Debug for MerkleProof<B>
where
    B: Digest,
    Buffer<B>: Copy,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MerkleProof")
            .field("leaf_range", &self.leaf_range)
            .field("leaf_indices_len", &self.leaf_indices.len())
            .field("leaf_lemmas_depth", &self.lemmas.len())
            .finish()
    }
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
    /// // A tree with 100 random leaves.
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
    ///     tree.root().unwrap(),
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
                let data = NodeData::<B>::try_from(v.as_ref()).unwrap();
                (NodeIndex(*k), data)
            })
            .collect();

        // Checks if `leaf_indices` covers all the required indices.
        let leaf_indices: BTreeSet<_> = leaves.keys().cloned().collect();
        if leaf_indices != self.leaf_indices {
            return None;
        }

        // Calculates the Merkle proof root.
        for _ in self.merkle_proof_iter(leaves) {}

        // last entry of lemmas holds the merkle root.
        self.lemmas
            .last()
            .and_then(|lemmas| lemmas.get(&NodeIndex(0)))
            .and_then(|node| node.0)
    }

    fn merkle_proof_iter(
        &mut self,
        leaf_hashes: BTreeMap<NodeIndex, NodeData<B>>,
    ) -> MerkleProofIter<B> {
        MerkleProofIter {
            level_hashes: leaf_hashes,
            level_range: self.leaf_range.clone(),
            lemmas: &mut self.lemmas[..],
        }
    }
}

/// A Merkle proof iterator.
///
/// Calculate the Merkle root as for the proof of inclusion.
struct MerkleProofIter<'a, B>
where
    B: Digest,
    Buffer<B>: Copy,
{
    /// A current level hashes to calculate the parent hashes.
    level_hashes: BTreeMap<NodeIndex, NodeData<B>>,

    /// A current level range.
    level_range: NodeIndexRange,

    /// Lemmas for the Merkle proof calculation.
    lemmas: &'a mut [BTreeMap<NodeIndex, NodeData<B>>],
}

impl<'a, B> Iterator for MerkleProofIter<'a, B>
where
    B: Digest,
    Buffer<B>: Copy,
{
    type Item = ();

    fn next(&mut self) -> Option<Self::Item> {
        // Gets the next level lemmas.
        let lemmas = match mem::take(&mut self.lemmas).split_first_mut() {
            None => return None,
            Some((first, remains)) if remains.is_empty() => {
                // There is a special case, not practical, that the Merkle
                // proof had been called against the single node tree.
                //
                // We just copy Merkle root, which was passed by the caller.
                if first.is_empty() {
                    *first = self.level_hashes.clone();
                }
                return None;
            }
            Some((first, remains)) => {
                self.lemmas = remains;
                first
            }
        };

        // Calculates the next level hashes.
        let mut level_hashes = BTreeMap::new();
        for (index, data) in &self.level_hashes {
            let sibling_index = index.sibling(&self.level_range).unwrap();
            let sibling = match self.level_hashes.get(&sibling_index) {
                Some(data) => data,
                None => match lemmas.get(&sibling_index) {
                    None => return None,
                    Some(data) => data,
                },
            };
            let mut hasher = B::new();
            if index.is_right(&self.level_range) {
                hasher.update(sibling);
                hasher.update(data);
            } else {
                hasher.update(data);
                hasher.update(sibling);
            }
            let parent_data = NodeData::<B>::from(hasher.finalize());
            let parent_index = *index / 2;
            level_hashes.insert(parent_index, parent_data);
        }

        // Keeps the Markle root in case it's in the root level.
        if self.lemmas.len() == 1 {
            if let Some(lemma) = self.lemmas.first_mut() {
                *lemma = level_hashes;
            }
        } else {
            self.level_hashes = level_hashes;
            self.level_range /= 2;
        }

        Some(())
    }
}

/// A Merkle proof lemmas iterator.
///
/// Get the Merkle tree lemmas for the Merkle proof.
struct MerkleLemmasIter<'a, B>
where
    B: OutputSizeUser,
    Buffer<B>: Copy,
{
    /// A current level indices needs lemma, e.g. sibling.
    level_indices: BTreeSet<NodeIndex>,

    /// A current level index range.
    level_range: NodeIndexRange,

    /// A remaining node of tree.
    data: &'a [NodeData<B>],
}

impl<'a, B> Iterator for MerkleLemmasIter<'a, B>
where
    B: OutputSizeUser,
    Buffer<B>: Copy,
{
    type Item = BTreeMap<NodeIndex, NodeData<B>>;

    fn next(&mut self) -> Option<Self::Item> {
        // Checks for the completion.
        if self.data.is_empty() {
            return None;
        }

        // Prepares the current level node.
        let split = *self.level_range.end;
        let (children, parents) = mem::take(&mut self.data).split_at(split);
        if parents.is_empty() {
            // Set's the data to zero and returns the empty `BTreeMap`
            // as a placeholder of the Merkle root calculated by
            // `MerkleProofIter`.
            self.data = parents;
            return Some(BTreeMap::new());
        }

        // Prepares the next level index and the level lemmas.
        let mut next_indices = BTreeSet::new();
        let mut lemmas = BTreeMap::new();
        for index in &self.level_indices {
            // Remembers the parent indices for the next iteration.
            next_indices.insert(*index / 2);

            // Gets the sibling index.
            let sibling = index.sibling(&self.level_range).unwrap();

            // We don't need to store the lemma in case of
            // the sibling pair is IN the `level_indices`.
            if self.level_indices.contains(&sibling) {
                continue;
            }

            // Stores the lemma.
            //
            // If in case the sibling is out of range, stores itself.
            if sibling == self.level_range.end {
                lemmas.insert(sibling, children[index.0].clone());
            } else {
                lemmas.insert(sibling, children[sibling.0].clone());
            }
        }

        // Update the next level indices.
        self.level_indices = next_indices;
        self.level_range /= 2;
        self.data = parents;

        Some(lemmas)
    }
}

/// A Merkle root calculation iterator based on [`NodeIndexRange`].
///
/// It iteratively calculates parent hashes for the range of
/// child hashes toward the Merkle root.
///
/// [`nodeindexrange`]: struct.NodeIndexRange.html
struct MerkleRootIter<'a, B>
where
    B: Digest,
    Buffer<B>: Copy,
{
    /// A changed range of the indices.
    changed_range: NodeIndexRange,

    /// A current level index range.
    level_range: NodeIndexRange,

    /// A remaining tree of node.
    data: &'a mut [NodeData<B>],
}

impl<'a, B> Iterator for MerkleRootIter<'a, B>
where
    B: Digest,
    Buffer<B>: Copy,
{
    type Item = NodeIndexRange;

    fn next(&mut self) -> Option<Self::Item> {
        if self.data.len() <= 1 {
            return None;
        }

        // Adjust the child and the parent ranges.
        let mut child_range = self.changed_range.clone();
        if child_range.start.is_right(&self.level_range) {
            // The updated index range always starts even.
            *child_range.start -= 1;
        }
        if child_range.is_empty() {
            // It's at least one node remains to update the
            // parent hash.
            *child_range.end += 1;
        }
        let mut parent_range = self.changed_range.clone() / 2;
        if parent_range.is_empty() {
            *parent_range.end += 1;
        }

        // Calculates the parent hash.
        let split = *self.level_range.end;
        let (children, parents) = mem::take(&mut self.data).split_at_mut(split);
        let siblings = children[child_range.as_range_usize()].chunks_exact(2);
        let mut parent_index = 0;
        for pair in siblings.clone() {
            let mut hasher = B::new();
            for child in pair {
                hasher.update(child);
            }
            parents[parent_index] = NodeData::from(hasher.finalize());
            parent_index += 1;
        }
        // Duplicates the last odd child, if there is.
        if let Some(child) = siblings.remainder().first() {
            let mut hasher = B::new();
            hasher.update(child);
            hasher.update(child);
            parents[parent_index] = NodeData::from(hasher.finalize());
        }

        // Prepare the iterator for the next round.
        self.changed_range = parent_range.clone();
        self.level_range /= 2;
        self.data = parents;

        Some(parent_range)
    }
}

/// A Merkle root calculation iterator based on [`LeftNodeIndexSet`].
///
/// It iteratively calculates parent hashes for the set of
/// child hashes toward the Merkle root.
///
/// [`leftnodeindexset`]: struct.LeftNodeIndexSet.html
struct MerkleRootSetIter<'a, B>
where
    B: Digest,
    Buffer<B>: Copy,
{
    /// A changed range of the indices.
    ///
    /// It only keeps track of the left side of the indices
    /// to make the parent hash calculation simpler.
    changed_set: LeftNodeIndexSet,

    /// A current level index range.
    level_range: NodeIndexRange,

    /// A remaining tree of node.
    data: &'a mut [NodeData<B>],
}

impl<'a, B> Iterator for MerkleRootSetIter<'a, B>
where
    B: Digest,
    Buffer<B>: Copy,
{
    type Item = usize;

    fn next(&mut self) -> Option<Self::Item> {
        if self.data.len() <= 1 {
            return None;
        }

        // `LeftNodeIndexSet` for the parent changed set.
        let mut next_set = LeftNodeIndexSet::default();

        // Splits the tree to get the current level node.
        let split = *self.level_range.end;
        let (current, next) = mem::take(&mut self.data).split_at_mut(split);

        // Calculates the parent hash.
        for index in self.changed_set.iter() {
            let sibling = index.sibling(&self.level_range).unwrap();
            let mut hasher = B::new();
            hasher.update(&current[**index]);
            hasher.update(&current[*sibling]);
            let parent = index.parent(&self.level_range).unwrap();
            next[*parent] = NodeData::from(hasher.finalize());
            next_set.insert(parent, &self.level_range);
        }

        // Update the changed sets and data for the next iteration.
        let changed_count = next_set.len();
        self.changed_set = next_set;
        self.level_range /= 2;
        self.data = next;

        Some(changed_count)
    }
}

/// A left node index set.
///
/// [`MerkleRootSetIter`] uses it to keep track
/// of the current changed set to calculate
/// the parent hashes.
///
/// It keeps track of the left side of the indices
/// to make the parent hash calculation simpler.
///
/// [`merklerootsetiter`]: struct.MerkleRootSetIter.html
#[derive(Clone, Debug, Default)]
struct LeftNodeIndexSet(BTreeSet<NodeIndex>);

impl Deref for LeftNodeIndexSet {
    type Target = BTreeSet<NodeIndex>;

    fn deref(&self) -> &BTreeSet<NodeIndex> {
        &self.0
    }
}

impl From<&NodeIndexRange> for LeftNodeIndexSet {
    fn from(range: &NodeIndexRange) -> Self {
        // The following code will be replaced by `BTreeSet::from_iter()`
        // with [`Range`] one liner once [`Step`] is in stable.
        //
        // [`range`]: https://doc.rust-lang.org/core/ops/struct.Range.html#impl-Iterator-forRange%3CA%3E
        // [`step`]: https://doc.rust-lang.org/core/iter/trait.Step.html
        let mut this = Self::default();
        for index in range.as_range_usize() {
            this.insert(NodeIndex(index), range);
        }
        this
    }
}

impl LeftNodeIndexSet {
    /// Gets an iterator that visits the `NodeIndex`es
    /// in `LeftNodeIndexSet`.
    fn iter(&self) -> impl Iterator<Item = &NodeIndex> {
        self.0.iter()
    }

    /// Adds a left side of the index to the set.
    fn insert(&mut self, index: NodeIndex, range: &NodeIndexRange) -> bool {
        assert!(range.contains(&index));
        if index.is_right(range) {
            match index.sibling(range) {
                Some(index) => self.0.insert(index),
                None => false,
            }
        } else {
            self.0.insert(index)
        }
    }
}

/// A node index range.
#[derive(Clone, Default)]
struct NodeIndexRange(core::ops::Range<NodeIndex>);

impl Debug for NodeIndexRange {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_fmt(format_args!("{}..{}", *self.start, *self.end))
    }
}

impl Deref for NodeIndexRange {
    type Target = core::ops::Range<NodeIndex>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DerefMut for NodeIndexRange {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
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

impl From<core::ops::RangeTo<usize>> for NodeIndexRange {
    fn from(range: core::ops::RangeTo<usize>) -> Self {
        Self(core::ops::Range {
            start: NodeIndex(0),
            end: NodeIndex(range.end),
        })
    }
}

impl From<NodeIndexRange> for core::ops::Range<usize> {
    fn from(range: NodeIndexRange) -> Self {
        core::ops::Range {
            start: *range.0.start,
            end: *range.0.end,
        }
    }
}

impl Div<usize> for NodeIndexRange {
    type Output = Self;

    fn div(mut self, rhs: usize) -> Self {
        self /= rhs;
        self
    }
}

impl DivAssign<usize> for NodeIndexRange {
    fn div_assign(&mut self, rhs: usize) {
        *self.0.start /= rhs;
        *self.0.end = (*self.0.end + (rhs - 1)) / rhs;
    }
}

impl NodeIndexRange {
    /// Returns the `NodeIndexRange` as `Range<usize>`.
    #[inline]
    const fn as_range_usize(&self) -> core::ops::Range<usize> {
        self.0.start.0..self.0.end.0
    }

    /// Returns the length of the range.
    #[inline]
    const fn len(&self) -> usize {
        self.0.end.0 - self.0.start.0
    }
}

/// A node index.
#[derive(Copy, Clone, Debug, Default, Eq, PartialEq, Ord, PartialOrd)]
struct NodeIndex(usize);

impl Deref for NodeIndex {
    type Target = usize;

    fn deref(&self) -> &usize {
        &self.0
    }
}

impl DerefMut for NodeIndex {
    fn deref_mut(&mut self) -> &mut usize {
        &mut self.0
    }
}

impl From<NodeIndex> for usize {
    fn from(index: NodeIndex) -> usize {
        index.0
    }
}

impl Div<usize> for NodeIndex {
    type Output = Self;

    fn div(self, rhs: usize) -> Self {
        Self(self.0 / rhs)
    }
}

impl NodeIndex {
    /// Returns `true` if the index is the right side of the node.
    #[inline]
    const fn is_right(&self, range: &NodeIndexRange) -> bool {
        (self.0 - range.0.start.0) % 2 == 1
    }

    /// Returns the parent index of `Self`, or `None`, in
    /// case of the `Self` is the root index.
    #[inline]
    const fn parent(&self, range: &NodeIndexRange) -> Option<Self> {
        if range.len() == 1 {
            None
        } else {
            Some(Self(self.0 / 2))
        }
    }

    /// Returns the sibling index of `Self`, or:
    ///
    /// 1) `None` in case of `Self` is the root index.
    /// 2) `Self` in case of the sibling is out of range.
    #[inline]
    fn sibling(&self, range: &NodeIndexRange) -> Option<Self> {
        if range.len() == 1 {
            None
        } else if self.is_right(range) {
            Some(Self(self.0 - 1))
        } else {
            let sibling = Self(self.0 + 1);
            if range.0.contains(&sibling) {
                Some(sibling)
            } else {
                Some(*self)
            }
        }
    }
}

/// A node data.
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
