//! Unit tests for `ChunkMerkleTree`, the domain-separated blake3 Merkle
//! tree over 64KB chunk hashes used to authenticate individual chunks of
//! a blob against a DAG-committed root. See `doc/merkle-tox-cas.md` §3
//! for the spec and `src/cas.rs::ChunkMerkleTree` for the implementation.
//!
//! These tests exist to ensure the **security properties** hold:
//!
//! 1. Correctness: any leaf + valid proof verifies against the root.
//! 2. Tamper detection: tampered leaf bytes, tampered chunk bytes,
//!    wrong leaf index, wrong root, truncated proof, or extra proof
//!    bytes all fail to verify.
//! 3. Edge cases: empty tree, single leaf, non-power-of-2 leaf count
//!    (exercises unpaired-tail duplication), large tree.
//! 4. Unpaired-tail integrity: an attacker cannot substitute a crafted
//!    sibling for the duplicated slot at an odd level.
//! 5. Domain separation: leaf hashes and internal-node hashes live in
//!    disjoint input spaces (second-preimage resistance).

use merkle_tox_core::cas::ChunkMerkleTree;

fn test_leaves(n: usize) -> Vec<[u8; 32]> {
    (0..n)
        .map(|i| ChunkMerkleTree::leaf_hash(&[i as u8; 1024]))
        .collect()
}

#[test]
fn empty_tree_has_stable_root() {
    let a = ChunkMerkleTree::from_leaf_hashes(&[]);
    let b = ChunkMerkleTree::from_leaf_hashes(&[]);
    assert_eq!(a.root(), b.root());
    // And an empty-chunk leaf should equal that root.
    assert_eq!(a.root(), ChunkMerkleTree::leaf_hash(&[]));
}

#[test]
fn single_leaf_root_equals_leaf_hash() {
    let leaves = test_leaves(1);
    let tree = ChunkMerkleTree::from_leaf_hashes(&leaves);
    assert_eq!(tree.root(), leaves[0]);
    // Proof for the single leaf is empty.
    let proof = tree.proof_for(0);
    assert!(proof.is_empty());
    assert!(ChunkMerkleTree::verify(
        leaves[0],
        0,
        1,
        &proof,
        &tree.root()
    ));
}

#[test]
fn two_leaf_tree_roundtrip() {
    let leaves = test_leaves(2);
    let tree = ChunkMerkleTree::from_leaf_hashes(&leaves);
    for (i, leaf) in leaves.iter().enumerate() {
        let proof = tree.proof_for(i);
        assert_eq!(proof.len(), 32); // depth = 1
        assert!(
            ChunkMerkleTree::verify(*leaf, i, 2, &proof, &tree.root()),
            "verify failed for leaf {}",
            i
        );
    }
}

#[test]
fn sixteen_leaf_tree_every_leaf_verifies() {
    let leaves = test_leaves(16);
    let tree = ChunkMerkleTree::from_leaf_hashes(&leaves);
    for (i, leaf) in leaves.iter().enumerate() {
        let proof = tree.proof_for(i);
        assert_eq!(proof.len(), 4 * 32); // depth = log2(16) = 4
        assert!(
            ChunkMerkleTree::verify(*leaf, i, 16, &proof, &tree.root()),
            "verify failed for leaf {}",
            i
        );
    }
}

#[test]
fn non_power_of_two_leaf_count() {
    // 5 leaves exercises the unpaired-tail duplication at levels with
    // odd node counts (5 -> 3 -> 2 -> 1).
    let leaves = test_leaves(5);
    let tree = ChunkMerkleTree::from_leaf_hashes(&leaves);
    for (i, leaf) in leaves.iter().enumerate() {
        let proof = tree.proof_for(i);
        assert!(
            ChunkMerkleTree::verify(*leaf, i, 5, &proof, &tree.root()),
            "verify failed for leaf {} of 5-leaf tree",
            i
        );
    }
}

#[test]
fn large_tree_depth_math_is_correct() {
    // 160 leaves = typical 10MB blob. Depth = ceil(log2(160)) = 8.
    let leaves = test_leaves(160);
    let tree = ChunkMerkleTree::from_leaf_hashes(&leaves);
    let proof = tree.proof_for(77);
    assert_eq!(proof.len(), 8 * 32, "proof length should be depth*32");
    assert!(ChunkMerkleTree::verify(
        leaves[77],
        77,
        160,
        &proof,
        &tree.root()
    ));
}

#[test]
fn verify_rejects_tampered_leaf() {
    let leaves = test_leaves(16);
    let tree = ChunkMerkleTree::from_leaf_hashes(&leaves);
    let proof = tree.proof_for(3);
    let mut tampered = leaves[3];
    tampered[0] ^= 0x01;
    assert!(
        !ChunkMerkleTree::verify(tampered, 3, 16, &proof, &tree.root()),
        "tampered leaf must not verify"
    );
}

#[test]
fn verify_rejects_tampered_chunk_bytes() {
    let chunks: Vec<Vec<u8>> = (0..16).map(|i| vec![i as u8; 1024]).collect();
    let tree = ChunkMerkleTree::from_chunks(chunks.iter().map(Vec::as_slice));
    let proof = tree.proof_for(5);
    let mut tampered = chunks[5].clone();
    tampered[0] ^= 0x01;
    assert!(
        !ChunkMerkleTree::verify_chunk(&tampered, 5, 16, &proof, &tree.root()),
        "tampered chunk bytes must not verify"
    );
}

#[test]
fn verify_rejects_wrong_leaf_index() {
    let leaves = test_leaves(16);
    let tree = ChunkMerkleTree::from_leaf_hashes(&leaves);
    let proof = tree.proof_for(3);
    // Use proof for leaf 3 but present leaf 5's hash. Should fail
    // even though the hash is a legitimate leaf of the same tree.
    assert!(
        !ChunkMerkleTree::verify(leaves[5], 3, 16, &proof, &tree.root()),
        "valid leaf under wrong proof/index must not verify"
    );
}

#[test]
fn verify_rejects_wrong_root() {
    let leaves = test_leaves(16);
    let tree = ChunkMerkleTree::from_leaf_hashes(&leaves);
    let proof = tree.proof_for(0);
    let wrong_root = [0x55u8; 32];
    assert!(!ChunkMerkleTree::verify(
        leaves[0],
        0,
        16,
        &proof,
        &wrong_root
    ));
}

#[test]
fn verify_rejects_truncated_proof() {
    let leaves = test_leaves(16);
    let tree = ChunkMerkleTree::from_leaf_hashes(&leaves);
    let mut proof = tree.proof_for(3);
    proof.truncate(proof.len() - 1);
    assert!(!ChunkMerkleTree::verify(
        leaves[3],
        3,
        16,
        &proof,
        &tree.root()
    ));
}

#[test]
fn verify_rejects_extra_bytes_in_proof() {
    let leaves = test_leaves(16);
    let tree = ChunkMerkleTree::from_leaf_hashes(&leaves);
    let mut proof = tree.proof_for(3);
    proof.push(0x00);
    assert!(!ChunkMerkleTree::verify(
        leaves[3],
        3,
        16,
        &proof,
        &tree.root()
    ));
}

#[test]
fn verify_rejects_unpaired_tail_sibling_substitution() {
    // 5 leaves: leaf 4 is the unpaired tail whose sibling is itself
    // (duplicated at tree build time). An attacker might try to
    // present a different sibling at the duplicated slot.
    let leaves = test_leaves(5);
    let tree = ChunkMerkleTree::from_leaf_hashes(&leaves);
    let mut proof = tree.proof_for(4);
    // Flip a bit in the first 32 bytes (the leaf-level sibling).
    proof[0] ^= 0xFF;
    assert!(
        !ChunkMerkleTree::verify(leaves[4], 4, 5, &proof, &tree.root()),
        "substituted sibling at unpaired-tail slot must not verify"
    );
}

#[test]
fn domain_separation_prevents_leaf_internal_confusion() {
    // A leaf hash and an internal node must not collide, even if an
    // attacker tries to craft chunk bytes that equal an internal hash.
    let leaves = test_leaves(4);
    let tree = ChunkMerkleTree::from_leaf_hashes(&leaves);

    // Compute what an internal node hashes to, then try to present the
    // same 64 bytes as a "leaf" and claim its hash matches.
    let l0 = leaves[0];
    let l1 = leaves[1];
    let mut fake_leaf = [0u8; 64];
    fake_leaf[..32].copy_from_slice(&l0);
    fake_leaf[32..].copy_from_slice(&l1);
    let attacker_leaf = ChunkMerkleTree::leaf_hash(&fake_leaf);

    let internal = ChunkMerkleTree::internal_hash(&l0, &l1);
    assert_ne!(
        attacker_leaf, internal,
        "leaf hash domain and internal hash domain must be disjoint"
    );

    // And just for good measure, the attacker's fake leaf should not
    // verify in place of leaf 0.
    let proof0 = tree.proof_for(0);
    assert!(!ChunkMerkleTree::verify(
        attacker_leaf,
        0,
        4,
        &proof0,
        &tree.root()
    ));
}
