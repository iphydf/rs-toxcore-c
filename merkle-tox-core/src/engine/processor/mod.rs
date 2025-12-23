use crate::dag::{Content, MerkleNode, NodeHash};

pub mod side_effects;
pub mod verification;

/// A private zero-sized type that can only be constructed within the processor module.
/// This serves as the "Evidence" that a node has been cryptographically and logically verified.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Evidence;

/// A wrapper that serves as type-level proof that a MerkleNode has passed
/// all cryptographic, identity, and protocol-rule checks.
#[derive(Debug, Clone)]
pub struct VerifiedNode<T = Content> {
    node: MerkleNode,
    content: T,
    #[allow(dead_code)]
    pub(crate) evidence: Evidence,
}

impl<T> VerifiedNode<T> {
    pub(crate) fn new(node: MerkleNode, content: T) -> Self {
        Self {
            node,
            content,
            evidence: Evidence,
        }
    }

    pub fn node(&self) -> &MerkleNode {
        &self.node
    }

    pub fn hash(&self) -> NodeHash {
        self.node.hash()
    }

    pub fn content(&self) -> &T {
        &self.content
    }

    pub fn into_parts(self) -> (MerkleNode, T) {
        (self.node, self.content)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VerificationStatus {
    Verified,
    Speculative,
}
