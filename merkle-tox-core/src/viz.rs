use crate::dag::{Content, ConversationId, MerkleNode, NodeHash, NodeType};
use crate::sync::NodeStore;
use std::collections::HashSet;
use std::fmt::Write;

/// Export the DAG for a given conversation to a Graphviz .dot format string.
pub fn export_dot(conversation_id: &ConversationId, store: &dyn NodeStore) -> String {
    let mut dot = String::new();
    dot.push_str("digraph DAG {\n");
    dot.push_str("  rankdir=LR;\n");
    dot.push_str("  node [shape=box, fontname=\"Courier\"];\n");

    let mut visited = HashSet::new();
    let mut stack = store.get_heads(conversation_id);

    while let Some(hash) = stack.pop() {
        if !visited.insert(hash) {
            continue;
        }

        if let Some(node) = store.get_node(&hash) {
            let label = format_node_label(&hash, &node);
            let color = match node.node_type() {
                NodeType::Admin => "lightblue",
                NodeType::Content => "white",
            };

            writeln!(
                dot,
                "  \"{}\" [label=\"{}\", fillcolor=\"{}\", style=filled];",
                hex::encode(hash.as_bytes()),
                label,
                color
            )
            .unwrap();

            for parent in &node.parents {
                writeln!(
                    dot,
                    "  \"{}\" -> \"{}\";",
                    hex::encode(hash.as_bytes()),
                    hex::encode(parent.as_bytes())
                )
                .unwrap();
                stack.push(*parent);
            }
        }
    }

    dot.push_str("}\n");
    dot
}

fn format_node_label(hash: &NodeHash, node: &MerkleNode) -> String {
    let hash_short = &hex::encode(hash.as_bytes())[0..8];
    let author_short = &hex::encode(node.author_pk.as_bytes())[0..8];
    let content_summary = match &node.content {
        Content::Text(t) => {
            let truncated = if t.len() > 20 {
                format!("{}...", &t[0..17])
            } else {
                t.clone()
            };
            format!("Text: {}", truncated)
        }
        Content::Control(c) => format!("Ctrl: {:?}", c),
        Content::Blob { name, .. } => format!("Blob: {}", name),
        Content::Reaction { emoji, .. } => format!("Reaction: {:?}", emoji),
        Content::Redaction { reason, .. } => format!("Redaction: {}", reason),
        Content::KeyWrap { epoch, .. } => format!("KeyWrap: epoch={}", epoch),
        Content::RatchetSnapshot { epoch, .. } => format!("RatchetSnapshot: epoch={}", epoch),
        _ => "Other".to_string(),
    };

    format!(
        "ID: {}\nAuthor: {}\nRank: {}\n{}",
        hash_short, author_short, node.topological_rank, content_summary
    )
    .replace("\"", "\\\"")
}
