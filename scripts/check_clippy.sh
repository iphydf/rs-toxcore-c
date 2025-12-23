#!/bin/bash

# Find all rust targets that are NOT covered by any rust_clippy target
# We use a single query to minimize overhead over SSHFS.
echo "Running bazel query to find missing clippy coverage..."

MISSING=$(bazel query "kind('rust_(library|binary|test|proc_macro)', //rs-toxcore-c/...) except deps(kind('rust_clippy', //rs-toxcore-c/...), 1)" 2>/dev/null)

if [ -n "$MISSING" ]; then
    echo "❌ The following Rust targets are not covered by any 'clippy' target:"
    echo "$MISSING" | sed 's/^/  /'
    exit 1
else
    echo "✅ All Rust targets are covered by clippy targets."
    exit 0
fi