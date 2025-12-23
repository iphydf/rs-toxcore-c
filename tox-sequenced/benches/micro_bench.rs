use criterion::{Criterion, criterion_group, criterion_main};
use std::hint::black_box;
use std::time::Instant;
use tox_sequenced::outgoing::OutgoingMessage;
use tox_sequenced::protocol::{FragmentCount, FragmentIndex, MessageId, MessageType};
use tox_sequenced::quota::Priority;
use tox_sequenced::reassembly::MessageReassembler;

fn bench_create_ack(c: &mut Criterion) {
    let mut reassembler = MessageReassembler::new(
        MessageId(1),
        FragmentCount(1024),
        Priority::Standard,
        0,
        Instant::now(),
    )
    .unwrap();
    // Simulate some received fragments
    for i in (0..1024).step_by(2) {
        reassembler
            .add_fragment(FragmentIndex(i), vec![0; 1300], Instant::now())
            .unwrap();
    }

    c.bench_function("create_ack_1024_sparse", |b| {
        b.iter(|| black_box(reassembler.create_ack(black_box(FragmentCount(100)))))
    });

    // Test with almost full
    let mut reassembler_full = MessageReassembler::new(
        MessageId(1),
        FragmentCount(1024),
        Priority::Standard,
        0,
        Instant::now(),
    )
    .unwrap();
    for i in 0..1023 {
        reassembler_full
            .add_fragment(FragmentIndex(i), vec![0; 1], Instant::now())
            .unwrap();
    }

    c.bench_function("create_ack_1024_full", |b| {
        b.iter(|| black_box(reassembler_full.create_ack(black_box(FragmentCount(100)))))
    });
}

fn bench_collect_acked_indices(c: &mut Criterion) {
    let mut msg = OutgoingMessage::new(
        MessageType::MerkleNode,
        vec![0; 1024 * 1300],
        1300,
        Instant::now(),
    )
    .unwrap();

    c.bench_function("collect_acked_indices_1024_sparse", |b| {
        b.iter(|| {
            msg.highest_cumulative_ack = FragmentIndex(0);
            black_box(msg.collect_acked_indices(
                black_box(FragmentIndex(512)),
                black_box(0xAAAAAAAAAAAAAAAAu64),
            ))
        })
    });

    c.bench_function("collect_acked_indices_1024_dense", |b| {
        b.iter(|| {
            msg.highest_cumulative_ack = FragmentIndex(0);
            msg.acked_bitset.fill();
            // Few holes
            msg.acked_bitset.unset(64 + 10);
            msg.acked_bitset.unset(4 * 64 + 20);
            black_box(msg.collect_acked_indices(
                black_box(FragmentIndex(512)),
                black_box(0xAAAAAAAAAAAAAAAAu64),
            ))
        })
    });
}

criterion_group!(benches, bench_create_ack, bench_collect_acked_indices);
criterion_main!(benches);
