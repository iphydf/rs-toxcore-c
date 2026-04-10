use criterion::{Criterion, criterion_group, criterion_main};
use std::hint::black_box;
use tox_sequenced::protocol::{MessageType, Packet};

fn bench_serialize_data_packet(c: &mut Criterion) {
    let packet = Packet::Data {
        seq: 42,
        msg_type: MessageType::BlobData,
        data: vec![0u8; 1300],
    };

    c.bench_function("serialize_data_packet", |b| {
        b.iter(|| black_box(tox_proto::serialize(black_box(&packet)).unwrap()))
    });
}

fn bench_deserialize_data_packet(c: &mut Criterion) {
    let packet = Packet::Data {
        seq: 42,
        msg_type: MessageType::BlobData,
        data: vec![0u8; 1300],
    };
    let serialized = tox_proto::serialize(&packet).unwrap();

    c.bench_function("deserialize_data_packet", |b| {
        b.iter(|| {
            black_box(tox_proto::deserialize::<Packet>(black_box(&serialized)).unwrap())
        })
    });
}

fn bench_serialize_ack_packet(c: &mut Criterion) {
    let packet = Packet::Ack {
        base_seq: tox_proto::Untrusted::new(100),
        recv_bytes: tox_proto::Untrusted::new(1_000_000),
        sack_ranges: tox_proto::Untrusted::new(tox_proto::bounded_vec![(200u32, 5u32), (300u32, 8u32)]),
    };

    c.bench_function("serialize_ack_packet", |b| {
        b.iter(|| black_box(tox_proto::serialize(black_box(&packet)).unwrap()))
    });
}

fn bench_serialize_fragment_packet(c: &mut Criterion) {
    let packet = Packet::Fragment {
        frag_id: 1,
        frag_index: 5,
        frag_total: 49,
        msg_type: MessageType::MerkleNode,
        data: vec![0u8; 1300],
    };

    c.bench_function("serialize_fragment_packet", |b| {
        b.iter(|| black_box(tox_proto::serialize(black_box(&packet)).unwrap()))
    });
}

criterion_group!(
    benches,
    bench_serialize_data_packet,
    bench_deserialize_data_packet,
    bench_serialize_ack_packet,
    bench_serialize_fragment_packet,
);
criterion_main!(benches);
