use criterion::{Criterion, criterion_group, criterion_main};
use smallvec::SmallVec;
use std::collections::{BTreeMap, HashMap, VecDeque};
use std::hint::black_box;
use tox_proto::{ToxProto, deserialize, serialize};

#[allow(dead_code)]
#[derive(Debug, PartialEq, ToxProto, Clone)]
struct SmallStruct {
    a: u32,
    b: bool,
}

#[allow(dead_code)]
#[derive(Debug, PartialEq, ToxProto, Clone)]
struct LargeStruct {
    f1: u64,
    f2: String,
    f3: Vec<u8>,
    f4: Vec<u32>,
    f5: Option<SmallStruct>,
}

#[allow(dead_code)]
#[derive(Debug, PartialEq, ToxProto, Clone)]
enum TestEnum {
    Unit,
    Data(Vec<u8>),
    Nested(Box<LargeStruct>),
}

fn bench_primitives(c: &mut Criterion) {
    let mut g = c.benchmark_group("primitives");
    let val: u64 = 0x123456789ABCDEF0;
    g.bench_function("serialize_u64", |b| {
        b.iter(|| black_box(serialize(black_box(&val)).unwrap()))
    });

    let encoded = serialize(&val).unwrap();
    g.bench_function("deserialize_u64", |b| {
        b.iter(|| black_box(deserialize::<u64>(black_box(&encoded)).unwrap()))
    });
    g.finish();
}

fn bench_collections(c: &mut Criterion) {
    let mut g = c.benchmark_group("collections");

    // HashMap
    let mut map = HashMap::new();
    for i in 0..100 {
        map.insert(i, format!("value_{}", i));
    }
    g.bench_function("serialize_hashmap_100", |b| {
        b.iter(|| black_box(serialize(black_box(&map)).unwrap()))
    });
    let encoded_map = serialize(&map).unwrap();
    g.bench_function("deserialize_hashmap_100", |b| {
        b.iter(|| black_box(deserialize::<HashMap<u32, String>>(black_box(&encoded_map)).unwrap()))
    });

    // BTreeMap
    let mut btree = BTreeMap::new();
    for i in 0..100 {
        btree.insert(i, format!("value_{}", i));
    }
    g.bench_function("serialize_btreemap_100", |b| {
        b.iter(|| black_box(serialize(black_box(&btree)).unwrap()))
    });

    // SmallVec
    let sv: SmallVec<u32, 8> = (0..8).collect();
    g.bench_function("serialize_smallvec_8", |b| {
        b.iter(|| black_box(serialize(black_box(&sv)).unwrap()))
    });

    // VecDeque
    let dq: VecDeque<u32> = (0..100).collect();
    g.bench_function("serialize_vecdeque_100", |b| {
        b.iter(|| black_box(serialize(black_box(&dq)).unwrap()))
    });

    g.finish();
}

fn bench_strings(c: &mut Criterion) {
    let mut g = c.benchmark_group("strings");

    let small_string = "hello".to_string();
    g.bench_function("serialize_string_5b", |b| {
        b.iter(|| black_box(serialize(black_box(&small_string)).unwrap()))
    });

    let large_string = "a".repeat(1024 * 64);
    g.bench_function("serialize_string_64kb", |b| {
        b.iter(|| black_box(serialize(black_box(&large_string)).unwrap()))
    });

    let encoded_large = serialize(&large_string).unwrap();
    g.bench_function("deserialize_string_64kb", |b| {
        b.iter(|| black_box(deserialize::<String>(black_box(&encoded_large)).unwrap()))
    });

    g.finish();
}

fn bench_blobs(c: &mut Criterion) {
    let mut g = c.benchmark_group("blobs");

    let small_blob = vec![0u8; 32];
    g.bench_function("serialize_blob_32b", |b| {
        b.iter(|| black_box(serialize(black_box(&small_blob)).unwrap()))
    });

    let large_blob = vec![0u8; 1024 * 1024];
    g.bench_function("serialize_blob_1mb", |b| {
        b.iter(|| black_box(serialize(black_box(&large_blob)).unwrap()))
    });

    let encoded_large = serialize(&large_blob).unwrap();
    g.bench_function("deserialize_blob_1mb", |b| {
        b.iter(|| black_box(deserialize::<Vec<u8>>(black_box(&encoded_large)).unwrap()))
    });

    g.finish();
}

fn bench_nesting(c: &mut Criterion) {
    #[derive(Debug, PartialEq, ToxProto, Clone)]
    enum Linked {
        Node(u32, Box<Linked>),
        Nil,
    }

    let mut list = Linked::Nil;
    for i in 0..100 {
        list = Linked::Node(i, Box::new(list));
    }

    let mut g = c.benchmark_group("nesting");
    g.bench_function("serialize_deep_list_100", |b| {
        b.iter(|| black_box(serialize(black_box(&list)).unwrap()))
    });

    let encoded = serialize(&list).unwrap();
    g.bench_function("deserialize_deep_list_100", |b| {
        b.iter(|| black_box(deserialize::<Linked>(black_box(&encoded)).unwrap()))
    });
    g.finish();
}

fn bench_complex(c: &mut Criterion) {
    let mut g = c.benchmark_group("complex");

    // Array of small structs
    let vec_small: Vec<SmallStruct> = vec![SmallStruct { a: 1, b: true }; 1000];
    g.bench_function("serialize_vec_small_struct_1000", |b| {
        b.iter(|| black_box(serialize(black_box(&vec_small)).unwrap()))
    });

    let encoded_vec = serialize(&vec_small).unwrap();
    g.bench_function("deserialize_vec_small_struct_1000", |b| {
        b.iter(|| black_box(deserialize::<Vec<SmallStruct>>(black_box(&encoded_vec)).unwrap()))
    });

    // Options and Results
    let vec_opt: Vec<Option<u32>> = (0..1000)
        .map(|i| if i % 2 == 0 { Some(i) } else { None })
        .collect();
    g.bench_function("serialize_vec_option_1000", |b| {
        b.iter(|| black_box(serialize(black_box(&vec_opt)).unwrap()))
    });

    let encoded_opt = serialize(&vec_opt).unwrap();
    g.bench_function("deserialize_vec_option_1000", |b| {
        b.iter(|| black_box(deserialize::<Vec<Option<u32>>>(black_box(&encoded_opt)).unwrap()))
    });

    g.finish();
}

fn bench_variants(c: &mut Criterion) {
    #[derive(ToxProto, Clone)]
    enum LargeEnum {
        V0,
        V1,
        V2,
        V3,
        V4,
        V5,
        V6,
        V7,
        V8,
        V9,
        V10,
        V11,
        V12,
        V13,
        V14,
        V15,
        V16,
        V17,
        V18,
        V19,
        Data(u64),
    }

    let mut g = c.benchmark_group("variants");
    let unit = LargeEnum::V19;
    g.bench_function("serialize_enum_unit_large", |b| {
        b.iter(|| black_box(serialize(black_box(&unit)).unwrap()))
    });

    let data = LargeEnum::Data(12345);
    g.bench_function("serialize_enum_data", |b| {
        b.iter(|| black_box(serialize(black_box(&data)).unwrap()))
    });
    g.finish();
}

fn bench_wide_struct(c: &mut Criterion) {
    #[derive(ToxProto, Clone)]
    struct Wide {
        f0: u32,
        f1: u32,
        f2: u32,
        f3: u32,
        f4: u32,
        f5: u32,
        f6: u32,
        f7: u32,
        f8: u32,
        f9: u32,
        f10: u32,
        f11: u32,
        f12: u32,
        f13: u32,
        f14: u32,
        f15: u32,
        f16: u32,
        f17: u32,
        f18: u32,
        f19: u32,
    }

    let w = Wide {
        f0: 0,
        f1: 1,
        f2: 2,
        f3: 3,
        f4: 4,
        f5: 5,
        f6: 6,
        f7: 7,
        f8: 8,
        f9: 9,
        f10: 10,
        f11: 11,
        f12: 12,
        f13: 13,
        f14: 14,
        f15: 15,
        f16: 16,
        f17: 17,
        f18: 18,
        f19: 19,
    };

    let mut g = c.benchmark_group("wide_struct");
    g.bench_function("serialize_wide_20_fields", |b| {
        b.iter(|| black_box(serialize(black_box(&w)).unwrap()))
    });

    let encoded = serialize(&w).unwrap();
    g.bench_function("deserialize_wide_20_fields", |b| {
        b.iter(|| black_box(deserialize::<Wide>(black_box(&encoded)).unwrap()))
    });
    g.finish();
}

criterion_group!(
    benches,
    bench_primitives,
    bench_collections,
    bench_strings,
    bench_blobs,
    bench_nesting,
    bench_complex,
    bench_variants,
    bench_wide_struct
);

criterion_main!(benches);
