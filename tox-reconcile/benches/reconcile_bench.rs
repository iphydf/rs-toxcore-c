use criterion::{BenchmarkId, Criterion, criterion_group, criterion_main};
use std::hint::black_box;
use tox_reconcile::{IbltSketch, Tier};

fn bench_iblt_ops(c: &mut Criterion) {
    let mut g = c.benchmark_group("iblt_ops");

    for tier in [Tier::Tiny, Tier::Small, Tier::Medium, Tier::Large] {
        let name = format!("{:?}", tier);

        g.bench_with_input(BenchmarkId::new("insert", &name), &tier, |b, tier| {
            let mut iblt = IbltSketch::new(tier.cell_count());
            let id = [42u8; 32];
            b.iter(|| iblt.insert(black_box(&id)))
        });

        g.bench_with_input(
            BenchmarkId::new("decode_no_diff", &name),
            &tier,
            |b, tier| {
                let mut iblt = IbltSketch::new(tier.cell_count());
                b.iter(|| black_box(iblt.decode().unwrap()))
            },
        );

        g.bench_with_input(
            BenchmarkId::new("decode_max_diff", &name),
            &tier,
            |b, tier| {
                let cell_count = tier.cell_count();
                let max_diff = cell_count / 2; // Approximate peelable limit
                let mut iblt = IbltSketch::new(cell_count);
                for i in 0..max_diff {
                    let mut h = [0u8; 32];
                    h[0..4].copy_from_slice(&(i as u32).to_le_bytes());
                    iblt.insert(&h);
                }
                b.iter(|| {
                    let mut clone = IbltSketch::from_cells(iblt.cells.clone());
                    black_box(clone.decode().unwrap())
                })
            },
        );
    }

    g.finish();
}

criterion_group!(benches, bench_iblt_ops);
criterion_main!(benches);
