//! Encryption performance benchmarks
//!
//! Run with: cargo bench --bench encryption_bench

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use secret_manager::crypto::{encrypt, decrypt, Key};
use secret_manager::crypto::key_derivation::derive_key_pbkdf2;

fn bench_encrypt_decrypt(c: &mut Criterion) {
    let key = Key::from_bytes([0x42u8; 32]);

    // Benchmark encryption/decryption for different data sizes
    for size in [16, 64, 256, 1024, 4096, 16384].iter() {
        let mut group = c.benchmark_group("encrypt");
        group.throughput(Throughput::Bytes(*size as u64));

        group.bench_with_input(BenchmarkId::from_parameter(size), size, |b, &size| {
            let data = vec![0x42u8; size];
            b.iter(|| {
                let encrypted = encrypt(black_box(&data), black_box(&key), None).unwrap();
                encrypted
            });
        });

        group.finish();
    }

    // Benchmark decryption
    let data = vec![0x42u8; 1024];
    let encrypted = encrypt(&data, &key, None).unwrap();

    c.bench_function("decrypt_1024", |b| {
        b.iter(|| {
            let decrypted = decrypt(black_box(&encrypted), black_box(&key), None).unwrap();
            decrypted
        });
    });
}

fn bench_key_derivation(c: &mut Criterion) {
    let password = b"test_password";
    let salt = b"test_salt_16bytes!";
    let iterations = [100_000, 600_000, 1_000_000];

    for iter in iterations.iter() {
        let mut group = c.benchmark_group("key_derivation");

        group.bench_with_input(BenchmarkId::from_parameter(iter), iter, |b, &iter| {
            b.iter(|| {
                derive_key_pbkdf2(black_box(password), black_box(salt), iter).unwrap()
            });
        });

        group.sample_size(10); // Key derivation is slow
        group.finish();
    }
}

fn bench_roundtrip(c: &mut Criterion) {
    let key = Key::from_bytes([0x42u8; 32]);

    for size in [64, 256, 1024, 4096].iter() {
        let mut group = c.benchmark_group("roundtrip");

        group.bench_with_input(BenchmarkId::from_parameter(size), size, |b, &size| {
            let data = vec![0x42u8; size];
            b.iter(|| {
                let encrypted = encrypt(black_box(&data), black_box(&key), None).unwrap();
                let decrypted = decrypt(black_box(&encrypted), black_box(&key), None).unwrap();
                decrypted
            });
        });

        group.finish();
    }
}

criterion_group!(benches, bench_encrypt_decrypt, bench_key_derivation, bench_roundtrip);
criterion_main!(benches);
