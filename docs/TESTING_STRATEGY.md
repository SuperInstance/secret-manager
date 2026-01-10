# Secret Manager Testing Strategy

## Philosophy

**Security-First Testing**: Every test is a security test. We assume the system is under attack and test accordingly.

## Testing Pyramid

```
              /\
             /  \
            / E2E\
           /------\
          /Integration
         /----------\
        /   Unit     \
       /--------------\
```

- **70% Unit Tests**: Fast, isolated, security-focused
- **20% Integration Tests**: Component interaction verification
- **10% E2E Tests**: Critical user journeys

## Core Principles

### 1. Test Isolation

**Rule**: No test should depend on another test

```rust
// GOOD: Each test sets up its own state
#[test]
fn test_secret_retrieval() {
    let manager = setup_test_manager();
    let secret = create_test_secret();
    manager.store(secret).unwrap();
    // ... test assertions
    cleanup_test_manager(manager);
}

// BAD: Depends on global state
#[test]
fn test_secret_retrieval_bad() {
    let secret = GLOBAL_MANAGER.get("test_secret").unwrap();
    // ... assumes secret exists from previous test
}
```

### 2. Determinism

**Rule**: Tests must be reproducible

```rust
// GOOD: Deterministic time handling
use std::time::{SystemTime, UNIX_EPOCH};

fn test_time() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

// BAD: Non-deterministic
#[test]
fn test_rotation_timing() {
    // Fails when system clock changes
    let now = std::time::Instant::now();
    // ... timing-dependent assertions
}
```

### 3. Security Assertions

**Rule**: Explicit security property verification

```rust
// GOOD: Explicit security check
#[test]
fn test_encryption_provides_confidentiality() {
    let plaintext = b"sensitive data";
    let encrypted = encrypt(plaintext, &key);
    let decrypted = decrypt(&encrypted, &wrong_key);

    assert!(decrypted.is_err(), "Wrong key should fail");
    assert_ne!(plaintext, &encrypted[..], "Ciphertext != plaintext");
}

// GOOD: Timing attack resistance
#[test]
fn test_auth_timing_is_constant() {
    let valid_token = generate_token("user");
    let invalid_token = "invalid".to_string();

    let times_valid = measure_auth_time(&valid_token);
    let times_invalid = measure_auth_time(&invalid_token);

    // Timing difference should be within noise
    assert_timing_independent(times_valid, times_invalid);
}
```

### 4. Fail-Safe Defaults

**Rule**: Tests verify secure defaults

```rust
#[test]
fn test_default_policy_is_deny_all() {
    let acl = AccessControlList::default();
    let result = acl.check_permission("anyone", "secret:read");

    assert_eq!(result, Err(AccessError::Denied));
}
```

### 5. Comprehensive Edge Cases

**Rule**: Test what can go wrong, not just what works

```rust
#[test]
fn test_secret_rotation_with_concurrent_access() {
    let manager = setup_manager();
    let secret_id = "concurrent_secret";

    // Simulate concurrent rotation and access
    let (rotate_tx, rotate_rx) = channel();
    let (access_tx, access_rx) = channel();

    // Spawn rotation thread
    thread::spawn(move || {
        manager.rotate(secret_id).unwrap();
        rotate_tx.send(()).unwrap();
    });

    // Spawn multiple access threads
    for _ in 0..10 {
        thread::spawn({
            let manager = manager.clone();
            move || {
                let _ = manager.get(secret_id);
                access_tx.send(()).unwrap();
            }
        });
    }

    // All operations should complete safely
    rotate_rx.recv().unwrap();
    for _ in 0..10 {
        access_rx.recv().unwrap();
    }
}
```

## Test Structure

### Standard Test Template

```rust
mod tests {
    use super::*;
    use crate::tests::common::setup;

    #[test]
    fn test_feature() {
        // Arrange
        let (manager, _guard) = setup::test_manager();

        // Act
        let result = manager.do_something();

        // Assert
        assert!(result.is_ok());
    }

    #[test]
    fn test_feature_error_handling() {
        let (manager, _guard) = setup::test_manager();

        let result = manager.do_something_invalid();

        assert_matches!(result, Err(Error::SpecificError));
    }
}
```

### Property-Based Testing

Use `proptest` for comprehensive testing:

```rust
use proptest::prelude::*;

proptest! {
    #[test]
    fn test_encryption_roundtrip(plaintext in prop::collection::vec(any::<u8>(), 0..1024)) {
        let key = generate_test_key();
        let encrypted = encrypt(&plaintext, &key).unwrap();
        let decrypted = decrypt(&encrypted, &key).unwrap();

        assert_eq!(plaintext, decrypted);
    }
}
```

### Fuzz Testing

Use `cargo-fuzz` for security-critical code:

```bash
cargo install cargo-fuzz
cargo fuzz add encrypt_decrypt
```

```rust
// fuzz/fuzz_targets/encrypt_decrypt.rs
#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(key) = Key::from_slice(data.get(..32)?.try_into()?) {
        if let Ok(plaintext) = std::str::from_utf8(data.get(32..)?) {
            let _ = encrypt(plaintext.as_bytes(), &key);
        }
    }
});
```

## Security Testing Techniques

### 1. Timing Analysis

```rust
use std::time::Instant;

fn measure_timing<F: FnOnce()>(f: F) -> u128 {
    let start = Instant::now();
    f();
    start.elapsed().as_nanos()
}

#[test]
fn test_constant_time_comparison() {
    let valid = "correct_password";
    let invalid_similar = "correct_passwore"; // 1 char diff
    let invalid_diff = "wrong";

    let times_similar: Vec<_> = (0..100)
        .map(|_| measure_timing(|| compare_passwords(valid, invalid_similar)))
        .collect();

    let times_diff: Vec<_> = (0..100)
        .map(|_| measure_timing(|| compare_passwords(valid, invalid_diff)))
        .collect();

    // Timing should be independent of input similarity
    let avg_similar: u128 = times_similar.iter().sum::<u128>() / 100;
    let avg_diff: u128 = times_diff.iter().sum::<u128>() / 100;

    assert!((avg_similar as i128 - avg_diff as i128).abs() < 1000,
            "Timing varies by input similarity");
}
```

### 2. Memory Leak Detection

```rust
#[test]
fn test_secret_memory_is_zeroed() {
    let secret = Secret::new("sensitive_data");
    let ptr = secret.as_ptr();

    drop(secret);

    // Verify memory is zeroed after drop
    let slice = unsafe { std::slice::from_raw_parts(ptr, 14) };
    assert!(slice.iter().all(|&b| b == 0), "Memory not zeroed");
}
```

### 3. Concurrency Stress Testing

```rust
#[test]
fn test_concurrent_secret_access() {
    let manager = Arc::new(RwLock::new(SecretManager::new()));
    let secret_id = "stress_test_secret";
    manager.write().store(secret_id, b"data".to_vec()).unwrap();

    let handles: Vec<_> = (0..100)
        .map(|_| {
            let manager = manager.clone();
            thread::spawn(move || {
                for _ in 0..1000 {
                    let _ = manager.read().get(secret_id);
                }
            })
        })
        .collect();

    for handle in handles {
        handle.join().unwrap();
    }

    // Verify no corruption occurred
    let secret = manager.read().get(secret_id).unwrap();
    assert_eq!(secret, b"data");
}
```

### 4. Fault Injection

```rust
#[test]
fn test_rotation_handles_storage_failure() {
    let mut manager = SecretManager::new_with_storage(FaultyStorage::new());

    // Inject fault during rotation
    manager.storage().inject_fault(Operation::Write);

    let result = manager.rotate("test_secret");

    // Should handle failure gracefully
    assert_matches!(result, Err(Error::StorageFailure));

    // Old secret should still be accessible
    let old_secret = manager.get("test_secret").unwrap();
    assert!(old_secret.version() == 1);
}
```

## Integration Testing

### Test Containers

Use Docker for real dependencies:

```rust
#[test]
fn test_postgres_storage_integration() {
    let docker = clients::Cli::default();

    let postgres = docker.run(Postgres::default());
    let connection_string = format!(
        "postgres://postgres:postgres@localhost:{}/test",
        postgres.get_host_port_ipv4(5432)
    );

    let storage = PostgresStorage::new(&connection_string).unwrap();
    let manager = SecretManager::new_with_storage(storage);

    // Run integration tests with real database
    manager.store("test", b"secret").unwrap();
    let retrieved = manager.get("test").unwrap();
    assert_eq!(retrieved, b"secret");
}
```

### Kubernetes Testing

```rust
#[tokio::test]
async fn test_kubernetes_secret_sync() {
    let kube_client = create_test_kube_client().await;

    let manager = SecretManager::new_with_k8s(kube_client.clone());
    let secret = create_test_secret("test-secret");

    // Store in secret manager
    manager.store("test-secret", secret.data()).unwrap();

    // Verify synced to Kubernetes
    let k8s_secret: Api<Secret> = Api::default();
    let retrieved = k8s_secret.get("test-secret").await.unwrap();

    assert_eq!(retrieved.data.unwrap(), secret.data());
}
```

## Performance Testing

### Criterion Benchmarks

```rust
use criterion::{black_box, criterion_group, criterion_main, Criterion, BenchmarkId};

fn bench_secret_retrieval(c: &mut Criterion) {
    let mut group = c.benchmark_group("secret_retrieval");
    let manager = setup_benchmark_manager();

    for size in [16, 64, 256, 1024, 4096].iter() {
        group.bench_with_input(BenchmarkId::from_parameter(size), size, |b, &size| {
            b.iter(|| {
                let secret_id = format!("secret_{}", size);
                black_box(manager.get(&secret_id))
            });
        });
    }
    group.finish();
}

criterion_group!(benches, bench_secret_retrieval);
criterion_main!(benches);
```

### Load Testing

```rust
#[test]
fn test_load_performance() {
    let manager = SecretManager::new();

    // Populate with secrets
    for i in 0..1000 {
        manager.store(&format!("secret_{}", i), vec![i as u8; 64]).unwrap();
    }

    let start = Instant::now();
    let handles: Vec<_> = (0..100)
        .map(|i| {
            let manager = manager.clone();
            thread::spawn(move || {
                for j in 0..1000 {
                    let _ = manager.get(&format!("secret_{}", j));
                }
            })
        })
        .collect();

    for handle in handles {
        handle.join().unwrap();
    }

    let elapsed = start.elapsed();
    let throughput = 100_000.0 / elapsed.as_secs_f64();

    assert!(throughput > 1000.0, "Throughput too low: {}", throughput);
}
```

## Continuous Testing

### Pre-Commit Hooks

```bash
#!/bin/bash
# .git/hooks/pre-commit

# Run fast tests
cargo test --lib

# Check formatting
cargo fmt -- --check

# Run clippy
cargo clippy -- -D warnings
```

### Pre-Push Hooks

```bash
#!/bin/bash
# .git/hooks/pre-push

# Run full test suite
cargo test

# Run security tests
cargo test --test security_* --release

# Check coverage
cargo tarpaulin --minimum-coverage 90
```

## Test Metrics & Monitoring

### Key Metrics

- **Test Execution Time**: Total time for full suite
- **Flakiness Rate**: Percentage of non-deterministic failures
- **Coverage**: Line and branch coverage percentages
- **Security Test Pass Rate**: Critical for security tests
- **Performance Regression**: Benchmark comparison over time

### Dashboard

Track metrics over time:
```bash
# Generate coverage report
cargo tarpaulin --out Json --output-dir ./metrics

# Generate performance report
cargo bench -- --output-format bencher | tee ./metrics/benches.txt
```

## Best Practices

### DO ✓

1. Write tests before fixing bugs (reproduce the bug first)
2. Test error conditions, not just success paths
3. Use descriptive test names that explain what and why
4. Keep tests fast and focused
5. Mock external dependencies for unit tests
6. Use real dependencies for integration tests
7. Clean up resources in tests
8. Use type system to prevent invalid states

### DON'T ✗

1. Don't test implementation details
2. Don't write brittle tests that break easily
3. Don't ignore flaky tests
4. Don't use real secrets in tests
5. Don't sleep in tests (use synchronization primitives)
6. Don't test third-party libraries
7. Don't write tests that require manual setup
8. Don't commit commented-out tests

## Documentation

Every test file should start with:
```rust
//! # Module Tests
//!
//! Tests for [module_name] functionality.
//!
//! ## Security Considerations
//! - [Describe security implications]
//!
//! ## Test Coverage
//! - [List what is covered]
//!
//! ## Known Limitations
//! - [Describe any testing limitations]
```

## References

- [Rust Testing Patterns](https://matklad.github.io/2021/05/31/how-to-test.html)
- [Google Testing Blog](https://testing.googleblog.com/)
- [The FAST Method for Unit Testing](https://www.assertible.com/blog/the-fast-method-for-unit-testing)
- [Security Testing Handbook](https://owasp.org/www-community/Security_Testing_Handbook)
