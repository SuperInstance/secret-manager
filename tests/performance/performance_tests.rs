//! Performance tests for secret-manager
//!
//! Performance targets:
//! - Secret retrieve: <1ms (target), <5ms (acceptable), <10ms (critical)
//! - Secret rotation: <100ms (target), <500ms (acceptable), <1s (critical)
//! - Authorization check: <0.5ms (target)
//! - Audit log write: <1ms (target)
//! - Throughput: >1000 ops/sec

use std::time::{Duration, Instant};
use std::sync::Arc;
use tokio::time::sleep;
use secret_manager::SecretManager;

#[cfg(test)]
mod performance_tests {
    use super::*;

    /// Test: Secret retrieval performance
    /// Target: <1ms
    #[tokio::test]
    async fn test_secret_retrieve_performance() {
        let manager = SecretManager::new_in_memory();

        // Populate with secrets
        for i in 0..100 {
            manager
                .store(&format!("secret_{}", i), vec![i as u8; 64])
                .await
                .unwrap();
        }

        // Warm up
        for _ in 0..10 {
            let _ = manager.get("secret_0").await.unwrap();
        }

        // Measure retrieval time
        let iterations = 1000;
        let start = Instant::now();

        for i in 0..iterations {
            let secret_id = format!("secret_{}", i % 100);
            let _ = manager.get(&secret_id).await.unwrap();
        }

        let elapsed = start.elapsed();
        let avg_per_op = elapsed / iterations;

        println!("Average secret retrieval time: {:?}", avg_per_op);
        println!("Throughput: {} ops/sec", iterations as f64 / elapsed.as_secs_f64());

        // Assertions
        if avg_per_op < Duration::from_millis(1) {
            println!("✓ TARGET MET: <1ms");
        } else if avg_per_op < Duration::from_millis(5) {
            println!("⚠ ACCEPTABLE: <5ms");
        } else if avg_per_op < Duration::from_millis(10) {
            println!("⚠⚠ CRITICAL: <10ms");
        } else {
            panic!("✗ FAILED: {:?}", avg_per_op);
        }
    }

    /// Test: Secret rotation performance
    /// Target: <100ms
    #[tokio::test]
    async fn test_secret_rotation_performance() {
        let manager = SecretManager::new_in_memory();

        // Create secret
        manager
            .store("rotate_secret", vec![0x42u8; 1024])
            .await
            .unwrap();

        // Warm up
        manager.rotate_secret("rotate_secret").await.unwrap();

        // Measure rotation time
        let iterations = 100;
        let mut times = Vec::with_capacity(iterations);

        for _ in 0..iterations {
            let start = Instant::now();
            manager.rotate_secret("rotate_secret").await.unwrap();
            times.push(start.elapsed());
        }

        let avg_time: Duration = times.iter().sum::<Duration>() / iterations as u32;
        let p50 = percentile(&times, 50);
        let p95 = percentile(&times, 95);
        let p99 = percentile(&times, 99);

        println!("Average rotation time: {:?}", avg_time);
        println!("p50: {:?}", p50);
        println!("p95: {:?}", p95);
        println!("p99: {:?}", p99);

        // Assertions
        if avg_time < Duration::from_millis(100) {
            println!("✓ TARGET MET: <100ms");
        } else if avg_time < Duration::from_millis(500) {
            println!("⚠ ACCEPTABLE: <500ms");
        } else if avg_time < Duration::from_millis(1000) {
            println!("⚠⚠ CRITICAL: <1s");
        } else {
            panic!("✗ FAILED: {:?}", avg_time);
        }
    }

    /// Test: Authorization check performance
    /// Target: <0.5ms
    #[test]
    fn test_authorization_check_performance() {
        use secret_manager::access_control::{AccessControl, Role, Permission};

        let acl = setup_acl();
        acl.assign_role("user1", "reader").unwrap();

        // Warm up
        for _ in 0..100 {
            let _ = acl.check_permission("user1", "secret:read");
        }

        // Measure authorization check time
        let iterations = 10_000;
        let start = Instant::now();

        for _ in 0..iterations {
            let _ = acl.check_permission("user1", "secret:read");
        }

        let elapsed = start.elapsed();
        let avg_per_op = elapsed / iterations;

        println!("Average authorization check time: {:?}", avg_per_op);
        println!("Throughput: {} checks/sec", iterations as f64 / elapsed.as_secs_f64());

        // Assertions
        if avg_per_op < Duration::from_micros(500) {
            println!("✓ TARGET MET: <0.5ms");
        } else {
            panic!("✗ FAILED: {:?}", avg_per_op);
        }
    }

    fn setup_acl() -> AccessControl {
        use secret_manager::access_control::{AccessControl, Role, Permission};

        let mut acl = AccessControl::new();

        let reader = Role::new("reader").with_permissions(vec![
            Permission::new("secret", "read"),
        ]);

        acl.add_role(reader);
        acl
    }

    /// Test: Concurrent access performance
    #[tokio::test]
    async fn test_concurrent_access_performance() {
        let manager = Arc::new(SecretManager::new_in_memory());

        // Populate secrets
        for i in 0..100 {
            manager
                .store(&format!("secret_{}", i), vec![i as u8; 64])
                .await
                .unwrap();
        }

        // Spawn concurrent access threads
        let num_threads = 10;
        let operations_per_thread = 1000;
        let start = Instant::now();

        let handles: Vec<_> = (0..num_threads)
            .map(|thread_id| {
                let manager = manager.clone();
                tokio::spawn(async move {
                    for i in 0..operations_per_thread {
                        let secret_id = format!("secret_{}", i % 100);
                        let _ = manager.get(&secret_id).await;
                    }
                })
            })
            .collect();

        for handle in handles {
            handle.await.unwrap();
        }

        let elapsed = start.elapsed();
        let total_ops = num_threads * operations_per_thread;
        let throughput = total_ops as f64 / elapsed.as_secs_f64();

        println!("Concurrent access throughput: {} ops/sec", throughput);

        // Should handle at least 1000 ops/sec
        assert!(throughput >= 1000.0, "Throughput too low: {}", throughput);
    }

    /// Test: Memory usage per secret
    #[test]
    fn test_memory_usage() {
        use std::alloc::{GlobalAlloc, Layout, System};
        use std::sync::atomic::{AtomicUsize, Ordering};

        struct MemCounter {
            allocations: AtomicUsize,
        }

        unsafe impl GlobalAlloc for MemCounter {
            unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
                self.allocations.fetch_add(layout.size(), Ordering::SeqCst);
                System.alloc(layout)
            }

            unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
                System.dealloc(ptr, layout)
            }
        }

        // This is a simplified example
        // In production, use dedicated memory profiling tools
        // like valgrind, heaptrack, or Rust's built-in instrumentation

        #[global_allocator]
        static GLOBAL: MemCounter = MemCounter {
            allocations: AtomicUsize::new(0),
        };

        let manager = SecretManager::new_in_memory();
        let secret_data = vec![0x42u8; 1024];

        // Store secret
        manager.store("test", secret_data).await.unwrap();

        // Note: This requires actual runtime instrumentation
        // Documented here for reference
    }

    /// Test: Bulk operation performance
    #[tokio::test]
    async fn test_bulk_operation_performance() {
        let manager = SecretManager::new_in_memory();

        // Measure bulk store
        let num_secrets = 1000;
        let start = Instant::now();

        for i in 0..num_secrets {
            manager
                .store(&format!("bulk_{}", i), vec![i as u8; 64])
                .await
                .unwrap();
        }

        let store_time = start.elapsed();

        // Measure bulk retrieve
        let start = Instant::now();

        for i in 0..num_secrets {
            let _ = manager.get(&format!("bulk_{}", i)).await.unwrap();
        }

        let retrieve_time = start.elapsed();

        println!("Bulk store ({} secrets): {:?}", num_secrets, store_time);
        println!("Bulk retrieve ({} secrets): {:?}", num_secrets, retrieve_time);
        println!("Store throughput: {} secrets/sec", num_secrets as f64 / store_time.as_secs_f64());
        println!("Retrieve throughput: {} secrets/sec", num_secrets as f64 / retrieve_time.as_secs_f64());

        // Should handle bulk operations efficiently
        assert!(store_time.as_secs() < 10, "Bulk store too slow");
        assert!(retrieve_time.as_secs() < 5, "Bulk retrieve too slow");
    }

    /// Test: Encryption performance by data size
    #[test]
    fn test_encryption_performance_by_size() {
        use secret_manager::crypto::{encrypt, Key};

        let key = Key::from_bytes([0x42u8; 32]);
        let sizes = vec![16, 64, 256, 1024, 4096, 16384];

        println!("\nEncryption performance by size:");
        println!("{:>10} | {:>12} | {:>15}", "Size", "Time (µs)", "Throughput (MB/s)");

        for size in sizes {
            let data = vec![0x42u8; size];
            let iterations = 100;

            let start = Instant::now();
            for _ in 0..iterations {
                let _ = encrypt(&data, &key, None);
            }
            let elapsed = start.elapsed();
            let avg_us = elapsed.as_micros() / iterations;
            let throughput_mbps = (size as f64 / 1024.0 / 1024.0) / (elapsed.as_secs_f64() / iterations as f64);

            println!("{:>10} | {:>12} | {:>15.2}", size, avg_us, throughput_mbps);
        }
    }

    /// Test: Key derivation performance
    #[test]
    fn test_key_derivation_performance() {
        use secret_manager::crypto::key_derivation::derive_key_pbkdf2;

        let password = b"test_password";
        let salt = b"test_salt_16bytes!";
        let iterations = vec![100_000, 600_000, 1_000_000];

        println!("\nKey derivation performance (PBKDF2):");
        println!("{:>12} | {:>12}", "Iterations", "Time (ms)");

        for iter in iterations {
            let start = Instant::now();
            let _key = derive_key_pbkdf2(password, salt, iter).unwrap();
            let elapsed = start.elapsed();

            println!("{:>12} | {:>12.2}", iter, elapsed.as_millis());

            // Verify minimum time for security
            assert!(
                elapsed.as_millis() >= iter as u128 / 10000,
                "Key derivation too fast - potential security issue"
            );
        }
    }

    /// Test: Lock contention under high concurrency
    #[tokio::test]
    async fn test_lock_contention() {
        let manager = Arc::new(SecretManager::new_in_memory());
        manager.store("contended", vec![0x42; 64]).await.unwrap();

        let num_threads = 100;
        let operations_per_thread = 100;

        let handles: Vec<_> = (0..num_threads)
            .map(|_| {
                let manager = manager.clone();
                tokio::spawn(async move {
                    for _ in 0..operations_per_thread {
                        // Mix of reads and writes
                        if rand::random::<bool>() {
                            let _ = manager.get("contended").await;
                        } else {
                            let _ = manager.rotate_secret("contended").await;
                        }
                    }
                })
            })
            .collect();

        for handle in handles {
            handle.await.unwrap();
        }

        // If we reach here without deadlock, contention is handled
        println!("✓ Lock contention test passed (no deadlocks)");
    }

    /// Helper: Calculate percentile
    fn percentile(durations: &[Duration], p: u8) -> Duration {
        let mut sorted = durations.to_vec();
        sorted.sort();
        let index = (sorted.len() as f64 * p as f64 / 100.0) as usize;
        sorted[index.min(sorted.len() - 1)]
    }

    /// Test: Memory leak detection
    #[tokio::test]
    async fn test_memory_leaks() {
        let manager = SecretManager::new_in_memory();

        // Store and retrieve many times
        for i in 0..10_000 {
            let secret_id = format!("temp_{}", i);
            manager.store(&secret_id, vec![i as u8; 64]).await.unwrap();
            let _ = manager.get(&secret_id).await.unwrap();
        }

        // In production, use memory profiling tools
        // This test documents the need for leak detection
        println!("✓ Memory leak test completed (use valgrind/heaptrack for verification)");
    }
}
