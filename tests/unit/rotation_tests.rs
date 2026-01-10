//! Unit tests for secret rotation functionality
//!
//! Tests cover:
//! - Automatic rotation scheduling
//! - Manual rotation triggers
//! - Version management
//! - Rollback capabilities
//! - Concurrent rotation handling
//! - Performance requirements

use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::time::sleep;
use secret_manager::rotation::{RotationManager, RotationConfig, RotationError};
use secret_manager::SecretManager;

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_manual_secret_rotation() {
        let manager = SecretManager::new_in_memory();
        let secret_id = "test_secret";

        // Create initial secret
        manager
            .store(secret_id, b"initial_secret".to_vec())
            .await
            .expect("Failed to store secret");

        let initial_secret = manager.get(secret_id).await.unwrap();
        assert_eq!(initial_secret.data(), b"initial_secret");
        assert_eq!(initial_secret.version(), 1);

        // Rotate secret
        let new_version = manager
            .rotate_secret(secret_id)
            .await
            .expect("Rotation failed");

        assert_eq!(new_version, 2, "Version should increment");

        let rotated_secret = manager.get(secret_id).await.unwrap();
        assert_eq!(rotated_secret.version(), 2);
        assert_ne!(
            rotated_secret.data(),
            initial_secret.data(),
            "Rotated secret should differ from original"
        );
    }

    #[tokio::test]
    async fn test_automatic_rotation_scheduling() {
        let manager = SecretManager::new_in_memory();
        let secret_id = "auto_rotate_secret";

        let config = RotationConfig {
            enabled: true,
            interval: Duration::from_millis(100),
            auto_generate: true,
        };

        manager
            .store(secret_id, b"initial_secret".to_vec())
            .await
            .expect("Failed to store secret");

        manager
            .enable_rotation(secret_id, config)
            .await
            .expect("Failed to enable rotation");

        // Wait for rotation to occur
        sleep(Duration::from_millis(150)).await;

        let secret = manager.get(secret_id).await.unwrap();
        assert_eq!(secret.version(), 2, "Secret should have rotated");
    }

    #[tokio::test]
    async fn test_rotation_preserves_metadata() {
        let manager = SecretManager::new_in_memory();
        let secret_id = "metadata_secret";

        manager
            .store_with_metadata(
                secret_id,
                b"secret_data".to_vec(),
                vec!["tag1".to_string(), "tag2".to_string()],
            )
            .await
            .expect("Failed to store secret");

        manager.rotate_secret(secret_id).await.unwrap();

        let rotated = manager.get(secret_id).await.unwrap();
        assert_eq!(rotated.version(), 2);
        assert!(rotated.tags().contains(&"tag1".to_string()));
        assert!(rotated.tags().contains(&"tag2".to_string()));
    }

    #[tokio::test]
    async fn test_rotation_rollback() {
        let manager = SecretManager::new_in_memory();
        let secret_id = "rollback_secret";

        // Create multiple versions
        manager
            .store(secret_id, b"version_1".to_vec())
            .await
            .unwrap();
        manager.rotate_secret(secret_id).await.unwrap();
        manager.rotate_secret(secret_id).await.unwrap();

        let current = manager.get(secret_id).await.unwrap();
        assert_eq!(current.version(), 3);

        // Rollback to version 2
        manager
            .rollback(secret_id, 2)
            .await
            .expect("Rollback failed");

        let rolled_back = manager.get(secret_id).await.unwrap();
        assert_eq!(rolled_back.version(), 4, "Rollback creates new version");
        assert_eq!(rolled_back.data(), b"version_2", "Should contain version 2 data");
    }

    #[tokio::test]
    async fn test_concurrent_rotation_handling() {
        let manager = Arc::new(SecretManager::new_in_memory());
        let secret_id = "concurrent_secret";

        manager
            .store(secret_id, b"initial".to_vec())
            .await
            .unwrap();

        // Spawn multiple concurrent rotation requests
        let handles: Vec<_> = (0..10)
            .map(|_| {
                let manager = manager.clone();
                let secret_id = secret_id.to_string();
                tokio::spawn(async move {
                    manager.rotate_secret(&secret_id).await
                })
            })
            .collect();

        // Wait for all rotations
        let results: Vec<_> = futures::future::join_all(handles)
            .await
            .into_iter()
            .map(|r| r.unwrap())
            .collect();

        // All should succeed
        for result in results {
            assert!(result.is_ok(), "Concurrent rotation should succeed");
        }

        // Final version should be 11 (initial + 10 rotations)
        let secret = manager.get(secret_id).await.unwrap();
        assert_eq!(secret.version(), 11);
    }

    #[tokio::test]
    async fn test_rotation_with_custom_secret() {
        let manager = SecretManager::new_in_memory();
        let secret_id = "custom_secret";

        manager
            .store(secret_id, b"old_secret".to_vec())
            .await
            .unwrap();

        // Rotate with specific new secret value
        manager
            .rotate_with_value(secret_id, b"new_secret".to_vec())
            .await
            .expect("Rotation failed");

        let secret = manager.get(secret_id).await.unwrap();
        assert_eq!(secret.version(), 2);
        assert_eq!(secret.data(), b"new_secret");
    }

    #[tokio::test]
    async fn test_rotation_performance() {
        let manager = SecretManager::new_in_memory();

        // Create secret
        manager
            .store("perf_secret", vec![0u8; 1024])
            .await
            .unwrap();

        // Measure rotation time
        let start = Instant::now();
        manager.rotate_secret("perf_secret").await.unwrap();
        let elapsed = start.elapsed();

        // Target: <100ms for rotation
        assert!(
            elapsed.as_millis() < 100,
            "Rotation too slow: {}ms",
            elapsed.as_millis()
        );
    }

    #[tokio::test]
    async fn test_bulk_rotation() {
        let manager = SecretManager::new_in_memory();

        // Create multiple secrets
        for i in 0..100 {
            manager
                .store(&format!("secret_{}", i), vec![i as u8; 64])
                .await
                .unwrap();
        }

        // Rotate all secrets
        let start = Instant::now();
        manager.rotate_all().await.expect("Bulk rotation failed");
        let elapsed = start.elapsed();

        // Verify all rotated
        for i in 0..100 {
            let secret = manager.get(&format!("secret_{}", i)).await.unwrap();
            assert_eq!(secret.version(), 2);
        }

        // Performance check: 100 rotations <5 seconds
        assert!(
            elapsed.as_secs() < 5,
            "Bulk rotation too slow: {}s",
            elapsed.as_secs()
        );
    }

    #[tokio::test]
    async fn test_rotation_history() {
        let manager = SecretManager::new_in_memory();
        let secret_id = "history_secret";

        manager
            .store(secret_id, b"v1".to_vec())
            .await
            .unwrap();
        manager.rotate_secret(secret_id).await.unwrap();
        manager.rotate_secret(secret_id).await.unwrap();

        let history = manager.get_history(secret_id).await.unwrap();

        assert_eq!(history.len(), 3);
        assert_eq!(history[0].version(), 1);
        assert_eq!(history[1].version(), 2);
        assert_eq!(history[2].version(), 3);
    }

    #[tokio::test]
    async fn test_rotation_error_handling() {
        let manager = SecretManager::new_in_memory();

        // Rotate non-existent secret
        let result = manager.rotate_secret("nonexistent").await;

        assert!(result.is_err());
        assert_matches!(result, Err(RotationError::SecretNotFound));
    }

    #[tokio::test]
    async fn test_rotation_disabled_by_default() {
        let manager = SecretManager::new_in_memory();
        let secret_id = "manual_only_secret";

        manager
            .store(secret_id, b"secret".to_vec())
            .await
            .unwrap();

        // Wait longer than would trigger rotation if enabled
        sleep(Duration::from_millis(200)).await;

        let secret = manager.get(secret_id).await.unwrap();
        assert_eq!(secret.version(), 1, "Should not auto-rotate when disabled");
    }

    #[tokio::test]
    async fn test_rotation_with_access_during_rotation() {
        let manager = Arc::new(SecretManager::new_in_memory());
        let secret_id = "access_during_rotation";

        manager
            .store(secret_id, b"initial".to_vec())
            .await
            .unwrap();

        // Spawn rotation in background
        let manager_clone = manager.clone();
        let secret_id_clone = secret_id.to_string();
        tokio::spawn(async move {
            sleep(Duration::from_millis(50)).await;
            manager_clone.rotate_secret(&secret_id_clone).await.unwrap();
        });

        // Immediately try to access (before rotation completes)
        let secret = manager.get(secret_id).await.unwrap();
        assert_eq!(secret.version(), 1);

        // After rotation completes, should get new version
        sleep(Duration::from_millis(100)).await;
        let secret = manager.get(secret_id).await.unwrap();
        assert_eq!(secret.version(), 2);
    }

    #[tokio::test]
    async fn test_rotation_cleanup_old_versions() {
        let manager = SecretManager::new_in_memory();
        let secret_id = "cleanup_secret";

        manager
            .store(secret_id, b"v1".to_vec())
            .await
            .unwrap();

        // Create multiple versions
        for _ in 0..10 {
            manager.rotate_secret(secret_id).await.unwrap();
        }

        // Configure retention to 5 versions
        manager
            .set_version_retention(secret_id, 5)
            .await
            .unwrap();

        // Cleanup old versions
        manager.cleanup_old_versions(secret_id).await.unwrap();

        let history = manager.get_history(secret_id).await.unwrap();
        assert_eq!(history.len(), 5, "Should keep only 5 versions");
    }
}
