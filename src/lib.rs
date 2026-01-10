//! # Secret Manager
//!
//! Security-first secret management library providing:
//! - Secret encryption and decryption
//! - Automatic secret rotation
//! - Role-based access control (RBAC)
//! - Comprehensive audit logging
//! - Kubernetes integration
//!
//! ## Performance Targets
//!
//! | Operation | Target | Acceptable | Critical |
//! |-----------|--------|------------|----------|
//! | Secret retrieve | <1ms | <5ms | <10ms |
//! | Secret rotation | <100ms | <500ms | <1s |
//! | Authorization check | <0.5ms | <2ms | <5ms |
//! | Audit log write | <1ms | <5ms | <10ms |
//!
//! ## Security Features
//!
//! - **Encryption**: AES-256-GCM or ChaCha20-Poly1305
//! - **Key Derivation**: PBKDF2 (600k+ iterations) or Argon2id
//! - **Access Control**: Whitelist-based RBAC with default deny
//! - **Audit Logging**: Immutable, tamper-evident logging
//!
//! ## Example Usage
//!
//! ```rust,no_run
//! use secret_manager::SecretManager;
//!
//! #[tokio::main]
//! async fn main() -> Result<(), Box<dyn std::error::Error>> {
//!     // Create manager
//!     let manager = SecretManager::new_in_memory();
//!
//!     // Store secret
//!     manager.store("api_key", b"secret-key").await?;
//!
//!     // Retrieve secret
//!     let secret = manager.get("api_key").await?;
//!
//!     // Rotate secret
//!     manager.rotate_secret("api_key").await?;
//!
//!     Ok(())
//! }
//! ```

pub mod crypto;
pub mod rotation;
pub mod access_control;
pub mod audit;
pub mod storage;

pub use crypto::{encrypt, decrypt, Key, EncryptionError};
pub use rotation::{RotationManager, RotationConfig, RotationError};
pub use access_control::{AccessControl, Role, Permission, AccessError, Token};
pub use audit::{AuditLogger, AuditEvent};

use std::sync::Arc;
use tokio::sync::RwLock;

/// Main secret manager providing high-level secret operations
pub struct SecretManager {
    storage: Arc<dyn storage::Storage>,
    rotation: Arc<rotation::RotationManager>,
    access_control: Arc<access_control::AccessControl>,
    audit: Arc<audit::AuditLogger>,
}

impl SecretManager {
    /// Create a new in-memory secret manager (for testing)
    pub fn new_in_memory() -> Self {
        Self {
            storage: Arc::new(storage::InMemoryStorage::new()),
            rotation: Arc::new(rotation::RotationManager::new()),
            access_control: Arc::new(access_control::AccessControl::new()),
            audit: Arc::new(audit::AuditLogger::new()),
        }
    }

    /// Create secret manager with file-based storage
    pub fn new_with_file_storage(path: &std::path::Path) -> Result<Self, storage::StorageError> {
        Ok(Self {
            storage: Arc::new(storage::FileStorage::new(path)?),
            rotation: Arc::new(rotation::RotationManager::new()),
            access_control: Arc::new(access_control::AccessControl::new()),
            audit: Arc::new(audit::AuditLogger::new()),
        })
    }

    /// Store a secret
    pub async fn store(&self, id: &str, data: Vec<u8>) -> Result<(), SecretError> {
        let secret = storage::Secret::new(id, data);
        self.storage.store(secret).await?;
        self.audit.log(audit::AuditEvent::secret_stored(id)).await?;
        Ok(())
    }

    /// Store a secret with metadata
    pub async fn store_with_metadata(
        &self,
        id: &str,
        data: Vec<u8>,
        tags: Vec<String>,
    ) -> Result<(), SecretError> {
        let mut secret = storage::Secret::new(id, data);
        secret.set_tags(tags);
        self.storage.store(secret).await?;
        self.audit.log(audit::AuditEvent::secret_stored(id)).await?;
        Ok(())
    }

    /// Retrieve a secret
    pub async fn get(&self, id: &str) -> Result<storage::Secret, SecretError> {
        let secret = self.storage.get(id).await?;
        self.audit.log(audit::AuditEvent::secret_accessed(id)).await?;
        Ok(secret)
    }

    /// Rotate a secret
    pub async fn rotate_secret(&self, id: &str) -> Result<u32, SecretError> {
        let new_version = self.rotation.rotate_secret(id, &*self.storage).await?;
        self.audit.log(audit::AuditEvent::secret_rotated(id, new_version)).await?;
        Ok(new_version)
    }

    /// Rotate with specific value
    pub async fn rotate_with_value(&self, id: &str, new_value: Vec<u8>) -> Result<u32, SecretError> {
        let new_version = self.rotation.rotate_with_value(id, new_value, &*self.storage).await?;
        self.audit.log(audit::AuditEvent::secret_rotated(id, new_version)).await?;
        Ok(new_version)
    }

    /// Enable automatic rotation for a secret
    pub async fn enable_rotation(&self, id: &str, config: rotation::RotationConfig) -> Result<(), SecretError> {
        self.rotation.enable_rotation(id, config).await?;
        Ok(())
    }

    /// Rollback to previous version
    pub async fn rollback(&self, id: &str, version: u32) -> Result<(), SecretError> {
        self.rotation.rollback(id, version, &*self.storage).await?;
        self.audit.log(audit::AuditEvent::secret_rollback(id, version)).await?;
        Ok(())
    }

    /// Get secret history
    pub async fn get_history(&self, id: &str) -> Result<Vec<storage::Secret>, SecretError> {
        self.storage.get_history(id).await
    }

    /// Delete a secret
    pub async fn delete(&self, id: &str) -> Result<(), SecretError> {
        self.storage.delete(id).await?;
        self.audit.log(audit::AuditEvent::secret_deleted(id)).await?;
        Ok(())
    }

    /// Rotate all secrets (bulk operation)
    pub async fn rotate_all(&self) -> Result<(), SecretError> {
        self.rotation.rotate_all(&*self.storage).await?;
        Ok(())
    }

    /// Set version retention policy
    pub async fn set_version_retention(&self, id: &str, count: usize) -> Result<(), SecretError> {
        self.rotation.set_retention(id, count).await?;
        Ok(())
    }

    /// Cleanup old versions
    pub async fn cleanup_old_versions(&self, id: &str) -> Result<(), SecretError> {
        self.rotation.cleanup_old_versions(id, &*self.storage).await?;
        Ok(())
    }

    /// Get access control instance
    pub fn access_control(&self) -> &Arc<access_control::AccessControl> {
        &self.access_control
    }

    /// Get audit logger instance
    pub fn audit_logger(&self) -> &Arc<audit::AuditLogger> {
        &self.audit
    }
}

/// Secret error types
#[derive(Debug, thiserror::Error)]
pub enum SecretError {
    #[error("Storage error: {0}")]
    Storage(#[from] storage::StorageError),

    #[error("Rotation error: {0}")]
    Rotation(#[from] rotation::RotationError),

    #[error("Access control error: {0}")]
    Access(#[from] access_control::AccessError),

    #[error("Secret not found: {0}")]
    NotFound(String),
}

/// Re-export storage module
pub mod storage_exports {
    pub use crate::storage::{Secret, StorageError};
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_basic_operations() {
        let manager = SecretManager::new_in_memory();

        // Store
        manager.store("test", b"secret".to_vec()).await.unwrap();

        // Retrieve
        let secret = manager.get("test").await.unwrap();
        assert_eq!(secret.data(), b"secret");

        // Delete
        manager.delete("test").await.unwrap();
        assert!(manager.get("test").await.is_err());
    }
}
