//! Test fixtures for secret-manager tests
//!
//! Provides predefined test data and sample objects for consistent testing

use std::time::Duration;
use uuid::Uuid;

/// Test secret data
pub struct TestSecret {
    pub id: String,
    pub data: Vec<u8>,
    pub metadata: SecretMetadata,
}

#[derive(Clone)]
pub struct SecretMetadata {
    pub name: String,
    pub description: String,
    pub tags: Vec<String>,
    pub rotation_period: Option<Duration>,
}

impl TestSecret {
    /// Create a basic test secret
    pub fn new(id: &str, data: &[u8]) -> Self {
        Self {
            id: id.to_string(),
            data: data.to_vec(),
            metadata: SecretMetadata {
                name: format!("secret_{}", id),
                description: format!("Test secret {}", id),
                tags: vec!["test".to_string()],
                rotation_period: None,
            },
        }
    }

    /// Create a test secret with rotation
    pub fn with_rotation(id: &str, data: &[u8], rotation_period: Duration) -> Self {
        let mut secret = Self::new(id, data);
        secret.metadata.rotation_period = Some(rotation_period);
        secret
    }

    /// Generate a random test secret
    pub fn random() -> Self {
        let id = Uuid::new_v4().to_string();
        let data = vec![0x42; 64]; // Fixed pattern for deterministic tests
        Self::new(&id, &data)
    }

    /// Generate a test secret with specific size
    pub fn with_size(size: usize) -> Self {
        let id = format!("secret_{}_bytes", size);
        let data = vec![0xAB; size];
        Self::new(&id, &data)
    }
}

/// Predefined test secrets
pub mod secrets {
    use super::*;

    pub fn basic_secret() -> TestSecret {
        TestSecret::new("basic", b"my_secret_password")
    }

    pub fn api_key() -> TestSecret {
        TestSecret::new("api_key", b"sk-1234567890abcdef")
    }

    pub fn database_url() -> TestSecret {
        TestSecret::new(
            "database_url",
            b"postgresql://user:pass@localhost:5432/db",
        )
    }

    pub fn certificate() -> TestSecret {
        let cert_data = b"-----BEGIN CERTIFICATE-----\n\
            MIIBkTCB+wIJAKHHcHGzVh8mMA0GCSqGSIb3DQEBCwUAMBExDzANBgNVBAMMBnRl\n\
            c3RDQTAeFw0yNDAxMDEwMDAwMDBaFw0yNTAxMDEwMDAwMDBaMBExDzANBgNVBAMM\n\
            -----END CERTIFICATE-----";
        TestSecret::new("certificate", cert_data)
    }

    pub fn large_secret() -> TestSecret {
        TestSecret::with_size(4096)
    }

    pub fn empty_secret() -> TestSecret {
        TestSecret::new("empty", b"")
    }

    pub fn unicode_secret() -> TestSecret {
        TestSecret::new("unicode", "密码🔑".as_bytes())
    }
}

/// Test user data for access control
pub struct TestUser {
    pub id: String,
    pub name: String,
    pub roles: Vec<String>,
    pub permissions: Vec<String>,
}

impl TestUser {
    pub fn new(id: &str, roles: Vec<String>) -> Self {
        Self {
            id: id.to_string(),
            name: format!("User {}", id),
            roles,
            permissions: vec![],
        }
    }

    pub fn admin() -> Self {
        Self::new("admin", vec!["admin".to_string()])
    }

    pub fn reader() -> Self {
        Self::new("reader", vec!["reader".to_string()])
    }

    pub fn writer() -> Self {
        Self::new("writer", vec!["writer".to_string()])
    }

    pub fn unprivileged() -> Self {
        Self::new("nobody", vec![])
    }
}

/// Test access control policies
pub mod policies {
    use super::*;

    pub fn admin_policy() -> AccessPolicy {
        AccessPolicy {
            name: "admin_policy".to_string(),
            permissions: vec![
                "secret:*".to_string(),
                "key:*".to_string(),
                "audit:*".to_string(),
            ],
            roles: vec!["admin".to_string()],
        }
    }

    pub fn reader_policy() -> AccessPolicy {
        AccessPolicy {
            name: "reader_policy".to_string(),
            permissions: vec!["secret:read".to_string()],
            roles: vec!["reader".to_string()],
        }
    }

    pub fn writer_policy() -> AccessPolicy {
        AccessPolicy {
            name: "writer_policy".to_string(),
            permissions: vec![
                "secret:read".to_string(),
                "secret:write".to_string(),
            ],
            roles: vec!["writer".to_string()],
        }
    }
}

pub struct AccessPolicy {
    pub name: String,
    pub permissions: Vec<String>,
    pub roles: Vec<String>,
}

/// Test encryption keys (for testing only, never used in production)
pub mod keys {
    use crate::crypto::Key;

    /// Generate a test key (deterministic for testing)
    pub fn test_key() -> Key {
        // In real implementation, this would generate from known test vector
        Key::from_bytes([0x42u8; 32])
    }

    /// Generate a different test key
    pub fn test_key_2() -> Key {
        Key::from_bytes([0x43u8; 32])
    }

    /// Invalid key (wrong length)
    pub fn invalid_key() -> Vec<u8> {
        vec![0x00; 16] // Too short for AES-256
    }
}

/// Test audit events
pub mod audit {
    use chrono::Utc;
    use crate::audit::AuditEvent;

    pub fn secret_created_event(secret_id: &str) -> AuditEvent {
        AuditEvent {
            timestamp: Utc::now(),
            event_type: "secret.created".to_string(),
            actor: "test_user".to_string(),
            resource: secret_id.to_string(),
            action: "create".to_string(),
            result: "success".to_string(),
            metadata: std::collections::HashMap::new(),
        }
    }

    pub fn secret_accessed_event(secret_id: &str) -> AuditEvent {
        AuditEvent {
            timestamp: Utc::now(),
            event_type: "secret.accessed".to_string(),
            actor: "test_user".to_string(),
            resource: secret_id.to_string(),
            action: "read".to_string(),
            result: "success".to_string(),
            metadata: std::collections::HashMap::new(),
        }
    }

    pub fn access_denied_event(secret_id: &str) -> AuditEvent {
        AuditEvent {
            timestamp: Utc::now(),
            event_type: "access.denied".to_string(),
            actor: "unauthorized_user".to_string(),
            resource: secret_id.to_string(),
            action: "read".to_string(),
            result: "denied".to_string(),
            metadata: std::collections::HashMap::new(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_test_secret_creation() {
        let secret = TestSecret::new("test", b"data");
        assert_eq!(secret.id, "test");
        assert_eq!(secret.data, b"data");
    }

    #[test]
    fn test_random_secret_generation() {
        let secret1 = TestSecret::random();
        let secret2 = TestSecret::random();
        assert_ne!(secret1.id, secret2.id);
    }

    #[test]
    fn test_test_user_roles() {
        let admin = TestUser::admin();
        assert!(admin.roles.contains(&"admin".to_string()));
    }
}
