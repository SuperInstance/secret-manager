//! Mock implementations for testing external dependencies

use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use async_trait::async_trait;

/// Mock storage backend for testing
pub struct MockStorage {
    data: Arc<RwLock<HashMap<String, Vec<u8>>>>,
    fail_on: Arc<RwLock<Vec<String>>>,
}

impl MockStorage {
    pub fn new() -> Self {
        Self {
            data: Arc::new(RwLock::new(HashMap::new())),
            fail_on: Arc::new(RwLock::new(Vec::new())),
        }
    }

    pub fn insert(&self, key: &str, value: &[u8]) {
        self.data
            .write()
            .unwrap()
            .insert(key.to_string(), value.to_vec());
    }

    pub fn get(&self, key: &str) -> Option<Vec<u8>> {
        self.data.read().unwrap().get(key).cloned()
    }

    pub fn contains_key(&self, key: &str) -> bool {
        self.data.read().unwrap().contains_key(key)
    }

    pub fn remove(&self, key: &str) -> bool {
        self.data.write().unwrap().remove(key).is_some()
    }

    pub fn clear(&self) {
        self.data.write().unwrap().clear();
    }

    /// Make operations fail for specific keys
    pub fn fail_on(&self, key: &str) {
        self.fail_on.write().unwrap().push(key.to_string());
    }

    pub fn should_fail(&self, key: &str) -> bool {
        self.fail_on.read().unwrap().contains(&key.to_string())
    }
}

impl Default for MockStorage {
    fn default() -> Self {
        Self::new()
    }
}

/// Mock key management service
pub struct MockKeyService {
    keys: Arc<RwLock<HashMap<String, Vec<u8>>>>,
}

impl MockKeyService {
    pub fn new() -> Self {
        Self {
            keys: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    pub fn add_key(&self, key_id: &str, key_data: &[u8]) {
        self.keys
            .write()
            .unwrap()
            .insert(key_id.to_string(), key_data.to_vec());
    }

    pub fn get_key(&self, key_id: &str) -> Option<Vec<u8>> {
        self.keys.read().unwrap().get(key_id).cloned()
    }

    pub fn generate_key(&self) -> Vec<u8> {
        vec![0x42u8; 32] // Deterministic for testing
    }
}

impl Default for MockKeyService {
    fn default() -> Self {
        Self::new()
    }
}

/// Mock audit logger
#[derive(Clone)]
pub struct MockAuditLogger {
    events: Arc<RwLock<Vec<crate::audit::AuditEvent>>>,
}

impl MockAuditLogger {
    pub fn new() -> Self {
        Self {
            events: Arc::new(RwLock::new(Vec::new())),
        }
    }

    pub fn log(&self, event: crate::audit::AuditEvent) {
        self.events.write().unwrap().push(event);
    }

    pub fn get_events(&self) -> Vec<crate::audit::AuditEvent> {
        self.events.read().unwrap().clone()
    }

    pub fn clear(&self) {
        self.events.write().unwrap().clear();
    }

    pub fn event_count(&self) -> usize {
        self.events.read().unwrap().len()
    }

    /// Find event by type
    pub fn find_event(&self, event_type: &str) -> Option<crate::audit::AuditEvent> {
        self.events
            .read()
            .unwrap()
            .iter()
            .find(|e| e.event_type == event_type)
            .cloned()
    }

    /// Check if event was logged
    pub fn has_event(&self, event_type: &str) -> bool {
        self.find_event(event_type).is_some()
    }
}

impl Default for MockAuditLogger {
    fn default() -> Self {
        Self::new()
    }
}

/// Mock access control service
pub struct MockAccessControl {
    permissions: Arc<RwLock<HashMap<String, Vec<String>>>>,
}

impl MockAccessControl {
    pub fn new() -> Self {
        Self {
            permissions: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    pub fn grant(&self, user: &str, permission: &str) {
        let mut perms = self.permissions.write().unwrap();
        perms
            .entry(user.to_string())
            .or_insert_with(Vec::new)
            .push(permission.to_string());
    }

    pub fn revoke(&self, user: &str, permission: &str) {
        let mut perms = self.permissions.write().unwrap();
        if let Some(user_perms) = perms.get_mut(user) {
            user_perms.retain(|p| p != permission);
        }
    }

    pub fn check(&self, user: &str, permission: &str) -> bool {
        let perms = self.permissions.read().unwrap();
        perms
            .get(user)
            .map(|user_perms| user_perms.iter().any(|p| p == permission || p == "*"))
            .unwrap_or(false)
    }

    /// Grant all permissions (admin)
    pub fn grant_all(&self, user: &str) {
        self.grant(user, "*");
    }
}

impl Default for MockAccessControl {
    pub default() -> Self {
        Self::new()
    }
}

/// Mock Kubernetes client
#[async_trait]
pub trait MockKubernetesClient {
    async fn get_secret(&self, name: &str) -> Result<Option<Vec<u8>>, String>;
    async fn create_secret(&self, name: &str, data: &[u8]) -> Result<(), String>;
    async fn update_secret(&self, name: &str, data: &[u8]) -> Result<(), String>;
    async fn delete_secret(&self, name: &str) -> Result<(), String>;
}

pub struct InMemoryK8sClient {
    secrets: Arc<RwLock<HashMap<String, Vec<u8>>>>,
}

impl InMemoryK8sClient {
    pub fn new() -> Self {
        Self {
            secrets: Arc::new(RwLock::new(HashMap::new())),
        }
    }
}

#[async_trait]
impl MockKubernetesClient for InMemoryK8sClient {
    async fn get_secret(&self, name: &str) -> Result<Option<Vec<u8>>, String> {
        Ok(self.secrets.read().unwrap().get(name).cloned())
    }

    async fn create_secret(&self, name: &str, data: &[u8]) -> Result<(), String> {
        self.secrets
            .write()
            .unwrap()
            .insert(name.to_string(), data.to_vec());
        Ok(())
    }

    async fn update_secret(&self, name: &str, data: &[u8]) -> Result<(), String> {
        if self.secrets.read().unwrap().contains_key(name) {
            self.secrets
                .write()
                .unwrap()
                .insert(name.to_string(), data.to_vec());
            Ok(())
        } else {
            Err(format!("Secret {} not found", name))
        }
    }

    async fn delete_secret(&self, name: &str) -> Result<(), String> {
        self.secrets.write().unwrap().remove(name);
        Ok(())
    }
}

/// Mock time provider for testing
pub struct MockTime {
    current_time: Arc<RwLock<std::time::SystemTime>>,
}

impl MockTime {
    pub fn new() -> Self {
        Self {
            current_time: Arc::new(RwLock::new(std::time::SystemTime::now())),
        }
    }

    pub fn set_time(&self, time: std::time::SystemTime) {
        *self.current_time.write().unwrap() = time;
    }

    pub fn advance(&self, duration: std::time::Duration) {
        let mut time = self.current_time.write().unwrap();
        *time = time
            .checked_add(duration)
            .expect("Time overflow");
    }

    pub fn now(&self) -> std::time::SystemTime {
        *self.current_time.read().unwrap()
    }
}

impl Default for MockTime {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mock_storage() {
        let storage = MockStorage::new();
        storage.insert("key1", b"value1");
        assert_eq!(storage.get("key1"), Some(b"value1".to_vec()));
        assert!(storage.contains_key("key1"));
        assert!(storage.remove("key1"));
        assert!(!storage.contains_key("key1"));
    }

    #[test]
    fn test_mock_key_service() {
        let service = MockKeyService::new();
        service.add_key("key1", b"key_data");
        assert_eq!(service.get_key("key1"), Some(b"key_data".to_vec()));
    }

    #[test]
    fn test_mock_audit_logger() {
        let logger = MockAuditLogger::new();
        assert_eq!(logger.event_count(), 0);

        let event = crate::audit::AuditEvent {
            timestamp: chrono::Utc::now(),
            event_type: "test.event".to_string(),
            actor: "test_user".to_string(),
            resource: "test_resource".to_string(),
            action: "test_action".to_string(),
            result: "success".to_string(),
            metadata: Default::default(),
        };

        logger.log(event.clone());
        assert_eq!(logger.event_count(), 1);
        assert!(logger.has_event("test.event"));
    }

    #[test]
    fn test_mock_access_control() {
        let acl = MockAccessControl::new();
        acl.grant("user1", "secret:read");
        assert!(acl.check("user1", "secret:read"));
        assert!(!acl.check("user1", "secret:write"));

        acl.grant_all("user2");
        assert!(acl.check("user2", "any_permission"));
    }

    #[tokio::test]
    async fn test_k8s_client() {
        let client = InMemoryK8sClient::new();

        // Create secret
        client.create_secret("test_secret", b"secret_data").await.unwrap();

        // Get secret
        let retrieved = client.get_secret("test_secret").await.unwrap();
        assert_eq!(retrieved, Some(b"secret_data".to_vec()));

        // Update secret
        client.update_secret("test_secret", b"new_data").await.unwrap();
        let updated = client.get_secret("test_secret").await.unwrap();
        assert_eq!(updated, Some(b"new_data".to_vec()));

        // Delete secret
        client.delete_secret("test_secret").await.unwrap();
        let deleted = client.get_secret("test_secret").await.unwrap();
        assert_eq!(deleted, None);
    }
}
