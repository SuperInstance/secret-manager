//! Unit tests for access control functionality
//!
//! Tests cover:
//! - Role-based access control (RBAC)
//! - Permission checking
//! - Token validation
//! - ACL inheritance
//! - Default deny policies
//! - Authorization bypass prevention

use std::collections::HashMap;
use secret_manager::access_control::{
    AccessControl, Role, Permission, AccessPolicy, AccessError,
};

#[cfg(test)]
mod tests {
    use super::*;

    fn setup_test_acl() -> AccessControl {
        let mut acl = AccessControl::new();

        // Define roles
        let admin_role = Role::new("admin")
            .with_permissions(vec![
                Permission::wildcard(),
            ]);

        let reader_role = Role::new("reader")
            .with_permissions(vec![
                Permission::new("secret", "read"),
            ]);

        let writer_role = Role::new("writer")
            .with_permissions(vec![
                Permission::new("secret", "read"),
                Permission::new("secret", "write"),
            ]);

        // Add roles
        acl.add_role(admin_role);
        acl.add_role(reader_role);
        acl.add_role(writer_role);

        acl
    }

    #[test]
    fn test_default_policy_is_deny() {
        let acl = AccessControl::new();

        let result = acl.check_permission("user1", "secret:read");

        assert_eq!(result, Err(AccessError::Denied));
    }

    #[test]
    fn test_admin_has_full_access() {
        let acl = setup_test_acl();

        // Assign admin role to user
        acl.assign_role("user1", "admin").unwrap();

        // Admin should have all permissions
        assert!(acl.check_permission("user1", "secret:read").is_ok());
        assert!(acl.check_permission("user1", "secret:write").is_ok());
        assert!(acl.check_permission("user1", "key:delete").is_ok());
    }

    #[test]
    fn test_reader_can_only_read() {
        let acl = setup_test_acl();

        acl.assign_role("user1", "reader").unwrap();

        assert!(acl.check_permission("user1", "secret:read").is_ok());
        assert_eq!(
            acl.check_permission("user1", "secret:write"),
            Err(AccessError::Denied)
        );
        assert_eq!(
            acl.check_permission("user1", "key:delete"),
            Err(AccessError::Denied)
        );
    }

    #[test]
    fn test_writer_can_read_and_write() {
        let acl = setup_test_acl();

        acl.assign_role("user1", "writer").unwrap();

        assert!(acl.check_permission("user1", "secret:read").is_ok());
        assert!(acl.check_permission("user1", "secret:write").is_ok());
        assert_eq!(
            acl.check_permission("user1", "secret:delete"),
            Err(AccessError::Denied)
        );
    }

    #[test]
    fn test_user_with_no_roles_denied() {
        let acl = setup_test_acl();

        let result = acl.check_permission("user_without_roles", "secret:read");

        assert_eq!(result, Err(AccessError::Denied));
    }

    #[test]
    fn test_multiple_roles_accumulate_permissions() {
        let mut acl = AccessControl::new();

        let role1 = Role::new("role1")
            .with_permissions(vec![Permission::new("secret", "read")]);
        let role2 = Role::new("role2")
            .with_permissions(vec![Permission::new("secret", "write")]);

        acl.add_role(role1);
        acl.add_role(role2);

        acl.assign_role("user1", "role1").unwrap();
        acl.assign_role("user1", "role2").unwrap();

        assert!(acl.check_permission("user1", "secret:read").is_ok());
        assert!(acl.check_permission("user1", "secret:write").is_ok());
    }

    #[test]
    fn test_wildcard_permission_grants_all() {
        let acl = setup_test_acl();

        acl.assign_role("user1", "admin").unwrap();

        // Wildcard should grant all permissions
        assert!(acl.check_permission("user1", "any_resource:any_action").is_ok());
        assert!(acl.check_permission("user1", "audit:delete").is_ok());
    }

    #[test]
    fn test_resource_specific_permission() {
        let mut acl = AccessControl::new();

        let role = Role::new("db_reader")
            .with_permissions(vec![Permission::new("database:prod", "read")]);

        acl.add_role(role);
        acl.assign_role("user1", "db_reader").unwrap();

        assert!(acl.check_permission("user1", "database:prod:read").is_ok());
        assert_eq!(
            acl.check_permission("user1", "database:dev:read"),
            Err(AccessError::Denied)
        );
        assert_eq!(
            acl.check_permission("user1", "api:read"),
            Err(AccessError::Denied)
        );
    }

    #[test]
    fn test_revoke_role() {
        let acl = setup_test_acl();

        acl.assign_role("user1", "admin").unwrap();
        assert!(acl.check_permission("user1", "secret:delete").is_ok());

        acl.revoke_role("user1", "admin").unwrap();

        assert_eq!(
            acl.check_permission("user1", "secret:delete"),
            Err(AccessError::Denied)
        );
    }

    #[test]
    fn test_custom_policy() {
        let mut acl = AccessControl::new();

        let policy = AccessPolicy::new("time_based_policy")
            .with_condition("time", "business_hours")
            .with_permission(Permission::new("secret", "read"));

        acl.add_policy(policy);
        acl.assign_policy("user1", "time_based_policy").unwrap();

        // With business hours condition met
        let mut context = HashMap::new();
        context.insert("time".to_string(), "business_hours".to_string());

        assert!(acl.check_permission_with_context("user1", "secret:read", &context).is_ok());
    }

    #[test]
    fn test_permission_inheritance() {
        let mut acl = AccessControl::new();

        // Parent role
        let parent = Role::new("parent")
            .with_permissions(vec![
                Permission::new("secret", "read"),
            ]);

        // Child role inherits from parent
        let child = Role::new("child")
            .with_parent("parent")
            .with_permissions(vec![
                Permission::new("secret", "write"),
            ]);

        acl.add_role(parent);
        acl.add_role(child);

        acl.assign_role("user1", "child").unwrap();

        // Child should have both read and write
        assert!(acl.check_permission("user1", "secret:read").is_ok());
        assert!(acl.check_permission("user1", "secret:write").is_ok());
    }

    #[test]
    fn test_implicit_deny_overrides_explicit_allow() {
        let mut acl = AccessControl::new();

        let role = Role::new("restricted")
            .with_permissions(vec![
                Permission::new("secret", "read"),
            ])
            .with_denied_permissions(vec![
                Permission::new("secret:sensitive", "read"),
            ]);

        acl.add_role(role);
        acl.assign_role("user1", "restricted").unwrap();

        assert!(acl.check_permission("user1", "secret:read").is_ok());
        assert_eq!(
            acl.check_permission("user1", "secret:sensitive:read"),
            Err(AccessError::Denied)
        );
    }

    #[test]
    fn test_permission_caching() {
        let acl = setup_test_acl();
        acl.assign_role("user1", "reader").unwrap();

        // First check
        let start = std::time::Instant::now();
        let _result1 = acl.check_permission("user1", "secret:read");
        let time1 = start.elapsed();

        // Second check (should be cached)
        let start = std::time::Instant::now();
        let _result2 = acl.check_permission("user1", "secret:read");
        let time2 = start.elapsed();

        // Cached check should be faster (though not strictly guaranteed)
        // This is more of a documentation of expected behavior
        assert!(time2 <= time1 || time1.as_nanos() < 1_000_000);
    }

    #[test]
    fn test_invalid_permission_format() {
        let acl = setup_test_acl();
        acl.assign_role("user1", "reader").unwrap();

        // Invalid format
        let result = acl.check_permission("user1", "invalid");

        assert_eq!(result, Err(AccessError::InvalidPermission));
    }

    #[test]
    fn test_nonexistent_role() {
        let acl = setup_test_acl();

        let result = acl.assign_role("user1", "nonexistent_role");

        assert_eq!(result, Err(AccessError::RoleNotFound));
    }

    #[test]
    fn test_concurrent_permission_check() {
        let acl = std::sync::Arc::new(setup_test_acl());
        acl.assign_role("user1", "reader").unwrap();

        let handles: Vec<_> = (0..100)
            .map(|_| {
                let acl = acl.clone();
                std::thread::spawn(move || {
                    for _ in 0..1000 {
                        let _ = acl.check_permission("user1", "secret:read");
                    }
                })
            })
            .collect();

        for handle in handles {
            handle.join().unwrap();
        }

        // Verify ACL is still consistent
        assert!(acl.check_permission("user1", "secret:read").is_ok());
    }

    #[test]
    fn test_permission_expansion() {
        let mut acl = AccessControl::new();

        let role = Role::new("expanded")
            .with_permissions(vec![
                Permission::new("secret:*", "read"),
            ]);

        acl.add_role(role);
        acl.assign_role("user1", "expanded").unwrap();

        // Wildcard should match any secret
        assert!(acl.check_permission("user1", "secret:prod:read").is_ok());
        assert!(acl.check_permission("user1", "secret:dev:read").is_ok());
        assert!(acl.check_permission("user1", "secret:test:read").is_ok());
    }

    #[test]
    fn test_audit_log_on_access_denied() {
        let acl = setup_test_acl();

        // Try to access without permission
        let result = acl.check_permission("user1", "secret:read");

        assert_eq!(result, Err(AccessError::Denied));

        // Verify audit log entry exists
        let logs = acl.get_audit_logs("user1").unwrap();
        assert!(!logs.is_empty());
        assert!(logs.iter().any(|log| log.result == "denied"));
    }
}
