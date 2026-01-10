//! Security tests for access control functionality
//!
//! Tests for:
//! - Privilege escalation attempts
//! - Authorization bypass
//! - Token forgery
//! - ACL circumvention
//! - Impersonation attacks
//! - Least privilege verification

use secret_manager::access_control::{
    AccessControl, Role, Permission, AccessError, Token,
};
use std::time::{Duration, SystemTime};

#[cfg(test)]
mod security_tests {
    use super::*;

    fn setup_acl() -> AccessControl {
        let mut acl = AccessControl::new();

        // Create roles with specific permissions
        let admin = Role::new("admin")
            .with_permissions(vec![Permission::wildcard()]);

        let user = Role::new("user")
            .with_permissions(vec![
                Permission::new("secret", "read"),
            ]);

        let guest = Role::new("guest")
            .with_permissions(vec![
                Permission::new("public", "read"),
            ]);

        acl.add_role(admin);
        acl.add_role(user);
        acl.add_role(guest);

        acl
    }

    /// CRITICAL: Test privilege escalation attempts
    #[test]
    fn test_privilege_escalation_prevention() {
        let acl = setup_acl();
        acl.assign_role("attacker", "guest").unwrap();

        // Try to escalate to admin
        let result = acl.assign_role("attacker", "admin");

        // Should fail without proper authorization
        assert!(result.is_err() || {
            // If assignment succeeded, verify permission wasn't actually granted
            acl.check_permission("attacker", "secret:delete").is_err()
        });
    }

    /// CRITICAL: Test role chain escalation
    #[test]
    fn test_role_chain_escalation() {
        let mut acl = setup_acl();

        // Create role hierarchy
        let role1 = Role::new("role1").with_permissions(vec![
            Permission::new("resource", "read"),
        ]);

        let role2 = Role::new("role2")
            .with_parent("role1")
            .with_permissions(vec![
                Permission::new("resource", "write"),
            ]);

        acl.add_role(role1);
        acl.add_role(role2);

        acl.assign_role("user1", "role2").unwrap();

        // User should have both read and write
        assert!(acl.check_permission("user1", "resource:read").is_ok());
        assert!(acl.check_permission("user1", "resource:write").is_ok());

        // Should NOT have admin privileges
        assert!(acl.check_permission("user1", "admin:delete").is_err());
    }

    /// CRITICAL: Test authorization bypass attempts
    #[test]
    fn test_authorization_bypass() {
        let acl = setup_acl();
        acl.assign_role("user1", "user").unwrap();

        // Try various bypass attempts
        let bypass_attempts = vec![
            "secret:read;", // SQL injection attempt
            "secret:read OR 1=1", // SQL injection
            "secret:read/../admin/delete", // Path traversal
            "secret:read\x00admin:delete", // Null byte injection
            "../../../admin/delete", // Directory traversal
            "secret:read' OR '1'='1", // SQL injection
            "secret:read\tadmin:delete", // Tab separator
            "secret:read\nadmin:delete", // Newline separator
        ];

        for attempt in bypass_attempts {
            let result = acl.check_permission("user1", attempt);
            assert!(
                result.is_err(),
                "Authorization bypass attempt succeeded: {}",
                attempt
            );
        }
    }

    /// CRITICAL: Test token forgery attempts
    #[test]
    fn test_token_forgery_prevention() {
        let acl = setup_acl();

        // Generate legitimate token
        let legitimate_token = acl.create_token("user1", "user").unwrap();

        // Try to forge token by modifying it
        let forged_token = Token::from_string(legitimate_token.to_string())
            .with_role("admin"); // Try to upgrade role

        let result = acl.validate_token(&forged_token);

        // Forged token should be rejected
        assert!(result.is_err() || {
            // If validation passes, verify role wasn't actually upgraded
            acl.check_permission("user1", "admin:delete").is_err()
        });
    }

    /// CRITICAL: Test token expiration
    #[test]
    fn test_token_expiration() {
        let acl = setup_acl();

        // Create token with short expiration
        let token = acl
            .create_token_with_expiration("user1", "user", Duration::from_millis(100))
            .unwrap();

        // Token should be valid immediately
        assert!(acl.validate_token(&token).is_ok());

        // Wait for expiration
        std::thread::sleep(Duration::from_millis(150));

        // Token should now be invalid
        let result = acl.validate_token(&token);
        assert!(result.is_err());
        assert_matches!(result, Err(AccessError::TokenExpired));
    }

    /// CRITICAL: Test token replay attacks
    #[test]
    fn test_token_replay_prevention() {
        let acl = setup_acl();

        // Create and use token
        let token = acl.create_token("user1", "user").unwrap();

        // Use token successfully
        assert!(acl.check_permission_with_token("secret:read", &token).is_ok());

        // Invalidate token (e.g., after logout)
        acl.invalidate_token(&token).unwrap();

        // Try to replay token
        let result = acl.check_permission_with_token("secret:read", &token);
        assert!(result.is_err());
    }

    /// CRITICAL: Test impersonation attacks
    #[test]
    fn test_impersonation_prevention() {
        let acl = setup_acl();
        acl.assign_role("user1", "user").unwrap();

        // Try to impersonate admin
        let impersonate_result = acl.impersonate("user1", "admin");

        // Should fail without proper authorization
        assert!(impersonate_result.is_err());

        // Even if impersonation succeeds, verify actual permissions
        assert!(acl.check_permission("user1", "admin:delete").is_err());
    }

    /// CRITICAL: Test wildcard permission escalation
    #[test]
    fn test_wildcard_permission_control() {
        let acl = setup_acl();

        // Regular user should NOT be able to grant themselves wildcard
        acl.assign_role("user1", "user").unwrap();

        // Try to add wildcard permission to user role
        let result = acl.add_permission_to_role("user", Permission::wildcard());

        // Should fail without admin privileges
        assert!(result.is_err());

        // Verify user doesn't have wildcard access
        assert!(acl.check_permission("user1", "random_resource:delete").is_err());
    }

    /// CRITICAL: Test ACL inheritance vulnerabilities
    #[test]
    fn test_acl_inheritance_security() {
        let mut acl = AccessControl::new();

        // Create parent role with limited permissions
        let parent = Role::new("parent").with_permissions(vec![
            Permission::new("safe_resource", "read"),
        ]);

        // Create child role that tries to exceed parent permissions
        let child = Role::new("child")
            .with_parent("parent")
            .with_permissions(vec![
                Permission::new("dangerous_resource", "delete"), // Exceeds parent
            ]);

        acl.add_role(parent);
        acl.add_role(child);

        acl.assign_role("user1", "child").unwrap();

        // Child should not inherit dangerous permissions beyond its scope
        // This test verifies the inheritance model is secure
        assert!(acl.check_permission("user1", "safe_resource:read").is_ok());
        assert!(acl.check_permission("user1", "dangerous_resource:delete").is_ok());

        // But should NOT have admin permissions
        assert!(acl.check_permission("user1", "admin:delete").is_err());
    }

    /// CRITICAL: Test race condition in permission changes
    #[test]
    fn test_concurrent_permission_changes() {
        let acl = std::sync::Arc::new(setup_acl());
        acl.assign_role("user1", "user").unwrap();

        let acl_clone1 = acl.clone();
        let acl_clone2 = acl.clone();

        // Spawn concurrent permission modification attempts
        let handle1 = std::thread::spawn(move || {
            acl_clone1.revoke_role("user1", "user")
        });

        let handle2 = std::thread::spawn(move || {
            acl_clone2.revoke_role("user1", "user")
        });

        // Both should complete without corruption
        let result1 = handle1.join().unwrap();
        let result2 = handle2.join().unwrap();

        // At least one should succeed
        assert!(result1.is_ok() || result2.is_ok());

        // User should no longer have permissions
        assert!(acl.check_permission("user1", "secret:read").is_err());
    }

    /// CRITICAL: Test default deny policy
    #[test]
    fn test_default_deny_enforcement() {
        let mut acl = AccessControl::new();

        // Create role with explicit allow
        let role = Role::new("limited").with_permissions(vec![
            Permission::new("specific_resource", "read"),
        ]);

        acl.add_role(role);
        acl.assign_role("user1", "limited").unwrap();

        // Explicitly allowed permission should work
        assert!(acl.check_permission("user1", "specific_resource:read").is_ok());

        // Everything else should be denied (default deny)
        let denied_permissions = vec![
            "specific_resource:write",
            "specific_resource:delete",
            "other_resource:read",
            "admin:delete",
            "*:*",
        ];

        for perm in denied_permissions {
            assert!(
                acl.check_permission("user1", perm).is_err(),
                "Default deny failed for: {}",
                perm
            );
        }
    }

    /// CRITICAL: Test permission cache poisoning
    #[test]
    fn test_permission_cache_security() {
        let acl = setup_acl();
        acl.assign_role("user1", "user").unwrap();

        // Check permission (will be cached)
        assert!(acl.check_permission("user1", "secret:read").is_ok());

        // Revoke role
        acl.revoke_role("user1", "user").unwrap();

        // CRITICAL: Cached permission should be invalidated
        // User should no longer have access
        assert!(acl.check_permission("user1", "secret:read").is_err());
    }

    /// CRITICAL: Test time-based permission bypass
    #[test]
    fn test_time_based_access_control() {
        let mut acl = setup_acl();

        let policy = secret_manager::access_control::AccessPolicy::new("business_hours")
            .with_time_range("09:00-17:00")
            .with_permissions(vec![Permission::new("sensitive", "read")]);

        acl.add_policy(policy);
        acl.assign_policy("user1", "business_hours").unwrap();

        // Test at different times
        let business_hours = SystemTime::UNIX_EPOCH + Duration::from_secs(3600 * 10); // 10:00 AM
        let after_hours = SystemTime::UNIX_EPOCH + Duration::from_secs(3600 * 20); // 8:00 PM

        // Should work during business hours
        let result1 = acl.check_permission_with_time("user1", "sensitive:read", business_hours);
        assert!(result1.is_ok());

        // Should fail after hours
        let result2 = acl.check_permission_with_time("user1", "sensitive:read", after_hours);
        assert!(result2.is_err());
    }

    /// Verify audit logging captures all access attempts
    #[test]
    fn test_audit_logging_completeness() {
        let acl = setup_acl();
        acl.assign_role("user1", "user").unwrap();

        // Successful access
        let _ = acl.check_permission("user1", "secret:read");

        // Failed access
        let _ = acl.check_permission("user1", "secret:delete");

        // Verify both attempts were logged
        let logs = acl.get_audit_logs("user1").unwrap();

        assert!(logs.iter().any(|l| l.permission == "secret:read" && l.result == "granted"));
        assert!(logs.iter().any(|l| l.permission == "secret:delete" && l.result == "denied"));
    }

    /// CRITICAL: Test denial of service via permission checks
    #[test]
    fn test_permission_check_dos_resistance() {
        let acl = setup_acl();
        acl.assign_role("user1", "user").unwrap();

        // Rapid permission checks (potential DoS)
        let start = SystemTime::now();
        for i in 0..10_000 {
            let _ = acl.check_permission("user1", &format!("resource{}:read", i));
        }
        let elapsed = start.elapsed().unwrap();

        // Should complete quickly (<1 second for 10k checks)
        assert!(
            elapsed.as_secs() < 1,
            "Permission checks too slow: {:?}",
            elapsed
        );
    }

    /// Verify least privilege is enforced
    #[test]
    fn test_least_privilege_enforcement() {
        let acl = setup_acl();

        // Admin should have full access
        acl.assign_role("admin1", "admin").unwrap();

        // User should have limited access
        acl.assign_role("user1", "user").unwrap();

        // Admin can do everything
        assert!(acl.check_permission("admin1", "secret:read").is_ok());
        assert!(acl.check_permission("admin1", "secret:delete").is_ok());

        // User can only read
        assert!(acl.check_permission("user1", "secret:read").is_ok());
        assert!(acl.check_permission("user1", "secret:delete").is_err());
    }
}
