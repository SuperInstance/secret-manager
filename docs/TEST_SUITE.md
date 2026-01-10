# Secret Manager Test Suite

## Overview

Comprehensive test suite for the secret-manager library, designed with security-first principles. This suite covers encryption, rotation, access control, audit logging, and Kubernetes integration.

## Test Categories

### 1. Unit Tests (`tests/unit/`)

**Purpose**: Test individual components in isolation

**Modules**:
- **encryption.rs** (Target: <1ms per operation)
  - AES-256-GCM encryption/decryption
  - Key derivation functions (PBKDF2, Argon2)
  - Key wrapping/unwrapping
  - Secure memory handling (zeroization)
  - Edge cases: empty inputs, invalid keys, corrupted data

- **rotation.rs** (Target: <100ms per rotation)
  - Automatic rotation scheduling
  - Manual rotation triggers
  - Version management
  - Rollback capabilities
  - Concurrent rotation handling

- **access_control.rs**
  - Role-based access control (RBAC)
  - Permission checking
  - Token validation
  - ACL inheritance
  - Default deny policies

- **storage.rs**
  - In-memory secret storage
  - Persistence layer abstraction
  - Transaction handling
  - Concurrency control
  - Data consistency

- **audit.rs**
  - Event logging
  - Audit trail generation
  - Log format validation
  - Tamper detection
  - Log rotation

### 2. Integration Tests (`tests/integration/`)

**Purpose**: Test component interactions and end-to-end workflows

**Scenarios**:
- **secret_lifecycle.rs**
  - Create → Store → Retrieve → Rotate → Delete
  - Multiple secret versions
  - Batch operations
  - Error recovery

- **kubernetes_integration.rs**
  - Secret synchronization with K8s
  - Watch/reconcile loops
  - Mutating webhook integration
  - Pod injection
  - ConfigMap/Secret mapping

- **persistence.rs**
  - Database backend integration
  - File system backend
  - Migration between backends
  - Backup/restore
  - Disaster recovery

- **api.rs**
  - HTTP API endpoints
  - gRPC service methods
  - Authentication flow
  - Rate limiting
  - Request validation

- **concurrent_access.rs**
  - Multi-threaded secret access
  - Lock contention
  - Race conditions
  - Deadlock prevention
  - Performance under load

### 3. Security Tests (`tests/security/`)

**Purpose**: Verify security properties and vulnerability resistance

**Critical Tests**:
- **encryption_security.rs**
  - Known answer tests (KAT vectors)
  - Side-channel resistance (timing attacks)
  - Key exposure prevention
  - Padding oracle attacks
  - Authenticated tag validation
  - Weak key detection

- **access_control_security.rs**
  - Privilege escalation attempts
  - Authorization bypass
  - Token forgery
  - ACL circumvention
  - Impersonation attacks
  - Least privilege verification

- **input_validation.rs**
  - SQL injection prevention
  - Command injection
  - Path traversal
  - Buffer overflow attempts
  - XSS prevention (for web UI)
  - Deserialization attacks

- **audit_security.rs**
  - Log tampering detection
  - Audit trail completeness
  - Event reconstruction
  - Compliance verification
  - Log injection prevention

- **key_management.rs**
  - Key generation entropy
  - Key storage security
  - Key destruction (zeroization)
  - Key rotation gaps
  - Master key protection
  - HSM integration (if applicable)

- **attack_vectors.rs**
  - Brute force protection
  - Dictionary attack resistance
  - Replay attack prevention
  - Man-in-the-middle attempts
  - Race condition exploits
  - Resource exhaustion

### 4. Performance Tests (`tests/performance/`)

**Purpose**: Verify performance requirements and identify bottlenecks

**Benchmarks**:
- **encryption_bench.rs**
  - Target: <1ms secret retrieve
  - Target: <100ms secret rotation
  - Throughput: secrets/second
  - Memory allocation patterns
  - Cache effectiveness

- **concurrent_bench.rs**
  - Scalability (1, 10, 100, 1000 threads)
  - Lock contention analysis
  - Throughput under load
  - Latency percentiles (p50, p95, p99)
  - Resource utilization

- **rotation_bench.rs**
  - Rotation time by secret size
  - Bulk rotation performance
  - Rotation queue depth
  - Backpressure handling

- **memory_bench.rs**
  - Memory usage per secret
  - Leak detection
  - Pool efficiency
  - Zeroization overhead

- **kubernetes_bench.rs**
  - Reconciliation latency
  - Watch event throughput
  - Webhook response time
  - Large-scale secret handling

### 5. Common Test Infrastructure (`tests/common/`)

**Utilities**:
- **mod.rs**: Common test setup/teardown
- **fixtures.rs**: Test data and mock objects
- **assertions.rs**: Custom assertions for security properties
- **helpers.rs**: Reusable test helpers
- **mock.rs**: Mock implementations for external dependencies

## Test Requirements

### Performance Targets

| Operation | Target | Acceptable | Critical |
|-----------|--------|------------|----------|
| Secret retrieve | <1ms | <5ms | <10ms |
| Secret store | <5ms | <20ms | <50ms |
| Secret rotation | <100ms | <500ms | <1s |
| Authorization check | <0.5ms | <2ms | <5ms |
| Audit log write | <1ms | <5ms | <10ms |

### Security Requirements

- **Encryption**: AES-256-GCM or ChaCha20-Poly1305
- **Key derivation**: PBKDF2 (600k+ iterations) or Argon2id
- **Authentication**: HMAC-based tokens with expiration
- **Authorization**: Whitelist-based RBAC with default deny
- **Audit**: Immutable, tamper-evident logging

### Test Coverage Goals

- **Line coverage**: ≥90%
- **Branch coverage**: ≥85%
- **Critical path coverage**: 100%
- **Security code coverage**: 100%

## Running Tests

### Unit Tests
```bash
cargo test --test '*' --lib
```

### Integration Tests
```bash
cargo test --test integration_*
```

### Security Tests
```bash
cargo test --test security_* --release
# Note: Run in release mode for accurate timing attack detection
```

### Performance Tests
```bash
cargo bench
```

### All Tests with Coverage
```bash
cargo install cargo-tarpaulin
cargo tarpaulin --out Html --output-dir ./coverage
```

### Security-Focused Test Run
```bash
# Run only security-critical tests
cargo test --test security_* -- --test-threads=1 --nocapture

# Run with sanitizers
RUSTFLAGS="-Z sanitizer=address" cargo test --test security_* --target x86_64-unknown-linux-gnu
```

## Continuous Integration

### GitHub Actions Workflow

```yaml
name: Secret Manager Tests

on: [push, pull_request]

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - uses: actions-rs/toolchain@v1
        with:
          toolchain: stable
          components: rustfmt, clippy

      - name: Run unit tests
        run: cargo test --lib

      - name: Run integration tests
        run: cargo test --test integration_*

      - name: Run security tests
        run: cargo test --test security_* --release

      - name: Run benchmarks
        run: cargo bench

      - name: Check coverage
        run: |
          cargo tarpaulin --out Xml
          bash <(curl -s https://codecov.io/bash)

      - name: Security audit
        run: |
          cargo install cargo-audit
          cargo audit

      - name: Lint
        run: cargo clippy -- -D warnings
```

## Test Data Management

### Fixtures

Located in `tests/common/fixtures/`:
- `test_keys.json`: Test encryption keys
- `test_secrets.json`: Sample secret data
- `test_policies.json`: RBAC policies
- `test_tokens.json`: Valid/invalid auth tokens

### Secrets in Tests

**CRITICAL**: Never use real secrets in tests
- Use deterministic test data
- Generate secrets programmatically
- Document all test secrets in fixtures
- Rotate test secrets regularly

### Test Database

- Use Docker containers for integration tests
- Reset database between tests
- Use transactions for rollback
- Parallel test execution with isolated databases

## Failure Analysis

### Test Failure Categories

1. **Critical Failures** (Block release)
   - Security test failures
   - Data corruption
   - Unauthorized access
   - Secret exposure

2. **High Priority** (Fix immediately)
   - Performance regression >20%
   - Integration test failures
   - Memory leaks
   - Deadlocks

3. **Medium Priority** (Fix soon)
   - Edge case failures
   - Non-critical bugs
   - Documentation gaps

4. **Low Priority** (Technical debt)
   - Test flakiness
   - Code style issues
   - Optimization opportunities

## Maintenance

### Regular Tasks

- **Weekly**: Review test results, update fixtures
- **Monthly**: Security test review, coverage analysis
- **Quarterly**: Performance regression analysis, test suite refactoring
- **Annually**: Security audit, threat model update

### Test Metrics

Track these metrics:
- Test execution time
- Flakiness rate
- Coverage percentage
- Security test pass rate
- Performance benchmarks

## Resources

- [Rust Testing Guide](https://doc.rust-lang.org/book/ch11-00-testing.html)
- [Cryptography Best Practices](https://github.com/veorq/cryptocoding)
- [OWASP Cryptographic Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html)
- [NIST Special Publication 800-57](https://csrc.nist.gov/publications/detail/sp/800-57-part-1/rev-5/final)
