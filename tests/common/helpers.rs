//! Test helper functions for secret-manager tests

use std::time::{Duration, Instant};
use std::thread;

/// Reusable test helpers

/// Wait for a condition with timeout
pub fn wait_for<F>(condition: F, timeout_ms: u64) -> bool
where
    F: Fn() -> bool,
{
    let start = Instant::now();
    while start.elapsed() < Duration::from_millis(timeout_ms) {
        if condition() {
            return true;
        }
        thread::sleep(Duration::from_millis(10));
    }
    false
}

/// Measure execution time of a function
pub fn measure_time<F, R>(f: F) -> (R, Duration)
where
    F: FnOnce() -> R,
{
    let start = Instant::now();
    let result = f();
    let elapsed = start.elapsed();
    (result, elapsed)
}

/// Assert that a duration is within expected bounds
#[macro_export]
macro_rules! assert_duration_within {
    ($actual:expr, $min:expr, $max:expr) => {
        let actual = $actual;
        let min = Duration::from_millis($min);
        let max = Duration::from_millis($max);
        assert!(
            actual >= min && actual <= max,
            "Duration {:?} not within bounds {:?} - {:?}",
            actual, min, max
        );
    };
}

/// Retry a function with backoff
pub fn retry<F, R, E>(mut f: F, max_attempts: u32, initial_delay_ms: u64) -> Result<R, E>
where
    F: FnMut() -> Result<R, E>,
{
    let mut attempt = 0;
    let mut delay = Duration::from_millis(initial_delay_ms);

    loop {
        match f() {
            Ok(result) => return Ok(result),
            Err(e) if attempt < max_attempts => {
                attempt += 1;
                thread::sleep(delay);
                delay *= 2; // Exponential backoff
            }
            Err(e) => return Err(e),
        }
    }
}

/// Generate test data of specific size
pub fn generate_test_data(size: usize) -> Vec<u8> {
    (0..size).map(|i| (i % 256) as u8).collect()
}

/// Compare two Vec<u8> in constant time
pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }

    let mut result = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        result |= x ^ y;
    }

    result == 0
}

/// Assert that two byte arrays are equal in constant time
pub fn assert_constant_time_eq(actual: &[u8], expected: &[u8]) {
    assert!(
        constant_time_eq(actual, expected),
        "Constant-time comparison failed"
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_wait_for_success() {
        let counter = std::sync::atomic::AtomicUsize::new(0);
        let result = wait_for(
            || {
                counter.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                counter.load(std::sync::atomic::Ordering::Relaxed) > 5
            },
            1000,
        );
        assert!(result);
    }

    #[test]
    fn test_wait_for_timeout() {
        let result = wait_for(|| false, 100);
        assert!(!result);
    }

    #[test]
    fn test_measure_time() {
        let (result, duration) = measure_time(|| {
            thread::sleep(Duration::from_millis(10));
            42
        });
        assert_eq!(result, 42);
        assert!(duration >= Duration::from_millis(10));
    }

    #[test]
    fn test_retry_success() {
        let mut attempts = 0;
        let result: Result<(), &str> = retry(
            || {
                attempts += 1;
                if attempts < 3 {
                    Err("try again")
                } else {
                    Ok(())
                }
            },
            5,
            10,
        );
        assert!(result.is_ok());
        assert_eq!(attempts, 3);
    }

    #[test]
    fn test_retry_failure() {
        let result: Result<(), &str> = retry(|| Err("always fails"), 3, 10);
        assert!(result.is_err());
    }

    #[test]
    fn test_constant_time_eq() {
        assert!(constant_time_eq(b"hello", b"hello"));
        assert!(!constant_time_eq(b"hello", b"world"));
        assert!(!constant_time_eq(b"hello", b"hello!"));
    }

    #[test]
    fn test_generate_test_data() {
        let data = generate_test_data(100);
        assert_eq!(data.len(), 100);
        assert_eq!(data[0], 0);
        assert_eq!(data[99], 99);
    }
}
