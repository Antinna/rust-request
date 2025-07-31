use crate::{Result, Error, Response};
use std::time::{Duration, Instant};

/// Retry policy for failed HTTP requests
#[derive(Debug, Clone)]
pub struct RetryPolicy {
    pub max_attempts: usize,
    pub initial_delay: Duration,
    pub max_delay: Duration,
    pub backoff_multiplier: f64,
    pub jitter: bool,
    pub retry_on_status: Vec<u16>,
    pub retry_on_timeout: bool,
    pub retry_on_connection_error: bool,
}

impl RetryPolicy {
    pub fn new() -> Self {
        RetryPolicy {
            max_attempts: 3,
            initial_delay: Duration::from_millis(100),
            max_delay: Duration::from_secs(30),
            backoff_multiplier: 2.0,
            jitter: true,
            retry_on_status: vec![500, 502, 503, 504, 408, 429],
            retry_on_timeout: true,
            retry_on_connection_error: true,
        }
    }

    pub fn max_attempts(mut self, attempts: usize) -> Self {
        self.max_attempts = attempts;
        self
    }

    pub fn initial_delay(mut self, delay: Duration) -> Self {
        self.initial_delay = delay;
        self
    }

    pub fn max_delay(mut self, delay: Duration) -> Self {
        self.max_delay = delay;
        self
    }

    pub fn backoff_multiplier(mut self, multiplier: f64) -> Self {
        self.backoff_multiplier = multiplier;
        self
    }

    pub fn with_jitter(mut self, jitter: bool) -> Self {
        self.jitter = jitter;
        self
    }

    pub fn retry_on_status(mut self, status_codes: Vec<u16>) -> Self {
        self.retry_on_status = status_codes;
        self
    }

    pub fn retry_on_timeout(mut self, retry: bool) -> Self {
        self.retry_on_timeout = retry;
        self
    }

    pub fn retry_on_connection_error(mut self, retry: bool) -> Self {
        self.retry_on_connection_error = retry;
        self
    }

    pub fn should_retry(&self, attempt: usize, error: &Error) -> bool {
        if attempt >= self.max_attempts {
            return false;
        }

        match error {
            Error::Timeout => self.retry_on_timeout,
            Error::ConnectionFailed(_) => self.retry_on_connection_error,
            Error::HttpError(status, _) => self.retry_on_status.contains(status),
            Error::Io(_) => self.retry_on_connection_error,
            _ => false,
        }
    }

    pub fn should_retry_response(&self, attempt: usize, response: &Response) -> bool {
        if attempt >= self.max_attempts {
            return false;
        }

        self.retry_on_status.contains(&response.status)
    }

    pub fn calculate_delay(&self, attempt: usize) -> Duration {
        let base_delay = self.initial_delay.as_millis() as f64;
        let multiplier = self.backoff_multiplier.powi(attempt as i32);
        let delay_ms = (base_delay * multiplier) as u64;
        
        let mut delay = Duration::from_millis(delay_ms);
        
        // Apply max delay limit
        if delay > self.max_delay {
            delay = self.max_delay;
        }

        // Apply jitter if enabled
        if self.jitter {
            let jitter_range = delay.as_millis() as f64 * 0.1; // 10% jitter
            let jitter_offset = (random_f64() - 0.5) * 2.0 * jitter_range;
            let jittered_ms = (delay.as_millis() as f64 + jitter_offset).max(0.0) as u64;
            delay = Duration::from_millis(jittered_ms);
        }

        delay
    }
}

impl Default for RetryPolicy {
    fn default() -> Self {
        Self::new()
    }
}

/// Retry executor that handles the retry logic
#[derive(Debug)]
pub struct RetryExecutor {
    policy: RetryPolicy,
}

impl RetryExecutor {
    pub fn new(policy: RetryPolicy) -> Self {
        RetryExecutor { policy }
    }

    pub fn execute<F, T>(&self, mut operation: F) -> Result<T>
    where
        F: FnMut() -> Result<T>,
    {
        let mut attempt = 0;
        let start_time = Instant::now();

        loop {
            match operation() {
                Ok(result) => return Ok(result),
                Err(error) => {
                    attempt += 1;
                    
                    if !self.policy.should_retry(attempt, &error) {
                        return Err(error);
                    }

                    let delay = self.policy.calculate_delay(attempt - 1);
                    
                    // Check if we've exceeded total retry time
                    if start_time.elapsed() + delay > Duration::from_secs(300) { // 5 minute max
                        return Err(Error::Timeout);
                    }

                    std::thread::sleep(delay);
                }
            }
        }
    }

    pub fn execute_with_response_check<F>(&self, mut operation: F) -> Result<Response>
    where
        F: FnMut() -> Result<Response>,
    {
        let mut attempt = 0;
        let start_time = Instant::now();

        loop {
            match operation() {
                Ok(response) => {
                    if !self.policy.should_retry_response(attempt, &response) {
                        return Ok(response);
                    }
                    
                    attempt += 1;
                    
                    if attempt >= self.policy.max_attempts {
                        return Ok(response);
                    }

                    let delay = self.policy.calculate_delay(attempt - 1);
                    
                    if start_time.elapsed() + delay > Duration::from_secs(300) {
                        return Ok(response);
                    }

                    std::thread::sleep(delay);
                }
                Err(error) => {
                    attempt += 1;
                    
                    if !self.policy.should_retry(attempt, &error) {
                        return Err(error);
                    }

                    let delay = self.policy.calculate_delay(attempt - 1);
                    
                    if start_time.elapsed() + delay > Duration::from_secs(300) {
                        return Err(Error::Timeout);
                    }

                    std::thread::sleep(delay);
                }
            }
        }
    }
}

/// Circuit breaker pattern implementation
#[derive(Debug, Clone)]
pub struct CircuitBreaker {
    failure_threshold: usize,
    recovery_timeout: Duration,
    state: CircuitBreakerState,
    failure_count: usize,
    last_failure_time: Option<Instant>,
}

#[derive(Debug, Clone, PartialEq)]
enum CircuitBreakerState {
    Closed,
    Open,
    HalfOpen,
}

impl CircuitBreaker {
    pub fn new(failure_threshold: usize, recovery_timeout: Duration) -> Self {
        CircuitBreaker {
            failure_threshold,
            recovery_timeout,
            state: CircuitBreakerState::Closed,
            failure_count: 0,
            last_failure_time: None,
        }
    }

    pub fn call<F, T>(&mut self, operation: F) -> Result<T>
    where
        F: FnOnce() -> Result<T>,
    {
        match self.state {
            CircuitBreakerState::Open => {
                if let Some(last_failure) = self.last_failure_time {
                    if last_failure.elapsed() >= self.recovery_timeout {
                        self.state = CircuitBreakerState::HalfOpen;
                    } else {
                        return Err(Error::ConnectionFailed("Circuit breaker is open".to_string()));
                    }
                }
            }
            CircuitBreakerState::Closed | CircuitBreakerState::HalfOpen => {}
        }

        match operation() {
            Ok(result) => {
                self.on_success();
                Ok(result)
            }
            Err(error) => {
                self.on_failure();
                Err(error)
            }
        }
    }

    fn on_success(&mut self) {
        self.failure_count = 0;
        self.state = CircuitBreakerState::Closed;
        self.last_failure_time = None;
    }

    fn on_failure(&mut self) {
        self.failure_count += 1;
        self.last_failure_time = Some(Instant::now());

        if self.failure_count >= self.failure_threshold {
            self.state = CircuitBreakerState::Open;
        }
    }

    pub fn is_open(&self) -> bool {
        self.state == CircuitBreakerState::Open
    }

    pub fn reset(&mut self) {
        self.failure_count = 0;
        self.state = CircuitBreakerState::Closed;
        self.last_failure_time = None;
    }
}

/// Rate limiter for controlling request frequency
#[derive(Debug)]
pub struct RateLimiter {
    max_requests: usize,
    time_window: Duration,
    requests: Vec<Instant>,
}

impl RateLimiter {
    pub fn new(max_requests: usize, time_window: Duration) -> Self {
        RateLimiter {
            max_requests,
            time_window,
            requests: Vec::new(),
        }
    }

    pub fn try_acquire(&mut self) -> bool {
        let now = Instant::now();
        
        // Remove old requests outside the time window
        self.requests.retain(|&time| now.duration_since(time) < self.time_window);

        if self.requests.len() < self.max_requests {
            self.requests.push(now);
            true
        } else {
            false
        }
    }

    pub fn wait_time(&self) -> Option<Duration> {
        if self.requests.len() < self.max_requests {
            return None;
        }

        if let Some(&oldest) = self.requests.first() {
            let elapsed = oldest.elapsed();
            if elapsed < self.time_window {
                Some(self.time_window - elapsed)
            } else {
                None
            }
        } else {
            None
        }
    }
}

// Simple random number generator for jitter
fn random_f64() -> f64 {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};
    use std::time::{SystemTime, UNIX_EPOCH};

    let mut hasher = DefaultHasher::new();
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos().hash(&mut hasher);
    let hash = hasher.finish();
    
    // Convert to 0.0-1.0 range
    (hash as f64) / (u64::MAX as f64)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_retry_policy_creation() {
        let policy = RetryPolicy::new();
        assert_eq!(policy.max_attempts, 3);
        assert!(policy.retry_on_timeout);
    }

    #[test]
    fn test_circuit_breaker() {
        let mut breaker = CircuitBreaker::new(2, Duration::from_secs(1));
        assert!(!breaker.is_open());

        // Simulate failures
        let _ = breaker.call(|| Err::<(), _>(Error::Timeout));
        assert!(!breaker.is_open());

        let _ = breaker.call(|| Err::<(), _>(Error::Timeout));
        assert!(breaker.is_open());
    }

    #[test]
    fn test_rate_limiter() {
        let mut limiter = RateLimiter::new(2, Duration::from_secs(1));
        
        assert!(limiter.try_acquire());
        assert!(limiter.try_acquire());
        assert!(!limiter.try_acquire()); // Should be rate limited
    }
}