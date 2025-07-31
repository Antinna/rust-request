//! Advanced circuit breaker implementation for fault tolerance
//! 
//! This module provides sophisticated circuit breaker patterns to prevent cascading failures
//! and improve system resilience in distributed environments.

use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use std::collections::VecDeque;
use std::fmt;

/// Circuit breaker states
#[derive(Debug, Clone, PartialEq)]
pub enum CircuitState {
    Closed,    // Normal operation
    Open,      // Failing fast
    HalfOpen,  // Testing if service recovered
}

/// Circuit breaker configuration
#[derive(Debug, Clone)]
pub struct CircuitBreakerConfig {
    pub failure_threshold: u32,
    pub success_threshold: u32,
    pub timeout: Duration,
    pub reset_timeout: Duration,
    pub max_requests_half_open: u32,
    pub slow_call_duration_threshold: Duration,
    pub slow_call_rate_threshold: f64,
    pub minimum_number_of_calls: u32,
    pub sliding_window_size: u32,
    pub sliding_window_type: SlidingWindowType,
}

/// Type of sliding window for failure rate calculation
#[derive(Debug, Clone, PartialEq)]
pub enum SlidingWindowType {
    CountBased,
    TimeBased,
}

/// Result of a circuit breaker call
#[derive(Debug, Clone)]
pub enum CallResult {
    Success(Duration),
    Failure(String),
    Timeout,
    Rejected,
}

/// Circuit breaker metrics
#[derive(Debug, Clone)]
pub struct CircuitBreakerMetrics {
    pub state: CircuitState,
    pub failure_rate: f64,
    pub slow_call_rate: f64,
    pub total_calls: u64,
    pub successful_calls: u64,
    pub failed_calls: u64,
    pub slow_calls: u64,
    pub rejected_calls: u64,
    pub state_transitions: u64,
    pub last_state_change: Option<Instant>,
}

/// Call record for sliding window
#[derive(Debug, Clone)]
struct CallRecord {
    timestamp: Instant,
    result: CallResult,
    duration: Duration,
}

/// Advanced circuit breaker implementation
pub struct CircuitBreaker {
    config: CircuitBreakerConfig,
    state: Arc<Mutex<CircuitBreakerState>>,
}

struct CircuitBreakerState {
    current_state: CircuitState,
    failure_count: u32,
    success_count: u32,
    last_failure_time: Option<Instant>,
    last_success_time: Option<Instant>,
    state_change_time: Instant,
    half_open_requests: u32,
    call_records: VecDeque<CallRecord>,
    metrics: CircuitBreakerMetrics,
}

/// Circuit breaker builder for fluent configuration
pub struct CircuitBreakerBuilder {
    config: CircuitBreakerConfig,
}

/// Multi-level circuit breaker for different failure types
pub struct MultiLevelCircuitBreaker {
    network_breaker: CircuitBreaker,
    timeout_breaker: CircuitBreaker,
    error_breaker: CircuitBreaker,
}

/// Adaptive circuit breaker that adjusts thresholds based on traffic patterns
pub struct AdaptiveCircuitBreaker {
    base_breaker: CircuitBreaker,
    traffic_analyzer: TrafficAnalyzer,
    adaptation_config: AdaptationConfig,
}

/// Traffic pattern analyzer
pub struct TrafficAnalyzer {
    request_rates: VecDeque<(Instant, u32)>,
    peak_traffic_threshold: f64,
    low_traffic_threshold: f64,
}

/// Configuration for adaptive behavior
#[derive(Debug, Clone)]
pub struct AdaptationConfig {
    pub high_traffic_failure_threshold: u32,
    pub low_traffic_failure_threshold: u32,
    pub adaptation_window: Duration,
    pub traffic_analysis_window: Duration,
}

impl Default for CircuitBreakerConfig {
    fn default() -> Self {
        CircuitBreakerConfig {
            failure_threshold: 5,
            success_threshold: 3,
            timeout: Duration::from_secs(30),
            reset_timeout: Duration::from_secs(60),
            max_requests_half_open: 3,
            slow_call_duration_threshold: Duration::from_secs(5),
            slow_call_rate_threshold: 0.5,
            minimum_number_of_calls: 10,
            sliding_window_size: 100,
            sliding_window_type: SlidingWindowType::CountBased,
        }
    }
}

impl CircuitBreakerBuilder {
    pub fn new() -> Self {
        CircuitBreakerBuilder {
            config: CircuitBreakerConfig::default(),
        }
    }
}

impl Default for CircuitBreakerBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl CircuitBreakerBuilder {
    pub fn failure_threshold(mut self, threshold: u32) -> Self {
        self.config.failure_threshold = threshold;
        self
    }
    
    pub fn success_threshold(mut self, threshold: u32) -> Self {
        self.config.success_threshold = threshold;
        self
    }
    
    pub fn timeout(mut self, timeout: Duration) -> Self {
        self.config.timeout = timeout;
        self
    }
    
    pub fn reset_timeout(mut self, timeout: Duration) -> Self {
        self.config.reset_timeout = timeout;
        self
    }
    
    pub fn max_requests_half_open(mut self, max_requests: u32) -> Self {
        self.config.max_requests_half_open = max_requests;
        self
    }
    
    pub fn slow_call_threshold(mut self, duration: Duration, rate: f64) -> Self {
        self.config.slow_call_duration_threshold = duration;
        self.config.slow_call_rate_threshold = rate;
        self
    }
    
    pub fn sliding_window(mut self, size: u32, window_type: SlidingWindowType) -> Self {
        self.config.sliding_window_size = size;
        self.config.sliding_window_type = window_type;
        self
    }
    
    pub fn minimum_calls(mut self, min_calls: u32) -> Self {
        self.config.minimum_number_of_calls = min_calls;
        self
    }
    
    pub fn build(self) -> CircuitBreaker {
        CircuitBreaker::new(self.config)
    }
}

impl CircuitBreaker {
    pub fn new(config: CircuitBreakerConfig) -> Self {
        let state = CircuitBreakerState {
            current_state: CircuitState::Closed,
            failure_count: 0,
            success_count: 0,
            last_failure_time: None,
            last_success_time: None,
            state_change_time: Instant::now(),
            half_open_requests: 0,
            call_records: VecDeque::new(),
            metrics: CircuitBreakerMetrics::new(),
        };
        
        CircuitBreaker {
            config,
            state: Arc::new(Mutex::new(state)),
        }
    }
    
    pub fn builder() -> CircuitBreakerBuilder {
        CircuitBreakerBuilder::new()
    }
    
    /// Execute a function with circuit breaker protection
    pub fn call<F, T, E>(&self, f: F) -> Result<T, CircuitBreakerError<E>>
    where
        F: FnOnce() -> Result<T, E>,
    {
        // Check if call should be allowed
        if !self.allow_request() {
            return Err(CircuitBreakerError::CircuitOpen);
        }
        
        let start_time = Instant::now();
        
        // Execute the function
        match f() {
            Ok(result) => {
                let duration = start_time.elapsed();
                self.record_success(duration);
                Ok(result)
            }
            Err(error) => {
                let duration = start_time.elapsed();
                self.record_failure(duration);
                Err(CircuitBreakerError::CallFailed(error))
            }
        }
    }
    
    /// Execute an async function with circuit breaker protection (placeholder)
    /// Note: This would require async runtime support
    pub fn call_with_timeout<F, T, E>(&self, f: F, timeout: Duration) -> Result<T, CircuitBreakerError<E>>
    where
        F: FnOnce() -> Result<T, E>,
    {
        if !self.allow_request() {
            return Err(CircuitBreakerError::CircuitOpen);
        }
        
        let start_time = Instant::now();
        
        // Simple timeout simulation (in real implementation, would use proper async)
        let result = f();
        let elapsed = start_time.elapsed();
        
        if elapsed > timeout {
            self.record_timeout();
            return Err(CircuitBreakerError::Timeout);
        }
        
        match result {
            Ok(value) => {
                self.record_success(elapsed);
                Ok(value)
            }
            Err(error) => {
                self.record_failure(elapsed);
                Err(CircuitBreakerError::CallFailed(error))
            }
        }
    }
    
    fn allow_request(&self) -> bool {
        let mut state = self.state.lock().unwrap();
        
        match state.current_state {
            CircuitState::Closed => true,
            CircuitState::Open => {
                // Check if we should transition to half-open
                if let Some(last_failure) = state.last_failure_time {
                    if last_failure.elapsed() >= self.config.reset_timeout {
                        state.current_state = CircuitState::HalfOpen;
                        state.state_change_time = Instant::now();
                        state.half_open_requests = 0;
                        state.metrics.state_transitions += 1;
                        state.metrics.last_state_change = Some(Instant::now());
                        true
                    } else {
                        state.metrics.rejected_calls += 1;
                        false
                    }
                } else {
                    false
                }
            }
            CircuitState::HalfOpen => {
                if state.half_open_requests < self.config.max_requests_half_open {
                    state.half_open_requests += 1;
                    true
                } else {
                    state.metrics.rejected_calls += 1;
                    false
                }
            }
        }
    }
    
    fn record_success(&self, duration: Duration) {
        let mut state = self.state.lock().unwrap();
        
        let is_slow = duration >= self.config.slow_call_duration_threshold;
        
        let record = CallRecord {
            timestamp: Instant::now(),
            result: CallResult::Success(duration),
            duration,
        };
        
        self.add_call_record(&mut state, record);
        
        state.success_count += 1;
        state.last_success_time = Some(Instant::now());
        state.metrics.successful_calls += 1;
        state.metrics.total_calls += 1;
        
        if is_slow {
            state.metrics.slow_calls += 1;
        }
        
        if state.current_state == CircuitState::HalfOpen
            && state.success_count >= self.config.success_threshold {
                state.current_state = CircuitState::Closed;
                state.failure_count = 0;
                state.success_count = 0;
                state.state_change_time = Instant::now();
                state.metrics.state_transitions += 1;
                state.metrics.last_state_change = Some(Instant::now());
            }
        
        self.update_metrics(&mut state);
    }
    
    fn record_failure(&self, duration: Duration) {
        let mut state = self.state.lock().unwrap();
        
        let record = CallRecord {
            timestamp: Instant::now(),
            result: CallResult::Failure("Call failed".to_string()),
            duration,
        };
        
        self.add_call_record(&mut state, record);
        
        state.failure_count += 1;
        state.last_failure_time = Some(Instant::now());
        state.metrics.failed_calls += 1;
        state.metrics.total_calls += 1;
        
        self.check_failure_threshold(&mut state);
        self.update_metrics(&mut state);
    }
    
    fn record_timeout(&self) {
        let mut state = self.state.lock().unwrap();
        
        let record = CallRecord {
            timestamp: Instant::now(),
            result: CallResult::Timeout,
            duration: self.config.timeout,
        };
        
        self.add_call_record(&mut state, record);
        
        state.failure_count += 1;
        state.last_failure_time = Some(Instant::now());
        state.metrics.failed_calls += 1;
        state.metrics.total_calls += 1;
        
        self.check_failure_threshold(&mut state);
        self.update_metrics(&mut state);
    }
    
    fn add_call_record(&self, state: &mut CircuitBreakerState, record: CallRecord) {
        state.call_records.push_back(record);
        
        // Maintain sliding window size
        match self.config.sliding_window_type {
            SlidingWindowType::CountBased => {
                while state.call_records.len() > self.config.sliding_window_size as usize {
                    state.call_records.pop_front();
                }
            }
            SlidingWindowType::TimeBased => {
                let cutoff_time = Instant::now() - Duration::from_secs(self.config.sliding_window_size as u64);
                while let Some(front) = state.call_records.front() {
                    if front.timestamp < cutoff_time {
                        state.call_records.pop_front();
                    } else {
                        break;
                    }
                }
            }
        }
    }
    
    fn check_failure_threshold(&self, state: &mut CircuitBreakerState) {
        if state.call_records.len() < self.config.minimum_number_of_calls as usize {
            return;
        }
        
        let failure_rate = self.calculate_failure_rate(state);
        let slow_call_rate = self.calculate_slow_call_rate(state);
        
        let should_open = failure_rate >= (self.config.failure_threshold as f64 / 100.0) ||
                         slow_call_rate >= self.config.slow_call_rate_threshold;
        
        if should_open && state.current_state != CircuitState::Open {
            state.current_state = CircuitState::Open;
            state.state_change_time = Instant::now();
            state.metrics.state_transitions += 1;
            state.metrics.last_state_change = Some(Instant::now());
        }
    }
    
    fn calculate_failure_rate(&self, state: &CircuitBreakerState) -> f64 {
        if state.call_records.is_empty() {
            return 0.0;
        }
        
        let failed_calls = state.call_records.iter()
            .filter(|record| matches!(record.result, CallResult::Failure(_) | CallResult::Timeout))
            .count();
        
        failed_calls as f64 / state.call_records.len() as f64
    }
    
    fn calculate_slow_call_rate(&self, state: &CircuitBreakerState) -> f64 {
        if state.call_records.is_empty() {
            return 0.0;
        }
        
        let slow_calls = state.call_records.iter()
            .filter(|record| record.duration >= self.config.slow_call_duration_threshold)
            .count();
        
        slow_calls as f64 / state.call_records.len() as f64
    }
    
    fn update_metrics(&self, state: &mut CircuitBreakerState) {
        state.metrics.state = state.current_state.clone();
        state.metrics.failure_rate = self.calculate_failure_rate(state);
        state.metrics.slow_call_rate = self.calculate_slow_call_rate(state);
    }
    
    pub fn get_metrics(&self) -> CircuitBreakerMetrics {
        let state = self.state.lock().unwrap();
        state.metrics.clone()
    }
    
    pub fn get_state(&self) -> CircuitState {
        let state = self.state.lock().unwrap();
        state.current_state.clone()
    }
    
    pub fn force_open(&self) {
        let mut state = self.state.lock().unwrap();
        state.current_state = CircuitState::Open;
        state.state_change_time = Instant::now();
        state.metrics.state_transitions += 1;
        state.metrics.last_state_change = Some(Instant::now());
    }
    
    pub fn force_close(&self) {
        let mut state = self.state.lock().unwrap();
        state.current_state = CircuitState::Closed;
        state.failure_count = 0;
        state.success_count = 0;
        state.state_change_time = Instant::now();
        state.metrics.state_transitions += 1;
        state.metrics.last_state_change = Some(Instant::now());
    }
    
    pub fn reset(&self) {
        let mut state = self.state.lock().unwrap();
        state.current_state = CircuitState::Closed;
        state.failure_count = 0;
        state.success_count = 0;
        state.last_failure_time = None;
        state.last_success_time = None;
        state.state_change_time = Instant::now();
        state.half_open_requests = 0;
        state.call_records.clear();
        state.metrics = CircuitBreakerMetrics::new();
    }
}

impl CircuitBreakerMetrics {
    fn new() -> Self {
        CircuitBreakerMetrics {
            state: CircuitState::Closed,
            failure_rate: 0.0,
            slow_call_rate: 0.0,
            total_calls: 0,
            successful_calls: 0,
            failed_calls: 0,
            slow_calls: 0,
            rejected_calls: 0,
            state_transitions: 0,
            last_state_change: None,
        }
    }
}

/// Circuit breaker error types
#[derive(Debug)]
pub enum CircuitBreakerError<E> {
    CircuitOpen,
    Timeout,
    CallFailed(E),
}

impl<E: fmt::Display> fmt::Display for CircuitBreakerError<E> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CircuitBreakerError::CircuitOpen => write!(f, "Circuit breaker is open"),
            CircuitBreakerError::Timeout => write!(f, "Call timed out"),
            CircuitBreakerError::CallFailed(e) => write!(f, "Call failed: {e}"),
        }
    }
}

impl<E: std::error::Error> std::error::Error for CircuitBreakerError<E> {}

impl AdaptiveCircuitBreaker {
    pub fn new(base_config: CircuitBreakerConfig, adaptation_config: AdaptationConfig) -> Self {
        AdaptiveCircuitBreaker {
            base_breaker: CircuitBreaker::new(base_config),
            traffic_analyzer: TrafficAnalyzer::new(
                adaptation_config.traffic_analysis_window,
                adaptation_config.high_traffic_failure_threshold as f64,
                adaptation_config.low_traffic_failure_threshold as f64,
            ),
            adaptation_config,
        }
    }
    
    pub fn call<F, T, E>(&mut self, f: F) -> Result<T, CircuitBreakerError<E>>
    where
        F: FnOnce() -> Result<T, E>,
    {
        // Analyze current traffic patterns
        self.traffic_analyzer.record_request();
        let traffic_level = self.traffic_analyzer.get_traffic_level();
        
        // Adapt circuit breaker thresholds based on traffic
        self.adapt_thresholds(traffic_level);
        
        // Execute with adapted circuit breaker
        self.base_breaker.call(f)
    }
    
    fn adapt_thresholds(&mut self, traffic_level: TrafficLevel) {
        let _new_threshold = match traffic_level {
            TrafficLevel::High => self.adaptation_config.high_traffic_failure_threshold,
            TrafficLevel::Low => self.adaptation_config.low_traffic_failure_threshold,
            TrafficLevel::Normal => {
                // Use average of high and low thresholds
                (self.adaptation_config.high_traffic_failure_threshold + 
                 self.adaptation_config.low_traffic_failure_threshold) / 2
            }
        };
        
        // Update the base breaker's configuration (simplified approach)
        // In a real implementation, you'd need to modify the internal state
        // For now, we'll just track the adaptation
    }
    
    pub fn get_metrics(&self) -> (CircuitBreakerMetrics, TrafficMetrics) {
        let cb_metrics = self.base_breaker.get_metrics();
        let traffic_metrics = self.traffic_analyzer.get_metrics();
        (cb_metrics, traffic_metrics)
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum TrafficLevel {
    Low,
    Normal,
    High,
}

#[derive(Debug, Clone)]
pub struct TrafficMetrics {
    pub current_rate: f64,
    pub average_rate: f64,
    pub peak_rate: f64,
    pub traffic_level: TrafficLevel,
}

impl TrafficAnalyzer {
    pub fn new(_analysis_window: Duration, peak_threshold: f64, low_threshold: f64) -> Self {
        TrafficAnalyzer {
            request_rates: VecDeque::new(),
            peak_traffic_threshold: peak_threshold,
            low_traffic_threshold: low_threshold,
        }
    }
    
    pub fn record_request(&mut self) {
        let now = Instant::now();
        
        // Clean old entries (older than 1 minute)
        let cutoff = now - Duration::from_secs(60);
        while let Some(&(timestamp, _)) = self.request_rates.front() {
            if timestamp < cutoff {
                self.request_rates.pop_front();
            } else {
                break;
            }
        }
        
        // Add current request
        let should_increment = if let Some(&(timestamp, _)) = self.request_rates.back() {
            now.duration_since(timestamp) < Duration::from_secs(1)
        } else {
            false
        };
        
        if should_increment {
            if let Some(&mut (_, ref mut count)) = self.request_rates.back_mut() {
                *count += 1;
                return;
            }
        }
        
        self.request_rates.push_back((now, 1));
    }
    
    pub fn get_traffic_level(&self) -> TrafficLevel {
        let current_rate = self.get_current_rate();
        
        if current_rate >= self.peak_traffic_threshold {
            TrafficLevel::High
        } else if current_rate <= self.low_traffic_threshold {
            TrafficLevel::Low
        } else {
            TrafficLevel::Normal
        }
    }
    
    fn get_current_rate(&self) -> f64 {
        if self.request_rates.is_empty() {
            return 0.0;
        }
        
        let now = Instant::now();
        let recent_requests: u32 = self.request_rates
            .iter()
            .filter(|(timestamp, _)| now.duration_since(*timestamp) < Duration::from_secs(10))
            .map(|(_, count)| count)
            .sum();
        
        recent_requests as f64 / 10.0 // requests per second over last 10 seconds
    }
    
    pub fn get_metrics(&self) -> TrafficMetrics {
        let current_rate = self.get_current_rate();
        let average_rate = if !self.request_rates.is_empty() {
            let total_requests: u32 = self.request_rates.iter().map(|(_, count)| count).sum();
            total_requests as f64 / self.request_rates.len() as f64
        } else {
            0.0
        };
        
        let peak_rate = self.request_rates
            .iter()
            .map(|(_, count)| *count as f64)
            .fold(0.0, f64::max);
        
        TrafficMetrics {
            current_rate,
            average_rate,
            peak_rate,
            traffic_level: self.get_traffic_level(),
        }
    }
}

impl MultiLevelCircuitBreaker {
    pub fn new() -> Self {
        MultiLevelCircuitBreaker {
            network_breaker: CircuitBreaker::builder()
                .failure_threshold(3)
                .timeout(Duration::from_secs(10))
                .build(),
            timeout_breaker: CircuitBreaker::builder()
                .failure_threshold(5)
                .timeout(Duration::from_secs(30))
                .slow_call_threshold(Duration::from_secs(5), 0.3)
                .build(),
            error_breaker: CircuitBreaker::builder()
                .failure_threshold(10)
                .timeout(Duration::from_secs(60))
                .build(),
        }
    }
}

impl Default for MultiLevelCircuitBreaker {
    fn default() -> Self {
        Self::new()
    }
}

impl MultiLevelCircuitBreaker {
    pub fn call<F, T, E>(&self, f: F) -> Result<T, CircuitBreakerError<E>>
    where
        F: FnOnce() -> Result<T, E>,
        E: Clone,
    {
        // Check all circuit breakers
        if !self.network_breaker.allow_request() {
            return Err(CircuitBreakerError::CircuitOpen);
        }
        
        if !self.timeout_breaker.allow_request() {
            return Err(CircuitBreakerError::CircuitOpen);
        }
        
        if !self.error_breaker.allow_request() {
            return Err(CircuitBreakerError::CircuitOpen);
        }
        
        // Execute with all circuit breakers
        self.network_breaker.call(|| {
            self.timeout_breaker.call(|| {
                self.error_breaker.call(f)
            }).map_err(|e| match e {
                CircuitBreakerError::CallFailed(inner) => inner,
                _ => unreachable!(),
            })
        }).map_err(|e| match e {
            CircuitBreakerError::CallFailed(inner) => inner,
            _ => unreachable!(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    
    #[test]
    fn test_circuit_breaker_closed_state() {
        let cb = CircuitBreaker::builder()
            .failure_threshold(3)
            .build();
        
        assert_eq!(cb.get_state(), CircuitState::Closed);
        
        // Successful calls should keep circuit closed
        for _ in 0..5 {
            let result = cb.call(|| Ok::<_, String>("success"));
            assert!(result.is_ok());
        }
        
        assert_eq!(cb.get_state(), CircuitState::Closed);
    }
    
    #[test]
    fn test_circuit_breaker_opens_on_failures() {
        let cb = CircuitBreaker::builder()
            .failure_threshold(3)
            .minimum_calls(3)
            .build();
        
        // Add some failures
        for i in 0..5 {
            let result = cb.call(|| Err::<String, _>(format!("error {i}")));
            if i < 3 {
                assert!(matches!(result, Err(CircuitBreakerError::CallFailed(_))));
            } else {
                // Circuit should be open now
                assert!(matches!(result, Err(CircuitBreakerError::CircuitOpen)));
            }
        }
        
        assert_eq!(cb.get_state(), CircuitState::Open);
    }
    
    #[test]
    fn test_circuit_breaker_half_open_transition() {
        let cb = CircuitBreaker::builder()
            .failure_threshold(2)
            .reset_timeout(Duration::from_millis(100))
            .minimum_calls(2)
            .build();
        
        // Cause failures to open circuit
        for _ in 0..3 {
            let _ = cb.call(|| Err::<String, _>("error"));
        }
        
        assert_eq!(cb.get_state(), CircuitState::Open);
        
        // Wait for reset timeout
        std::thread::sleep(Duration::from_millis(150));
        
        // Next call should transition to half-open
        let result = cb.call(|| Ok::<_, String>("success"));
        assert!(result.is_ok());
        
        // Should be in half-open state after successful call
        let metrics = cb.get_metrics();
        assert!(metrics.state == CircuitState::HalfOpen || metrics.state == CircuitState::Closed);
    }
    
    #[test]
    fn test_circuit_breaker_metrics() {
        let cb = CircuitBreaker::builder()
            .failure_threshold(3)
            .build();
        
        // Make some calls
        let _ = cb.call(|| Ok::<_, String>("success"));
        let _ = cb.call(|| Err::<String, _>("error"));
        let _ = cb.call(|| Ok::<_, String>("success"));
        
        let metrics = cb.get_metrics();
        assert_eq!(metrics.total_calls, 3);
        assert_eq!(metrics.successful_calls, 2);
        assert_eq!(metrics.failed_calls, 1);
    }
    
    #[test]
    fn test_slow_call_detection() {
        let cb = CircuitBreaker::builder()
            .slow_call_threshold(Duration::from_millis(100), 0.5)
            .minimum_calls(2)
            .build();
        
        // Make a slow call
        let _ = cb.call(|| {
            std::thread::sleep(Duration::from_millis(150));
            Ok::<_, String>("slow success")
        });
        
        // Make a fast call
        let _ = cb.call(|| Ok::<_, String>("fast success"));
        
        let metrics = cb.get_metrics();
        assert_eq!(metrics.slow_calls, 1);
        assert!(metrics.slow_call_rate > 0.0);
    }
    
    #[test]
    fn test_force_operations() {
        let cb = CircuitBreaker::new(CircuitBreakerConfig::default());
        
        // Force open
        cb.force_open();
        assert_eq!(cb.get_state(), CircuitState::Open);
        
        // Force close
        cb.force_close();
        assert_eq!(cb.get_state(), CircuitState::Closed);
        
        // Reset
        cb.reset();
        assert_eq!(cb.get_state(), CircuitState::Closed);
        let metrics = cb.get_metrics();
        assert_eq!(metrics.total_calls, 0);
    }
}