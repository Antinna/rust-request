//! Advanced rate limiting and throttling mechanisms
//! 
//! This module provides sophisticated rate limiting algorithms including token bucket,
//! sliding window, and adaptive rate limiting for HTTP requests.

use std::collections::{HashMap, VecDeque};
use std::time::{Duration, Instant};
use std::sync::{Arc, RwLock};

/// Advanced rate limiter with multiple algorithms
#[derive(Debug)]
pub struct AdvancedRateLimiter {
    limiters: HashMap<String, Box<dyn RateLimiter + Send + Sync>>,
    global_limiter: Option<Box<dyn RateLimiter + Send + Sync>>,
    config: RateLimiterConfig,
}

/// Rate limiter configuration
#[derive(Debug, Clone)]
pub struct RateLimiterConfig {
    pub default_algorithm: RateLimitingAlgorithm,
    pub enable_burst: bool,
    pub burst_multiplier: f64,
    pub adaptive_enabled: bool,
    pub backpressure_enabled: bool,
}

/// Rate limiting algorithms
#[derive(Debug, Clone, PartialEq)]
pub enum RateLimitingAlgorithm {
    TokenBucket,
    SlidingWindow,
    FixedWindow,
    LeakyBucket,
    Adaptive,
}

/// Rate limiter trait
pub trait RateLimiter: std::fmt::Debug {
    fn allow_request(&mut self, tokens: u32) -> RateLimitResult;
    fn get_stats(&self) -> RateLimitStats;
    fn reset(&mut self);
}

/// Rate limit result
#[derive(Debug, Clone, PartialEq)]
pub enum RateLimitResult {
    Allowed,
    Denied(RateLimitInfo),
    Throttled(Duration),
}

/// Rate limit information
#[derive(Debug, Clone, PartialEq)]
pub struct RateLimitInfo {
    pub limit: u32,
    pub remaining: u32,
    pub reset_time: Instant,
    pub retry_after: Duration,
}

/// Rate limit statistics
#[derive(Debug, Clone)]
pub struct RateLimitStats {
    pub total_requests: u64,
    pub allowed_requests: u64,
    pub denied_requests: u64,
    pub throttled_requests: u64,
    pub current_rate: f64,
    pub average_rate: f64,
}

/// Token bucket rate limiter
#[derive(Debug)]
pub struct TokenBucketLimiter {
    capacity: u32,
    tokens: f64,
    refill_rate: f64, // tokens per second
    last_refill: Instant,
    stats: RateLimitStats,
}

/// Sliding window rate limiter
#[derive(Debug)]
pub struct SlidingWindowLimiter {
    limit: u32,
    window_size: Duration,
    requests: VecDeque<Instant>,
    stats: RateLimitStats,
}

/// Fixed window rate limiter
#[derive(Debug)]
pub struct FixedWindowLimiter {
    limit: u32,
    window_size: Duration,
    current_window_start: Instant,
    current_window_count: u32,
    stats: RateLimitStats,
}

/// Leaky bucket rate limiter
#[derive(Debug)]
pub struct LeakyBucketLimiter {
    capacity: u32,
    leak_rate: f64, // requests per second
    queue: VecDeque<Instant>,
    last_leak: Instant,
    stats: RateLimitStats,
}

/// Adaptive rate limiter
#[derive(Debug)]
pub struct AdaptiveRateLimiter {
    base_limiter: Box<dyn RateLimiter + Send + Sync>,
    adaptation_config: AdaptationConfig,
    performance_tracker: PerformanceTracker,
    stats: RateLimitStats,
}

/// Adaptation configuration
#[derive(Debug, Clone)]
pub struct AdaptationConfig {
    pub min_rate: f64,
    pub max_rate: f64,
    pub adaptation_factor: f64,
    pub measurement_window: Duration,
    pub target_success_rate: f64,
    pub target_latency: Duration,
}

/// Performance tracker for adaptive rate limiting
#[derive(Debug)]
pub struct PerformanceTracker {
    success_rate: f64,
    average_latency: Duration,
    error_rate: f64,
    measurement_window: Duration,
    samples: VecDeque<PerformanceSample>,
}

/// Performance sample
#[derive(Debug, Clone)]
pub struct PerformanceSample {
    timestamp: Instant,
    success: bool,
    latency: Duration,
}

/// Distributed rate limiter for multiple instances
#[derive(Debug)]
pub struct DistributedRateLimiter {
    local_limiter: Box<dyn RateLimiter + Send + Sync>,
    coordination_strategy: CoordinationStrategy,
    instance_id: String,
    shared_state: Arc<RwLock<SharedRateLimitState>>,
}

/// Coordination strategy for distributed rate limiting
#[derive(Debug, Clone, PartialEq)]
pub enum CoordinationStrategy {
    LocalOnly,
    SharedCounter,
    ConsistentHashing,
    LeaderElection,
}

/// Shared state for distributed rate limiting
#[derive(Debug)]
pub struct SharedRateLimitState {
    global_count: u64,
    instance_counts: HashMap<String, u64>,
    last_sync: Instant,
    sync_interval: Duration,
}

impl SharedRateLimitState {
    pub fn new() -> Self {
        SharedRateLimitState {
            global_count: 0,
            instance_counts: HashMap::new(),
            last_sync: Instant::now(),
            sync_interval: Duration::from_secs(1),
        }
    }
    
    pub fn get_global_count(&self) -> u64 {
        self.global_count
    }
    
    pub fn get_instance_count(&self, instance_id: &str) -> u64 {
        self.instance_counts.get(instance_id).copied().unwrap_or(0)
    }
    
    pub fn increment_count(&mut self, instance_id: &str, count: u64) {
        self.global_count += count;
        *self.instance_counts.entry(instance_id.to_string()).or_insert(0) += count;
    }
    
    pub fn should_sync(&self) -> bool {
        self.last_sync.elapsed() >= self.sync_interval
    }
    
    pub fn mark_synced(&mut self) {
        self.last_sync = Instant::now();
    }
}

impl Default for SharedRateLimitState {
    fn default() -> Self {
        Self::new()
    }
}

impl DistributedRateLimiter {
    pub fn new(
        local_limiter: Box<dyn RateLimiter + Send + Sync>,
        coordination_strategy: CoordinationStrategy,
        instance_id: String,
    ) -> Self {
        let shared_state = Arc::new(RwLock::new(SharedRateLimitState::new()));
        
        DistributedRateLimiter {
            local_limiter,
            coordination_strategy,
            instance_id,
            shared_state,
        }
    }
    
    pub fn allow_request(&mut self, tokens: u32) -> RateLimitResult {
        match self.coordination_strategy {
            CoordinationStrategy::LocalOnly => {
                self.local_limiter.allow_request(tokens)
            }
            CoordinationStrategy::SharedCounter => {
                self.allow_request_with_shared_counter(tokens)
            }
            _ => {
                // Fallback to local limiter for other strategies
                self.local_limiter.allow_request(tokens)
            }
        }
    }
    
    fn allow_request_with_shared_counter(&mut self, tokens: u32) -> RateLimitResult {
        let mut shared = self.shared_state.write().unwrap();
        
        // Sync with other instances if needed
        if shared.should_sync() {
            shared.mark_synced();
        }
        
        // Update instance count
        shared.increment_count(&self.instance_id, tokens as u64);
        
        // Check local limiter first
        self.local_limiter.allow_request(tokens)
    }
    
    pub fn get_instance_id(&self) -> &str {
        &self.instance_id
    }
    
    pub fn get_coordination_strategy(&self) -> &CoordinationStrategy {
        &self.coordination_strategy
    }
    
    pub fn get_global_count(&self) -> u64 {
        self.shared_state.read().unwrap().get_global_count()
    }
}

/// Backpressure controller
#[derive(Debug)]
pub struct BackpressureController {
    queue_size_threshold: usize,
    latency_threshold: Duration,
    error_rate_threshold: f64,
    current_pressure: f64,
    adjustment_factor: f64,
}

impl BackpressureController {
    pub fn new() -> Self {
        BackpressureController {
            queue_size_threshold: 1000,
            latency_threshold: Duration::from_millis(500),
            error_rate_threshold: 0.1,
            current_pressure: 0.0,
            adjustment_factor: 0.1,
        }
    }
    
    pub fn calculate_pressure(&mut self, queue_size: usize, avg_latency: Duration, error_rate: f64) -> f64 {
        let queue_pressure = if queue_size > self.queue_size_threshold {
            (queue_size - self.queue_size_threshold) as f64 / self.queue_size_threshold as f64
        } else {
            0.0
        };
        
        let latency_pressure = if avg_latency > self.latency_threshold {
            (avg_latency.as_millis() as f64 - self.latency_threshold.as_millis() as f64) / 
            self.latency_threshold.as_millis() as f64
        } else {
            0.0
        };
        
        let error_pressure = if error_rate > self.error_rate_threshold {
            (error_rate - self.error_rate_threshold) / self.error_rate_threshold
        } else {
            0.0
        };
        
        // Combine pressures with weights
        let total_pressure = (queue_pressure * 0.4) + (latency_pressure * 0.4) + (error_pressure * 0.2);
        
        // Apply exponential smoothing
        self.current_pressure = (1.0 - self.adjustment_factor) * self.current_pressure + 
                               self.adjustment_factor * total_pressure;
        
        self.current_pressure
    }
    
    pub fn should_apply_backpressure(&self) -> bool {
        self.current_pressure > 0.5
    }
    
    pub fn get_throttle_factor(&self) -> f64 {
        if self.current_pressure > 1.0 {
            0.1 // Severe throttling
        } else if self.current_pressure > 0.7 {
            0.5 // Moderate throttling
        } else if self.current_pressure > 0.3 {
            0.8 // Light throttling
        } else {
            1.0 // No throttling
        }
    }
    
    pub fn get_current_pressure(&self) -> f64 {
        self.current_pressure
    }
    
    pub fn reset(&mut self) {
        self.current_pressure = 0.0;
    }
}

impl Default for BackpressureController {
    fn default() -> Self {
        Self::new()
    }
}

impl Default for RateLimiterConfig {
    fn default() -> Self {
        RateLimiterConfig {
            default_algorithm: RateLimitingAlgorithm::TokenBucket,
            enable_burst: true,
            burst_multiplier: 2.0,
            adaptive_enabled: false,
            backpressure_enabled: true,
        }
    }
}

impl AdvancedRateLimiter {
    pub fn new(config: RateLimiterConfig) -> Self {
        AdvancedRateLimiter {
            limiters: HashMap::new(),
            global_limiter: None,
            config,
        }
    }
    
    pub fn add_limiter(&mut self, key: String, limiter: Box<dyn RateLimiter + Send + Sync>) {
        self.limiters.insert(key, limiter);
    }
    
    pub fn set_global_limiter(&mut self, limiter: Box<dyn RateLimiter + Send + Sync>) {
        self.global_limiter = Some(limiter);
    }
    
    pub fn check_rate_limit(&mut self, key: &str, tokens: u32) -> RateLimitResult {
        // Check global limiter first
        if let Some(ref mut global) = self.global_limiter {
            match global.allow_request(tokens) {
                RateLimitResult::Denied(info) => return RateLimitResult::Denied(info),
                RateLimitResult::Throttled(duration) => return RateLimitResult::Throttled(duration),
                RateLimitResult::Allowed => {}
            }
        }
        
        // Check specific limiter
        if let Some(limiter) = self.limiters.get_mut(key) {
            limiter.allow_request(tokens)
        } else {
            // Create default limiter if none exists
            let mut limiter = self.create_default_limiter();
            let result = limiter.allow_request(tokens);
            self.limiters.insert(key.to_string(), limiter);
            result
        }
    }
    
    pub fn get_stats(&self, key: &str) -> Option<RateLimitStats> {
        self.limiters.get(key).map(|limiter| limiter.get_stats())
    }
    
    pub fn get_global_stats(&self) -> Option<RateLimitStats> {
        self.global_limiter.as_ref().map(|limiter| limiter.get_stats())
    }
    
    fn create_default_limiter(&self) -> Box<dyn RateLimiter + Send + Sync> {
        match self.config.default_algorithm {
            RateLimitingAlgorithm::TokenBucket => {
                Box::new(TokenBucketLimiter::new(100, 10.0))
            }
            RateLimitingAlgorithm::SlidingWindow => {
                Box::new(SlidingWindowLimiter::new(100, Duration::from_secs(60)))
            }
            RateLimitingAlgorithm::FixedWindow => {
                Box::new(FixedWindowLimiter::new(100, Duration::from_secs(60)))
            }
            RateLimitingAlgorithm::LeakyBucket => {
                Box::new(LeakyBucketLimiter::new(100, 10.0))
            }
            RateLimitingAlgorithm::Adaptive => {
                let base = Box::new(TokenBucketLimiter::new(100, 10.0));
                Box::new(AdaptiveRateLimiter::new(base, AdaptationConfig::default()))
            }
        }
    }
}

impl TokenBucketLimiter {
    pub fn new(capacity: u32, refill_rate: f64) -> Self {
        TokenBucketLimiter {
            capacity,
            tokens: capacity as f64,
            refill_rate,
            last_refill: Instant::now(),
            stats: RateLimitStats::new(),
        }
    }
    
    fn refill_tokens(&mut self) {
        let now = Instant::now();
        let elapsed = now.duration_since(self.last_refill).as_secs_f64();
        let tokens_to_add = elapsed * self.refill_rate;
        
        self.tokens = (self.tokens + tokens_to_add).min(self.capacity as f64);
        self.last_refill = now;
    }
}

impl RateLimiter for TokenBucketLimiter {
    fn allow_request(&mut self, tokens: u32) -> RateLimitResult {
        self.refill_tokens();
        self.stats.total_requests += 1;
        
        if self.tokens >= tokens as f64 {
            self.tokens -= tokens as f64;
            self.stats.allowed_requests += 1;
            RateLimitResult::Allowed
        } else {
            self.stats.denied_requests += 1;
            let retry_after = Duration::from_secs_f64((tokens as f64 - self.tokens) / self.refill_rate);
            RateLimitResult::Denied(RateLimitInfo {
                limit: self.capacity,
                remaining: self.tokens as u32,
                reset_time: self.last_refill + Duration::from_secs_f64(self.capacity as f64 / self.refill_rate),
                retry_after,
            })
        }
    }
    
    fn get_stats(&self) -> RateLimitStats {
        self.stats.clone()
    }
    
    fn reset(&mut self) {
        self.tokens = self.capacity as f64;
        self.last_refill = Instant::now();
        self.stats = RateLimitStats::new();
    }
}

impl SlidingWindowLimiter {
    pub fn new(limit: u32, window_size: Duration) -> Self {
        SlidingWindowLimiter {
            limit,
            window_size,
            requests: VecDeque::new(),
            stats: RateLimitStats::new(),
        }
    }
    
    fn cleanup_old_requests(&mut self) {
        let cutoff = Instant::now() - self.window_size;
        while let Some(&front_time) = self.requests.front() {
            if front_time < cutoff {
                self.requests.pop_front();
            } else {
                break;
            }
        }
    }
}

impl RateLimiter for SlidingWindowLimiter {
    fn allow_request(&mut self, tokens: u32) -> RateLimitResult {
        self.cleanup_old_requests();
        self.stats.total_requests += 1;
        
        if self.requests.len() + tokens as usize <= self.limit as usize {
            for _ in 0..tokens {
                self.requests.push_back(Instant::now());
            }
            self.stats.allowed_requests += 1;
            RateLimitResult::Allowed
        } else {
            self.stats.denied_requests += 1;
            let oldest_request = self.requests.front().copied().unwrap_or(Instant::now());
            let retry_after = self.window_size - oldest_request.elapsed();
            
            RateLimitResult::Denied(RateLimitInfo {
                limit: self.limit,
                remaining: (self.limit as usize).saturating_sub(self.requests.len()) as u32,
                reset_time: oldest_request + self.window_size,
                retry_after,
            })
        }
    }
    
    fn get_stats(&self) -> RateLimitStats {
        let mut stats = self.stats.clone();
        stats.current_rate = self.requests.len() as f64 / self.window_size.as_secs_f64();
        stats
    }
    
    fn reset(&mut self) {
        self.requests.clear();
        self.stats = RateLimitStats::new();
    }
}

impl FixedWindowLimiter {
    pub fn new(limit: u32, window_size: Duration) -> Self {
        FixedWindowLimiter {
            limit,
            window_size,
            current_window_start: Instant::now(),
            current_window_count: 0,
            stats: RateLimitStats::new(),
        }
    }
    
    fn check_window_reset(&mut self) {
        let now = Instant::now();
        if now.duration_since(self.current_window_start) >= self.window_size {
            self.current_window_start = now;
            self.current_window_count = 0;
        }
    }
}

impl RateLimiter for FixedWindowLimiter {
    fn allow_request(&mut self, tokens: u32) -> RateLimitResult {
        self.check_window_reset();
        self.stats.total_requests += 1;
        
        if self.current_window_count + tokens <= self.limit {
            self.current_window_count += tokens;
            self.stats.allowed_requests += 1;
            RateLimitResult::Allowed
        } else {
            self.stats.denied_requests += 1;
            let retry_after = self.window_size - self.current_window_start.elapsed();
            
            RateLimitResult::Denied(RateLimitInfo {
                limit: self.limit,
                remaining: self.limit.saturating_sub(self.current_window_count),
                reset_time: self.current_window_start + self.window_size,
                retry_after,
            })
        }
    }
    
    fn get_stats(&self) -> RateLimitStats {
        self.stats.clone()
    }
    
    fn reset(&mut self) {
        self.current_window_start = Instant::now();
        self.current_window_count = 0;
        self.stats = RateLimitStats::new();
    }
}

impl LeakyBucketLimiter {
    pub fn new(capacity: u32, leak_rate: f64) -> Self {
        LeakyBucketLimiter {
            capacity,
            leak_rate,
            queue: VecDeque::new(),
            last_leak: Instant::now(),
            stats: RateLimitStats::new(),
        }
    }
    
    fn leak_requests(&mut self) {
        let now = Instant::now();
        let elapsed = now.duration_since(self.last_leak).as_secs_f64();
        let requests_to_leak = (elapsed * self.leak_rate) as usize;
        
        for _ in 0..requests_to_leak.min(self.queue.len()) {
            self.queue.pop_front();
        }
        
        self.last_leak = now;
    }
}

impl RateLimiter for LeakyBucketLimiter {
    fn allow_request(&mut self, tokens: u32) -> RateLimitResult {
        self.leak_requests();
        self.stats.total_requests += 1;
        
        if self.queue.len() + tokens as usize <= self.capacity as usize {
            for _ in 0..tokens {
                self.queue.push_back(Instant::now());
            }
            self.stats.allowed_requests += 1;
            RateLimitResult::Allowed
        } else {
            self.stats.denied_requests += 1;
            let queue_time = Duration::from_secs_f64(self.queue.len() as f64 / self.leak_rate);
            
            RateLimitResult::Throttled(queue_time)
        }
    }
    
    fn get_stats(&self) -> RateLimitStats {
        self.stats.clone()
    }
    
    fn reset(&mut self) {
        self.queue.clear();
        self.last_leak = Instant::now();
        self.stats = RateLimitStats::new();
    }
}

impl AdaptiveRateLimiter {
    pub fn new(base_limiter: Box<dyn RateLimiter + Send + Sync>, config: AdaptationConfig) -> Self {
        AdaptiveRateLimiter {
            base_limiter,
            adaptation_config: config.clone(),
            performance_tracker: PerformanceTracker::new(config.measurement_window),
            stats: RateLimitStats::new(),
        }
    }
    
    pub fn record_performance(&mut self, success: bool, latency: Duration) {
        self.performance_tracker.record_sample(PerformanceSample {
            timestamp: Instant::now(),
            success,
            latency,
        });
        
        self.adapt_rate_limit();
    }
    
    fn adapt_rate_limit(&mut self) {
        let performance = self.performance_tracker.get_current_performance();
        
        // Adjust rate based on performance metrics
        let success_factor = if performance.success_rate < self.adaptation_config.target_success_rate {
            0.8 // Reduce rate if success rate is low
        } else {
            1.2 // Increase rate if success rate is good
        };
        
        let latency_factor = if performance.average_latency > self.adaptation_config.target_latency {
            0.9 // Reduce rate if latency is high
        } else {
            1.1 // Increase rate if latency is good
        };
        
        let _adjustment = success_factor * latency_factor * self.adaptation_config.adaptation_factor;
        
        // Apply adjustment to base limiter (implementation depends on limiter type)
        // This is a simplified version - real implementation would modify the limiter's parameters
    }
}

impl RateLimiter for AdaptiveRateLimiter {
    fn allow_request(&mut self, tokens: u32) -> RateLimitResult {
        self.stats.total_requests += 1;
        let result = self.base_limiter.allow_request(tokens);
        
        match result {
            RateLimitResult::Allowed => self.stats.allowed_requests += 1,
            RateLimitResult::Denied(_) => self.stats.denied_requests += 1,
            RateLimitResult::Throttled(_) => self.stats.throttled_requests += 1,
        }
        
        result
    }
    
    fn get_stats(&self) -> RateLimitStats {
        self.stats.clone()
    }
    
    fn reset(&mut self) {
        self.base_limiter.reset();
        self.stats = RateLimitStats::new();
        self.performance_tracker = PerformanceTracker::new(self.adaptation_config.measurement_window);
    }
}

impl PerformanceTracker {
    pub fn new(window: Duration) -> Self {
        PerformanceTracker {
            success_rate: 1.0,
            average_latency: Duration::from_millis(0),
            error_rate: 0.0,
            measurement_window: window,
            samples: VecDeque::new(),
        }
    }
    
    pub fn record_sample(&mut self, sample: PerformanceSample) {
        self.samples.push_back(sample);
        
        // Clean old samples
        let cutoff = Instant::now() - self.measurement_window;
        while let Some(front) = self.samples.front() {
            if front.timestamp < cutoff {
                self.samples.pop_front();
            } else {
                break;
            }
        }
        
        self.update_metrics();
    }
    
    fn update_metrics(&mut self) {
        if self.samples.is_empty() {
            return;
        }
        
        let successful = self.samples.iter().filter(|s| s.success).count();
        self.success_rate = successful as f64 / self.samples.len() as f64;
        self.error_rate = 1.0 - self.success_rate;
        
        let total_latency: Duration = self.samples.iter().map(|s| s.latency).sum();
        self.average_latency = total_latency / self.samples.len() as u32;
    }
    
    pub fn get_current_performance(&self) -> CurrentPerformance {
        CurrentPerformance {
            success_rate: self.success_rate,
            average_latency: self.average_latency,
            error_rate: self.error_rate,
            sample_count: self.samples.len(),
        }
    }
}

impl RateLimitStats {
    pub fn new() -> Self {
        RateLimitStats {
            total_requests: 0,
            allowed_requests: 0,
            denied_requests: 0,
            throttled_requests: 0,
            current_rate: 0.0,
            average_rate: 0.0,
        }
    }
}

impl Default for RateLimitStats {
    fn default() -> Self {
        Self::new()
    }
}

impl Default for AdaptationConfig {
    fn default() -> Self {
        AdaptationConfig {
            min_rate: 1.0,
            max_rate: 1000.0,
            adaptation_factor: 0.1,
            measurement_window: Duration::from_secs(60),
            target_success_rate: 0.95,
            target_latency: Duration::from_millis(100),
        }
    }
}

/// Current performance metrics
#[derive(Debug, Clone)]
pub struct CurrentPerformance {
    pub success_rate: f64,
    pub average_latency: Duration,
    pub error_rate: f64,
    pub sample_count: usize,
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_token_bucket_limiter() {
        let mut limiter = TokenBucketLimiter::new(10, 1.0);
        
        // Should allow requests up to capacity
        for _ in 0..10 {
            assert_eq!(limiter.allow_request(1), RateLimitResult::Allowed);
        }
        
        // Should deny the next request
        match limiter.allow_request(1) {
            RateLimitResult::Denied(_) => {},
            _ => panic!("Expected denied result"),
        }
        
        let stats = limiter.get_stats();
        assert_eq!(stats.allowed_requests, 10);
        assert_eq!(stats.denied_requests, 1);
    }
    
    #[test]
    fn test_sliding_window_limiter() {
        let mut limiter = SlidingWindowLimiter::new(5, Duration::from_secs(1));
        
        // Should allow requests up to limit
        for _ in 0..5 {
            assert_eq!(limiter.allow_request(1), RateLimitResult::Allowed);
        }
        
        // Should deny the next request
        match limiter.allow_request(1) {
            RateLimitResult::Denied(_) => {},
            _ => panic!("Expected denied result"),
        }
    }
    
    #[test]
    fn test_fixed_window_limiter() {
        let mut limiter = FixedWindowLimiter::new(5, Duration::from_secs(1));
        
        // Should allow requests up to limit
        for _ in 0..5 {
            assert_eq!(limiter.allow_request(1), RateLimitResult::Allowed);
        }
        
        // Should deny the next request
        match limiter.allow_request(1) {
            RateLimitResult::Denied(_) => {},
            _ => panic!("Expected denied result"),
        }
    }
    
    #[test]
    fn test_leaky_bucket_limiter() {
        let mut limiter = LeakyBucketLimiter::new(5, 1.0);
        
        // Should allow requests up to capacity
        for _ in 0..5 {
            assert_eq!(limiter.allow_request(1), RateLimitResult::Allowed);
        }
        
        // Should throttle the next request
        match limiter.allow_request(1) {
            RateLimitResult::Throttled(_) => {},
            _ => panic!("Expected throttled result"),
        }
    }
    
    #[test]
    fn test_advanced_rate_limiter() {
        let mut limiter = AdvancedRateLimiter::new(RateLimiterConfig::default());
        
        // Add a token bucket limiter for a specific key
        limiter.add_limiter("api_key_1".to_string(), Box::new(TokenBucketLimiter::new(10, 1.0)));
        
        // Should allow requests
        assert_eq!(limiter.check_rate_limit("api_key_1", 1), RateLimitResult::Allowed);
        
        // Should have stats
        let stats = limiter.get_stats("api_key_1").unwrap();
        assert_eq!(stats.allowed_requests, 1);
    }
    
    #[test]
    fn test_performance_tracker() {
        let mut tracker = PerformanceTracker::new(Duration::from_secs(60));
        
        tracker.record_sample(PerformanceSample {
            timestamp: Instant::now(),
            success: true,
            latency: Duration::from_millis(100),
        });
        
        tracker.record_sample(PerformanceSample {
            timestamp: Instant::now(),
            success: false,
            latency: Duration::from_millis(200),
        });
        
        let performance = tracker.get_current_performance();
        assert_eq!(performance.success_rate, 0.5);
        assert_eq!(performance.error_rate, 0.5);
        assert_eq!(performance.sample_count, 2);
    }
}