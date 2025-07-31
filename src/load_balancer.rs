//! Advanced load balancing algorithms and strategies
//! 
//! This module provides sophisticated load balancing capabilities for distributing
//! HTTP requests across multiple backend servers with health checking and failover.

use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant};
use std::net::SocketAddr;
use std::fmt;

/// Load balancing strategies
#[derive(Debug, Clone, PartialEq)]
pub enum LoadBalancingStrategy {
    RoundRobin,
    WeightedRoundRobin,
    LeastConnections,
    WeightedLeastConnections,
    Random,
    WeightedRandom,
    IpHash,
    ConsistentHash,
    LeastResponseTime,
    ResourceBased,
}

/// Backend server configuration
#[derive(Debug, Clone)]
pub struct Backend {
    pub id: String,
    pub address: SocketAddr,
    pub weight: u32,
    pub max_connections: u32,
    pub health_check_url: Option<String>,
    pub metadata: HashMap<String, String>,
}

/// Backend server status
#[derive(Debug, Clone, PartialEq)]
pub enum BackendStatus {
    Healthy,
    Unhealthy,
    Draining,
    Maintenance,
}

/// Backend server statistics
#[derive(Debug, Clone)]
pub struct BackendStats {
    pub active_connections: u32,
    pub total_requests: u64,
    pub successful_requests: u64,
    pub failed_requests: u64,
    pub average_response_time: Duration,
    pub last_health_check: Option<Instant>,
    pub status: BackendStatus,
    pub cpu_usage: f64,
    pub memory_usage: f64,
    pub load_average: f64,
}

/// Load balancer configuration
#[derive(Debug, Clone)]
pub struct LoadBalancerConfig {
    pub strategy: LoadBalancingStrategy,
    pub health_check_interval: Duration,
    pub health_check_timeout: Duration,
    pub health_check_retries: u32,
    pub failover_threshold: u32,
    pub sticky_sessions: bool,
    pub session_affinity_cookie: Option<String>,
    pub circuit_breaker_enabled: bool,
    pub max_retries: u32,
    pub retry_backoff: Duration,
}

/// Session affinity information
#[derive(Debug, Clone)]
pub struct SessionAffinity {
    pub session_id: String,
    pub backend_id: String,
    pub created_at: Instant,
    pub last_used: Instant,
    pub ttl: Duration,
}

/// Load balancer implementation
pub struct LoadBalancer {
    config: LoadBalancerConfig,
    backends: Arc<RwLock<HashMap<String, Backend>>>,
    backend_stats: Arc<RwLock<HashMap<String, BackendStats>>>,
    strategy_state: Arc<Mutex<StrategyState>>,
    session_store: Arc<RwLock<HashMap<String, SessionAffinity>>>,
    health_checker: Arc<HealthChecker>,
}

/// Internal state for different load balancing strategies
#[derive(Debug)]
struct StrategyState {
    round_robin_index: usize,
    weighted_round_robin_state: WeightedRoundRobinState,
    consistent_hash_ring: ConsistentHashRing,
    response_time_tracker: ResponseTimeTracker,
}

/// State for weighted round robin algorithm
#[derive(Debug)]
pub struct WeightedRoundRobinState {
    current_weights: HashMap<String, i32>,
    pub total_weight: i32,
}

/// Consistent hash ring for consistent hashing
#[derive(Debug)]
pub struct ConsistentHashRing {
    ring: std::collections::BTreeMap<u64, String>,
    virtual_nodes: u32,
}

/// Response time tracking for least response time algorithm
#[derive(Debug)]
pub struct ResponseTimeTracker {
    response_times: HashMap<String, VecDeque<Duration>>,
    window_size: usize,
}

/// Health checker for monitoring backend health
pub struct HealthChecker {
    client: crate::Client,
    check_interval: Duration,
    timeout: Duration,
    retries: u32,
}

/// Load balancing decision result
#[derive(Debug, Clone)]
pub struct LoadBalancingDecision {
    pub backend: Backend,
    pub reason: String,
    pub session_affinity: Option<SessionAffinity>,
    pub retry_count: u32,
}

/// Load balancer metrics
#[derive(Debug, Clone)]
pub struct LoadBalancerMetrics {
    pub total_requests: u64,
    pub successful_requests: u64,
    pub failed_requests: u64,
    pub backend_distribution: HashMap<String, u64>,
    pub average_response_time: Duration,
    pub active_backends: u32,
    pub unhealthy_backends: u32,
    pub session_count: u32,
}

impl Default for LoadBalancerConfig {
    fn default() -> Self {
        LoadBalancerConfig {
            strategy: LoadBalancingStrategy::RoundRobin,
            health_check_interval: Duration::from_secs(30),
            health_check_timeout: Duration::from_secs(5),
            health_check_retries: 3,
            failover_threshold: 3,
            sticky_sessions: false,
            session_affinity_cookie: None,
            circuit_breaker_enabled: true,
            max_retries: 3,
            retry_backoff: Duration::from_millis(100),
        }
    }
}

impl Backend {
    pub fn new(id: String, address: SocketAddr) -> Self {
        Backend {
            id,
            address,
            weight: 1,
            max_connections: 1000,
            health_check_url: None,
            metadata: HashMap::new(),
        }
    }
    
    pub fn with_weight(mut self, weight: u32) -> Self {
        self.weight = weight;
        self
    }
    
    pub fn with_max_connections(mut self, max_connections: u32) -> Self {
        self.max_connections = max_connections;
        self
    }
    
    pub fn with_health_check(mut self, url: String) -> Self {
        self.health_check_url = Some(url);
        self
    }
    
    pub fn with_metadata(mut self, key: String, value: String) -> Self {
        self.metadata.insert(key, value);
        self
    }
}

impl BackendStats {
    pub fn new() -> Self {
        BackendStats {
            active_connections: 0,
            total_requests: 0,
            successful_requests: 0,
            failed_requests: 0,
            average_response_time: Duration::from_millis(0),
            last_health_check: None,
            status: BackendStatus::Healthy,
            cpu_usage: 0.0,
            memory_usage: 0.0,
            load_average: 0.0,
        }
    }
}

impl Default for BackendStats {
    fn default() -> Self {
        Self::new()
    }
}

impl BackendStats {
    pub fn is_healthy(&self) -> bool {
        self.status == BackendStatus::Healthy
    }
    
    pub fn is_available(&self) -> bool {
        matches!(self.status, BackendStatus::Healthy | BackendStatus::Draining)
    }
    
    pub fn can_accept_connections(&self, max_connections: u32) -> bool {
        self.active_connections < max_connections && self.is_available()
    }
}

impl LoadBalancer {
    pub fn new(config: LoadBalancerConfig) -> Self {
        let health_checker = Arc::new(HealthChecker::new(
            config.health_check_timeout,
            config.health_check_retries,
        ));
        
        LoadBalancer {
            config,
            backends: Arc::new(RwLock::new(HashMap::new())),
            backend_stats: Arc::new(RwLock::new(HashMap::new())),
            strategy_state: Arc::new(Mutex::new(StrategyState::new())),
            session_store: Arc::new(RwLock::new(HashMap::new())),
            health_checker,
        }
    }
    
    pub fn add_backend(&self, backend: Backend) {
        let backend_id = backend.id.clone();
        
        // Add backend
        self.backends.write().unwrap().insert(backend_id.clone(), backend);
        
        // Initialize stats
        self.backend_stats.write().unwrap().insert(backend_id.clone(), BackendStats::new());
        
        // Update strategy state
        let mut state = self.strategy_state.lock().unwrap();
        state.weighted_round_robin_state.add_backend(&backend_id, 1);
        state.consistent_hash_ring.add_backend(&backend_id);
        state.response_time_tracker.add_backend(&backend_id);
    }
    
    pub fn remove_backend(&self, backend_id: &str) {
        // Remove backend
        self.backends.write().unwrap().remove(backend_id);
        self.backend_stats.write().unwrap().remove(backend_id);
        
        // Update strategy state
        let mut state = self.strategy_state.lock().unwrap();
        state.weighted_round_robin_state.remove_backend(backend_id);
        state.consistent_hash_ring.remove_backend(backend_id);
        state.response_time_tracker.remove_backend(backend_id);
        
        // Remove related sessions
        let mut sessions = self.session_store.write().unwrap();
        sessions.retain(|_, affinity| affinity.backend_id != backend_id);
    }
    
    pub fn select_backend(&self, request_info: &RequestInfo) -> Option<LoadBalancingDecision> {
        // Check for session affinity first
        if self.config.sticky_sessions {
            if let Some(session_id) = &request_info.session_id {
                if let Some(affinity) = self.get_session_affinity(session_id) {
                    if self.is_backend_available(&affinity.backend_id) {
                        let backend = self.backends.read().unwrap()
                            .get(&affinity.backend_id)?.clone();
                        
                        return Some(LoadBalancingDecision {
                            backend,
                            reason: "Session affinity".to_string(),
                            session_affinity: Some(affinity),
                            retry_count: 0,
                        });
                    }
                }
            }
        }
        
        // Use load balancing strategy
        let backend_id = match self.config.strategy {
            LoadBalancingStrategy::RoundRobin => self.round_robin_select(),
            LoadBalancingStrategy::WeightedRoundRobin => self.weighted_round_robin_select(),
            LoadBalancingStrategy::LeastConnections => self.least_connections_select(),
            LoadBalancingStrategy::WeightedLeastConnections => self.weighted_least_connections_select(),
            LoadBalancingStrategy::Random => self.random_select(),
            LoadBalancingStrategy::WeightedRandom => self.weighted_random_select(),
            LoadBalancingStrategy::IpHash => self.ip_hash_select(&request_info.client_ip),
            LoadBalancingStrategy::ConsistentHash => self.consistent_hash_select(&request_info.hash_key),
            LoadBalancingStrategy::LeastResponseTime => self.least_response_time_select(),
            LoadBalancingStrategy::ResourceBased => self.resource_based_select(),
        }?;
        
        let backend = self.backends.read().unwrap().get(&backend_id)?.clone();
        
        // Create session affinity if needed
        let session_affinity = if self.config.sticky_sessions {
            request_info.session_id.as_ref().map(|session_id| {
                let affinity = SessionAffinity {
                    session_id: session_id.clone(),
                    backend_id: backend_id.clone(),
                    created_at: Instant::now(),
                    last_used: Instant::now(),
                    ttl: Duration::from_secs(24 * 60 * 60), // 24 hours
                };
                
                self.session_store.write().unwrap()
                    .insert(session_id.clone(), affinity.clone());
                
                affinity
            })
        } else {
            None
        };
        
        Some(LoadBalancingDecision {
            backend,
            reason: format!("Strategy: {:?}", self.config.strategy),
            session_affinity,
            retry_count: 0,
        })
    }
    
    fn round_robin_select(&self) -> Option<String> {
        let backends = self.backends.read().unwrap();
        let available_backends: Vec<_> = backends.iter()
            .filter(|(id, _)| self.is_backend_available(id))
            .collect();
        
        if available_backends.is_empty() {
            return None;
        }
        
        let mut state = self.strategy_state.lock().unwrap();
        let index = state.round_robin_index % available_backends.len();
        state.round_robin_index = (state.round_robin_index + 1) % available_backends.len();
        
        Some(available_backends[index].0.clone())
    }
    
    fn weighted_round_robin_select(&self) -> Option<String> {
        let backends = self.backends.read().unwrap();
        let mut state = self.strategy_state.lock().unwrap();
        
        let available_backends: Vec<_> = backends.iter()
            .filter(|(id, _)| self.is_backend_available(id))
            .collect();
        
        if available_backends.is_empty() {
            return None;
        }
        
        state.weighted_round_robin_state.select_backend(&available_backends)
    }
    
    fn least_connections_select(&self) -> Option<String> {
        let stats = self.backend_stats.read().unwrap();
        
        stats.iter()
            .filter(|(id, stat)| self.is_backend_available(id) && stat.is_available())
            .min_by_key(|(_, stat)| stat.active_connections)
            .map(|(id, _)| id.clone())
    }
    
    fn weighted_least_connections_select(&self) -> Option<String> {
        let backends = self.backends.read().unwrap();
        let stats = self.backend_stats.read().unwrap();
        
        backends.iter()
            .filter(|(id, _)| self.is_backend_available(id))
            .filter_map(|(id, backend)| {
                let stat = stats.get(id)?;
                if !stat.is_available() {
                    return None;
                }
                
                let weighted_connections = stat.active_connections as f64 / backend.weight as f64;
                Some((id.clone(), weighted_connections))
            })
            .min_by(|(_, a), (_, b)| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal))
            .map(|(id, _)| id)
    }
    
    fn random_select(&self) -> Option<String> {
        let backends = self.backends.read().unwrap();
        let available_backends: Vec<_> = backends.iter()
            .filter(|(id, _)| self.is_backend_available(id))
            .collect();
        
        if available_backends.is_empty() {
            return None;
        }
        
        let index = self.random_index(available_backends.len());
        Some(available_backends[index].0.clone())
    }
    
    fn weighted_random_select(&self) -> Option<String> {
        let backends = self.backends.read().unwrap();
        let available_backends: Vec<_> = backends.iter()
            .filter(|(id, _)| self.is_backend_available(id))
            .collect();
        
        if available_backends.is_empty() {
            return None;
        }
        
        let total_weight: u32 = available_backends.iter()
            .map(|(_, backend)| backend.weight)
            .sum();
        
        if total_weight == 0 {
            return self.random_select();
        }
        
        let mut random_weight = self.random_index(total_weight as usize) as u32;
        
        for (id, backend) in available_backends {
            if random_weight < backend.weight {
                return Some(id.clone());
            }
            random_weight -= backend.weight;
        }
        
        None
    }
    
    fn ip_hash_select(&self, client_ip: &str) -> Option<String> {
        let backends = self.backends.read().unwrap();
        let available_backends: Vec<_> = backends.iter()
            .filter(|(id, _)| self.is_backend_available(id))
            .collect();
        
        if available_backends.is_empty() {
            return None;
        }
        
        let hash = self.hash_string(client_ip);
        let index = hash as usize % available_backends.len();
        Some(available_backends[index].0.clone())
    }
    
    fn consistent_hash_select(&self, key: &str) -> Option<String> {
        let state = self.strategy_state.lock().unwrap();
        state.consistent_hash_ring.get_backend(key)
    }
    
    fn least_response_time_select(&self) -> Option<String> {
        let state = self.strategy_state.lock().unwrap();
        let stats = self.backend_stats.read().unwrap();
        
        stats.iter()
            .filter(|(id, stat)| self.is_backend_available(id) && stat.is_available())
            .min_by_key(|(id, stat)| {
                let avg_response_time = state.response_time_tracker
                    .get_average_response_time(id)
                    .unwrap_or(Duration::from_millis(0));
                
                // Combine response time with active connections
                let penalty = stat.active_connections as u64 * 10; // 10ms penalty per connection
                avg_response_time + Duration::from_millis(penalty)
            })
            .map(|(id, _)| id.clone())
    }
    
    fn resource_based_select(&self) -> Option<String> {
        let stats = self.backend_stats.read().unwrap();
        
        stats.iter()
            .filter(|(id, stat)| self.is_backend_available(id) && stat.is_available())
            .min_by(|(_, a), (_, b)| {
                // Calculate resource score (lower is better)
                let score_a = a.cpu_usage + a.memory_usage + a.load_average;
                let score_b = b.cpu_usage + b.memory_usage + b.load_average;
                score_a.partial_cmp(&score_b).unwrap_or(std::cmp::Ordering::Equal)
            })
            .map(|(id, _)| id.clone())
    }
    
    fn is_backend_available(&self, backend_id: &str) -> bool {
        self.backend_stats.read().unwrap()
            .get(backend_id)
            .map(|stat| stat.is_available())
            .unwrap_or(false)
    }
    
    fn get_session_affinity(&self, session_id: &str) -> Option<SessionAffinity> {
        let mut sessions = self.session_store.write().unwrap();
        
        if let Some(affinity) = sessions.get_mut(session_id) {
            // Check if session is still valid
            if affinity.created_at.elapsed() < affinity.ttl {
                affinity.last_used = Instant::now();
                return Some(affinity.clone());
            } else {
                // Session expired, remove it
                sessions.remove(session_id);
            }
        }
        
        None
    }
    
    pub fn record_request_start(&self, backend_id: &str) {
        if let Some(stats) = self.backend_stats.write().unwrap().get_mut(backend_id) {
            stats.active_connections += 1;
            stats.total_requests += 1;
        }
    }
    
    pub fn record_request_end(&self, backend_id: &str, success: bool, response_time: Duration) {
        let mut stats_guard = self.backend_stats.write().unwrap();
        if let Some(stats) = stats_guard.get_mut(backend_id) {
            stats.active_connections = stats.active_connections.saturating_sub(1);
            
            if success {
                stats.successful_requests += 1;
            } else {
                stats.failed_requests += 1;
            }
            
            // Update average response time (exponential moving average)
            let alpha = 0.1; // Smoothing factor
            let current_avg = stats.average_response_time.as_millis() as f64;
            let new_time = response_time.as_millis() as f64;
            let new_avg = alpha * new_time + (1.0 - alpha) * current_avg;
            stats.average_response_time = Duration::from_millis(new_avg as u64);
        }
        
        // Update response time tracker
        let mut state = self.strategy_state.lock().unwrap();
        state.response_time_tracker.record_response_time(backend_id, response_time);
    }
    
    pub fn start_health_checking(&self) {
        self.health_checker.start_health_checking(
            Arc::clone(&self.backends),
            Arc::clone(&self.backend_stats)
        );
    }
    
    pub fn get_health_check_interval(&self) -> Duration {
        self.health_checker.get_check_interval()
    }
    
    pub fn get_health_check_timeout(&self) -> Duration {
        self.health_checker.get_timeout()
    }
    
    pub fn get_metrics(&self) -> LoadBalancerMetrics {
        let stats = self.backend_stats.read().unwrap();
        let sessions = self.session_store.read().unwrap();
        
        let total_requests = stats.values().map(|s| s.total_requests).sum();
        let successful_requests = stats.values().map(|s| s.successful_requests).sum();
        let failed_requests = stats.values().map(|s| s.failed_requests).sum();
        
        let backend_distribution = stats.iter()
            .map(|(id, stat)| (id.clone(), stat.total_requests))
            .collect();
        
        let average_response_time = if !stats.is_empty() {
            let total_time: u64 = stats.values()
                .map(|s| s.average_response_time.as_millis() as u64)
                .sum();
            Duration::from_millis(total_time / stats.len() as u64)
        } else {
            Duration::from_millis(0)
        };
        
        let active_backends = stats.values()
            .filter(|s| s.is_healthy())
            .count() as u32;
        
        let unhealthy_backends = stats.values()
            .filter(|s| !s.is_healthy())
            .count() as u32;
        
        LoadBalancerMetrics {
            total_requests,
            successful_requests,
            failed_requests,
            backend_distribution,
            average_response_time,
            active_backends,
            unhealthy_backends,
            session_count: sessions.len() as u32,
        }
    }
    
    // Utility methods
    fn random_index(&self, max: usize) -> usize {
        use std::time::{SystemTime, UNIX_EPOCH};
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap();
        (now.as_nanos() % max as u128) as usize
    }
    
    fn hash_string(&self, s: &str) -> u32 {
        let mut hash = 0u32;
        for byte in s.bytes() {
            hash = hash.wrapping_mul(31).wrapping_add(byte as u32);
        }
        hash
    }
}

/// Request information for load balancing decisions
#[derive(Debug, Clone)]
pub struct RequestInfo {
    pub client_ip: String,
    pub session_id: Option<String>,
    pub hash_key: String,
    pub headers: HashMap<String, String>,
    pub path: String,
    pub method: String,
}

impl StrategyState {
    fn new() -> Self {
        StrategyState {
            round_robin_index: 0,
            weighted_round_robin_state: WeightedRoundRobinState::new(),
            consistent_hash_ring: ConsistentHashRing::new(150), // 150 virtual nodes per backend
            response_time_tracker: ResponseTimeTracker::new(10), // Track last 10 response times
        }
    }
}

impl WeightedRoundRobinState {
    pub fn new() -> Self {
        WeightedRoundRobinState {
            current_weights: HashMap::new(),
            total_weight: 0,
        }
    }
}

impl Default for WeightedRoundRobinState {
    fn default() -> Self {
        Self::new()
    }
}

impl WeightedRoundRobinState {
    pub fn add_backend(&mut self, backend_id: &str, weight: u32) {
        self.current_weights.insert(backend_id.to_string(), 0);
        self.total_weight += weight as i32;
    }
    
    fn remove_backend(&mut self, backend_id: &str) {
        self.current_weights.remove(backend_id);
        // Note: total_weight should be recalculated from actual backends
    }
    
    pub fn select_backend(&mut self, available_backends: &[(&String, &Backend)]) -> Option<String> {
        if available_backends.is_empty() {
            return None;
        }
        
        let mut best_backend = None;
        let mut best_weight = i32::MIN;
        
        // Update current weights and find the best backend
        for (id, backend) in available_backends {
            let current_weight = self.current_weights.get_mut(*id)?;
            *current_weight += backend.weight as i32;
            
            if *current_weight > best_weight {
                best_weight = *current_weight;
                best_backend = Some((*id).clone());
            }
        }
        
        // Decrease the selected backend's weight
        if let Some(ref backend_id) = best_backend {
            if let Some(weight) = self.current_weights.get_mut(backend_id) {
                *weight -= self.total_weight;
            }
        }
        
        best_backend
    }
}

impl ConsistentHashRing {
    pub fn new(virtual_nodes: u32) -> Self {
        ConsistentHashRing {
            ring: std::collections::BTreeMap::new(),
            virtual_nodes,
        }
    }
    
    pub fn add_backend(&mut self, backend_id: &str) {
        for i in 0..self.virtual_nodes {
            let virtual_key = format!("{backend_id}:{i}");
            let hash = self.hash(&virtual_key);
            self.ring.insert(hash, backend_id.to_string());
        }
    }
    
    pub fn remove_backend(&mut self, backend_id: &str) {
        for i in 0..self.virtual_nodes {
            let virtual_key = format!("{backend_id}:{i}");
            let hash = self.hash(&virtual_key);
            self.ring.remove(&hash);
        }
    }
    
    pub fn get_backend(&self, key: &str) -> Option<String> {
        if self.ring.is_empty() {
            return None;
        }
        
        let hash = self.hash(key);
        
        // Find the first backend with hash >= key hash
        if let Some((_, backend_id)) = self.ring.range(hash..).next() {
            Some(backend_id.clone())
        } else {
            // Wrap around to the first backend
            self.ring.values().next().cloned()
        }
    }
    
    fn hash(&self, key: &str) -> u64 {
        // Better hash function for more even distribution
        let mut hash = 0u64;
        let mut multiplier = 1u64;
        for byte in key.bytes() {
            hash = hash.wrapping_add((byte as u64).wrapping_mul(multiplier));
            multiplier = multiplier.wrapping_mul(257); // Use a prime number
        }
        // Add some additional mixing
        hash ^= hash >> 32;
        hash = hash.wrapping_mul(0x9e3779b97f4a7c15u64);
        hash ^= hash >> 32;
        hash
    }
}

impl ResponseTimeTracker {
    pub fn new(window_size: usize) -> Self {
        ResponseTimeTracker {
            response_times: HashMap::new(),
            window_size,
        }
    }
    
    pub fn add_backend(&mut self, backend_id: &str) {
        self.response_times.insert(backend_id.to_string(), VecDeque::new());
    }
    
    pub fn remove_backend(&mut self, backend_id: &str) {
        self.response_times.remove(backend_id);
    }
    
    pub fn record_response_time(&mut self, backend_id: &str, response_time: Duration) {
        if let Some(times) = self.response_times.get_mut(backend_id) {
            times.push_back(response_time);
            
            // Maintain window size
            while times.len() > self.window_size {
                times.pop_front();
            }
        }
    }
    
    pub fn get_average_response_time(&self, backend_id: &str) -> Option<Duration> {
        let times = self.response_times.get(backend_id)?;
        
        if times.is_empty() {
            return None;
        }
        
        let total: Duration = times.iter().sum();
        Some(total / times.len() as u32)
    }
}

impl HealthChecker {
    pub fn new(timeout: Duration, retries: u32) -> Self {
        HealthChecker {
            client: crate::Client::new(),
            check_interval: Duration::from_secs(30),
            timeout,
            retries,
        }
    }
    
    pub fn start_health_checking(&self, backends: Arc<RwLock<HashMap<String, Backend>>>, 
                                 backend_stats: Arc<RwLock<HashMap<String, BackendStats>>>) {
        // In a real implementation, this would spawn a background thread
        // For now, we'll provide a method to manually trigger health checks
        self.check_all_backends(backends, backend_stats);
    }
    
    fn check_all_backends(&self, backends: Arc<RwLock<HashMap<String, Backend>>>, 
                          backend_stats: Arc<RwLock<HashMap<String, BackendStats>>>) {
        let backends_guard = backends.read().unwrap();
        let mut stats_guard = backend_stats.write().unwrap();
        
        for (backend_id, backend) in backends_guard.iter() {
            let status = self.check_backend_health(backend);
            
            if let Some(stats) = stats_guard.get_mut(backend_id) {
                stats.status = status;
                stats.last_health_check = Some(Instant::now());
            }
        }
    }
    
    pub fn get_check_interval(&self) -> Duration {
        self.check_interval
    }
    
    pub fn get_timeout(&self) -> Duration {
        self.timeout
    }
    
    pub fn check_backend_health(&self, backend: &Backend) -> BackendStatus {
        let health_url = match &backend.health_check_url {
            Some(url) => url,
            None => return BackendStatus::Healthy, // Assume healthy if no health check URL
        };
        
        for attempt in 0..=self.retries {
            match self.perform_health_check(health_url) {
                Ok(true) => return BackendStatus::Healthy,
                Ok(false) => {
                    if attempt == self.retries {
                        return BackendStatus::Unhealthy;
                    }
                }
                Err(_) => {
                    if attempt == self.retries {
                        return BackendStatus::Unhealthy;
                    }
                }
            }
            
            // Wait before retry (simplified for std library only)
            if attempt < self.retries {
                std::thread::sleep(Duration::from_millis(100));
            }
        }
        
        BackendStatus::Unhealthy
    }
    
    fn perform_health_check(&self, url: &str) -> Result<bool, Box<dyn std::error::Error>> {
        // Simplified health check (in real implementation would make HTTP request)
        // For now, just simulate a health check
        let _request = self.client.get(url);
        
        // Simulate network call with timeout
        std::thread::sleep(Duration::from_millis(10));
        
        // For testing purposes, assume healthy if URL contains "health"
        Ok(url.contains("health") || url.contains("/"))
    }
}

impl fmt::Display for LoadBalancingStrategy {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            LoadBalancingStrategy::RoundRobin => write!(f, "Round Robin"),
            LoadBalancingStrategy::WeightedRoundRobin => write!(f, "Weighted Round Robin"),
            LoadBalancingStrategy::LeastConnections => write!(f, "Least Connections"),
            LoadBalancingStrategy::WeightedLeastConnections => write!(f, "Weighted Least Connections"),
            LoadBalancingStrategy::Random => write!(f, "Random"),
            LoadBalancingStrategy::WeightedRandom => write!(f, "Weighted Random"),
            LoadBalancingStrategy::IpHash => write!(f, "IP Hash"),
            LoadBalancingStrategy::ConsistentHash => write!(f, "Consistent Hash"),
            LoadBalancingStrategy::LeastResponseTime => write!(f, "Least Response Time"),
            LoadBalancingStrategy::ResourceBased => write!(f, "Resource Based"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};
    
    #[test]
    fn test_backend_creation() {
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 8080);
        let backend = Backend::new("backend1".to_string(), addr)
            .with_weight(2)
            .with_max_connections(500)
            .with_health_check("/health".to_string())
            .with_metadata("region".to_string(), "us-east-1".to_string());
        
        assert_eq!(backend.id, "backend1");
        assert_eq!(backend.weight, 2);
        assert_eq!(backend.max_connections, 500);
        assert_eq!(backend.health_check_url, Some("/health".to_string()));
        assert_eq!(backend.metadata.get("region"), Some(&"us-east-1".to_string()));
    }
    
    #[test]
    fn test_load_balancer_round_robin() {
        let config = LoadBalancerConfig {
            strategy: LoadBalancingStrategy::RoundRobin,
            ..Default::default()
        };
        
        let lb = LoadBalancer::new(config);
        
        // Add backends
        let addr1 = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 8080);
        let addr2 = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 8081);
        
        lb.add_backend(Backend::new("backend1".to_string(), addr1));
        lb.add_backend(Backend::new("backend2".to_string(), addr2));
        
        let request_info = RequestInfo {
            client_ip: "192.168.1.1".to_string(),
            session_id: None,
            hash_key: "test".to_string(),
            headers: HashMap::new(),
            path: "/test".to_string(),
            method: "GET".to_string(),
        };
        
        // Test round robin selection
        let decision1 = lb.select_backend(&request_info).unwrap();
        let decision2 = lb.select_backend(&request_info).unwrap();
        
        // Should alternate between backends
        assert_ne!(decision1.backend.id, decision2.backend.id);
    }
    
    #[test]
    fn test_consistent_hash_ring() {
        let mut ring = ConsistentHashRing::new(3);
        
        ring.add_backend("backend1");
        ring.add_backend("backend2");
        ring.add_backend("backend3");
        
        // Same key should always map to same backend
        let backend1 = ring.get_backend("test_key").unwrap();
        let backend2 = ring.get_backend("test_key").unwrap();
        assert_eq!(backend1, backend2);
        
        // Different keys might map to different backends
        let _backend3 = ring.get_backend("different_key").unwrap();
        // Note: This might be the same backend due to hash distribution
        
        // Remove a backend and test
        ring.remove_backend("backend1");
        let backend4 = ring.get_backend("test_key");
        assert!(backend4.is_some());
    }
    
    #[test]
    fn test_weighted_round_robin() {
        let mut state = WeightedRoundRobinState::new();
        state.add_backend("backend1", 1);
        state.add_backend("backend2", 2);
        state.total_weight = 3;
        
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 8080);
        let backend1 = Backend::new("backend1".to_string(), addr).with_weight(1);
        let backend2 = Backend::new("backend2".to_string(), addr).with_weight(2);
        
        let backend1_id = "backend1".to_string();
        let backend2_id = "backend2".to_string();
        let backends = vec![
            (&backend1_id, &backend1),
            (&backend2_id, &backend2),
        ];
        
        let mut backend2_count = 0;
        let mut backend1_count = 0;
        
        // backend2 should be selected more often due to higher weight
        for _ in 0..9 {
            if let Some(selected) = state.select_backend(&backends) {
                if selected == "backend2" {
                    backend2_count += 1;
                } else {
                    backend1_count += 1;
                }
            }
        }
        
        // backend2 (weight 2) should be selected twice as often as backend1 (weight 1)
        assert!(backend2_count > backend1_count);
    }
    
    #[test]
    fn test_backend_stats() {
        let mut stats = BackendStats::new();
        
        assert!(stats.is_healthy());
        assert!(stats.is_available());
        assert!(stats.can_accept_connections(1000));
        
        stats.status = BackendStatus::Unhealthy;
        assert!(!stats.is_healthy());
        assert!(!stats.is_available());
        
        stats.status = BackendStatus::Draining;
        assert!(!stats.is_healthy());
        assert!(stats.is_available());
    }
    
    #[test]
    fn test_response_time_tracker() {
        let mut tracker = ResponseTimeTracker::new(3);
        tracker.add_backend("backend1");
        
        // Record some response times
        tracker.record_response_time("backend1", Duration::from_millis(100));
        tracker.record_response_time("backend1", Duration::from_millis(200));
        tracker.record_response_time("backend1", Duration::from_millis(300));
        
        let avg = tracker.get_average_response_time("backend1").unwrap();
        assert_eq!(avg, Duration::from_millis(200));
        
        // Add one more (should remove the first due to window size)
        tracker.record_response_time("backend1", Duration::from_millis(400));
        
        let new_avg = tracker.get_average_response_time("backend1").unwrap();
        assert_eq!(new_avg, Duration::from_millis(300)); // (200 + 300 + 400) / 3
    }
}