//! Advanced caching strategies and implementations
//! 
//! This module provides sophisticated caching mechanisms including multi-level caching,
//! cache warming, intelligent eviction policies, and distributed caching support.

use std::collections::{HashMap, BTreeMap};
use std::time::{Duration, Instant};
use std::sync::{Arc, RwLock, Mutex};
// Removed unused imports

/// Advanced multi-level cache system
#[derive(Debug)]
pub struct MultiLevelCache {
    l1_cache: Arc<RwLock<LRUCache>>,
    l2_cache: Arc<RwLock<LFUCache>>,
    l3_cache: Option<Arc<RwLock<dyn DistributedCache + Send + Sync>>>,
    config: CacheConfig,
    stats: Arc<Mutex<CacheStats>>,
}

/// Cache configuration
#[derive(Debug, Clone)]
pub struct CacheConfig {
    pub l1_size: usize,
    pub l2_size: usize,
    pub l3_enabled: bool,
    pub default_ttl: Duration,
    pub warming_enabled: bool,
    pub compression_enabled: bool,
    pub encryption_enabled: bool,
}

/// Cache statistics
#[derive(Debug, Clone)]
pub struct CacheStats {
    pub l1_hits: u64,
    pub l1_misses: u64,
    pub l2_hits: u64,
    pub l2_misses: u64,
    pub l3_hits: u64,
    pub l3_misses: u64,
    pub evictions: u64,
    pub warming_operations: u64,
}

/// LRU (Least Recently Used) cache implementation
#[derive(Debug)]
pub struct LRUCache {
    capacity: usize,
    data: HashMap<String, CacheEntry>,
    access_order: BTreeMap<Instant, String>,
}

/// LFU (Least Frequently Used) cache implementation
#[derive(Debug)]
pub struct LFUCache {
    capacity: usize,
    data: HashMap<String, CacheEntry>,
    frequency: HashMap<String, u64>,
    frequency_buckets: BTreeMap<u64, Vec<String>>,
    min_frequency: u64,
}

/// Cache entry with metadata
#[derive(Debug, Clone)]
pub struct CacheEntry {
    pub key: String,
    pub value: Vec<u8>,
    pub created_at: Instant,
    pub last_accessed: Instant,
    pub access_count: u64,
    pub ttl: Option<Duration>,
    pub size: usize,
    pub metadata: HashMap<String, String>,
}

/// Distributed cache trait
pub trait DistributedCache: std::fmt::Debug {
    fn get(&self, key: &str) -> Option<CacheEntry>;
    fn set(&mut self, key: String, entry: CacheEntry) -> bool;
    fn delete(&mut self, key: &str) -> bool;
    fn exists(&self, key: &str) -> bool;
    fn clear(&mut self);
    fn size(&self) -> usize;
}

/// Redis-like distributed cache implementation
#[derive(Debug)]
pub struct RedisLikeCache {
    data: HashMap<String, CacheEntry>,
    cluster_nodes: Vec<String>,
    replication_factor: usize,
    consistency_level: ConsistencyLevel,
}

impl RedisLikeCache {
    pub fn new(cluster_nodes: Vec<String>, replication_factor: usize, consistency_level: ConsistencyLevel) -> Self {
        RedisLikeCache {
            data: HashMap::new(),
            cluster_nodes,
            replication_factor,
            consistency_level,
        }
    }
    
    pub fn get_cluster_nodes(&self) -> &[String] {
        &self.cluster_nodes
    }
    
    pub fn get_replication_factor(&self) -> usize {
        self.replication_factor
    }
    
    pub fn get_consistency_level(&self) -> &ConsistencyLevel {
        &self.consistency_level
    }
    
    pub fn add_node(&mut self, node: String) {
        if !self.cluster_nodes.contains(&node) {
            self.cluster_nodes.push(node);
        }
    }
    
    pub fn remove_node(&mut self, node: &str) -> bool {
        if let Some(pos) = self.cluster_nodes.iter().position(|n| n == node) {
            self.cluster_nodes.remove(pos);
            true
        } else {
            false
        }
    }
    
    pub fn get_node_for_key(&self, key: &str) -> Option<&String> {
        if self.cluster_nodes.is_empty() {
            return None;
        }
        
        // Simple hash-based node selection
        let hash = self.hash_key(key);
        let index = hash % self.cluster_nodes.len();
        self.cluster_nodes.get(index)
    }
    
    fn hash_key(&self, key: &str) -> usize {
        let mut hash = 0usize;
        for byte in key.bytes() {
            hash = hash.wrapping_mul(31).wrapping_add(byte as usize);
        }
        hash
    }
}

impl DistributedCache for RedisLikeCache {
    fn get(&self, key: &str) -> Option<CacheEntry> {
        self.data.get(key).cloned()
    }
    
    fn set(&mut self, key: String, entry: CacheEntry) -> bool {
        self.data.insert(key, entry);
        true
    }
    
    fn delete(&mut self, key: &str) -> bool {
        self.data.remove(key).is_some()
    }
    
    fn exists(&self, key: &str) -> bool {
        self.data.contains_key(key)
    }
    
    fn clear(&mut self) {
        self.data.clear();
    }
    
    fn size(&self) -> usize {
        self.data.len()
    }
}

/// Consistency level for distributed operations
#[derive(Debug, Clone, PartialEq)]
pub enum ConsistencyLevel {
    Eventual,
    Strong,
    Quorum,
}

/// Cache warming system
#[derive(Debug)]
pub struct CacheWarmer {
    warming_strategies: Vec<WarmingStrategy>,
    scheduler: WarmingScheduler,
    stats: WarmingStats,
}

/// Cache warming strategy
#[derive(Debug, Clone)]
pub enum WarmingStrategy {
    Predictive(PredictiveWarming),
    Scheduled(ScheduledWarming),
    OnDemand(OnDemandWarming),
    PopularityBased(PopularityWarming),
}

/// Predictive cache warming
#[derive(Debug, Clone)]
pub struct PredictiveWarming {
    pub prediction_model: PredictionModel,
    pub confidence_threshold: f64,
    pub warming_window: Duration,
}

/// Prediction model for cache warming
#[derive(Debug, Clone)]
pub enum PredictionModel {
    LinearRegression,
    MovingAverage,
    ExponentialSmoothing,
    MachineLearning,
}

/// Scheduled cache warming
#[derive(Debug, Clone)]
pub struct ScheduledWarming {
    pub schedule: CronSchedule,
    pub keys_to_warm: Vec<String>,
    pub batch_size: usize,
}

/// On-demand cache warming
#[derive(Debug, Clone)]
pub struct OnDemandWarming {
    pub trigger_threshold: f64, // Miss rate threshold
    pub warming_batch_size: usize,
    pub max_warming_time: Duration,
}

/// Popularity-based cache warming
#[derive(Debug, Clone)]
pub struct PopularityWarming {
    pub popularity_window: Duration,
    pub min_access_count: u64,
    pub warming_percentage: f64,
}

/// Cron-like schedule
#[derive(Debug, Clone)]
pub struct CronSchedule {
    pub minute: String,
    pub hour: String,
    pub day: String,
    pub month: String,
    pub weekday: String,
}

/// Cache warming scheduler
#[derive(Debug)]
pub struct WarmingScheduler {
    scheduled_tasks: Vec<ScheduledTask>,
    running_tasks: HashMap<String, TaskHandle>,
}

/// Scheduled warming task
#[derive(Debug)]
pub struct ScheduledTask {
    pub id: String,
    pub strategy: WarmingStrategy,
    pub next_run: Instant,
    pub interval: Duration,
    pub enabled: bool,
}

/// Task handle for running warming operations
#[derive(Debug)]
pub struct TaskHandle {
    pub task_id: String,
    pub started_at: Instant,
    pub progress: f64,
    pub status: TaskStatus,
}

/// Task execution status
#[derive(Debug, Clone, PartialEq)]
pub enum TaskStatus {
    Running,
    Completed,
    Failed(String),
    Cancelled,
}

/// Cache warming statistics
#[derive(Debug, Clone)]
pub struct WarmingStats {
    pub total_warming_operations: u64,
    pub successful_warmings: u64,
    pub failed_warmings: u64,
    pub average_warming_time: Duration,
    pub cache_hit_improvement: f64,
}

/// Intelligent cache eviction policies
#[derive(Debug)]
pub struct EvictionPolicy {
    policy_type: EvictionPolicyType,
    config: EvictionConfig,
}

/// Eviction policy types
#[derive(Debug, Clone, PartialEq)]
pub enum EvictionPolicyType {
    LRU,
    LFU,
    FIFO,
    Random,
    TTL,
    Adaptive,
    CostBased,
}

/// Eviction configuration
#[derive(Debug, Clone)]
pub struct EvictionConfig {
    pub high_water_mark: f64, // Percentage of capacity
    pub low_water_mark: f64,
    pub batch_size: usize,
    pub cost_function: CostFunction,
}

/// Cost function for cache entries
#[derive(Debug, Clone)]
pub enum CostFunction {
    Size,
    AccessFrequency,
    RetrievalCost,
    BusinessValue,
    Composite(Vec<(CostFunction, f64)>), // Weighted combination
}

impl EvictionPolicy {
    pub fn new(policy_type: EvictionPolicyType, config: EvictionConfig) -> Self {
        EvictionPolicy {
            policy_type,
            config,
        }
    }
    
    pub fn get_policy_type(&self) -> &EvictionPolicyType {
        &self.policy_type
    }
    
    pub fn get_config(&self) -> &EvictionConfig {
        &self.config
    }
    
    pub fn should_evict(&self, cache_size: usize, capacity: usize) -> bool {
        let usage_ratio = cache_size as f64 / capacity as f64;
        usage_ratio >= self.config.high_water_mark
    }
    
    pub fn calculate_eviction_count(&self, cache_size: usize, capacity: usize) -> usize {
        if !self.should_evict(cache_size, capacity) {
            return 0;
        }
        
        let target_size = (capacity as f64 * self.config.low_water_mark) as usize;
        cache_size.saturating_sub(target_size).min(self.config.batch_size)
    }
    
    pub fn select_eviction_candidates(&self, entries: &[CacheEntry]) -> Vec<usize> {
        match self.policy_type {
            EvictionPolicyType::LRU => self.select_lru_candidates(entries),
            EvictionPolicyType::LFU => self.select_lfu_candidates(entries),
            EvictionPolicyType::FIFO => self.select_fifo_candidates(entries),
            EvictionPolicyType::Random => self.select_random_candidates(entries),
            EvictionPolicyType::TTL => self.select_ttl_candidates(entries),
            EvictionPolicyType::Adaptive => self.select_adaptive_candidates(entries),
            EvictionPolicyType::CostBased => self.select_cost_based_candidates(entries),
        }
    }
    
    fn select_lru_candidates(&self, entries: &[CacheEntry]) -> Vec<usize> {
        let mut indexed_entries: Vec<(usize, &CacheEntry)> = entries.iter().enumerate().collect();
        indexed_entries.sort_by_key(|(_, entry)| entry.last_accessed);
        indexed_entries.into_iter().take(self.config.batch_size).map(|(i, _)| i).collect()
    }
    
    fn select_lfu_candidates(&self, entries: &[CacheEntry]) -> Vec<usize> {
        let mut indexed_entries: Vec<(usize, &CacheEntry)> = entries.iter().enumerate().collect();
        indexed_entries.sort_by_key(|(_, entry)| entry.access_count);
        indexed_entries.into_iter().take(self.config.batch_size).map(|(i, _)| i).collect()
    }
    
    fn select_fifo_candidates(&self, entries: &[CacheEntry]) -> Vec<usize> {
        let mut indexed_entries: Vec<(usize, &CacheEntry)> = entries.iter().enumerate().collect();
        indexed_entries.sort_by_key(|(_, entry)| entry.created_at);
        indexed_entries.into_iter().take(self.config.batch_size).map(|(i, _)| i).collect()
    }
    
    fn select_random_candidates(&self, entries: &[CacheEntry]) -> Vec<usize> {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};
        
        let mut candidates: Vec<usize> = (0..entries.len()).collect();
        // Simple shuffle using hash
        candidates.sort_by_key(|&i| {
            let mut hasher = DefaultHasher::new();
            i.hash(&mut hasher);
            hasher.finish()
        });
        candidates.into_iter().take(self.config.batch_size).collect()
    }
    
    fn select_ttl_candidates(&self, entries: &[CacheEntry]) -> Vec<usize> {
        let now = Instant::now();
        let mut indexed_entries: Vec<(usize, &CacheEntry)> = entries.iter().enumerate().collect();
        indexed_entries.sort_by_key(|(_, entry)| {
            entry.ttl.map(|ttl| {
                let expires_at = entry.created_at + ttl;
                if now >= expires_at {
                    Duration::ZERO
                } else {
                    expires_at - now
                }
            }).unwrap_or(Duration::MAX)
        });
        indexed_entries.into_iter().take(self.config.batch_size).map(|(i, _)| i).collect()
    }
    
    fn select_adaptive_candidates(&self, entries: &[CacheEntry]) -> Vec<usize> {
        // Adaptive policy combines multiple factors
        let mut scored_entries: Vec<(usize, f64)> = entries.iter().enumerate().map(|(i, entry)| {
            let age_score = entry.created_at.elapsed().as_secs() as f64;
            let access_score = 1.0 / (entry.access_count as f64 + 1.0);
            let size_score = entry.size as f64;
            let combined_score = age_score * 0.4 + access_score * 0.4 + size_score * 0.2;
            (i, combined_score)
        }).collect();
        
        scored_entries.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap());
        scored_entries.into_iter().take(self.config.batch_size).map(|(i, _)| i).collect()
    }
    
    fn select_cost_based_candidates(&self, entries: &[CacheEntry]) -> Vec<usize> {
        let mut scored_entries: Vec<(usize, f64)> = entries.iter().enumerate().map(|(i, entry)| {
            let cost = self.calculate_entry_cost(entry);
            (i, cost)
        }).collect();
        
        scored_entries.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap());
        scored_entries.into_iter().take(self.config.batch_size).map(|(i, _)| i).collect()
    }
    
    fn calculate_entry_cost(&self, entry: &CacheEntry) -> f64 {
        match &self.config.cost_function {
            CostFunction::Size => entry.size as f64,
            CostFunction::AccessFrequency => 1.0 / (entry.access_count as f64 + 1.0),
            CostFunction::RetrievalCost => entry.created_at.elapsed().as_secs() as f64,
            CostFunction::BusinessValue => {
                entry.metadata.get("priority")
                    .and_then(|p| p.parse::<f64>().ok())
                    .unwrap_or(1.0)
            }
            CostFunction::Composite(functions) => {
                functions.iter().map(|(func, weight)| {
                    self.calculate_single_cost(func, entry) * weight
                }).sum()
            }
        }
    }
    
    fn calculate_single_cost(&self, cost_function: &CostFunction, entry: &CacheEntry) -> f64 {
        match cost_function {
            CostFunction::Size => entry.size as f64,
            CostFunction::AccessFrequency => 1.0 / (entry.access_count as f64 + 1.0),
            CostFunction::RetrievalCost => entry.created_at.elapsed().as_secs() as f64,
            CostFunction::BusinessValue => {
                entry.metadata.get("priority")
                    .and_then(|p| p.parse::<f64>().ok())
                    .unwrap_or(1.0)
            }
            CostFunction::Composite(_) => 1.0, // Avoid infinite recursion
        }
    }
}

/// Cache compression system
#[derive(Debug)]
pub struct CacheCompression {
    algorithm: CompressionAlgorithm,
    compression_threshold: usize,
    stats: CompressionStats,
}

impl CacheCompression {
    pub fn new(algorithm: CompressionAlgorithm, threshold: usize) -> Self {
        CacheCompression {
            algorithm,
            compression_threshold: threshold,
            stats: CompressionStats::new(),
        }
    }
    
    pub fn get_algorithm(&self) -> &CompressionAlgorithm {
        &self.algorithm
    }
    
    pub fn get_threshold(&self) -> usize {
        self.compression_threshold
    }
    
    pub fn get_stats(&self) -> &CompressionStats {
        &self.stats
    }
    
    pub fn should_compress(&self, data_size: usize) -> bool {
        data_size >= self.compression_threshold
    }
    
    pub fn compress(&mut self, data: &[u8]) -> Result<Vec<u8>, String> {
        if !self.should_compress(data.len()) {
            return Ok(data.to_vec());
        }
        
        let start_time = Instant::now();
        let compressed = match self.algorithm {
            CompressionAlgorithm::Gzip => {
                // Simulate gzip compression (simplified)
                let compressed_size = (data.len() as f64 * 0.7) as usize;
                vec![0u8; compressed_size]
            }
            CompressionAlgorithm::Lz4 => {
                // Simulate LZ4 compression (simplified)
                let compressed_size = (data.len() as f64 * 0.8) as usize;
                vec![0u8; compressed_size]
            }
            CompressionAlgorithm::Snappy => {
                // Simulate Snappy compression (simplified)
                let compressed_size = (data.len() as f64 * 0.75) as usize;
                vec![0u8; compressed_size]
            }
            CompressionAlgorithm::Zstd => {
                // Simulate Zstd compression (simplified)
                let compressed_size = (data.len() as f64 * 0.65) as usize;
                vec![0u8; compressed_size]
            }
        };
        
        let compression_time = start_time.elapsed();
        self.stats.compression_time = 
            (self.stats.compression_time + compression_time) / 2;
        
        self.stats.record_compression(data.len(), compressed.len());
        Ok(compressed)
    }
    
    pub fn decompress(&mut self, compressed_data: &[u8], original_size: usize) -> Result<Vec<u8>, String> {
        let start_time = Instant::now();
        let decompressed = vec![0u8; original_size]; // Simplified decompression
        
        let decompression_time = start_time.elapsed();
        self.stats.decompression_time = 
            (self.stats.decompression_time + decompression_time) / 2;
        
        self.stats.record_decompression(compressed_data.len(), original_size);
        Ok(decompressed)
    }
}

/// Compression algorithms
#[derive(Debug, Clone, PartialEq)]
pub enum CompressionAlgorithm {
    Gzip,
    Lz4,
    Snappy,
    Zstd,
}

/// Compression statistics
#[derive(Debug, Clone)]
pub struct CompressionStats {
    pub compressed_entries: u64,
    pub original_size: u64,
    pub compressed_size: u64,
    pub compression_ratio: f64,
    pub compression_time: Duration,
    pub decompression_time: Duration,
}

impl CompressionStats {
    pub fn new() -> Self {
        CompressionStats {
            compressed_entries: 0,
            original_size: 0,
            compressed_size: 0,
            compression_ratio: 0.0,
            compression_time: Duration::from_millis(0),
            decompression_time: Duration::from_millis(0),
        }
    }
    
    pub fn record_compression(&mut self, original: usize, compressed: usize) {
        self.compressed_entries += 1;
        self.original_size += original as u64;
        self.compressed_size += compressed as u64;
        
        if self.original_size > 0 {
            self.compression_ratio = self.compressed_size as f64 / self.original_size as f64;
        }
    }
    
    pub fn record_decompression(&mut self, _compressed: usize, _original: usize) {
        // Record decompression statistics
        // In a real implementation, this would track decompression metrics
    }
    
    pub fn get_compression_ratio(&self) -> f64 {
        self.compression_ratio
    }
    
    pub fn get_space_saved(&self) -> u64 {
        self.original_size.saturating_sub(self.compressed_size)
    }
}

impl Default for CompressionStats {
    fn default() -> Self {
        Self::new()
    }
}

impl Default for CacheConfig {
    fn default() -> Self {
        CacheConfig {
            l1_size: 1000,
            l2_size: 10000,
            l3_enabled: false,
            default_ttl: Duration::from_secs(3600),
            warming_enabled: true,
            compression_enabled: false,
            encryption_enabled: false,
        }
    }
}

impl MultiLevelCache {
    pub fn new(config: CacheConfig) -> Self {
        MultiLevelCache {
            l1_cache: Arc::new(RwLock::new(LRUCache::new(config.l1_size))),
            l2_cache: Arc::new(RwLock::new(LFUCache::new(config.l2_size))),
            l3_cache: None,
            config,
            stats: Arc::new(Mutex::new(CacheStats::new())),
        }
    }
    
    pub fn get(&self, key: &str) -> Option<Vec<u8>> {
        let mut stats = self.stats.lock().unwrap();
        
        // Try L1 cache first
        if let Some(entry) = self.l1_cache.read().unwrap().get(key) {
            stats.l1_hits += 1;
            return Some(entry.value.clone());
        }
        stats.l1_misses += 1;
        
        // Try L2 cache
        if let Some(entry) = self.l2_cache.read().unwrap().get(key) {
            stats.l2_hits += 1;
            // Promote to L1
            self.l1_cache.write().unwrap().set(key.to_string(), entry.clone());
            return Some(entry.value.clone());
        }
        stats.l2_misses += 1;
        
        // Try L3 cache if enabled
        if let Some(ref l3) = self.l3_cache {
            if let Some(entry) = l3.read().unwrap().get(key) {
                stats.l3_hits += 1;
                // Promote to L2 and L1
                self.l2_cache.write().unwrap().set(key.to_string(), entry.clone());
                self.l1_cache.write().unwrap().set(key.to_string(), entry.clone());
                return Some(entry.value.clone());
            }
            stats.l3_misses += 1;
        }
        
        None
    }
    
    pub fn set(&self, key: String, value: Vec<u8>) {
        self.set_with_ttl(key, value, self.config.default_ttl);
    }
    
    pub fn set_with_ttl(&self, key: String, value: Vec<u8>, ttl: Duration) {
        let entry = CacheEntry {
            key: key.clone(),
            value: value.clone(),
            created_at: Instant::now(),
            last_accessed: Instant::now(),
            access_count: 1,
            ttl: Some(ttl),
            size: value.len(),
            metadata: HashMap::new(),
        };
        
        // Set in all cache levels
        self.l1_cache.write().unwrap().set(key.clone(), entry.clone());
        self.l2_cache.write().unwrap().set(key.clone(), entry.clone());
        
        if let Some(ref l3) = self.l3_cache {
            l3.write().unwrap().set(key, entry);
        }
    }
    
    pub fn delete(&self, key: &str) -> bool {
        let l1_deleted = self.l1_cache.write().unwrap().delete(key);
        let l2_deleted = self.l2_cache.write().unwrap().delete(key);
        let l3_deleted = if let Some(ref l3) = self.l3_cache {
            l3.write().unwrap().delete(key)
        } else {
            false
        };
        
        l1_deleted || l2_deleted || l3_deleted
    }
    
    pub fn get_stats(&self) -> CacheStats {
        self.stats.lock().unwrap().clone()
    }
    
    pub fn clear(&self) {
        self.l1_cache.write().unwrap().clear();
        self.l2_cache.write().unwrap().clear();
        if let Some(ref l3) = self.l3_cache {
            l3.write().unwrap().clear();
        }
        *self.stats.lock().unwrap() = CacheStats::new();
    }
}

impl LRUCache {
    pub fn new(capacity: usize) -> Self {
        LRUCache {
            capacity,
            data: HashMap::new(),
            access_order: BTreeMap::new(),
        }
    }
    
    pub fn get(&self, key: &str) -> Option<CacheEntry> {
        self.data.get(key).cloned()
    }
    
    pub fn set(&mut self, key: String, mut entry: CacheEntry) {
        // Update access time
        entry.last_accessed = Instant::now();
        entry.access_count += 1;
        
        // Remove old entry if exists
        if let Some(old_entry) = self.data.remove(&key) {
            self.access_order.remove(&old_entry.last_accessed);
        }
        
        // Add new entry
        self.access_order.insert(entry.last_accessed, key.clone());
        self.data.insert(key, entry);
        
        // Evict if over capacity
        while self.data.len() > self.capacity {
            self.evict_lru();
        }
    }
    
    pub fn delete(&mut self, key: &str) -> bool {
        if let Some(entry) = self.data.remove(key) {
            self.access_order.remove(&entry.last_accessed);
            true
        } else {
            false
        }
    }
    
    pub fn clear(&mut self) {
        self.data.clear();
        self.access_order.clear();
    }
    
    fn evict_lru(&mut self) {
        if let Some((&oldest_time, oldest_key)) = self.access_order.iter().next() {
            let oldest_key = oldest_key.clone();
            self.data.remove(&oldest_key);
            self.access_order.remove(&oldest_time);
        }
    }
}

impl LFUCache {
    pub fn new(capacity: usize) -> Self {
        LFUCache {
            capacity,
            data: HashMap::new(),
            frequency: HashMap::new(),
            frequency_buckets: BTreeMap::new(),
            min_frequency: 1,
        }
    }
    
    pub fn get(&self, key: &str) -> Option<CacheEntry> {
        self.data.get(key).cloned()
    }
    
    pub fn set(&mut self, key: String, entry: CacheEntry) {
        if self.data.len() >= self.capacity && !self.data.contains_key(&key) {
            self.evict_lfu();
        }
        
        // Update frequency
        let freq = self.frequency.get(&key).copied().unwrap_or(0) + 1;
        self.update_frequency(&key, freq);
        
        self.data.insert(key, entry);
    }
    
    pub fn delete(&mut self, key: &str) -> bool {
        if self.data.remove(key).is_some() {
            if let Some(freq) = self.frequency.remove(key) {
                self.remove_from_frequency_bucket(key, freq);
            }
            true
        } else {
            false
        }
    }
    
    pub fn clear(&mut self) {
        self.data.clear();
        self.frequency.clear();
        self.frequency_buckets.clear();
        self.min_frequency = 1;
    }
    
    fn evict_lfu(&mut self) {
        if let Some(bucket) = self.frequency_buckets.get_mut(&self.min_frequency) {
            if let Some(key) = bucket.pop() {
                self.data.remove(&key);
                self.frequency.remove(&key);
                
                if bucket.is_empty() {
                    self.frequency_buckets.remove(&self.min_frequency);
                    // Find next minimum frequency
                    self.min_frequency = self.frequency_buckets.keys().next().copied().unwrap_or(1);
                }
            }
        }
    }
    
    fn update_frequency(&mut self, key: &str, new_freq: u64) {
        // Remove from old frequency bucket
        if let Some(old_freq) = self.frequency.get(key) {
            self.remove_from_frequency_bucket(key, *old_freq);
        }
        
        // Add to new frequency bucket
        self.frequency_buckets
            .entry(new_freq)
            .or_default()
            .push(key.to_string());
        
        self.frequency.insert(key.to_string(), new_freq);
        
        // Update minimum frequency
        if new_freq < self.min_frequency {
            self.min_frequency = new_freq;
        }
    }
    
    fn remove_from_frequency_bucket(&mut self, key: &str, freq: u64) {
        if let Some(bucket) = self.frequency_buckets.get_mut(&freq) {
            bucket.retain(|k| k != key);
            if bucket.is_empty() {
                self.frequency_buckets.remove(&freq);
            }
        }
    }
}

impl CacheWarmer {
    pub fn new() -> Self {
        CacheWarmer {
            warming_strategies: Vec::new(),
            scheduler: WarmingScheduler::new(),
            stats: WarmingStats::new(),
        }
    }
    
    pub fn add_strategy(&mut self, strategy: WarmingStrategy) {
        self.warming_strategies.push(strategy);
    }
    
    pub fn warm_cache(&mut self, cache: &MultiLevelCache, keys: Vec<String>) {
        let start_time = Instant::now();
        let mut successful = 0;
        let mut failed = 0;
        
        for key in keys {
            // Simulate cache warming by fetching data
            match self.fetch_data_for_warming(&key) {
                Ok(data) => {
                    cache.set(key, data);
                    successful += 1;
                }
                Err(_) => {
                    failed += 1;
                }
            }
        }
        
        // Update stats
        self.stats.total_warming_operations += 1;
        self.stats.successful_warmings += successful;
        self.stats.failed_warmings += failed;
        
        let warming_time = start_time.elapsed();
        self.stats.average_warming_time = 
            (self.stats.average_warming_time + warming_time) / 2;
    }
    
    fn fetch_data_for_warming(&self, _key: &str) -> Result<Vec<u8>, String> {
        // Simulate data fetching
        Ok(b"warmed_data".to_vec())
    }
    
    pub fn get_stats(&self) -> WarmingStats {
        self.stats.clone()
    }
    
    pub fn get_scheduler(&self) -> &WarmingScheduler {
        &self.scheduler
    }
    
    pub fn get_scheduler_mut(&mut self) -> &mut WarmingScheduler {
        &mut self.scheduler
    }
    
    pub fn execute_scheduled_warming(&mut self, cache: &MultiLevelCache) {
        // Collect tasks to execute to avoid borrowing issues
        let now = Instant::now();
        let mut tasks_to_execute = Vec::new();
        
        for task in &self.scheduler.scheduled_tasks {
            if task.enabled && now >= task.next_run {
                match &task.strategy {
                    WarmingStrategy::Scheduled(scheduled) => {
                        tasks_to_execute.push(scheduled.keys_to_warm.clone());
                    }
                    _ => {
                        // Other strategies would be implemented here
                    }
                }
            }
        }
        
        // Execute the warming tasks
        for keys in tasks_to_execute {
            self.warm_cache(cache, keys);
        }
        
        // Update scheduler state
        self.scheduler.update_task_run_times();
    }
    
    pub fn schedule_warming_task(&mut self, task: ScheduledTask) {
        self.scheduler.schedule_task(task);
    }
    
    pub fn get_pending_tasks_count(&self) -> usize {
        self.scheduler.get_pending_tasks().len()
    }
}

impl Default for CacheWarmer {
    fn default() -> Self {
        Self::new()
    }
}

impl WarmingScheduler {
    pub fn new() -> Self {
        WarmingScheduler {
            scheduled_tasks: Vec::new(),
            running_tasks: HashMap::new(),
        }
    }
    
    pub fn schedule_task(&mut self, task: ScheduledTask) {
        self.scheduled_tasks.push(task);
    }
    
    pub fn run_scheduled_tasks(&mut self, cache: &MultiLevelCache, warmer: &mut CacheWarmer) {
        let now = Instant::now();
        let mut tasks_to_run = Vec::new();
        
        // Collect tasks that need to run
        for (index, task) in self.scheduled_tasks.iter().enumerate() {
            if task.enabled && now >= task.next_run {
                tasks_to_run.push(index);
            }
        }
        
        // Execute tasks and update their next run time
        for index in tasks_to_run {
            if index < self.scheduled_tasks.len() {
                let task_id = self.scheduled_tasks[index].id.clone();
                let strategy = self.scheduled_tasks[index].strategy.clone();
                let interval = self.scheduled_tasks[index].interval;
                
                // Execute the task
                self.execute_warming_task_by_strategy(&task_id, &strategy, cache, warmer);
                
                // Update next run time
                self.scheduled_tasks[index].next_run = now + interval;
            }
        }
    }
    
    fn execute_warming_task_by_strategy(&mut self, task_id: &str, strategy: &WarmingStrategy, cache: &MultiLevelCache, warmer: &mut CacheWarmer) {
        let handle = TaskHandle {
            task_id: task_id.to_string(),
            started_at: Instant::now(),
            progress: 0.0,
            status: TaskStatus::Running,
        };
        
        self.running_tasks.insert(task_id.to_string(), handle);
        
        // Execute warming based on strategy
        match strategy {
            WarmingStrategy::Scheduled(scheduled) => {
                warmer.warm_cache(cache, scheduled.keys_to_warm.clone());
            }
            _ => {
                // Other strategies would be implemented here
            }
        }
        
        // Mark task as completed
        if let Some(handle) = self.running_tasks.get_mut(task_id) {
            handle.status = TaskStatus::Completed;
            handle.progress = 1.0;
        }
    }
    
    pub fn get_pending_tasks(&self) -> Vec<&ScheduledTask> {
        let now = Instant::now();
        self.scheduled_tasks.iter()
            .filter(|task| task.enabled && now >= task.next_run)
            .collect()
    }
    
    pub fn update_task_run_times(&mut self) {
        let now = Instant::now();
        for task in &mut self.scheduled_tasks {
            if task.enabled && now >= task.next_run {
                task.next_run = now + task.interval;
            }
        }
    }
}

impl Default for WarmingScheduler {
    fn default() -> Self {
        Self::new()
    }
}

impl CacheStats {
    pub fn new() -> Self {
        CacheStats {
            l1_hits: 0,
            l1_misses: 0,
            l2_hits: 0,
            l2_misses: 0,
            l3_hits: 0,
            l3_misses: 0,
            evictions: 0,
            warming_operations: 0,
        }
    }
    
    pub fn total_hits(&self) -> u64 {
        self.l1_hits + self.l2_hits + self.l3_hits
    }
    
    pub fn total_misses(&self) -> u64 {
        self.l1_misses + self.l2_misses + self.l3_misses
    }
    
    pub fn hit_rate(&self) -> f64 {
        let total = self.total_hits() + self.total_misses();
        if total > 0 {
            self.total_hits() as f64 / total as f64
        } else {
            0.0
        }
    }
}

impl Default for CacheStats {
    fn default() -> Self {
        Self::new()
    }
}

impl WarmingStats {
    pub fn new() -> Self {
        WarmingStats {
            total_warming_operations: 0,
            successful_warmings: 0,
            failed_warmings: 0,
            average_warming_time: Duration::from_millis(0),
            cache_hit_improvement: 0.0,
        }
    }
}

impl Default for WarmingStats {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_multi_level_cache() {
        let cache = MultiLevelCache::new(CacheConfig::default());
        
        // Test set and get
        cache.set("key1".to_string(), b"value1".to_vec());
        assert_eq!(cache.get("key1"), Some(b"value1".to_vec()));
        
        // Test miss
        assert_eq!(cache.get("nonexistent"), None);
        
        // Test delete
        assert!(cache.delete("key1"));
        assert_eq!(cache.get("key1"), None);
    }
    
    #[test]
    fn test_lru_cache() {
        let mut cache = LRUCache::new(2);
        
        let entry1 = CacheEntry {
            key: "key1".to_string(),
            value: b"value1".to_vec(),
            created_at: Instant::now(),
            last_accessed: Instant::now(),
            access_count: 1,
            ttl: None,
            size: 6,
            metadata: HashMap::new(),
        };
        
        let entry2 = CacheEntry {
            key: "key2".to_string(),
            value: b"value2".to_vec(),
            created_at: Instant::now(),
            last_accessed: Instant::now(),
            access_count: 1,
            ttl: None,
            size: 6,
            metadata: HashMap::new(),
        };
        
        cache.set("key1".to_string(), entry1);
        cache.set("key2".to_string(), entry2);
        
        assert!(cache.get("key1").is_some());
        assert!(cache.get("key2").is_some());
        
        // Adding third entry should evict least recently used
        let entry3 = CacheEntry {
            key: "key3".to_string(),
            value: b"value3".to_vec(),
            created_at: Instant::now(),
            last_accessed: Instant::now(),
            access_count: 1,
            ttl: None,
            size: 6,
            metadata: HashMap::new(),
        };
        
        cache.set("key3".to_string(), entry3);
        
        // key1 should be evicted (least recently used)
        assert_eq!(cache.data.len(), 2);
    }
    
    #[test]
    fn test_lfu_cache() {
        let mut cache = LFUCache::new(2);
        
        let entry1 = CacheEntry {
            key: "key1".to_string(),
            value: b"value1".to_vec(),
            created_at: Instant::now(),
            last_accessed: Instant::now(),
            access_count: 1,
            ttl: None,
            size: 6,
            metadata: HashMap::new(),
        };
        
        cache.set("key1".to_string(), entry1);
        
        assert!(cache.get("key1").is_some());
        assert_eq!(cache.data.len(), 1);
    }
    
    #[test]
    fn test_cache_warmer() {
        let mut warmer = CacheWarmer::new();
        let cache = MultiLevelCache::new(CacheConfig::default());
        
        let keys = vec!["key1".to_string(), "key2".to_string()];
        warmer.warm_cache(&cache, keys);
        
        let stats = warmer.get_stats();
        assert_eq!(stats.total_warming_operations, 1);
        assert_eq!(stats.successful_warmings, 2);
    }
    
    #[test]
    fn test_cache_stats() {
        let mut stats = CacheStats::new();
        stats.l1_hits = 10;
        stats.l1_misses = 5;
        stats.l2_hits = 3;
        stats.l2_misses = 2;
        
        assert_eq!(stats.total_hits(), 13);
        assert_eq!(stats.total_misses(), 7);
        assert_eq!(stats.hit_rate(), 13.0 / 20.0);
    }
}