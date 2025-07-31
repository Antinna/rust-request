use crate::{Response, Result, Error};
use std::collections::HashMap;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use std::sync::{Arc, Mutex};

/// HTTP cache implementation following RFC 7234
#[derive(Debug)]
pub struct HttpCache {
    storage: Arc<Mutex<HashMap<String, CacheEntry>>>,
    max_size: usize,
    default_ttl: Duration,
}

impl HttpCache {
    pub fn new(max_size: usize, default_ttl: Duration) -> Self {
        HttpCache {
            storage: Arc::new(Mutex::new(HashMap::new())),
            max_size,
            default_ttl,
        }
    }

    pub fn get(&self, key: &str) -> Option<Response> {
        if let Ok(mut storage) = self.storage.lock() {
            if let Some(entry) = storage.get(key) {
                if entry.is_valid() {
                    entry.access_count.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    return Some(entry.response.clone());
                } else {
                    storage.remove(key);
                }
            }
        }
        None
    }

    pub fn put(&self, key: String, response: Response) -> Result<()> {
        if !self.is_cacheable(&response) {
            return Ok(());
        }

        let ttl = self.calculate_ttl(&response);
        let expires_at = Instant::now() + ttl;

        let entry = CacheEntry {
            response,
            expires_at,
            created_at: Instant::now(),
            access_count: std::sync::atomic::AtomicUsize::new(0),
            size: self.estimate_size(&key),
        };

        if let Ok(mut storage) = self.storage.lock() {
            // Evict entries if we're at capacity
            if storage.len() >= self.max_size {
                self.evict_lru(&mut storage);
            }

            storage.insert(key, entry);
        }

        Ok(())
    }

    pub fn invalidate(&self, key: &str) {
        if let Ok(mut storage) = self.storage.lock() {
            storage.remove(key);
        }
    }

    pub fn clear(&self) {
        if let Ok(mut storage) = self.storage.lock() {
            storage.clear();
        }
    }

    pub fn size(&self) -> usize {
        if let Ok(storage) = self.storage.lock() {
            storage.len()
        } else {
            0
        }
    }

    fn is_cacheable(&self, response: &Response) -> bool {
        // Check if response is cacheable based on status code
        match response.status {
            200 | 203 | 204 | 206 | 300 | 301 | 404 | 405 | 410 | 414 | 501 => {},
            _ => return false,
        }

        // Check Cache-Control headers
        if let Some(cache_control) = response.headers.get("Cache-Control") {
            if cache_control.contains("no-cache") || cache_control.contains("no-store") {
                return false;
            }
        }

        // Check for private responses
        if let Some(cache_control) = response.headers.get("Cache-Control") {
            if cache_control.contains("private") {
                return false;
            }
        }

        true
    }

    fn calculate_ttl(&self, response: &Response) -> Duration {
        // Check Cache-Control max-age
        if let Some(cache_control) = response.headers.get("Cache-Control") {
            if let Some(max_age) = extract_max_age(cache_control) {
                return Duration::from_secs(max_age);
            }
        }

        // Check Expires header
        if let Some(expires) = response.headers.get("Expires") {
            if let Ok(expires_time) = parse_http_date(expires) {
                let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
                if expires_time > now {
                    return Duration::from_secs(expires_time - now);
                }
            }
        }

        // Use default TTL
        self.default_ttl
    }

    fn estimate_size(&self, key: &str) -> usize {
        // Rough estimate of memory usage
        key.len() + 1024 // Assume ~1KB per response
    }

    fn evict_lru(&self, storage: &mut HashMap<String, CacheEntry>) {
        if storage.is_empty() {
            return;
        }

        // Find the least recently used entry
        let mut oldest_key = String::new();
        let mut oldest_time = Instant::now();

        for (key, entry) in storage.iter() {
            if entry.created_at < oldest_time {
                oldest_time = entry.created_at;
                oldest_key = key.clone();
            }
        }

        if !oldest_key.is_empty() {
            storage.remove(&oldest_key);
        }
    }
}

impl Clone for HttpCache {
    fn clone(&self) -> Self {
        HttpCache {
            storage: Arc::clone(&self.storage),
            max_size: self.max_size,
            default_ttl: self.default_ttl,
        }
    }
}

impl Default for HttpCache {
    fn default() -> Self {
        Self::new(1000, Duration::from_secs(300)) // 1000 entries, 5 minute default TTL
    }
}

#[derive(Debug)]
struct CacheEntry {
    response: Response,
    expires_at: Instant,
    created_at: Instant,
    access_count: std::sync::atomic::AtomicUsize,
    size: usize,
}

impl Clone for CacheEntry {
    fn clone(&self) -> Self {
        CacheEntry {
            response: self.response.clone(),
            expires_at: self.expires_at,
            created_at: self.created_at,
            access_count: std::sync::atomic::AtomicUsize::new(
                self.access_count.load(std::sync::atomic::Ordering::Relaxed)
            ),
            size: self.size,
        }
    }
}

impl CacheEntry {
    fn is_valid(&self) -> bool {
        Instant::now() < self.expires_at
    }
}

/// Cache key generator for HTTP requests
pub fn generate_cache_key(method: &str, url: &str, headers: &HashMap<String, String>) -> String {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};

    let mut hasher = DefaultHasher::new();
    method.hash(&mut hasher);
    url.hash(&mut hasher);

    // Include relevant headers that affect caching
    let cache_relevant_headers = ["Accept", "Accept-Encoding", "Accept-Language", "Authorization"];
    for header_name in &cache_relevant_headers {
        if let Some(value) = headers.get(*header_name) {
            header_name.hash(&mut hasher);
            value.hash(&mut hasher);
        }
    }

    format!("{:x}", hasher.finish())
}

/// Conditional request helper
pub struct ConditionalRequest {
    pub if_modified_since: Option<String>,
    pub if_none_match: Option<String>,
}

impl ConditionalRequest {
    pub fn from_cached_response(response: &Response) -> Self {
        ConditionalRequest {
            if_modified_since: response.headers.get("Last-Modified").cloned(),
            if_none_match: response.headers.get("ETag").cloned(),
        }
    }

    pub fn apply_to_headers(&self, headers: &mut HashMap<String, String>) {
        if let Some(ref last_modified) = self.if_modified_since {
            headers.insert("If-Modified-Since".to_string(), last_modified.clone());
        }
        if let Some(ref etag) = self.if_none_match {
            headers.insert("If-None-Match".to_string(), etag.clone());
        }
    }
}

/// Cache statistics
#[derive(Debug, Clone)]
pub struct CacheStats {
    pub hits: usize,
    pub misses: usize,
    pub entries: usize,
    pub hit_rate: f64,
}

impl CacheStats {
    pub fn new(hits: usize, misses: usize, entries: usize) -> Self {
        let total = hits + misses;
        let hit_rate = if total > 0 {
            hits as f64 / total as f64
        } else {
            0.0
        };

        CacheStats {
            hits,
            misses,
            entries,
            hit_rate,
        }
    }
}

// Helper functions

fn extract_max_age(cache_control: &str) -> Option<u64> {
    for directive in cache_control.split(',') {
        let directive = directive.trim();
        if let Some(max_age_str) = directive.strip_prefix("max-age=") {
            if let Ok(max_age) = max_age_str.parse::<u64>() {
                return Some(max_age);
            }
        }
    }
    None
}

fn parse_http_date(_date_str: &str) -> Result<u64> {
    // Simplified HTTP date parsing
    // In a real implementation, this would handle all HTTP date formats
    // RFC 1123, RFC 850, and asctime() formats
    
    // For now, we'll just return an error to use default TTL
    Err(Error::InvalidResponse("Date parsing not implemented".to_string()))
}

/// Memory-based cache storage
#[derive(Debug)]
pub struct MemoryCache {
    cache: HttpCache,
    stats: Arc<Mutex<(usize, usize)>>, // (hits, misses)
}

impl MemoryCache {
    pub fn new(max_size: usize, default_ttl: Duration) -> Self {
        MemoryCache {
            cache: HttpCache::new(max_size, default_ttl),
            stats: Arc::new(Mutex::new((0, 0))),
        }
    }

    pub fn get(&self, key: &str) -> Option<Response> {
        if let Some(response) = self.cache.get(key) {
            if let Ok(mut stats) = self.stats.lock() {
                stats.0 += 1; // hits
            }
            Some(response)
        } else {
            if let Ok(mut stats) = self.stats.lock() {
                stats.1 += 1; // misses
            }
            None
        }
    }

    pub fn put(&self, key: String, response: Response) -> Result<()> {
        self.cache.put(key, response)
    }

    pub fn stats(&self) -> CacheStats {
        if let Ok(stats) = self.stats.lock() {
            CacheStats::new(stats.0, stats.1, self.cache.size())
        } else {
            CacheStats::new(0, 0, 0)
        }
    }

    pub fn clear_stats(&self) {
        if let Ok(mut stats) = self.stats.lock() {
            *stats = (0, 0);
        }
    }
}

impl Clone for MemoryCache {
    fn clone(&self) -> Self {
        MemoryCache {
            cache: self.cache.clone(),
            stats: Arc::clone(&self.stats),
        }
    }
}

impl Default for MemoryCache {
    fn default() -> Self {
        Self::new(1000, Duration::from_secs(300))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Response;
    use std::collections::HashMap;

    #[test]
    fn test_cache_key_generation() {
        let headers = HashMap::new();
        let key1 = generate_cache_key("GET", "http://example.com", &headers);
        let key2 = generate_cache_key("GET", "http://example.com", &headers);
        let key3 = generate_cache_key("POST", "http://example.com", &headers);
        
        assert_eq!(key1, key2);
        assert_ne!(key1, key3);
    }

    #[test]
    fn test_cache_operations() {
        let cache = HttpCache::new(10, Duration::from_secs(60));
        
        let response = Response {
            status: 200,
            status_text: "OK".to_string(),
            headers: HashMap::new(),
            body: b"test".to_vec(),
            version: crate::Version::Http11,
            url: crate::Url::parse("http://example.com").unwrap(),
            remote_addr: None,
            elapsed: Duration::from_millis(100),
            cookies: Vec::new(),
        };

        let key = "test_key".to_string();
        cache.put(key.clone(), response.clone()).unwrap();
        
        let cached = cache.get(&key);
        assert!(cached.is_some());
        assert_eq!(cached.unwrap().body, response.body);
    }

    #[test]
    fn test_cache_expiration() {
        let cache = HttpCache::new(10, Duration::from_millis(1));
        
        let response = Response {
            status: 200,
            status_text: "OK".to_string(),
            headers: HashMap::new(),
            body: b"test".to_vec(),
            version: crate::Version::Http11,
            url: crate::Url::parse("http://example.com").unwrap(),
            remote_addr: None,
            elapsed: Duration::from_millis(100),
            cookies: Vec::new(),
        };

        let key = "test_key".to_string();
        cache.put(key.clone(), response).unwrap();
        
        // Wait for expiration
        std::thread::sleep(Duration::from_millis(10));
        
        let cached = cache.get(&key);
        assert!(cached.is_none());
    }
}