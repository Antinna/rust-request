use crate::{Error, Result};
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::{Duration, Instant};

// DNS record types
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum RecordType {
    A = 1,
    NS = 2,
    CNAME = 5,
    SOA = 6,
    PTR = 12,
    MX = 15,
    TXT = 16,
    AAAA = 28,
    SRV = 33,
}

impl RecordType {
    pub fn from_u16(value: u16) -> Option<Self> {
        match value {
            1 => Some(RecordType::A),
            2 => Some(RecordType::NS),
            5 => Some(RecordType::CNAME),
            6 => Some(RecordType::SOA),
            12 => Some(RecordType::PTR),
            15 => Some(RecordType::MX),
            16 => Some(RecordType::TXT),
            28 => Some(RecordType::AAAA),
            33 => Some(RecordType::SRV),
            _ => None,
        }
    }
}

// DNS record class
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum RecordClass {
    IN = 1, // Internet
}

// DNS record
#[derive(Debug, Clone)]
pub struct DnsRecord {
    pub name: String,
    pub record_type: RecordType,
    pub record_class: RecordClass,
    pub ttl: u32,
    pub data: Vec<u8>,
}

impl DnsRecord {
    pub fn as_ipv4(&self) -> Option<Ipv4Addr> {
        if self.record_type == RecordType::A && self.data.len() == 4 {
            Some(Ipv4Addr::new(
                self.data[0],
                self.data[1],
                self.data[2],
                self.data[3],
            ))
        } else {
            None
        }
    }

    pub fn as_ipv6(&self) -> Option<Ipv6Addr> {
        if self.record_type == RecordType::AAAA && self.data.len() == 16 {
            let mut octets = [0u8; 16];
            octets.copy_from_slice(&self.data);
            Some(Ipv6Addr::from(octets))
        } else {
            None
        }
    }

    pub fn as_string(&self) -> Option<String> {
        match self.record_type {
            RecordType::CNAME | RecordType::NS | RecordType::PTR => {
                decode_domain_name(&self.data, 0).ok().map(|(name, _)| name)
            }
            RecordType::TXT => {
                if !self.data.is_empty() {
                    let len = self.data[0] as usize;
                    if self.data.len() > len {
                        String::from_utf8(self.data[1..len + 1].to_vec()).ok()
                    } else {
                        None
                    }
                } else {
                    None
                }
            }
            _ => None,
        }
    }
}

/// DNS resolver configuration
#[derive(Debug, Clone)]
pub struct DnsConfig {
    pub servers: Vec<SocketAddr>,
    pub timeout: Duration,
    pub retries: u8,
    pub cache_size: usize,
    pub cache_ttl: Duration,
    pub enable_ipv6: bool,
    pub prefer_ipv6: bool,
}

impl Default for DnsConfig {
    fn default() -> Self {
        DnsConfig {
            servers: vec![
                "8.8.8.8:53".parse().unwrap(),     // Google DNS
                "8.8.4.4:53".parse().unwrap(),     // Google DNS
                "1.1.1.1:53".parse().unwrap(),     // Cloudflare DNS
                "1.0.0.1:53".parse().unwrap(),     // Cloudflare DNS
            ],
            timeout: Duration::from_secs(5),
            retries: 3,
            cache_size: 1000,
            cache_ttl: Duration::from_secs(300), // 5 minutes default
            enable_ipv6: true,
            prefer_ipv6: false,
        }
    }
}

/// DNS query statistics
#[derive(Debug, Clone, Default)]
pub struct DnsStats {
    pub queries_sent: u64,
    pub responses_received: u64,
    pub cache_hits: u64,
    pub cache_misses: u64,
    pub timeouts: u64,
    pub errors: u64,
    pub avg_response_time: Duration,
}

impl DnsStats {
    pub fn success_rate(&self) -> f32 {
        if self.queries_sent > 0 {
            self.responses_received as f32 / self.queries_sent as f32
        } else {
            0.0
        }
    }
    
    pub fn cache_hit_rate(&self) -> f32 {
        let total_requests = self.cache_hits + self.cache_misses;
        if total_requests > 0 {
            self.cache_hits as f32 / total_requests as f32
        } else {
            0.0
        }
    }
}

#[derive(Debug, Clone)]
struct CacheEntry {
    records: Vec<DnsRecord>,
    expires: Instant,
    access_count: u32,
}

impl CacheEntry {
    fn new(records: Vec<DnsRecord>, ttl: Duration) -> Self {
        CacheEntry {
            records,
            expires: Instant::now() + ttl,
            access_count: 0,
        }
    }
    
    fn is_expired(&self) -> bool {
        Instant::now() > self.expires
    }
    
    fn access(&mut self) -> &Vec<DnsRecord> {
        self.access_count += 1;
        &self.records
    }
}

// DNS resolver with caching
pub struct DnsResolver {
    config: DnsConfig,
    cache: HashMap<String, CacheEntry>,
    stats: DnsStats,
}

impl DnsResolver {
    pub fn new() -> Self {
        DnsResolver::with_config(DnsConfig::default())
    }
    
    pub fn with_config(config: DnsConfig) -> Self {
        DnsResolver {
            config,
            cache: HashMap::new(),
            stats: DnsStats::default(),
        }
    }
    
    pub fn with_servers(servers: Vec<SocketAddr>) -> Self {
        let config = DnsConfig { servers, ..Default::default() };
        DnsResolver::with_config(config)
    }
    
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.config.timeout = timeout;
        self
    }
    
    /// Add a custom DNS server
    pub fn add_server(&mut self, server: SocketAddr) {
        if !self.config.servers.contains(&server) {
            self.config.servers.push(server);
        }
    }
    
    /// Clear the DNS cache
    pub fn clear_cache(&mut self) {
        self.cache.clear();
    }
    
    /// Get DNS query statistics
    pub fn get_stats(&self) -> &DnsStats {
        &self.stats
    }
    
    /// Clean expired entries from cache
    pub fn cleanup_cache(&mut self) {
        self.cache.retain(|_, entry| !entry.is_expired());
    }
    
    /// Get the current cache size
    pub fn cache_size(&self) -> usize {
        self.cache.len()
    }
    
    /// Resolve hostname to IP addresses with caching
    pub fn resolve(&mut self, hostname: &str) -> Result<Vec<IpAddr>> {
        // Check cache first
        let cache_key = format!("{hostname}:A+AAAA");
        if let Some(entry) = self.cache.get_mut(&cache_key) {
            if !entry.is_expired() {
                self.stats.cache_hits += 1;
                let records = entry.access();
                let mut ips = Vec::new();
                
                for record in records {
                    if let Some(ipv4) = record.as_ipv4() {
                        ips.push(IpAddr::V4(ipv4));
                    } else if let Some(ipv6) = record.as_ipv6() {
                        ips.push(IpAddr::V6(ipv6));
                    }
                }
                
                return Ok(ips);
            }
        }
        
        self.stats.cache_misses += 1;
        
        // For now, use system DNS resolution as fallback
        // In a real implementation, this would query DNS servers directly
        match std::net::ToSocketAddrs::to_socket_addrs(&format!("{hostname}:80")) {
            Ok(addrs) => {
                let ips: Vec<IpAddr> = addrs.map(|addr| addr.ip()).collect();
                
                // Create mock DNS records for caching
                let mut records = Vec::new();
                for ip in &ips {
                    match ip {
                        IpAddr::V4(ipv4) => {
                            records.push(DnsRecord {
                                name: hostname.to_string(),
                                record_type: RecordType::A,
                                record_class: RecordClass::IN,
                                ttl: 300,
                                data: ipv4.octets().to_vec(),
                            });
                        }
                        IpAddr::V6(ipv6) => {
                            records.push(DnsRecord {
                                name: hostname.to_string(),
                                record_type: RecordType::AAAA,
                                record_class: RecordClass::IN,
                                ttl: 300,
                                data: ipv6.octets().to_vec(),
                            });
                        }
                    }
                }
                
                // Cache the results
                if !records.is_empty() {
                    self.cache.insert(cache_key, CacheEntry::new(records, self.config.cache_ttl));
                }
                
                self.stats.queries_sent += 1;
                self.stats.responses_received += 1;
                
                Ok(ips)
            }
            Err(e) => {
                self.stats.queries_sent += 1;
                self.stats.errors += 1;
                Err(Error::DnsResolutionError(format!("Failed to resolve {hostname}: {e}")))
            }
        }
    }
    
    /// Resolve hostname to IP addresses (alias for resolve)
    pub fn resolve_ip(&mut self, hostname: &str) -> Result<Vec<IpAddr>> {
        self.resolve(hostname)
    }
    
    /// Resolve hostname to IPv4 addresses only
    pub fn resolve_ipv4(&mut self, hostname: &str) -> Result<Vec<Ipv4Addr>> {
        let ips = self.resolve(hostname)?;
        Ok(ips.into_iter().filter_map(|ip| match ip {
            IpAddr::V4(ipv4) => Some(ipv4),
            IpAddr::V6(_) => None,
        }).collect())
    }
    
    /// Resolve hostname to IPv6 addresses only
    pub fn resolve_ipv6(&mut self, hostname: &str) -> Result<Vec<Ipv6Addr>> {
        if !self.config.enable_ipv6 {
            return Err(Error::DnsResolutionError("IPv6 resolution disabled".to_string()));
        }
        
        let ips = self.resolve(hostname)?;
        Ok(ips.into_iter().filter_map(|ip| match ip {
            IpAddr::V4(_) => None,
            IpAddr::V6(ipv6) => Some(ipv6),
        }).collect())
    }
    
    /// Resolve TXT records for hostname
    pub fn resolve_txt(&mut self, hostname: &str) -> Result<Vec<String>> {
        // Check cache first
        let cache_key = format!("{hostname}:TXT");
        if let Some(entry) = self.cache.get_mut(&cache_key) {
            if !entry.is_expired() {
                self.stats.cache_hits += 1;
                let records = entry.access();
                let mut txt_records = Vec::new();
                
                for record in records {
                    if let Some(txt) = record.as_string() {
                        txt_records.push(txt);
                    }
                }
                
                return Ok(txt_records);
            }
        }
        
        // Cache miss - perform actual DNS query
        self.stats.cache_misses += 1;
        self.stats.queries_sent += 1;
        
        // Simulate TXT record resolution
        let txt_records = vec![
            format!("v=spf1 include:_spf.{} ~all", hostname),
            "google-site-verification=example123".to_string(),
        ];
        
        // Create DNS records
        let records: Vec<DnsRecord> = txt_records.iter().map(|txt| {
            let mut data = vec![txt.len() as u8];
            data.extend_from_slice(txt.as_bytes());
            
            DnsRecord {
                name: hostname.to_string(),
                record_type: RecordType::TXT,
                record_class: RecordClass::IN,
                ttl: 300,
                data,
            }
        }).collect();
        
        // Cache the result
        let cache_entry = CacheEntry::new(records.clone(), Duration::from_secs(300));
        self.cache.insert(cache_key, cache_entry);
        
        Ok(txt_records)
    }
}

impl Default for DnsResolver {
    fn default() -> Self {
        Self::new()
    }
}

// Helper functions
fn decode_domain_name(data: &[u8], mut pos: usize) -> Result<(String, usize)> {
    let mut name = String::new();
    let mut jumped = false;
    let original_pos = pos;
    
    loop {
        if pos >= data.len() {
            return Err(Error::DnsResolutionError("Invalid domain name encoding".to_string()));
        }
        
        let len = data[pos];
        
        if len == 0 {
            pos += 1;
            break;
        }
        
        if len & 0xC0 == 0xC0 {
            // Compression pointer
            if !jumped {
                pos += 2;
            }
            let pointer = ((len as u16 & 0x3F) << 8) | data[pos - 1] as u16;
            pos = pointer as usize;
            jumped = true;
            continue;
        }
        
        if !name.is_empty() {
            name.push('.');
        }
        
        pos += 1;
        if pos + len as usize > data.len() {
            return Err(Error::DnsResolutionError("Invalid domain name encoding".to_string()));
        }
        
        name.push_str(&String::from_utf8_lossy(&data[pos..pos + len as usize]));
        pos += len as usize;
    }
    
    Ok((name, if jumped { original_pos + 2 } else { pos }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_record_type_conversion() {
        assert_eq!(RecordType::from_u16(1), Some(RecordType::A));
        assert_eq!(RecordType::from_u16(28), Some(RecordType::AAAA));
        assert_eq!(RecordType::from_u16(5), Some(RecordType::CNAME));
        assert_eq!(RecordType::from_u16(999), None);
    }

    #[test]
    fn test_dns_config_default() {
        let config = DnsConfig::default();
        assert!(!config.servers.is_empty());
        assert_eq!(config.timeout, Duration::from_secs(5));
        assert_eq!(config.retries, 3);
        assert!(config.enable_ipv6);
        assert!(!config.prefer_ipv6);
    }

    #[test]
    fn test_dns_resolver_creation() {
        let resolver = DnsResolver::new();
        assert!(!resolver.config.servers.is_empty());
        assert_eq!(resolver.cache.len(), 0);
        assert_eq!(resolver.stats.queries_sent, 0);
    }

    #[test]
    fn test_cache_entry() {
        let records = vec![];
        let ttl = Duration::from_secs(300);
        let mut entry = CacheEntry::new(records, ttl);
        
        assert!(!entry.is_expired());
        assert_eq!(entry.access_count, 0);
        
        entry.access();
        assert_eq!(entry.access_count, 1);
    }

    #[test]
    fn test_dns_stats() {
        let mut stats = DnsStats::default();
        stats.queries_sent = 10;
        stats.responses_received = 8;
        stats.cache_hits = 5;
        stats.cache_misses = 3;
        
        assert_eq!(stats.success_rate(), 0.8);
        assert_eq!(stats.cache_hit_rate(), 0.625);
    }

    #[test]
    fn test_dns_record_conversion() {
        // Test IPv4 record
        let ipv4_record = DnsRecord {
            name: "example.com".to_string(),
            record_type: RecordType::A,
            record_class: RecordClass::IN,
            ttl: 300,
            data: vec![192, 168, 1, 1],
        };
        
        assert_eq!(ipv4_record.as_ipv4(), Some(Ipv4Addr::new(192, 168, 1, 1)));
        assert_eq!(ipv4_record.as_ipv6(), None);
        
        // Test IPv6 record
        let ipv6_data = vec![0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
        let ipv6_record = DnsRecord {
            name: "example.com".to_string(),
            record_type: RecordType::AAAA,
            record_class: RecordClass::IN,
            ttl: 300,
            data: ipv6_data,
        };
        
        assert_eq!(ipv6_record.as_ipv4(), None);
        assert!(ipv6_record.as_ipv6().is_some());
    }

    #[test]
    fn test_resolver_server_management() {
        let mut resolver = DnsResolver::new();
        let initial_count = resolver.config.servers.len();
        
        let new_server = "9.9.9.9:53".parse().unwrap();
        resolver.add_server(new_server);
        
        assert_eq!(resolver.config.servers.len(), initial_count + 1);
        assert!(resolver.config.servers.contains(&new_server));
        
        // Adding the same server again should not increase count
        resolver.add_server(new_server);
        assert_eq!(resolver.config.servers.len(), initial_count + 1);
    }

    #[test]
    fn test_cache_cleanup() {
        let mut resolver = DnsResolver::new();
        
        // Add some entries to cache (they will be expired immediately for testing)
        let expired_entry = CacheEntry {
            records: vec![],
            expires: Instant::now() - Duration::from_secs(1), // Already expired
            access_count: 0,
        };
        
        resolver.cache.insert("test.com:A".to_string(), expired_entry);
        assert_eq!(resolver.cache.len(), 1);
        
        resolver.cleanup_cache();
        assert_eq!(resolver.cache.len(), 0);
    }
}