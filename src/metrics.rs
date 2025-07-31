use std::time::{Duration, Instant};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

/// Performance metrics for HTTP requests
#[derive(Debug, Clone)]
pub struct RequestMetrics {
    pub dns_lookup_time: Option<Duration>,
    pub connect_time: Option<Duration>,
    pub tls_handshake_time: Option<Duration>,
    pub request_time: Duration,
    pub response_time: Duration,
    pub total_time: Duration,
    pub bytes_sent: usize,
    pub bytes_received: usize,
    pub redirects: usize,
}

impl RequestMetrics {
    pub fn new() -> Self {
        RequestMetrics {
            dns_lookup_time: None,
            connect_time: None,
            tls_handshake_time: None,
            request_time: Duration::from_secs(0),
            response_time: Duration::from_secs(0),
            total_time: Duration::from_secs(0),
            bytes_sent: 0,
            bytes_received: 0,
            redirects: 0,
        }
    }
}

impl Default for RequestMetrics {
    fn default() -> Self {
        Self::new()
    }
}

/// Global metrics collector for the HTTP client
#[derive(Debug)]
pub struct MetricsCollector {
    requests: Arc<Mutex<HashMap<String, Vec<RequestMetrics>>>>,
}

impl MetricsCollector {
    pub fn new() -> Self {
        MetricsCollector {
            requests: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    pub fn record_request(&self, host: &str, metrics: RequestMetrics) {
        if let Ok(mut requests) = self.requests.lock() {
            requests.entry(host.to_string()).or_insert_with(Vec::new).push(metrics);
        }
    }

    pub fn get_stats(&self, host: &str) -> Option<HostStats> {
        if let Ok(requests) = self.requests.lock() {
            if let Some(host_requests) = requests.get(host) {
                if host_requests.is_empty() {
                    return None;
                }

                let total_requests = host_requests.len();
                let total_time: Duration = host_requests.iter().map(|r| r.total_time).sum();
                let avg_time = total_time / total_requests as u32;
                
                let min_time = host_requests.iter().map(|r| r.total_time).min().unwrap_or_default();
                let max_time = host_requests.iter().map(|r| r.total_time).max().unwrap_or_default();
                
                let total_bytes_sent: usize = host_requests.iter().map(|r| r.bytes_sent).sum();
                let total_bytes_received: usize = host_requests.iter().map(|r| r.bytes_received).sum();
                
                let total_redirects: usize = host_requests.iter().map(|r| r.redirects).sum();

                return Some(HostStats {
                    total_requests,
                    avg_response_time: avg_time,
                    min_response_time: min_time,
                    max_response_time: max_time,
                    total_bytes_sent,
                    total_bytes_received,
                    total_redirects,
                });
            }
        }
        None
    }

    pub fn clear_stats(&self, host: Option<&str>) {
        if let Ok(mut requests) = self.requests.lock() {
            if let Some(host) = host {
                requests.remove(host);
            } else {
                requests.clear();
            }
        }
    }

    pub fn get_all_hosts(&self) -> Vec<String> {
        if let Ok(requests) = self.requests.lock() {
            requests.keys().cloned().collect()
        } else {
            Vec::new()
        }
    }
}

impl Default for MetricsCollector {
    fn default() -> Self {
        Self::new()
    }
}

impl Clone for MetricsCollector {
    fn clone(&self) -> Self {
        MetricsCollector {
            requests: Arc::clone(&self.requests),
        }
    }
}

/// Statistics for a specific host
#[derive(Debug, Clone)]
pub struct HostStats {
    pub total_requests: usize,
    pub avg_response_time: Duration,
    pub min_response_time: Duration,
    pub max_response_time: Duration,
    pub total_bytes_sent: usize,
    pub total_bytes_received: usize,
    pub total_redirects: usize,
}

/// Timer utility for measuring request phases
#[derive(Debug)]
pub struct RequestTimer {
    start_time: Instant,
    phase_times: HashMap<String, Duration>,
    last_phase_start: Instant,
}

impl RequestTimer {
    pub fn new() -> Self {
        let now = Instant::now();
        RequestTimer {
            start_time: now,
            phase_times: HashMap::new(),
            last_phase_start: now,
        }
    }

    pub fn mark_phase(&mut self, phase_name: &str) {
        let now = Instant::now();
        let phase_duration = now.duration_since(self.last_phase_start);
        self.phase_times.insert(phase_name.to_string(), phase_duration);
        self.last_phase_start = now;
    }

    pub fn get_phase_time(&self, phase_name: &str) -> Option<Duration> {
        self.phase_times.get(phase_name).copied()
    }

    pub fn total_time(&self) -> Duration {
        Instant::now().duration_since(self.start_time)
    }

    pub fn to_metrics(&self) -> RequestMetrics {
        RequestMetrics {
            dns_lookup_time: self.get_phase_time("dns_lookup"),
            connect_time: self.get_phase_time("connect"),
            tls_handshake_time: self.get_phase_time("tls_handshake"),
            request_time: self.get_phase_time("request").unwrap_or_default(),
            response_time: self.get_phase_time("response").unwrap_or_default(),
            total_time: self.total_time(),
            bytes_sent: 0, // These would be set externally
            bytes_received: 0,
            redirects: 0,
        }
    }
}

impl Default for RequestTimer {
    fn default() -> Self {
        Self::new()
    }
}

/// Bandwidth calculator for monitoring transfer speeds
#[derive(Debug)]
pub struct BandwidthMonitor {
    start_time: Instant,
    bytes_transferred: usize,
}

impl BandwidthMonitor {
    pub fn new() -> Self {
        BandwidthMonitor {
            start_time: Instant::now(),
            bytes_transferred: 0,
        }
    }

    pub fn add_bytes(&mut self, bytes: usize) {
        self.bytes_transferred += bytes;
    }

    pub fn bytes_per_second(&self) -> f64 {
        let elapsed = self.start_time.elapsed().as_secs_f64();
        if elapsed > 0.0 {
            self.bytes_transferred as f64 / elapsed
        } else {
            0.0
        }
    }

    pub fn megabytes_per_second(&self) -> f64 {
        self.bytes_per_second() / (1024.0 * 1024.0)
    }

    pub fn total_bytes(&self) -> usize {
        self.bytes_transferred
    }

    pub fn elapsed_time(&self) -> Duration {
        self.start_time.elapsed()
    }
}

impl Default for BandwidthMonitor {
    fn default() -> Self {
        Self::new()
    }
}