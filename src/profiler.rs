use crate::{Result, Error, Request, Response};
use std::time::{Duration, Instant};
use std::collections::HashMap;

fn get_memory_usage() -> usize {
    // Simplified memory usage estimation
    // In a real implementation, this would use platform-specific APIs
    std::mem::size_of::<usize>() * 1024 // Placeholder
}
use std::sync::{Arc, Mutex};


/// Advanced profiler for HTTP requests with detailed performance analysis
#[derive(Debug)]
pub struct HttpProfiler {
    profiles: Arc<Mutex<HashMap<String, ProfileData>>>,
    enabled: bool,
    sample_rate: f64,
    max_profiles: usize,
}

impl HttpProfiler {
    pub fn new() -> Self {
        HttpProfiler {
            profiles: Arc::new(Mutex::new(HashMap::new())),
            enabled: true,
            sample_rate: 1.0, // Profile 100% of requests by default
            max_profiles: 10000,
        }
    }

    pub fn enabled(mut self, enabled: bool) -> Self {
        self.enabled = enabled;
        self
    }

    pub fn sample_rate(mut self, rate: f64) -> Self {
        self.sample_rate = rate.clamp(0.0, 1.0);
        self
    }

    pub fn max_profiles(mut self, max: usize) -> Self {
        self.max_profiles = max;
        self
    }

    pub fn start_profile(&self, request: &Request) -> Option<ProfileSession> {
        if !self.enabled || !self.should_sample() {
            return None;
        }

        Some(ProfileSession::new(
            self.generate_profile_id(request),
            Arc::clone(&self.profiles),
        ))
    }

    fn should_sample(&self) -> bool {
        if self.sample_rate >= 1.0 {
            return true;
        }
        
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};
        use std::time::{SystemTime, UNIX_EPOCH};

        let mut hasher = DefaultHasher::new();
        SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos().hash(&mut hasher);
        let hash = hasher.finish();
        
        (hash as f64 / u64::MAX as f64) < self.sample_rate
    }

    fn generate_profile_id(&self, request: &Request) -> String {
        format!("{}_{}", request.method.as_str(), request.url.host)
    }

    pub fn get_profile_summary(&self, profile_id: &str) -> Option<ProfileSummary> {
        if let Ok(profiles) = self.profiles.lock() {
            profiles.get(profile_id).map(|data| data.to_summary())
        } else {
            None
        }
    }

    pub fn get_all_profiles(&self) -> Vec<(String, ProfileSummary)> {
        if let Ok(profiles) = self.profiles.lock() {
            profiles
                .iter()
                .map(|(id, data)| (id.clone(), data.to_summary()))
                .collect()
        } else {
            Vec::new()
        }
    }

    pub fn clear_profiles(&self) {
        if let Ok(mut profiles) = self.profiles.lock() {
            profiles.clear();
        }
    }

    pub fn get_performance_report(&self) -> PerformanceReport {
        if let Ok(profiles) = self.profiles.lock() {
            let mut report = PerformanceReport::new();
            
            for (_, data) in profiles.iter() {
                report.add_profile_data(data);
            }
            
            report.finalize();
            report
        } else {
            PerformanceReport::new()
        }
    }
}

impl Default for HttpProfiler {
    fn default() -> Self {
        Self::new()
    }
}

impl Clone for HttpProfiler {
    fn clone(&self) -> Self {
        HttpProfiler {
            profiles: Arc::clone(&self.profiles),
            enabled: self.enabled,
            sample_rate: self.sample_rate,
            max_profiles: self.max_profiles,
        }
    }
}

/// Profile session for tracking a single request
pub struct ProfileSession {
    profile_id: String,
    profiles: Arc<Mutex<HashMap<String, ProfileData>>>,
    start_time: Instant,
    phases: HashMap<String, PhaseData>,
    current_phase: Option<String>,
    memory_usage: MemoryTracker,
}

impl ProfileSession {
    fn new(profile_id: String, profiles: Arc<Mutex<HashMap<String, ProfileData>>>) -> Self {
        ProfileSession {
            profile_id,
            profiles,
            start_time: Instant::now(),
            phases: HashMap::new(),
            current_phase: None,
            memory_usage: MemoryTracker::new(),
        }
    }

    pub fn start_phase(&mut self, phase_name: &str) {
        if let Some(current) = self.current_phase.clone() {
            self.end_phase(&current);
        }

        self.current_phase = Some(phase_name.to_string());
        self.phases.insert(
            phase_name.to_string(),
            PhaseData {
                start_time: Instant::now(),
                end_time: None,
                memory_start: self.memory_usage.current_usage(),
                memory_peak: 0,
                cpu_usage: CpuTracker::new(),
            },
        );
    }

    pub fn end_phase(&mut self, phase_name: &str) {
        if let Some(phase) = self.phases.get_mut(phase_name) {
            phase.end_time = Some(Instant::now());
            phase.memory_peak = self.memory_usage.peak_usage();
            phase.cpu_usage.stop();
        }
        
        if self.current_phase.as_ref() == Some(&phase_name.to_string()) {
            self.current_phase = None;
        }
    }

    pub fn record_metric(&mut self, name: &str, value: f64) {
        // Record custom metrics during profiling
        if let Some(ref phase_name) = self.current_phase {
            if let Some(phase) = self.phases.get_mut(phase_name) {
                phase.cpu_usage.record_metric(name.to_string(), value);
            }
        }
    }

    pub fn finish(mut self, response: Option<&Response>) -> Result<()> {
        // End any current phase
        if let Some(ref current) = self.current_phase.clone() {
            self.end_phase(current);
        }

        let total_duration = self.start_time.elapsed();
        let profile_data = ProfileData {
            total_duration,
            phases: self.phases,
            response_status: response.map(|r| r.status),
            response_size: response.map(|r| r.body.len()),
            memory_usage: self.memory_usage.total_usage(),
            timestamp: self.start_time,
        };

        // Store the profile data
        if let Ok(mut profiles) = self.profiles.lock() {
            profiles.insert(self.profile_id, profile_data);
        }

        Ok(())
    }
}

/// Data for a single profiled request
#[derive(Debug, Clone)]
struct ProfileData {
    total_duration: Duration,
    phases: HashMap<String, PhaseData>,
    response_status: Option<u16>,
    response_size: Option<usize>,
    memory_usage: usize,
    timestamp: Instant,
}

impl ProfileData {
    fn to_summary(&self) -> ProfileSummary {
        ProfileSummary {
            total_duration: self.total_duration,
            phase_durations: self.phases
                .iter()
                .map(|(name, data)| {
                    let duration = if let Some(end) = data.end_time {
                        end.duration_since(data.start_time)
                    } else {
                        Duration::from_millis(0)
                    };
                    (name.clone(), duration)
                })
                .collect(),
            response_status: self.response_status,
            response_size: self.response_size,
            memory_usage: self.memory_usage,
            timestamp: self.timestamp,
        }
    }
}

/// Data for a single phase within a request
#[derive(Debug, Clone)]
pub struct PhaseData {
    start_time: Instant,
    end_time: Option<Instant>,
    memory_start: usize,
    memory_peak: usize,
    cpu_usage: CpuTracker,
}

impl PhaseData {
    pub fn new() -> Self {
        PhaseData {
            start_time: Instant::now(),
            end_time: None,
            memory_start: get_memory_usage(),
            memory_peak: get_memory_usage(),
            cpu_usage: CpuTracker::new(),
        }
    }
    
    pub fn finish(&mut self) {
        self.end_time = Some(Instant::now());
        self.memory_peak = self.memory_peak.max(get_memory_usage());
    }
    
    pub fn duration(&self) -> Option<Duration> {
        self.end_time.map(|end| end.duration_since(self.start_time))
    }
}

impl Default for PhaseData {
    fn default() -> Self {
        Self::new()
    }
}

impl PhaseData {
    pub fn memory_delta(&self) -> usize {
        self.memory_peak.saturating_sub(self.memory_start)
    }
    
    pub fn memory_efficiency(&self) -> f64 {
        if self.memory_start == 0 {
            return 1.0;
        }
        self.memory_start as f64 / self.memory_peak as f64
    }
}

/// Summary of a profiled request
#[derive(Debug, Clone)]
pub struct ProfileSummary {
    pub total_duration: Duration,
    pub phase_durations: HashMap<String, Duration>,
    pub response_status: Option<u16>,
    pub response_size: Option<usize>,
    pub memory_usage: usize,
    pub timestamp: Instant,
}

impl ProfileSummary {
    pub fn slowest_phase(&self) -> Option<(&String, &Duration)> {
        self.phase_durations
            .iter()
            .max_by_key(|(_, duration)| *duration)
    }

    pub fn fastest_phase(&self) -> Option<(&String, &Duration)> {
        self.phase_durations
            .iter()
            .min_by_key(|(_, duration)| *duration)
    }

    pub fn phase_percentage(&self, phase_name: &str) -> Option<f64> {
        if let Some(phase_duration) = self.phase_durations.get(phase_name) {
            let total_ms = self.total_duration.as_millis() as f64;
            let phase_ms = phase_duration.as_millis() as f64;
            Some((phase_ms / total_ms) * 100.0)
        } else {
            None
        }
    }
}

/// Performance report aggregating multiple profiles
#[derive(Debug)]
pub struct PerformanceReport {
    pub total_requests: usize,
    pub avg_duration: Duration,
    pub min_duration: Duration,
    pub max_duration: Duration,
    pub p50_duration: Duration,
    pub p95_duration: Duration,
    pub p99_duration: Duration,
    pub success_rate: f64,
    pub avg_response_size: f64,
    pub phase_breakdown: HashMap<String, PhaseStats>,
    pub status_distribution: HashMap<u16, usize>,
}

impl PerformanceReport {
    fn new() -> Self {
        PerformanceReport {
            total_requests: 0,
            avg_duration: Duration::from_millis(0),
            min_duration: Duration::from_secs(u64::MAX),
            max_duration: Duration::from_millis(0),
            p50_duration: Duration::from_millis(0),
            p95_duration: Duration::from_millis(0),
            p99_duration: Duration::from_millis(0),
            success_rate: 0.0,
            avg_response_size: 0.0,
            phase_breakdown: HashMap::new(),
            status_distribution: HashMap::new(),
        }
    }

    fn add_profile_data(&mut self, data: &ProfileData) {
        self.total_requests += 1;
        
        // Update duration stats
        if data.total_duration < self.min_duration {
            self.min_duration = data.total_duration;
        }
        if data.total_duration > self.max_duration {
            self.max_duration = data.total_duration;
        }

        // Update status distribution
        if let Some(status) = data.response_status {
            *self.status_distribution.entry(status).or_insert(0) += 1;
        }

        // Update phase breakdown
        for (phase_name, phase_data) in &data.phases {
            let phase_stats = self.phase_breakdown
                .entry(phase_name.clone())
                .or_insert_with(PhaseStats::new);
            
            if let Some(end_time) = phase_data.end_time {
                let duration = end_time.duration_since(phase_data.start_time);
                phase_stats.add_duration(duration);
            }
        }
    }

    fn finalize(&mut self) {
        if self.total_requests == 0 {
            return;
        }

        // Calculate success rate
        let successful_requests = self.status_distribution
            .iter()
            .filter(|(&status, _)| (200..400).contains(&status))
            .map(|(_, &count)| count)
            .sum::<usize>();
        
        self.success_rate = (successful_requests as f64 / self.total_requests as f64) * 100.0;

        // Finalize phase stats
        for phase_stats in self.phase_breakdown.values_mut() {
            phase_stats.finalize();
        }
    }

    pub fn print_report(&self) {
        println!("=== HTTP Performance Report ===");
        println!("Total Requests: {}", self.total_requests);
        println!("Success Rate: {:.2}%", self.success_rate);
        println!("Average Duration: {:?}", self.avg_duration);
        println!("Min Duration: {:?}", self.min_duration);
        println!("Max Duration: {:?}", self.max_duration);
        println!("P95 Duration: {:?}", self.p95_duration);
        println!("P99 Duration: {:?}", self.p99_duration);
        
        println!("\n=== Status Code Distribution ===");
        for (&status, &count) in &self.status_distribution {
            let percentage = (count as f64 / self.total_requests as f64) * 100.0;
            println!("{status}: {count} ({percentage:.1}%)");
        }

        println!("\n=== Phase Breakdown ===");
        for (phase_name, stats) in &self.phase_breakdown {
            println!("{}: avg={:?}, min={:?}, max={:?}", 
                phase_name, stats.avg_duration, stats.min_duration, stats.max_duration);
        }
    }
}

/// Statistics for a specific phase across multiple requests
#[derive(Debug)]
pub struct PhaseStats {
    pub avg_duration: Duration,
    pub min_duration: Duration,
    pub max_duration: Duration,
    pub total_duration: Duration,
    pub count: usize,
}

impl PhaseStats {
    fn new() -> Self {
        PhaseStats {
            avg_duration: Duration::from_millis(0),
            min_duration: Duration::from_secs(u64::MAX),
            max_duration: Duration::from_millis(0),
            total_duration: Duration::from_millis(0),
            count: 0,
        }
    }

    fn add_duration(&mut self, duration: Duration) {
        self.count += 1;
        self.total_duration += duration;
        
        if duration < self.min_duration {
            self.min_duration = duration;
        }
        if duration > self.max_duration {
            self.max_duration = duration;
        }
    }

    fn finalize(&mut self) {
        if self.count > 0 {
            self.avg_duration = self.total_duration / self.count as u32;
        }
    }
}

/// Memory usage tracker
#[derive(Debug, Clone)]
struct MemoryTracker {
    start_usage: usize,
    peak_usage: usize,
}

impl MemoryTracker {
    fn new() -> Self {
        let current = Self::get_memory_usage();
        MemoryTracker {
            start_usage: current,
            peak_usage: current,
        }
    }

    fn current_usage(&mut self) -> usize {
        let current = Self::get_memory_usage();
        if current > self.peak_usage {
            self.peak_usage = current;
        }
        current
    }

    fn peak_usage(&self) -> usize {
        self.peak_usage
    }

    fn total_usage(&self) -> usize {
        self.peak_usage.saturating_sub(self.start_usage)
    }

    fn get_memory_usage() -> usize {
        // Simplified memory usage estimation
        // In a real implementation, this would use platform-specific APIs
        std::mem::size_of::<usize>() * 1024 // Placeholder
    }
}

/// CPU usage tracker
#[derive(Debug, Clone)]
pub struct CpuTracker {
    start_time: Instant,
    metrics: HashMap<String, f64>,
    active: bool,
}

impl CpuTracker {
    pub fn new() -> Self {
        CpuTracker {
            start_time: Instant::now(),
            metrics: HashMap::new(),
            active: true,
        }
    }
    
    pub fn record_metric(&mut self, name: String, value: f64) {
        self.metrics.insert(name, value);
    }
    
    pub fn get_elapsed_time(&self) -> Duration {
        self.start_time.elapsed()
    }
    
    pub fn get_cpu_usage(&self) -> f64 {
        // Simplified CPU usage calculation
        // In a real implementation, this would use platform-specific APIs
        let elapsed = self.get_elapsed_time().as_millis() as f64;
        if elapsed > 0.0 {
            // Simulate CPU usage based on elapsed time
            (elapsed / 1000.0).min(100.0)
        } else {
            0.0
        }
    }
    
    pub fn stop(&mut self) {
        self.active = false;
        self.record_metric("final_cpu_usage".to_string(), self.get_cpu_usage());
    }
}

impl Default for CpuTracker {
    fn default() -> Self {
        Self::new()
    }
}

impl CpuTracker {
    pub fn is_active(&self) -> bool {
        self.active
    }
}



/// Profiler middleware for automatic profiling
pub struct ProfilerMiddleware {
    profiler: HttpProfiler,
}

impl ProfilerMiddleware {
    pub fn new(profiler: HttpProfiler) -> Self {
        ProfilerMiddleware { profiler }
    }
}

impl crate::middleware::Middleware for ProfilerMiddleware {
    fn process_request(&self, request: &mut crate::Request) -> crate::Result<()> {
        // Start profiling session
        if let Some(mut session) = self.profiler.start_profile(request) {
            session.start_phase("request_preparation");
            // Store session in request context (simplified)
        }
        Ok(())
    }

    fn process_response(&self, _request: &crate::Request, _response: &mut crate::Response) -> crate::Result<()> {
        // End profiling session
        // In a real implementation, we'd retrieve the session from request context
        Ok(())
    }

    fn name(&self) -> &'static str {
        "ProfilerMiddleware"
    }
}

/// Flame graph generator for performance visualization
pub struct FlameGraphGenerator {
    samples: Vec<StackSample>,
}

impl FlameGraphGenerator {
    pub fn new() -> Self {
        FlameGraphGenerator {
            samples: Vec::new(),
        }
    }

    pub fn add_sample(&mut self, stack: Vec<String>, duration: Duration) {
        self.samples.push(StackSample {
            stack,
            duration,
            timestamp: Instant::now(),
        });
    }

    pub fn generate_svg(&self) -> String {
        // Simplified flame graph generation
        let mut svg = String::new();
        svg.push_str(r#"<svg width="800" height="600" xmlns="http://www.w3.org/2000/svg">"#);
        
        let mut y = 0;
        for sample in &self.samples {
            let width = (sample.duration.as_millis() as f64 / 10.0) as i32;
            svg.push_str(&format!(
                r#"<rect x="10" y="{y}" width="{width}" height="20" fill="orange" stroke="black"/>"#
            ));
            svg.push_str(&format!(
                r#"<text x="15" y="{}" font-size="12">{}</text>"#,
                y + 15,
                sample.stack.join(" -> ")
            ));
            y += 25;
        }
        
        svg.push_str("</svg>");
        svg
    }

    pub fn save_to_file(&self, filename: &str) -> Result<()> {
        use std::fs::File;
        use std::io::Write;

        let svg_content = self.generate_svg();
        let mut file = File::create(filename)
            .map_err(Error::Io)?;
        
        file.write_all(svg_content.as_bytes())
            .map_err(Error::Io)?;

        Ok(())
    }
}

impl Default for FlameGraphGenerator {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone)]
pub struct StackSample {
    stack: Vec<String>,
    duration: Duration,
    timestamp: Instant,
}

impl StackSample {
    pub fn new(stack: Vec<String>, duration: Duration) -> Self {
        StackSample {
            stack,
            duration,
            timestamp: Instant::now(),
        }
    }
    
    pub fn age(&self) -> Duration {
        self.timestamp.elapsed()
    }
    
    pub fn is_recent(&self, threshold: Duration) -> bool {
        self.age() < threshold
    }
    
    pub fn stack_depth(&self) -> usize {
        self.stack.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Method, Url};

    #[test]
    fn test_profiler_creation() {
        let profiler = HttpProfiler::new();
        assert!(profiler.enabled);
        assert_eq!(profiler.sample_rate, 1.0);
    }

    #[test]
    fn test_profile_session() {
        let profiler = HttpProfiler::new();
        let request = crate::Request {
            method: Method::GET,
            url: Url::parse("http://example.com").unwrap(),
            headers: std::collections::HashMap::new(),
            body: None,
        };

        let mut session = profiler.start_profile(&request).unwrap();
        session.start_phase("dns_lookup");
        std::thread::sleep(std::time::Duration::from_millis(10));
        session.end_phase("dns_lookup");
        
        session.start_phase("connect");
        std::thread::sleep(std::time::Duration::from_millis(5));
        session.end_phase("connect");

        assert!(session.finish(None).is_ok());
    }

    #[test]
    fn test_flame_graph_generator() {
        let mut generator = FlameGraphGenerator::new();
        generator.add_sample(
            vec!["main".to_string(), "http_request".to_string(), "dns_lookup".to_string()],
            Duration::from_millis(100)
        );
        
        let svg = generator.generate_svg();
        assert!(svg.contains("<svg"));
        assert!(svg.contains("</svg>"));
        assert!(svg.contains("dns_lookup"));
    }

    #[test]
    fn test_performance_report() {
        let report = PerformanceReport::new();
        assert_eq!(report.total_requests, 0);
        assert_eq!(report.success_rate, 0.0);
    }
}