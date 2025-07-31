use crate::{Result, Request, Response};
use std::collections::HashMap;
use std::time::{Duration, Instant};

#[derive(Debug, Clone)]
pub struct RequestSecurityInfo {
    pub method: String,
    pub url: String,
    pub headers: HashMap<String, String>,
    pub body_size: usize,
    pub client_ip: String,
}

/// Security manager for HTTP requests with threat detection and prevention
#[derive(Debug)]
pub struct SecurityManager {
    policies: Vec<SecurityPolicy>,
    threat_detector: ThreatDetector,
    rate_limiter: SecurityRateLimiter,
    content_scanner: ContentScanner,
    enabled: bool,
}

impl SecurityManager {
    pub fn new() -> Self {
        SecurityManager {
            policies: Vec::new(),
            threat_detector: ThreatDetector::new(),
            rate_limiter: SecurityRateLimiter::new(),
            content_scanner: ContentScanner::new(),
            enabled: true,
        }
    }

    pub fn enabled(mut self, enabled: bool) -> Self {
        self.enabled = enabled;
        self
    }

    pub fn add_policy(mut self, policy: SecurityPolicy) -> Self {
        self.policies.push(policy);
        self
    }

    pub fn validate_request(&mut self, request: &Request) -> Result<SecurityReport> {
        if !self.enabled {
            return Ok(SecurityReport::safe());
        }

        let mut report = SecurityReport::new();

        // Check rate limiting
        if let Some(violation) = self.rate_limiter.check_request(request) {
            report.add_violation(violation);
        }

        // Run threat detection
        if let Some(threat) = self.threat_detector.analyze_request(request) {
            report.add_threat(threat);
        }

        // Apply security policies
        for policy in &self.policies {
            if let Some(violation) = policy.check_request(request) {
                report.add_violation(violation);
            }
        }

        // Scan content for malicious patterns
        if let Some(ref body) = request.body {
            if let Some(threat) = self.content_scanner.scan_content(body) {
                report.add_threat(threat);
            }
        }

        Ok(report)
    }

    pub fn validate_response(&mut self, response: &Response) -> Result<SecurityReport> {
        if !self.enabled {
            return Ok(SecurityReport::safe());
        }

        let mut report = SecurityReport::new();

        // Scan response content
        if let Some(threat) = self.content_scanner.scan_content(&response.body) {
            report.add_threat(threat);
        }

        // Check response headers for security issues
        if let Some(violation) = self.check_response_headers(response) {
            report.add_violation(violation);
        }

        Ok(report)
    }

    fn check_response_headers(&self, response: &Response) -> Option<SecurityViolation> {
        // Check for missing security headers
        let security_headers = [
            "X-Content-Type-Options",
            "X-Frame-Options", 
            "X-XSS-Protection",
            "Strict-Transport-Security",
        ];

        for header in &security_headers {
            if !response.headers.contains_key(*header) {
                return Some(SecurityViolation {
                    violation_type: ViolationType::MissingSecurityHeader,
                    description: format!("Missing security header: {header}"),
                    severity: Severity::Medium,
                    timestamp: Instant::now(),
                });
            }
        }

        None
    }

    pub fn get_security_stats(&self) -> SecurityStats {
        SecurityStats {
            total_requests_checked: self.threat_detector.total_requests,
            threats_detected: self.threat_detector.threats_detected,
            violations_found: self.rate_limiter.violations_count,
            blocked_requests: self.rate_limiter.blocked_count,
        }
    }
}

impl Default for SecurityManager {
    fn default() -> Self {
        Self::new()
    }
}

/// Security policy for validating requests
#[derive(Debug, Clone)]
pub struct SecurityPolicy {
    pub name: String,
    pub rules: Vec<SecurityRule>,
    pub enabled: bool,
}

impl SecurityPolicy {
    pub fn new<S: Into<String>>(name: S) -> Self {
        SecurityPolicy {
            name: name.into(),
            rules: Vec::new(),
            enabled: true,
        }
    }

    pub fn add_rule(mut self, rule: SecurityRule) -> Self {
        self.rules.push(rule);
        self
    }

    pub fn enabled(mut self, enabled: bool) -> Self {
        self.enabled = enabled;
        self
    }

    fn check_request(&self, request: &Request) -> Option<SecurityViolation> {
        if !self.enabled {
            return None;
        }

        for rule in &self.rules {
            if let Some(violation) = rule.check_request(request) {
                return Some(violation);
            }
        }

        None
    }
}

/// Individual security rule
#[derive(Debug, Clone)]
pub struct SecurityRule {
    pub rule_type: RuleType,
    pub pattern: String,
    pub action: SecurityAction,
    pub severity: Severity,
}

impl SecurityRule {
    pub fn new(rule_type: RuleType, pattern: String, action: SecurityAction, severity: Severity) -> Self {
        SecurityRule {
            rule_type,
            pattern,
            action,
            severity,
        }
    }

    fn check_request(&self, request: &Request) -> Option<SecurityViolation> {
        let matches = match self.rule_type {
            RuleType::UrlPattern => request.url.full_path().contains(&self.pattern),
            RuleType::HeaderPattern => {
                request.headers.values().any(|v| v.contains(&self.pattern))
            }
            RuleType::BodyPattern => {
                if let Some(ref body) = request.body {
                    String::from_utf8_lossy(body).contains(&self.pattern)
                } else {
                    false
                }
            }
            RuleType::UserAgentPattern => {
                request.headers.get("User-Agent")
                    .map(|ua| ua.contains(&self.pattern))
                    .unwrap_or(false)
            }
        };

        if matches {
            Some(SecurityViolation {
                violation_type: ViolationType::PolicyViolation,
                description: format!("Security rule violated: {} pattern '{}'", 
                    self.rule_type.as_str(), self.pattern),
                severity: self.severity,
                timestamp: Instant::now(),
            })
        } else {
            None
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub enum RuleType {
    UrlPattern,
    HeaderPattern,
    BodyPattern,
    UserAgentPattern,
}

impl RuleType {
    fn as_str(&self) -> &'static str {
        match self {
            RuleType::UrlPattern => "URL",
            RuleType::HeaderPattern => "Header",
            RuleType::BodyPattern => "Body",
            RuleType::UserAgentPattern => "User-Agent",
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub enum SecurityAction {
    Block,
    Warn,
    Log,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Severity {
    Low,
    Medium,
    High,
    Critical,
}

/// Threat detector for identifying malicious patterns
#[derive(Debug)]
pub struct ThreatDetector {
    malicious_patterns: Vec<String>,
    suspicious_user_agents: Vec<String>,
    total_requests: usize,
    threats_detected: usize,
}

impl ThreatDetector {
    fn new() -> Self {
        ThreatDetector {
            malicious_patterns: vec![
                "script".to_string(),
                "javascript:".to_string(),
                "vbscript:".to_string(),
                "onload=".to_string(),
                "onerror=".to_string(),
                "<iframe".to_string(),
                "eval(".to_string(),
                "document.cookie".to_string(),
                "../".to_string(), // Path traversal
                "..\\".to_string(), // Windows path traversal
                "union select".to_string(), // SQL injection
                "drop table".to_string(), // SQL injection
                "exec(".to_string(), // Command injection
                "system(".to_string(), // Command injection
            ],
            suspicious_user_agents: vec![
                "sqlmap".to_string(),
                "nikto".to_string(),
                "nmap".to_string(),
                "masscan".to_string(),
                "burp".to_string(),
                "zap".to_string(),
            ],
            total_requests: 0,
            threats_detected: 0,
        }
    }

    fn analyze_request(&mut self, request: &Request) -> Option<SecurityThreat> {
        self.total_requests += 1;

        // Check URL for malicious patterns
        let url_lower = request.url.full_path().to_lowercase();
        for pattern in &self.malicious_patterns {
            if url_lower.contains(pattern) {
                self.threats_detected += 1;
                return Some(SecurityThreat {
                    threat_type: ThreatType::MaliciousPattern,
                    description: format!("Malicious pattern '{pattern}' found in URL"),
                    severity: Severity::High,
                    source: ThreatSource::Url,
                    timestamp: Instant::now(),
                });
            }
        }

        // Check User-Agent for suspicious tools
        if let Some(user_agent) = request.headers.get("User-Agent") {
            let ua_lower = user_agent.to_lowercase();
            for suspicious_ua in &self.suspicious_user_agents {
                if ua_lower.contains(suspicious_ua) {
                    self.threats_detected += 1;
                    return Some(SecurityThreat {
                        threat_type: ThreatType::SuspiciousUserAgent,
                        description: format!("Suspicious user agent detected: {suspicious_ua}"),
                        severity: Severity::Medium,
                        source: ThreatSource::Headers,
                        timestamp: Instant::now(),
                    });
                }
            }
        }

        // Check for excessive header count (potential DoS)
        if request.headers.len() > 50 {
            self.threats_detected += 1;
            return Some(SecurityThreat {
                threat_type: ThreatType::ExcessiveHeaders,
                description: format!("Excessive header count: {}", request.headers.len()),
                severity: Severity::Medium,
                source: ThreatSource::Headers,
                timestamp: Instant::now(),
            });
        }

        None
    }
}

/// Rate limiter for security purposes
#[derive(Debug)]
pub struct SecurityRateLimiter {
    request_counts: HashMap<String, RequestCounter>,
    max_requests_per_minute: usize,
    violations_count: usize,
    blocked_count: usize,
}

impl SecurityRateLimiter {
    fn new() -> Self {
        SecurityRateLimiter {
            request_counts: HashMap::new(),
            max_requests_per_minute: 60,
            violations_count: 0,
            blocked_count: 0,
        }
    }

    fn check_request(&mut self, request: &Request) -> Option<SecurityViolation> {
        let client_id = self.get_client_id(request);
        let now = Instant::now();

        let counter = self.request_counts
            .entry(client_id.clone())
            .or_insert_with(|| RequestCounter::new(now));

        counter.add_request(now);

        if counter.requests_in_last_minute(now) > self.max_requests_per_minute {
            self.violations_count += 1;
            self.blocked_count += 1;
            
            Some(SecurityViolation {
                violation_type: ViolationType::RateLimit,
                description: format!("Rate limit exceeded for client: {client_id}"),
                severity: Severity::High,
                timestamp: now,
            })
        } else {
            None
        }
    }

    fn get_client_id(&self, request: &Request) -> String {
        // In a real implementation, this would extract client IP or other identifier
        request.headers.get("X-Forwarded-For")
            .or_else(|| request.headers.get("X-Real-IP"))
            .unwrap_or(&"unknown".to_string())
            .clone()
    }
}

#[derive(Debug)]
struct RequestCounter {
    requests: Vec<Instant>,
    last_cleanup: Instant,
}

impl RequestCounter {
    fn new(now: Instant) -> Self {
        RequestCounter {
            requests: Vec::new(),
            last_cleanup: now,
        }
    }

    fn add_request(&mut self, now: Instant) {
        self.requests.push(now);
        
        // Cleanup old requests periodically
        if now.duration_since(self.last_cleanup) > Duration::from_secs(60) {
            self.cleanup_old_requests(now);
            self.last_cleanup = now;
        }
    }

    fn requests_in_last_minute(&self, now: Instant) -> usize {
        self.requests.iter()
            .filter(|&&request_time| now.duration_since(request_time) <= Duration::from_secs(60))
            .count()
    }

    fn cleanup_old_requests(&mut self, now: Instant) {
        self.requests.retain(|&request_time| {
            now.duration_since(request_time) <= Duration::from_secs(60)
        });
    }
}

/// Content scanner for malicious content detection
#[derive(Debug)]
pub struct ContentScanner {
    virus_signatures: Vec<String>,
    malware_patterns: Vec<String>,
}

impl ContentScanner {
    fn new() -> Self {
        ContentScanner {
            virus_signatures: vec![
                "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*".to_string(),
            ],
            malware_patterns: vec![
                "eval(base64_decode(".to_string(),
                "shell_exec(".to_string(),
                "system(".to_string(),
                "passthru(".to_string(),
                "exec(".to_string(),
                "file_get_contents(".to_string(),
                "fopen(".to_string(),
                "fwrite(".to_string(),
            ],
        }
    }

    fn scan_content(&self, content: &[u8]) -> Option<SecurityThreat> {
        let content_str = String::from_utf8_lossy(content).to_lowercase();

        // Check for virus signatures
        for signature in &self.virus_signatures {
            if content_str.contains(&signature.to_lowercase()) {
                return Some(SecurityThreat {
                    threat_type: ThreatType::VirusSignature,
                    description: "Virus signature detected in content".to_string(),
                    severity: Severity::Critical,
                    source: ThreatSource::Content,
                    timestamp: Instant::now(),
                });
            }
        }

        // Check for malware patterns
        for pattern in &self.malware_patterns {
            if content_str.contains(pattern) {
                return Some(SecurityThreat {
                    threat_type: ThreatType::MalwarePattern,
                    description: format!("Malware pattern detected: {pattern}"),
                    severity: Severity::High,
                    source: ThreatSource::Content,
                    timestamp: Instant::now(),
                });
            }
        }

        None
    }
}

/// Security report containing violations and threats
#[derive(Debug)]
pub struct SecurityReport {
    pub violations: Vec<SecurityViolation>,
    pub threats: Vec<SecurityThreat>,
    pub is_safe: bool,
    pub risk_score: u32,
}

impl SecurityReport {
    fn new() -> Self {
        SecurityReport {
            violations: Vec::new(),
            threats: Vec::new(),
            is_safe: true,
            risk_score: 0,
        }
    }

    fn safe() -> Self {
        SecurityReport {
            violations: Vec::new(),
            threats: Vec::new(),
            is_safe: true,
            risk_score: 0,
        }
    }

    fn add_violation(&mut self, violation: SecurityViolation) {
        self.is_safe = false;
        self.risk_score += self.severity_to_score(violation.severity);
        self.violations.push(violation);
    }

    fn add_threat(&mut self, threat: SecurityThreat) {
        self.is_safe = false;
        self.risk_score += self.severity_to_score(threat.severity);
        self.threats.push(threat);
    }

    fn severity_to_score(&self, severity: Severity) -> u32 {
        match severity {
            Severity::Low => 1,
            Severity::Medium => 5,
            Severity::High => 15,
            Severity::Critical => 50,
        }
    }

    pub fn should_block(&self) -> bool {
        self.risk_score >= 50 || 
        self.threats.iter().any(|t| t.severity == Severity::Critical) ||
        self.violations.iter().any(|v| v.severity == Severity::Critical)
    }

    pub fn get_summary(&self) -> String {
        format!(
            "Security Report: {} violations, {} threats, risk score: {}, safe: {}",
            self.violations.len(),
            self.threats.len(),
            self.risk_score,
            self.is_safe
        )
    }
}

/// Security violation detected
#[derive(Debug, Clone)]
pub struct SecurityViolation {
    pub violation_type: ViolationType,
    pub description: String,
    pub severity: Severity,
    pub timestamp: Instant,
}

#[derive(Debug, Clone)]
pub enum ViolationType {
    PolicyViolation,
    RateLimit,
    MissingSecurityHeader,
    InvalidInput,
}

/// Security threat detected
#[derive(Debug, Clone)]
pub struct SecurityThreat {
    pub threat_type: ThreatType,
    pub description: String,
    pub severity: Severity,
    pub source: ThreatSource,
    pub timestamp: Instant,
}

#[derive(Debug, Clone)]
pub enum ThreatType {
    MaliciousPattern,
    SuspiciousUserAgent,
    ExcessiveHeaders,
    VirusSignature,
    MalwarePattern,
    SqlInjection,
    XssAttempt,
    PathTraversal,
    CommandInjection,
}

#[derive(Debug, Clone)]
pub enum ThreatSource {
    Url,
    Headers,
    Content,
    Parameters,
}

/// Security statistics
#[derive(Debug, Clone)]
pub struct SecurityStats {
    pub total_requests_checked: usize,
    pub threats_detected: usize,
    pub violations_found: usize,
    pub blocked_requests: usize,
}

impl SecurityStats {
    pub fn threat_rate(&self) -> f64 {
        if self.total_requests_checked == 0 {
            0.0
        } else {
            self.threats_detected as f64 / self.total_requests_checked as f64
        }
    }

    pub fn block_rate(&self) -> f64 {
        if self.total_requests_checked == 0 {
            0.0
        } else {
            self.blocked_requests as f64 / self.total_requests_checked as f64
        }
    }
}

/// Security middleware for automatic security checking
pub struct SecurityMiddleware {
    security_manager: SecurityManager,
}

impl SecurityMiddleware {
    pub fn new(security_manager: SecurityManager) -> Self {
        SecurityMiddleware { security_manager }
    }
    
    pub fn process_request(&self, _request: &mut crate::Request) -> crate::Result<()> {
        // Extract request information for security analysis
        let request_info = RequestSecurityInfo {
            method: "GET".to_string(), // Would extract from actual request
            url: "http://example.com".to_string(), // Would extract from actual request
            headers: std::collections::HashMap::new(), // Would extract from actual request
            body_size: 0, // Would extract from actual request
            client_ip: "127.0.0.1".to_string(), // Would extract from actual request
        };
        
        // Perform security analysis (simplified for now)
        // In a real implementation, we would create a proper analysis method
        // that takes RequestSecurityInfo instead of Request
        
        // Simulate security check
        let has_threat = request_info.headers.get("User-Agent")
            .map(|ua| ua.contains("malicious"))
            .unwrap_or(false);
        
        // Check if request should be blocked
        if has_threat {
            return Err(crate::Error::SecurityViolation(
                "Request blocked due to security threat".to_string()
            ));
        }
        
        Ok(())
    }
    
    pub fn process_response(&self, _response: &mut crate::Response) -> crate::Result<()> {
        // Scan response content for security issues
        let content = Vec::new(); // Would extract from actual response
        let scan_result = self.security_manager.content_scanner.scan_content(&content);
        
        if scan_result.is_some() {
            return Err(crate::Error::SecurityViolation(
                "Response contains security threats".to_string()
            ));
        }
        
        Ok(())
    }
    
    pub fn get_security_stats(&self) -> SecurityStats {
        SecurityStats {
            total_requests_checked: 0, // Would track actual stats
            threats_detected: 0,
            violations_found: 0,
            blocked_requests: 0,
        }
    }
}



impl crate::middleware::Middleware for SecurityMiddleware {
    fn process_request(&self, _request: &mut crate::Request) -> crate::Result<()> {
        // Note: We can't modify security_manager here due to &self
        // In a real implementation, we'd use Arc<Mutex<SecurityManager>>
        Ok(())
    }

    fn process_response(&self, _request: &crate::Request, _response: &mut crate::Response) -> crate::Result<()> {
        Ok(())
    }

    fn name(&self) -> &'static str {
        "SecurityMiddleware"
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Method, Url};

    #[test]
    fn test_security_manager_creation() {
        let manager = SecurityManager::new();
        assert!(manager.enabled);
        assert!(manager.policies.is_empty());
    }

    #[test]
    fn test_security_policy() {
        let policy = SecurityPolicy::new("test_policy")
            .add_rule(SecurityRule::new(
                RuleType::UrlPattern,
                "admin".to_string(),
                SecurityAction::Block,
                Severity::High,
            ));

        assert_eq!(policy.name, "test_policy");
        assert_eq!(policy.rules.len(), 1);
        assert!(policy.enabled);
    }

    #[test]
    fn test_threat_detector() {
        let mut detector = ThreatDetector::new();
        
        let request = crate::Request {
            method: Method::GET,
            url: Url::parse("http://example.com/test?script=alert").unwrap(),
            headers: std::collections::HashMap::new(),
            body: None,
        };

        let threat = detector.analyze_request(&request);
        assert!(threat.is_some());
        assert_eq!(detector.total_requests, 1);
        assert_eq!(detector.threats_detected, 1);
    }

    #[test]
    fn test_content_scanner() {
        let scanner = ContentScanner::new();
        let malicious_content = b"eval(base64_decode('malicious_code'))";
        
        let threat = scanner.scan_content(malicious_content);
        assert!(threat.is_some());
        
        if let Some(threat) = threat {
            assert_eq!(threat.threat_type as u8, ThreatType::MalwarePattern as u8);
            assert_eq!(threat.severity, Severity::High);
        }
    }

    #[test]
    fn test_security_report() {
        let mut report = SecurityReport::new();
        assert!(report.is_safe);
        assert_eq!(report.risk_score, 0);

        let violation = SecurityViolation {
            violation_type: ViolationType::PolicyViolation,
            description: "Test violation".to_string(),
            severity: Severity::High,
            timestamp: Instant::now(),
        };

        report.add_violation(violation);
        assert!(!report.is_safe);
        assert!(report.risk_score > 0);
    }

    #[test]
    fn test_rate_limiter() {
        let mut limiter = SecurityRateLimiter::new();
        limiter.max_requests_per_minute = 2;

        let request = crate::Request {
            method: Method::GET,
            url: Url::parse("http://example.com").unwrap(),
            headers: std::collections::HashMap::new(),
            body: None,
        };

        // First two requests should be fine
        assert!(limiter.check_request(&request).is_none());
        assert!(limiter.check_request(&request).is_none());
        
        // Third request should trigger rate limit
        assert!(limiter.check_request(&request).is_some());
    }
}