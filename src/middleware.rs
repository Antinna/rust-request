use crate::{Request, Response, Result, Error};
use std::time::{Duration, Instant};
use std::collections::HashMap;

/// Trait for request/response middleware
pub trait Middleware: Send + Sync {
    /// Process the request before it's sent
    fn process_request(&self, _request: &mut Request) -> Result<()> {
        Ok(())
    }

    /// Process the response after it's received
    fn process_response(&self, _request: &Request, _response: &mut Response) -> Result<()> {
        Ok(())
    }

    /// Handle errors that occur during request processing
    fn handle_error(&self, _request: &Request, error: Error) -> Result<Error> {
        Ok(error)
    }

    /// Get middleware name for debugging
    fn name(&self) -> &'static str {
        "Unknown"
    }
}

/// Middleware chain for processing requests and responses
pub struct MiddlewareChain {
    middlewares: Vec<Box<dyn Middleware>>,
}

impl std::fmt::Debug for MiddlewareChain {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MiddlewareChain")
            .field("middleware_count", &self.middlewares.len())
            .field("middleware_names", &self.middlewares.iter().map(|m| m.name()).collect::<Vec<_>>())
            .finish()
    }
}

impl MiddlewareChain {
    pub fn new() -> Self {
        MiddlewareChain {
            middlewares: Vec::new(),
        }
    }

    pub fn with_middleware<M: Middleware + 'static>(mut self, middleware: M) -> Self {
        self.middlewares.push(Box::new(middleware));
        self
    }

    pub fn process_request(&self, request: &mut Request) -> Result<()> {
        for middleware in &self.middlewares {
            middleware.process_request(request)?;
        }
        Ok(())
    }

    pub fn process_response(&self, request: &Request, response: &mut Response) -> Result<()> {
        // Process in reverse order for response
        for middleware in self.middlewares.iter().rev() {
            middleware.process_response(request, response)?;
        }
        Ok(())
    }

    pub fn handle_error(&self, request: &Request, mut error: Error) -> Error {
        for middleware in &self.middlewares {
            match middleware.handle_error(request, error) {
                Ok(new_error) => error = new_error,
                Err(middleware_error) => return middleware_error,
            }
        }
        error
    }
    
    /// Get the number of middlewares in the chain
    pub fn len(&self) -> usize {
        self.middlewares.len()
    }
    
    /// Check if the middleware chain is empty
    pub fn is_empty(&self) -> bool {
        self.middlewares.is_empty()
    }
}

impl Default for MiddlewareChain {
    fn default() -> Self {
        Self::new()
    }
}

/// Logging middleware for request/response logging
#[derive(Debug)]
pub struct LoggingMiddleware {
    log_requests: bool,
    log_responses: bool,
    log_headers: bool,
    log_body: bool,
    max_body_size: usize,
}

impl LoggingMiddleware {
    pub fn new() -> Self {
        LoggingMiddleware {
            log_requests: true,
            log_responses: true,
            log_headers: false,
            log_body: false,
            max_body_size: 1024,
        }
    }

    pub fn log_requests(mut self, log: bool) -> Self {
        self.log_requests = log;
        self
    }

    pub fn log_responses(mut self, log: bool) -> Self {
        self.log_responses = log;
        self
    }

    pub fn log_headers(mut self, log: bool) -> Self {
        self.log_headers = log;
        self
    }

    pub fn log_body(mut self, log: bool) -> Self {
        self.log_body = log;
        self
    }

    pub fn max_body_size(mut self, size: usize) -> Self {
        self.max_body_size = size;
        self
    }
}

impl Default for LoggingMiddleware {
    fn default() -> Self {
        Self::new()
    }
}

impl Middleware for LoggingMiddleware {
    fn process_request(&self, request: &mut Request) -> Result<()> {
        if self.log_requests {
            println!("→ {} {}", request.method.as_str(), request.url.full_path());
            
            if self.log_headers && !request.headers.is_empty() {
                println!("  Headers:");
                for (key, value) in &request.headers {
                    println!("    {key}: {value}");
                }
            }

            if self.log_body {
                if let Some(ref body) = request.body {
                    let body_preview = if body.len() > self.max_body_size {
                        format!("{}... ({} bytes total)", 
                            String::from_utf8_lossy(&body[..self.max_body_size]), 
                            body.len())
                    } else {
                        String::from_utf8_lossy(body).to_string()
                    };
                    println!("  Body: {body_preview}");
                }
            }
        }
        Ok(())
    }

    fn process_response(&self, request: &Request, response: &mut Response) -> Result<()> {
        if self.log_responses {
            println!("← {} {} ({})", 
                request.method.as_str(), 
                response.status, 
                response.status_text);

            if self.log_headers && !response.headers.is_empty() {
                println!("  Headers:");
                for (key, value) in &response.headers {
                    println!("    {key}: {value}");
                }
            }

            if self.log_body && !response.body.is_empty() {
                let body_preview = if response.body.len() > self.max_body_size {
                    format!("{}... ({} bytes total)", 
                        String::from_utf8_lossy(&response.body[..self.max_body_size]), 
                        response.body.len())
                } else {
                    String::from_utf8_lossy(&response.body).to_string()
                };
                println!("  Body: {body_preview}");
            }
        }
        Ok(())
    }

    fn name(&self) -> &'static str {
        "LoggingMiddleware"
    }
}

/// Timing middleware for measuring request duration
#[derive(Debug)]
pub struct TimingMiddleware {
    start_times: std::sync::Arc<std::sync::Mutex<HashMap<String, Instant>>>,
}

impl TimingMiddleware {
    pub fn new() -> Self {
        TimingMiddleware {
            start_times: std::sync::Arc::new(std::sync::Mutex::new(HashMap::new())),
        }
    }

    fn get_request_id(request: &Request) -> String {
        format!("{}:{}", request.method.as_str(), request.url.full_path())
    }
}

impl Default for TimingMiddleware {
    fn default() -> Self {
        Self::new()
    }
}

impl Middleware for TimingMiddleware {
    fn process_request(&self, request: &mut Request) -> Result<()> {
        let request_id = Self::get_request_id(request);
        if let Ok(mut times) = self.start_times.lock() {
            times.insert(request_id, Instant::now());
        }
        Ok(())
    }

    fn process_response(&self, request: &Request, _response: &mut Response) -> Result<()> {
        let request_id = Self::get_request_id(request);
        if let Ok(mut times) = self.start_times.lock() {
            if let Some(start_time) = times.remove(&request_id) {
                let duration = start_time.elapsed();
                println!("⏱ Request took: {duration:?}");
            }
        }
        Ok(())
    }

    fn name(&self) -> &'static str {
        "TimingMiddleware"
    }
}

/// Authentication middleware for automatic auth header injection
#[derive(Debug)]
pub struct AuthMiddleware {
    auth_type: AuthType,
}

#[derive(Debug, Clone)]
enum AuthType {
    Basic { username: String, password: String },
    Bearer { token: String },
    ApiKey { header: String, value: String },
    Custom { header: String, value: String },
}

impl AuthMiddleware {
    pub fn basic<U, P>(username: U, password: P) -> Self
    where
        U: Into<String>,
        P: Into<String>,
    {
        AuthMiddleware {
            auth_type: AuthType::Basic {
                username: username.into(),
                password: password.into(),
            },
        }
    }

    pub fn bearer<T: Into<String>>(token: T) -> Self {
        AuthMiddleware {
            auth_type: AuthType::Bearer {
                token: token.into(),
            },
        }
    }

    pub fn api_key<H, V>(header: H, value: V) -> Self
    where
        H: Into<String>,
        V: Into<String>,
    {
        AuthMiddleware {
            auth_type: AuthType::ApiKey {
                header: header.into(),
                value: value.into(),
            },
        }
    }

    pub fn custom<H, V>(header: H, value: V) -> Self
    where
        H: Into<String>,
        V: Into<String>,
    {
        AuthMiddleware {
            auth_type: AuthType::Custom {
                header: header.into(),
                value: value.into(),
            },
        }
    }
}

impl Middleware for AuthMiddleware {
    fn process_request(&self, request: &mut Request) -> Result<()> {
        match &self.auth_type {
            AuthType::Basic { username, password } => {
                let credentials = format!("{username}:{password}");
                let encoded = base64_encode(credentials.as_bytes());
                request.headers.insert("Authorization".to_string(), format!("Basic {encoded}"));
            }
            AuthType::Bearer { token } => {
                request.headers.insert("Authorization".to_string(), format!("Bearer {token}"));
            }
            AuthType::ApiKey { header, value } => {
                request.headers.insert(header.clone(), value.clone());
            }
            AuthType::Custom { header, value } => {
                request.headers.insert(header.clone(), value.clone());
            }
        }
        Ok(())
    }

    fn name(&self) -> &'static str {
        "AuthMiddleware"
    }
}

/// Rate limiting middleware
#[derive(Debug)]
pub struct RateLimitMiddleware {
    requests: std::sync::Arc<std::sync::Mutex<Vec<Instant>>>,
    max_requests: usize,
    time_window: Duration,
}

impl RateLimitMiddleware {
    pub fn new(max_requests: usize, time_window: Duration) -> Self {
        RateLimitMiddleware {
            requests: std::sync::Arc::new(std::sync::Mutex::new(Vec::new())),
            max_requests,
            time_window,
        }
    }
}

impl Middleware for RateLimitMiddleware {
    fn process_request(&self, _request: &mut Request) -> Result<()> {
        if let Ok(mut requests) = self.requests.lock() {
            let now = Instant::now();
            
            // Remove old requests outside the time window
            requests.retain(|&time| now.duration_since(time) < self.time_window);

            if requests.len() >= self.max_requests {
                return Err(Error::ConnectionFailed("Rate limit exceeded".to_string()));
            }

            requests.push(now);
        }
        Ok(())
    }

    fn name(&self) -> &'static str {
        "RateLimitMiddleware"
    }
}

/// User-Agent middleware for setting consistent user agent
#[derive(Debug)]
pub struct UserAgentMiddleware {
    user_agent: String,
}

impl UserAgentMiddleware {
    pub fn new<S: Into<String>>(user_agent: S) -> Self {
        UserAgentMiddleware {
            user_agent: user_agent.into(),
        }
    }
}

impl Middleware for UserAgentMiddleware {
    fn process_request(&self, request: &mut Request) -> Result<()> {
        if !request.headers.contains_key("User-Agent") {
            request.headers.insert("User-Agent".to_string(), self.user_agent.clone());
        }
        Ok(())
    }

    fn name(&self) -> &'static str {
        "UserAgentMiddleware"
    }
}

/// Retry middleware with exponential backoff
#[derive(Debug)]
pub struct RetryMiddleware {
    max_attempts: usize,
    initial_delay: Duration,
    max_delay: Duration,
    backoff_multiplier: f64,
    retry_on_status: Vec<u16>,
}

impl RetryMiddleware {
    pub fn new() -> Self {
        RetryMiddleware {
            max_attempts: 3,
            initial_delay: Duration::from_millis(100),
            max_delay: Duration::from_secs(30),
            backoff_multiplier: 2.0,
            retry_on_status: vec![500, 502, 503, 504, 408, 429],
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

    pub fn retry_on_status(mut self, status_codes: Vec<u16>) -> Self {
        self.retry_on_status = status_codes;
        self
    }
}

impl Default for RetryMiddleware {
    fn default() -> Self {
        Self::new()
    }
}

impl Middleware for RetryMiddleware {
    fn process_response(&self, _request: &Request, response: &mut Response) -> Result<()> {
        if self.retry_on_status.contains(&response.status) {
            // Calculate delay for potential retry
            let delay = self.calculate_delay(1); // First retry attempt
            println!("⚠ Response status {} would trigger retry with delay {:?}", response.status, delay);
        }
        Ok(())
    }

    fn name(&self) -> &'static str {
        "RetryMiddleware"
    }
}

impl RetryMiddleware {
    fn calculate_delay(&self, attempt: usize) -> Duration {
        let base_delay = self.initial_delay.as_millis() as f64;
        let multiplier = self.backoff_multiplier.powi(attempt as i32);
        let delay_ms = (base_delay * multiplier) as u64;
        
        let mut delay = Duration::from_millis(delay_ms);
        
        // Apply max delay limit
        if delay > self.max_delay {
            delay = self.max_delay;
        }

        delay
    }
}

/// Compression middleware for automatic request compression
#[derive(Debug)]
pub struct CompressionMiddleware {
    compression_type: crate::compression::Compression,
    min_size: usize,
}

impl CompressionMiddleware {
    pub fn new(compression_type: crate::compression::Compression) -> Self {
        CompressionMiddleware {
            compression_type,
            min_size: 1024, // Only compress bodies larger than 1KB
        }
    }

    pub fn min_size(mut self, size: usize) -> Self {
        self.min_size = size;
        self
    }
}

impl Middleware for CompressionMiddleware {
    fn process_request(&self, request: &mut Request) -> Result<()> {
        if let Some(ref body) = request.body {
            if body.len() >= self.min_size {
                match crate::compression::compress_request_body(body, self.compression_type) {
                    Ok(compressed_body) => {
                        request.body = Some(compressed_body);
                        request.headers.insert(
                            "Content-Encoding".to_string(),
                            self.compression_type.as_str().to_string(),
                        );
                    }
                    Err(_) => {
                        // Compression failed, continue with original body
                    }
                }
            }
        }
        Ok(())
    }

    fn name(&self) -> &'static str {
        "CompressionMiddleware"
    }
}

// Helper function for base64 encoding
fn base64_encode(input: &[u8]) -> String {
    const CHARS: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut result = String::new();
    
    for chunk in input.chunks(3) {
        let mut buf = [0u8; 3];
        for (i, &byte) in chunk.iter().enumerate() {
            buf[i] = byte;
        }
        
        let b = ((buf[0] as u32) << 16) | ((buf[1] as u32) << 8) | (buf[2] as u32);
        
        result.push(CHARS[((b >> 18) & 63) as usize] as char);
        result.push(CHARS[((b >> 12) & 63) as usize] as char);
        result.push(if chunk.len() > 1 { CHARS[((b >> 6) & 63) as usize] as char } else { '=' });
        result.push(if chunk.len() > 2 { CHARS[(b & 63) as usize] as char } else { '=' });
    }
    
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Method, Url};

    #[test]
    fn test_middleware_chain() {
        let chain = MiddlewareChain::new()
            .with_middleware(LoggingMiddleware::new().log_requests(false).log_responses(false))
            .with_middleware(TimingMiddleware::new())
            .with_middleware(UserAgentMiddleware::new("test-agent/1.0"));

        let mut request = Request {
            method: Method::GET,
            url: Url::parse("http://example.com").unwrap(),
            headers: HashMap::new(),
            body: None,
        };

        assert!(chain.process_request(&mut request).is_ok());
        assert_eq!(request.headers.get("User-Agent"), Some(&"test-agent/1.0".to_string()));
    }

    #[test]
    fn test_auth_middleware() {
        let auth = AuthMiddleware::basic("user", "pass");
        let mut request = Request {
            method: Method::GET,
            url: Url::parse("http://example.com").unwrap(),
            headers: HashMap::new(),
            body: None,
        };

        auth.process_request(&mut request).unwrap();
        assert!(request.headers.contains_key("Authorization"));
        assert!(request.headers.get("Authorization").unwrap().starts_with("Basic "));
    }

    #[test]
    fn test_rate_limit_middleware() {
        let rate_limiter = RateLimitMiddleware::new(2, Duration::from_secs(1));
        let mut request = Request {
            method: Method::GET,
            url: Url::parse("http://example.com").unwrap(),
            headers: HashMap::new(),
            body: None,
        };

        // First two requests should succeed
        assert!(rate_limiter.process_request(&mut request).is_ok());
        assert!(rate_limiter.process_request(&mut request).is_ok());
        
        // Third request should fail
        assert!(rate_limiter.process_request(&mut request).is_err());
    }
}