use crate::{Method, RequestBuilder, CookieJar, Auth, Proxy, Version, Result};
use crate::redirect::RedirectPolicy;
use crate::tls::TlsConfig;
use crate::compression::Compression;
use std::time::Duration;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::net::TcpStream;

// Connection pool for reusing TCP connections
#[derive(Debug)]
pub struct ConnectionPool {
    connections: Arc<Mutex<HashMap<String, Vec<TcpStream>>>>,
    max_connections_per_host: usize,
}

impl ConnectionPool {
    pub fn new(max_connections_per_host: usize) -> Self {
        ConnectionPool {
            connections: Arc::new(Mutex::new(HashMap::new())),
            max_connections_per_host,
        }
    }

    pub fn get_connection(&self, host: &str) -> Option<TcpStream> {
        let mut connections = self.connections.lock().ok()?;
        connections.get_mut(host)?.pop()
    }

    pub fn return_connection(&self, host: String, stream: TcpStream) {
        if let Ok(mut connections) = self.connections.lock() {
            let host_connections = connections.entry(host).or_insert_with(Vec::new);
            if host_connections.len() < self.max_connections_per_host {
                host_connections.push(stream);
            }
        }
    }
}

impl Clone for ConnectionPool {
    fn clone(&self) -> Self {
        ConnectionPool {
            connections: Arc::clone(&self.connections),
            max_connections_per_host: self.max_connections_per_host,
        }
    }
}

#[derive(Debug, Clone)]
pub struct Client {
    pub timeout: Option<Duration>,
    pub connect_timeout: Option<Duration>,
    pub read_timeout: Option<Duration>,
    pub write_timeout: Option<Duration>,
    pub default_headers: HashMap<String, String>,
    pub cookie_jar: Option<CookieJar>,
    pub auth: Option<Auth>,
    pub proxy: Option<Proxy>,
    pub redirect_policy: RedirectPolicy,
    pub tls_config: TlsConfig,
    pub user_agent: String,
    pub version: Version,
    pub max_connections_per_host: usize,
    pub keep_alive: bool,
    pub compression: Vec<Compression>,
    pub max_response_size: Option<usize>,
    pub dns_cache_timeout: Option<Duration>,
    pub tcp_nodelay: bool,
    pub tcp_keepalive: Option<Duration>,
    pub connection_pool: ConnectionPool,
}

impl Client {
    pub fn new() -> Self {
        let default_headers = HashMap::from([
            ("User-Agent".to_string(), "advanced-http-client/1.0.0".to_string()),
            ("Accept".to_string(), "*/*".to_string()),
            ("Accept-Encoding".to_string(), "gzip, deflate".to_string()),
        ]);
        
        Client {
            timeout: Some(Duration::from_secs(30)),
            connect_timeout: Some(Duration::from_secs(10)),
            read_timeout: Some(Duration::from_secs(30)),
            write_timeout: Some(Duration::from_secs(30)),
            default_headers,
            cookie_jar: Some(CookieJar::new()),
            auth: None,
            proxy: crate::proxy::parse_proxy_env(),
            redirect_policy: RedirectPolicy::new(),
            tls_config: TlsConfig::new(),
            user_agent: "advanced-http-client/1.0.0".to_string(),
            version: Version::Http11,
            max_connections_per_host: 10,
            keep_alive: true,
            compression: vec![Compression::Gzip, Compression::Deflate],
            max_response_size: Some(10 * 1024 * 1024), // 10MB
            dns_cache_timeout: Some(Duration::from_secs(300)), // 5 minutes
            tcp_nodelay: true,
            tcp_keepalive: Some(Duration::from_secs(60)),
            connection_pool: ConnectionPool::new(10),
        }
    }

    pub fn builder() -> ClientBuilder {
        ClientBuilder::new()
    }

    // Timeout methods
    pub fn timeout(mut self, timeout: Duration) -> Self {
        self.timeout = Some(timeout);
        self
    }

    pub fn connect_timeout(mut self, timeout: Duration) -> Self {
        self.connect_timeout = Some(timeout);
        self
    }

    pub fn read_timeout(mut self, timeout: Duration) -> Self {
        self.read_timeout = Some(timeout);
        self
    }

    pub fn write_timeout(mut self, timeout: Duration) -> Self {
        self.write_timeout = Some(timeout);
        self
    }

    // Header methods
    pub fn default_headers(mut self, headers: HashMap<String, String>) -> Self {
        self.default_headers.extend(headers);
        self
    }

    pub fn user_agent<T: Into<String>>(mut self, user_agent: T) -> Self {
        let ua = user_agent.into();
        self.user_agent = ua.clone();
        self.default_headers.insert("User-Agent".to_string(), ua);
        self
    }

    // Cookie methods
    pub fn cookie_jar(mut self, jar: CookieJar) -> Self {
        self.cookie_jar = Some(jar);
        self
    }

    pub fn no_cookies(mut self) -> Self {
        self.cookie_jar = None;
        self
    }

    // Authentication methods
    pub fn auth(mut self, auth: Auth) -> Self {
        self.auth = Some(auth);
        self
    }

    pub fn basic_auth<U, P>(mut self, username: U, password: P) -> Self
    where
        U: Into<String>,
        P: Into<String>,
    {
        self.auth = Some(Auth::basic(&username.into(), &password.into()));
        self
    }

    pub fn bearer_auth<T: Into<String>>(mut self, token: T) -> Self {
        self.auth = Some(Auth::bearer(&token.into()));
        self
    }

    // Proxy methods
    pub fn proxy(mut self, proxy: Proxy) -> Self {
        self.proxy = Some(proxy);
        self
    }

    pub fn no_proxy(mut self) -> Self {
        self.proxy = None;
        self
    }

    // Redirect methods
    pub fn redirect(mut self, policy: RedirectPolicy) -> Self {
        self.redirect_policy = policy;
        self
    }

    pub fn max_redirects(mut self, max: usize) -> Self {
        self.redirect_policy.max_redirects = max;
        self
    }

    // TLS methods
    pub fn tls_config(mut self, config: TlsConfig) -> Self {
        self.tls_config = config;
        self
    }

    pub fn danger_accept_invalid_certs(mut self) -> Self {
        self.tls_config = self.tls_config.danger_accept_invalid_certs();
        self
    }

    pub fn danger_accept_invalid_hostnames(mut self) -> Self {
        self.tls_config = self.tls_config.danger_accept_invalid_hostnames();
        self
    }

    // Compression methods
    pub fn compression(mut self, compression: Vec<Compression>) -> Self {
        self.compression = compression;
        self
    }

    pub fn no_compression(mut self) -> Self {
        self.compression.clear();
        self
    }

    // Connection methods
    pub fn version(mut self, version: Version) -> Self {
        self.version = version;
        self
    }

    pub fn keep_alive(mut self, keep_alive: bool) -> Self {
        self.keep_alive = keep_alive;
        if !keep_alive {
            self.default_headers.insert("Connection".to_string(), "close".to_string());
        } else {
            self.default_headers.remove("Connection");
        }
        self
    }

    pub fn tcp_nodelay(mut self, nodelay: bool) -> Self {
        self.tcp_nodelay = nodelay;
        self
    }

    pub fn tcp_keepalive(mut self, keepalive: Option<Duration>) -> Self {
        self.tcp_keepalive = keepalive;
        self
    }

    // Size limits
    pub fn max_response_size(mut self, size: Option<usize>) -> Self {
        self.max_response_size = size;
        self
    }

    // HTTP method builders
    pub fn get(&self, url: &str) -> RequestBuilder {
        RequestBuilder::new(Method::GET, url, self.clone())
    }

    pub fn post(&self, url: &str) -> RequestBuilder {
        RequestBuilder::new(Method::POST, url, self.clone())
    }

    pub fn put(&self, url: &str) -> RequestBuilder {
        RequestBuilder::new(Method::PUT, url, self.clone())
    }

    pub fn delete(&self, url: &str) -> RequestBuilder {
        RequestBuilder::new(Method::DELETE, url, self.clone())
    }

    pub fn head(&self, url: &str) -> RequestBuilder {
        RequestBuilder::new(Method::HEAD, url, self.clone())
    }

    pub fn patch(&self, url: &str) -> RequestBuilder {
        RequestBuilder::new(Method::PATCH, url, self.clone())
    }

    pub fn options(&self, url: &str) -> RequestBuilder {
        RequestBuilder::new(Method::OPTIONS, url, self.clone())
    }

    pub fn trace(&self, url: &str) -> RequestBuilder {
        RequestBuilder::new(Method::TRACE, url, self.clone())
    }

    pub fn connect(&self, url: &str) -> RequestBuilder {
        RequestBuilder::new(Method::CONNECT, url, self.clone())
    }

    pub fn request(&self, method: Method, url: &str) -> RequestBuilder {
        RequestBuilder::new(method, url, self.clone())
    }

    // Advanced configuration methods
    pub fn max_connections_per_host(mut self, max: usize) -> Self {
        self.max_connections_per_host = max;
        self.connection_pool = ConnectionPool::new(max);
        self
    }
    
    pub fn dns_cache_timeout(mut self, timeout: Option<Duration>) -> Self {
        self.dns_cache_timeout = timeout;
        self
    }
    
    pub fn with_metrics(self) -> ClientWithMetrics {
        ClientWithMetrics::new(self)
    }
    
    pub fn with_middleware(self, middleware: crate::middleware::MiddlewareChain) -> ClientWithMiddleware {
        ClientWithMiddleware::new(self, middleware)
    }

    // Utility methods
    pub fn execute(&self, request: crate::Request) -> Result<crate::Response> {
        // Execute a pre-built request using the client's configuration
        let start_time = std::time::Instant::now();
        
        // Create a request builder from the request
        let builder = RequestBuilder::from_request(request, self.clone());
        
        // Execute the request
        builder.execute_direct(start_time)
    }
}

impl Default for Client {
    fn default() -> Self {
        Self::new()
    }
}

/// Client wrapper with built-in metrics collection
#[derive(Debug)]
pub struct ClientWithMetrics {
    client: Client,
    metrics: Arc<Mutex<ClientMetrics>>,
}

#[derive(Debug, Default)]
pub struct ClientMetrics {
    pub total_requests: u64,
    pub successful_requests: u64,
    pub failed_requests: u64,
    pub total_bytes_sent: u64,
    pub total_bytes_received: u64,
    pub avg_response_time: Duration,
    pub connection_pool_hits: u64,
    pub connection_pool_misses: u64,
    pub dns_cache_hits: u64,
    pub dns_cache_misses: u64,
}

impl ClientWithMetrics {
    pub fn new(client: Client) -> Self {
        ClientWithMetrics {
            client,
            metrics: Arc::new(Mutex::new(ClientMetrics::default())),
        }
    }
    
    pub fn get_metrics(&self) -> ClientMetrics {
        self.metrics.lock().unwrap().clone()
    }
    
    pub fn reset_metrics(&self) {
        *self.metrics.lock().unwrap() = ClientMetrics::default();
    }
    
    // Delegate HTTP methods to the inner client
    pub fn get(&self, url: &str) -> RequestBuilder {
        self.client.get(url)
    }
    
    pub fn post(&self, url: &str) -> RequestBuilder {
        self.client.post(url)
    }
    
    pub fn put(&self, url: &str) -> RequestBuilder {
        self.client.put(url)
    }
    
    pub fn delete(&self, url: &str) -> RequestBuilder {
        self.client.delete(url)
    }
    
    pub fn head(&self, url: &str) -> RequestBuilder {
        self.client.head(url)
    }
    
    pub fn patch(&self, url: &str) -> RequestBuilder {
        self.client.patch(url)
    }
    
    pub fn options(&self, url: &str) -> RequestBuilder {
        self.client.options(url)
    }
    
    pub fn request(&self, method: Method, url: &str) -> RequestBuilder {
        self.client.request(method, url)
    }
}

impl Clone for ClientMetrics {
    fn clone(&self) -> Self {
        ClientMetrics {
            total_requests: self.total_requests,
            successful_requests: self.successful_requests,
            failed_requests: self.failed_requests,
            total_bytes_sent: self.total_bytes_sent,
            total_bytes_received: self.total_bytes_received,
            avg_response_time: self.avg_response_time,
            connection_pool_hits: self.connection_pool_hits,
            connection_pool_misses: self.connection_pool_misses,
            dns_cache_hits: self.dns_cache_hits,
            dns_cache_misses: self.dns_cache_misses,
        }
    }
}

/// Client wrapper with middleware support
#[derive(Debug)]
pub struct ClientWithMiddleware {
    client: Client,
    middleware: crate::middleware::MiddlewareChain,
}

impl ClientWithMiddleware {
    pub fn new(client: Client, middleware: crate::middleware::MiddlewareChain) -> Self {
        ClientWithMiddleware {
            client,
            middleware,
        }
    }
    
    // Delegate HTTP methods to the inner client
    pub fn get(&self, url: &str) -> RequestBuilder {
        self.client.get(url)
    }
    
    pub fn post(&self, url: &str) -> RequestBuilder {
        self.client.post(url)
    }
    
    pub fn put(&self, url: &str) -> RequestBuilder {
        self.client.put(url)
    }
    
    pub fn delete(&self, url: &str) -> RequestBuilder {
        self.client.delete(url)
    }
    
    pub fn head(&self, url: &str) -> RequestBuilder {
        self.client.head(url)
    }
    
    pub fn patch(&self, url: &str) -> RequestBuilder {
        self.client.patch(url)
    }
    
    pub fn options(&self, url: &str) -> RequestBuilder {
        self.client.options(url)
    }
    
    pub fn request(&self, method: Method, url: &str) -> RequestBuilder {
        self.client.request(method, url)
    }
    
    /// Get the middleware chain
    pub fn get_middleware(&self) -> &crate::middleware::MiddlewareChain {
        &self.middleware
    }
    
    /// Execute a request with middleware processing
    pub fn execute_with_middleware(&self, mut request: crate::Request) -> Result<crate::Response> {
        // Process request through middleware chain
        self.middleware.process_request(&mut request)?;
        
        // Execute the request
        let mut response = self.client.execute(request.clone())?;
        
        // Process response through middleware chain
        self.middleware.process_response(&request, &mut response)?;
        
        Ok(response)
    }
    
    /// Get the underlying client
    pub fn inner_client(&self) -> &Client {
        &self.client
    }
}

#[derive(Debug)]
pub struct ClientBuilder {
    timeout: Option<Duration>,
    connect_timeout: Option<Duration>,
    read_timeout: Option<Duration>,
    write_timeout: Option<Duration>,
    default_headers: HashMap<String, String>,
    cookie_jar: Option<CookieJar>,
    auth: Option<Auth>,
    proxy: Option<Proxy>,
    redirect_policy: RedirectPolicy,
    tls_config: TlsConfig,
    user_agent: String,
    version: Version,
    max_connections_per_host: usize,
    keep_alive: bool,
    compression: Vec<Compression>,
    max_response_size: Option<usize>,
    dns_cache_timeout: Option<Duration>,
    tcp_nodelay: bool,
    tcp_keepalive: Option<Duration>,
}

impl ClientBuilder {
    pub fn new() -> Self {
        ClientBuilder {
            timeout: Some(Duration::from_secs(30)),
            connect_timeout: Some(Duration::from_secs(10)),
            read_timeout: Some(Duration::from_secs(30)),
            write_timeout: Some(Duration::from_secs(30)),
            default_headers: HashMap::new(),
            cookie_jar: Some(CookieJar::new()),
            auth: None,
            proxy: crate::proxy::parse_proxy_env(),
            redirect_policy: RedirectPolicy::new(),
            tls_config: TlsConfig::new(),
            user_agent: "advanced-http-client/1.0.0".to_string(),
            version: Version::Http11,
            max_connections_per_host: 10,
            keep_alive: true,
            compression: vec![Compression::Gzip, Compression::Deflate],
            max_response_size: Some(10 * 1024 * 1024),
            dns_cache_timeout: Some(Duration::from_secs(300)),
            tcp_nodelay: true,
            tcp_keepalive: Some(Duration::from_secs(60)),
        }
    }

    // All the same methods as Client, but returning Self instead of Client
    pub fn timeout(mut self, timeout: Duration) -> Self {
        self.timeout = Some(timeout);
        self
    }

    pub fn connect_timeout(mut self, timeout: Duration) -> Self {
        self.connect_timeout = Some(timeout);
        self
    }

    pub fn connection_timeout(mut self, timeout: Duration) -> Self {
        self.connect_timeout = Some(timeout);
        self
    }

    pub fn read_timeout(mut self, timeout: Duration) -> Self {
        self.read_timeout = Some(timeout);
        self
    }

    pub fn write_timeout(mut self, timeout: Duration) -> Self {
        self.write_timeout = Some(timeout);
        self
    }

    pub fn default_headers(mut self, headers: HashMap<String, String>) -> Self {
        self.default_headers.extend(headers);
        self
    }

    pub fn user_agent<T: Into<String>>(mut self, user_agent: T) -> Self {
        self.user_agent = user_agent.into();
        self
    }

    pub fn cookie_jar(mut self, jar: CookieJar) -> Self {
        self.cookie_jar = Some(jar);
        self
    }

    pub fn no_cookies(mut self) -> Self {
        self.cookie_jar = None;
        self
    }

    pub fn auth(mut self, auth: Auth) -> Self {
        self.auth = Some(auth);
        self
    }

    pub fn basic_auth<U, P>(mut self, username: U, password: P) -> Self
    where
        U: Into<String>,
        P: Into<String>,
    {
        self.auth = Some(Auth::basic(&username.into(), &password.into()));
        self
    }

    pub fn bearer_auth<T: Into<String>>(mut self, token: T) -> Self {
        self.auth = Some(Auth::bearer(&token.into()));
        self
    }

    pub fn proxy(mut self, proxy: Proxy) -> Self {
        self.proxy = Some(proxy);
        self
    }

    pub fn no_proxy(mut self) -> Self {
        self.proxy = None;
        self
    }

    pub fn redirect(mut self, policy: RedirectPolicy) -> Self {
        self.redirect_policy = policy;
        self
    }

    pub fn max_redirects(mut self, max: usize) -> Self {
        self.redirect_policy.max_redirects = max;
        self
    }

    pub fn tls_config(mut self, config: TlsConfig) -> Self {
        self.tls_config = config;
        self
    }

    pub fn danger_accept_invalid_certs(mut self) -> Self {
        self.tls_config = self.tls_config.danger_accept_invalid_certs();
        self
    }

    pub fn danger_accept_invalid_hostnames(mut self) -> Self {
        self.tls_config = self.tls_config.danger_accept_invalid_hostnames();
        self
    }

    pub fn compression(mut self, compression: Vec<Compression>) -> Self {
        self.compression = compression;
        self
    }

    pub fn no_compression(mut self) -> Self {
        self.compression.clear();
        self
    }

    pub fn version(mut self, version: Version) -> Self {
        self.version = version;
        self
    }

    pub fn keep_alive(mut self, keep_alive: bool) -> Self {
        self.keep_alive = keep_alive;
        self
    }

    pub fn max_connections_per_host(mut self, max_connections: usize) -> Self {
        self.max_connections_per_host = max_connections;
        self
    }

    pub fn tcp_nodelay(mut self, nodelay: bool) -> Self {
        self.tcp_nodelay = nodelay;
        self
    }

    pub fn tcp_keepalive(mut self, keepalive: Option<Duration>) -> Self {
        self.tcp_keepalive = keepalive;
        self
    }

    pub fn max_response_size(mut self, size: Option<usize>) -> Self {
        self.max_response_size = size;
        self
    }

    pub fn pool_size(mut self, size: usize) -> Self {
        self.max_connections_per_host = size;
        self
    }
    
    pub fn enable_http2(mut self) -> Self {
        self.version = Version::Http2;
        self
    }
    
    pub fn disable_compression(mut self) -> Self {
        self.compression.clear();
        self
    }
    
    pub fn gzip_only(mut self) -> Self {
        self.compression = vec![Compression::Gzip];
        self
    }
    
    pub fn deflate_only(mut self) -> Self {
        self.compression = vec![Compression::Deflate];
        self
    }
    
    pub fn with_header<K, V>(mut self, key: K, value: V) -> Self 
    where
        K: Into<String>,
        V: Into<String>,
    {
        self.default_headers.insert(key.into(), value.into());
        self
    }

    pub fn build(self) -> Client {
        let mut default_headers = HashMap::new();
        default_headers.insert("User-Agent".to_string(), self.user_agent.clone());
        default_headers.insert("Accept".to_string(), "*/*".to_string());
        
        if !self.compression.is_empty() {
            let accept_encoding = crate::compression::parse_accept_encoding(&self.compression);
            default_headers.insert("Accept-Encoding".to_string(), accept_encoding);
        }

        if !self.keep_alive {
            default_headers.insert("Connection".to_string(), "close".to_string());
        }

        default_headers.extend(self.default_headers);

        Client {
            timeout: self.timeout,
            connect_timeout: self.connect_timeout,
            read_timeout: self.read_timeout,
            write_timeout: self.write_timeout,
            default_headers,
            cookie_jar: self.cookie_jar,
            auth: self.auth,
            proxy: self.proxy,
            redirect_policy: self.redirect_policy,
            tls_config: self.tls_config,
            user_agent: self.user_agent,
            version: self.version,
            max_connections_per_host: self.max_connections_per_host,
            keep_alive: self.keep_alive,
            compression: self.compression,
            max_response_size: self.max_response_size,
            dns_cache_timeout: self.dns_cache_timeout,
            tcp_nodelay: self.tcp_nodelay,
            tcp_keepalive: self.tcp_keepalive,
            connection_pool: ConnectionPool::new(self.max_connections_per_host),
        }
    }
    
    pub fn build_with_metrics(self) -> ClientWithMetrics {
        ClientWithMetrics::new(self.build())
    }
    
    pub fn build_with_middleware(self, middleware: crate::middleware::MiddlewareChain) -> ClientWithMiddleware {
        ClientWithMiddleware::new(self.build(), middleware)
    }
}

impl Default for ClientBuilder {
    fn default() -> Self {
        Self::new()
    }
}#[
cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_client_creation() {
        let client = Client::new();
        assert!(client.timeout.is_some());
        assert!(!client.default_headers.is_empty());
    }

    #[test]
    fn test_client_builder() {
        let client = Client::builder()
            .timeout(Duration::from_secs(60))
            .user_agent("test-agent")
            .max_redirects(5)
            .build();

        assert_eq!(client.timeout, Some(Duration::from_secs(60)));
        assert_eq!(client.user_agent, "test-agent");
        assert_eq!(client.redirect_policy.max_redirects, 5);
    }

    #[test]
    fn test_connection_pool() {
        let pool = ConnectionPool::new(5);
        assert_eq!(pool.max_connections_per_host, 5);
    }
    
    #[test]
    fn test_client_builder_enhancements() {
        let client = Client::builder()
            .pool_size(20)
            .enable_http2()
            .gzip_only()
            .with_header("X-Custom", "value")
            .build();
            
        assert_eq!(client.max_connections_per_host, 20);
        assert_eq!(client.version, Version::Http2);
        assert_eq!(client.compression, vec![Compression::Gzip]);
        assert_eq!(client.default_headers.get("X-Custom"), Some(&"value".to_string()));
    }
    
    #[test]
    fn test_client_with_metrics() {
        let client = Client::builder()
            .build_with_metrics();
            
        let metrics = client.get_metrics();
        assert_eq!(metrics.total_requests, 0);
        assert_eq!(metrics.successful_requests, 0);
        assert_eq!(metrics.failed_requests, 0);
    }
    
    #[test]
    fn test_client_metrics_reset() {
        let client = Client::builder()
            .build_with_metrics();
            
        client.reset_metrics();
        let metrics = client.get_metrics();
        assert_eq!(metrics.total_requests, 0);
    }
    
    #[test]
    fn test_client_with_middleware() {
        let middleware_chain = crate::middleware::MiddlewareChain::new();
        let client = Client::builder()
            .build_with_middleware(middleware_chain);
            
        // Test that we can access the middleware
        let middleware = client.get_middleware();
        assert_eq!(middleware.len(), 0); // Empty chain
        
        // Test that we can access the inner client
        let inner = client.inner_client();
        assert!(inner.timeout.is_some());
    }
    
    #[test]
    fn test_client_with_middleware_methods() {
        let middleware_chain = crate::middleware::MiddlewareChain::new();
        let client = Client::builder()
            .build_with_middleware(middleware_chain);
            
        // Test that all HTTP method builders work
        let _get_builder = client.get("http://example.com");
        let _post_builder = client.post("http://example.com");
        let _put_builder = client.put("http://example.com");
        let _delete_builder = client.delete("http://example.com");
        let _head_builder = client.head("http://example.com");
        let _patch_builder = client.patch("http://example.com");
        let _options_builder = client.options("http://example.com");
        let _request_builder = client.request(Method::GET, "http://example.com");
    }
}