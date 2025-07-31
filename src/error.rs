use std::fmt;
use std::io;

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug)]
pub enum Error {
    Io(io::Error),
    InvalidUrl(String),
    InvalidResponse(String),
    Timeout,
    ConnectionFailed(String),
    HttpError(u16, String),
    TlsError(String),
    ProxyError(String),
    AuthenticationError(String),
    CompressionError(String),
    JsonParseError(String),
    JsonSerializeError(String),
    TooManyRedirects(usize),
    RedirectLoop,
    InvalidHeader(String),
    InvalidCookie(String),
    MultipartError(String),
    EncodingError(String),
    CertificateError(String),
    HostnameVerificationError(String),
    WebSocketError(String),
    Http2Error(String),
    SecurityViolation(String),
    // New error types
    RateLimitExceeded(String),
    CircuitBreakerOpen(String),
    CacheError(String),
    RetryExhausted(usize),
    ConfigurationError(String),
    NetworkError(String),
    DnsResolutionError(String),
    ProtocolError(String),
    SerializationError(String),
    DeserializationError(String),
    ValidationError(String),
    ResourceExhausted(String),
    PermissionDenied(String),
    ServiceUnavailable(String),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Io(err) => write!(f, "IO error: {err}"),
            Error::InvalidUrl(msg) => write!(f, "Invalid URL: {msg}"),
            Error::InvalidResponse(msg) => write!(f, "Invalid response: {msg}"),
            Error::Timeout => write!(f, "Request timeout"),
            Error::ConnectionFailed(msg) => write!(f, "Connection failed: {msg}"),
            Error::HttpError(code, msg) => write!(f, "HTTP error {code}: {msg}"),
            Error::TlsError(msg) => write!(f, "TLS error: {msg}"),
            Error::ProxyError(msg) => write!(f, "Proxy error: {msg}"),
            Error::AuthenticationError(msg) => write!(f, "Authentication error: {msg}"),
            Error::CompressionError(msg) => write!(f, "Compression error: {msg}"),
            Error::JsonParseError(msg) => write!(f, "JSON parse error: {msg}"),
            Error::JsonSerializeError(msg) => write!(f, "JSON serialize error: {msg}"),
            Error::TooManyRedirects(count) => write!(f, "Too many redirects: {count}"),
            Error::RedirectLoop => write!(f, "Redirect loop detected"),
            Error::InvalidHeader(msg) => write!(f, "Invalid header: {msg}"),
            Error::InvalidCookie(msg) => write!(f, "Invalid cookie: {msg}"),
            Error::MultipartError(msg) => write!(f, "Multipart error: {msg}"),
            Error::EncodingError(msg) => write!(f, "Encoding error: {msg}"),
            Error::CertificateError(msg) => write!(f, "Certificate error: {msg}"),
            Error::HostnameVerificationError(msg) => write!(f, "Hostname verification error: {msg}"),
            Error::WebSocketError(msg) => write!(f, "WebSocket error: {msg}"),
            Error::Http2Error(msg) => write!(f, "HTTP/2 error: {msg}"),
            Error::SecurityViolation(msg) => write!(f, "Security violation: {msg}"),
            Error::RateLimitExceeded(msg) => write!(f, "Rate limit exceeded: {msg}"),
            Error::CircuitBreakerOpen(msg) => write!(f, "Circuit breaker open: {msg}"),
            Error::CacheError(msg) => write!(f, "Cache error: {msg}"),
            Error::RetryExhausted(attempts) => write!(f, "Retry exhausted after {attempts} attempts"),
            Error::ConfigurationError(msg) => write!(f, "Configuration error: {msg}"),
            Error::NetworkError(msg) => write!(f, "Network error: {msg}"),
            Error::DnsResolutionError(msg) => write!(f, "DNS resolution error: {msg}"),
            Error::ProtocolError(msg) => write!(f, "Protocol error: {msg}"),
            Error::SerializationError(msg) => write!(f, "Serialization error: {msg}"),
            Error::DeserializationError(msg) => write!(f, "Deserialization error: {msg}"),
            Error::ValidationError(msg) => write!(f, "Validation error: {msg}"),
            Error::ResourceExhausted(msg) => write!(f, "Resource exhausted: {msg}"),
            Error::PermissionDenied(msg) => write!(f, "Permission denied: {msg}"),
            Error::ServiceUnavailable(msg) => write!(f, "Service unavailable: {msg}"),
        }
    }
}

impl std::error::Error for Error {}

impl Clone for Error {
    fn clone(&self) -> Self {
        match self {
            Error::Io(e) => Error::Io(io::Error::new(e.kind(), e.to_string())),
            Error::InvalidUrl(msg) => Error::InvalidUrl(msg.clone()),
            Error::InvalidResponse(msg) => Error::InvalidResponse(msg.clone()),
            Error::Timeout => Error::Timeout,
            Error::ConnectionFailed(msg) => Error::ConnectionFailed(msg.clone()),
            Error::HttpError(code, msg) => Error::HttpError(*code, msg.clone()),
            Error::TlsError(msg) => Error::TlsError(msg.clone()),
            Error::ProxyError(msg) => Error::ProxyError(msg.clone()),
            Error::AuthenticationError(msg) => Error::AuthenticationError(msg.clone()),
            Error::CompressionError(msg) => Error::CompressionError(msg.clone()),
            Error::JsonParseError(msg) => Error::JsonParseError(msg.clone()),
            Error::JsonSerializeError(msg) => Error::JsonSerializeError(msg.clone()),
            Error::TooManyRedirects(count) => Error::TooManyRedirects(*count),
            Error::RedirectLoop => Error::RedirectLoop,
            Error::InvalidHeader(msg) => Error::InvalidHeader(msg.clone()),
            Error::InvalidCookie(msg) => Error::InvalidCookie(msg.clone()),
            Error::MultipartError(msg) => Error::MultipartError(msg.clone()),
            Error::EncodingError(msg) => Error::EncodingError(msg.clone()),
            Error::CertificateError(msg) => Error::CertificateError(msg.clone()),
            Error::HostnameVerificationError(msg) => Error::HostnameVerificationError(msg.clone()),
            Error::WebSocketError(msg) => Error::WebSocketError(msg.clone()),
            Error::Http2Error(msg) => Error::Http2Error(msg.clone()),
            Error::SecurityViolation(msg) => Error::SecurityViolation(msg.clone()),
            Error::RateLimitExceeded(msg) => Error::RateLimitExceeded(msg.clone()),
            Error::CircuitBreakerOpen(msg) => Error::CircuitBreakerOpen(msg.clone()),
            Error::CacheError(msg) => Error::CacheError(msg.clone()),
            Error::RetryExhausted(attempts) => Error::RetryExhausted(*attempts),
            Error::ConfigurationError(msg) => Error::ConfigurationError(msg.clone()),
            Error::NetworkError(msg) => Error::NetworkError(msg.clone()),
            Error::DnsResolutionError(msg) => Error::DnsResolutionError(msg.clone()),
            Error::ProtocolError(msg) => Error::ProtocolError(msg.clone()),
            Error::SerializationError(msg) => Error::SerializationError(msg.clone()),
            Error::DeserializationError(msg) => Error::DeserializationError(msg.clone()),
            Error::ValidationError(msg) => Error::ValidationError(msg.clone()),
            Error::ResourceExhausted(msg) => Error::ResourceExhausted(msg.clone()),
            Error::PermissionDenied(msg) => Error::PermissionDenied(msg.clone()),
            Error::ServiceUnavailable(msg) => Error::ServiceUnavailable(msg.clone()),
        }
    }
}

impl From<io::Error> for Error {
    fn from(err: io::Error) -> Self {
        Error::Io(err)
    }
}

impl Error {
    /// Check if the error is retryable
    pub fn is_retryable(&self) -> bool {
        match self {
            Error::Timeout |
            Error::ConnectionFailed(_) |
            Error::NetworkError(_) |
            Error::DnsResolutionError(_) |
            Error::ServiceUnavailable(_) => true,
            Error::HttpError(status, _) if *status >= 500 => true,
            _ => false,
        }
    }
    
    /// Check if the error is a client error (4xx)
    pub fn is_client_error(&self) -> bool {
        match self {
            Error::HttpError(status, _) if *status >= 400 && *status < 500 => true,
            Error::AuthenticationError(_) |
            Error::ValidationError(_) |
            Error::PermissionDenied(_) => true,
            _ => false,
        }
    }
    
    /// Check if the error is a server error (5xx)
    pub fn is_server_error(&self) -> bool {
        match self {
            Error::HttpError(status, _) if *status >= 500 => true,
            Error::ServiceUnavailable(_) => true,
            _ => false,
        }
    }
    
    /// Check if the error is a network-related error
    pub fn is_network_error(&self) -> bool {
        matches!(self, Error::Io(_) |
            Error::ConnectionFailed(_) |
            Error::NetworkError(_) |
            Error::DnsResolutionError(_) |
            Error::Timeout)
    }
    
    /// Get the HTTP status code if this is an HTTP error
    pub fn status_code(&self) -> Option<u16> {
        match self {
            Error::HttpError(status, _) => Some(*status),
            _ => None,
        }
    }
    
    /// Create a timeout error
    pub fn timeout() -> Self {
        Error::Timeout
    }
    
    /// Create a connection failed error
    pub fn connection_failed<S: Into<String>>(msg: S) -> Self {
        Error::ConnectionFailed(msg.into())
    }
    
    /// Create an HTTP error
    pub fn http_error(status: u16, message: String) -> Self {
        Error::HttpError(status, message)
    }
    
    /// Create a rate limit exceeded error
    pub fn rate_limit_exceeded<S: Into<String>>(msg: S) -> Self {
        Error::RateLimitExceeded(msg.into())
    }
    
    /// Create a circuit breaker open error
    pub fn circuit_breaker_open<S: Into<String>>(msg: S) -> Self {
        Error::CircuitBreakerOpen(msg.into())
    }
    
    /// Create a retry exhausted error
    pub fn retry_exhausted(attempts: usize) -> Self {
        Error::RetryExhausted(attempts)
    }
}#[cfg
(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_display() {
        let error = Error::timeout();
        assert_eq!(error.to_string(), "Request timeout");
        
        let error = Error::http_error(404, "Not Found".to_string());
        assert_eq!(error.to_string(), "HTTP error 404: Not Found");
    }

    #[test]
    fn test_error_classification() {
        let timeout_error = Error::timeout();
        assert!(timeout_error.is_retryable());
        assert!(timeout_error.is_network_error());
        assert!(!timeout_error.is_client_error());
        assert!(!timeout_error.is_server_error());

        let client_error = Error::http_error(400, "Bad Request".to_string());
        assert!(!client_error.is_retryable());
        assert!(client_error.is_client_error());
        assert!(!client_error.is_server_error());
        assert_eq!(client_error.status_code(), Some(400));

        let server_error = Error::http_error(500, "Internal Server Error".to_string());
        assert!(server_error.is_retryable());
        assert!(!server_error.is_client_error());
        assert!(server_error.is_server_error());
        assert_eq!(server_error.status_code(), Some(500));
    }

    #[test]
    fn test_error_creation_helpers() {
        let error = Error::connection_failed("Connection refused");
        assert!(matches!(error, Error::ConnectionFailed(_)));
        
        let error = Error::rate_limit_exceeded("Too many requests");
        assert!(matches!(error, Error::RateLimitExceeded(_)));
        
        let error = Error::circuit_breaker_open("Service unavailable");
        assert!(matches!(error, Error::CircuitBreakerOpen(_)));
        
        let error = Error::retry_exhausted(3);
        assert!(matches!(error, Error::RetryExhausted(3)));
    }

    #[test]
    fn test_error_clone() {
        let original = Error::http_error(404, "Not Found".to_string());
        let cloned = original.clone();
        
        assert_eq!(original.to_string(), cloned.to_string());
        assert_eq!(original.status_code(), cloned.status_code());
    }
}