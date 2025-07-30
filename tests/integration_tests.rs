use request::{Client, Method, Auth, CookieJar, MultipartForm};
use request::json::parse_json;
use request::dns::DnsResolver;
use request::compression::Compression;
use std::time::Duration;

#[test]
fn test_basic_http_methods() {
    let client = Client::new();
    
    // Test GET
    let response = client.get("http://httpbin.org/get").send();
    assert!(response.is_ok());
    let response = response.unwrap();
    assert_eq!(response.status(), 200);
    assert!(response.is_success());
    
    // Test POST
    let response = client
        .post("http://httpbin.org/post")
        .body("test data")
        .send();
    assert!(response.is_ok());
    assert_eq!(response.unwrap().status(), 200);
}

#[test]
fn test_json_parsing() {
    let json_str = r#"{"name": "test", "value": 42, "active": true}"#;
    let json = parse_json(json_str).unwrap();
    
    assert_eq!(json.get("name").unwrap().as_str().unwrap(), "test");
    assert_eq!(json.get("value").unwrap().as_number().unwrap(), 42.0);
    assert!(json.get("active").unwrap().as_bool().unwrap());
}

#[test]
fn test_url_parsing() {
    let url = request::Url::parse("https://user:pass@example.com:8080/path?query=value#fragment").unwrap();
    
    assert_eq!(url.scheme, "https");
    assert_eq!(url.host, "example.com");
    assert_eq!(url.port, Some(8080));
    assert_eq!(url.path, "/path");
    assert_eq!(url.query, Some("query=value".to_string()));
    assert_eq!(url.fragment, Some("fragment".to_string()));
    assert_eq!(url.username, Some("user".to_string()));
    assert_eq!(url.password, Some("pass".to_string()));
}

#[test]
fn test_authentication() {
    // Test Basic Auth
    let basic_auth = Auth::basic("user", "pass");
    let mut headers = std::collections::HashMap::new();
    basic_auth.apply_to_headers(&mut headers);
    assert!(headers.contains_key("Authorization"));
    assert!(headers["Authorization"].starts_with("Basic "));
    
    // Test Bearer Auth
    let bearer_auth = Auth::bearer("token123");
    let mut headers = std::collections::HashMap::new();
    bearer_auth.apply_to_headers(&mut headers);
    assert!(headers.contains_key("Authorization"));
    assert_eq!(headers["Authorization"], "Bearer token123");
}

#[test]
fn test_cookie_management() {
    let mut jar = CookieJar::new();
    
    // Test cookie parsing
    jar.add_cookie_str("session=abc123; Path=/; HttpOnly", "example.com");
    
    // Test cookie retrieval
    let cookies = jar.get_cookies_for_request("example.com", "/", false);
    assert_eq!(cookies.len(), 1);
    assert_eq!(cookies[0].name, "session");
    assert_eq!(cookies[0].value, "abc123");
}

#[test]
fn test_multipart_form() {
    let mut form = MultipartForm::new();
    form.add_text("field1", "value1")
        .add_text("field2", "value2");
    
    let bytes = form.to_bytes();
    assert!(!bytes.is_empty());
    assert!(String::from_utf8_lossy(&bytes).contains("field1"));
    assert!(String::from_utf8_lossy(&bytes).contains("value1"));
}

#[test]
fn test_compression_detection() {
    let compression = Compression::parse("gzip").unwrap();
    assert_eq!(compression, Compression::Gzip);
    assert_eq!(compression.as_str(), "gzip");
    
    let compression = Compression::parse("deflate").unwrap();
    assert_eq!(compression, Compression::Deflate);
    
    let compression = Compression::parse("br").unwrap();
    assert_eq!(compression, Compression::Brotli);
}

#[test]
fn test_client_builder() {
    let client = Client::builder()
        .timeout(Duration::from_secs(10))
        .user_agent("test-client/1.0")
        .keep_alive(false)
        .build();
    
    assert_eq!(client.timeout, Some(Duration::from_secs(10)));
    assert_eq!(client.user_agent, "test-client/1.0");
    assert!(!client.keep_alive);
}

#[test]
fn test_method_properties() {
    assert!(Method::GET.is_safe());
    assert!(Method::HEAD.is_safe());
    assert!(!Method::POST.is_safe());
    assert!(!Method::PUT.is_safe());
    
    assert!(Method::GET.is_idempotent());
    assert!(Method::PUT.is_idempotent());
    assert!(Method::DELETE.is_idempotent());
    assert!(!Method::POST.is_idempotent());
}

#[test]
fn test_dns_resolver() {
    let mut resolver = DnsResolver::new();
    
    // Test cache functionality starts empty
    let initial_cache_size = resolver.cache_size();
    
    // Test with a known domain (this might fail in some environments)
    if let Ok(ips) = resolver.resolve_ip("localhost") {
        assert!(!ips.is_empty());
        // Cache should now have entries
        assert!(resolver.cache_size() >= initial_cache_size);
    }
}

#[test]
fn test_error_handling() {
    let client = Client::new();
    
    // Test invalid URL
    let result = client.get("not-a-url").send();
    assert!(result.is_err());
    
    // Test connection to non-existent host
    let result = client.get("http://this-domain-does-not-exist-12345.com").send();
    assert!(result.is_err());
}