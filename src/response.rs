use crate::compression::decompress_response;
use crate::json::{parse_json, JsonValue};
use crate::{Cookie, Error, Result, Url, Version};
use std::collections::HashMap;
use std::time::Duration;

#[derive(Debug, Clone)]
pub struct Response {
    pub status: u16,
    pub status_text: String,
    pub headers: HashMap<String, String>,
    pub body: Vec<u8>,
    pub version: Version,
    pub url: Url,
    pub remote_addr: Option<String>,
    pub elapsed: Duration,
    pub cookies: Vec<Cookie>,
}

impl Response {
    pub fn new(
        status: u16,
        status_text: String,
        headers: HashMap<String, String>,
        body: Vec<u8>,
    ) -> Self {
        Response {
            status,
            status_text,
            headers,
            body,
            version: Version::Http11,
            url: Url::parse("http://unknown").unwrap_or_else(|_| Url {
                scheme: "http".to_string(),
                host: "unknown".to_string(),
                port: Some(80),
                path: "/".to_string(),
                query: None,
                fragment: None,
                username: None,
                password: None,
            }),
            remote_addr: None,
            elapsed: Duration::from_secs(0),
            cookies: Vec::new(),
        }
    }

    pub fn with_url(mut self, url: Url) -> Self {
        self.url = url;
        self
    }

    pub fn with_version(mut self, version: Version) -> Self {
        self.version = version;
        self
    }

    pub fn with_remote_addr(mut self, addr: String) -> Self {
        self.remote_addr = Some(addr);
        self
    }

    pub fn with_elapsed(mut self, elapsed: Duration) -> Self {
        self.elapsed = elapsed;
        self
    }

    pub fn with_cookies(mut self, cookies: Vec<Cookie>) -> Self {
        self.cookies = cookies;
        self
    }

    // Status methods
    pub fn status(&self) -> u16 {
        self.status
    }

    pub fn status_text(&self) -> &str {
        &self.status_text
    }

    // Cookie methods
    pub fn cookies(&self) -> &[Cookie] {
        &self.cookies
    }

    pub fn version(&self) -> Version {
        self.version
    }

    pub fn url(&self) -> &Url {
        &self.url
    }

    pub fn remote_addr(&self) -> Option<&str> {
        self.remote_addr.as_deref()
    }

    pub fn elapsed(&self) -> Duration {
        self.elapsed
    }

    // Header methods
    pub fn headers(&self) -> &HashMap<String, String> {
        &self.headers
    }

    pub fn header(&self, name: &str) -> Option<&String> {
        // Case-insensitive header lookup
        self.headers
            .iter()
            .find(|(k, _)| k.to_lowercase() == name.to_lowercase())
            .map(|(_, v)| v)
    }

    pub fn header_values(&self, name: &str) -> Vec<&str> {
        self.headers
            .iter()
            .filter(|(k, _)| k.to_lowercase() == name.to_lowercase())
            .map(|(_, v)| v.as_str())
            .collect()
    }

    // Body methods
    pub fn bytes(&self) -> &[u8] {
        &self.body
    }

    pub fn text(&self) -> Result<String> {
        // Handle decompression if needed
        let body = if let Some(encoding) = self.header("content-encoding") {
            decompress_response(&self.body, encoding)?
        } else {
            self.body.clone()
        };

        String::from_utf8(body)
            .map_err(|_| Error::InvalidResponse("Invalid UTF-8 in response body".to_string()))
    }

    pub fn text_with_charset(&self, charset: &str) -> Result<String> {
        // Basic charset handling - in a real implementation you'd use encoding_rs
        match charset.to_lowercase().as_str() {
            "utf-8" | "utf8" => self.text(),
            _ => {
                // For now, just try UTF-8
                self.text()
            }
        }
    }

    pub fn json(&self) -> Result<JsonValue> {
        let text = self.text()?;
        parse_json(&text)
    }
    
    /// Get the content type of the response
    pub fn content_type(&self) -> Option<&String> {
        self.header("content-type")
    }
    
    /// Get the content length of the response
    pub fn content_length(&self) -> Option<usize> {
        self.header("content-length")
            .and_then(|s| s.parse().ok())
    }
    
    /// Get the ETag of the response
    pub fn etag(&self) -> Option<&String> {
        self.header("etag")
    }
    
    /// Get the Last-Modified header
    pub fn last_modified(&self) -> Option<&String> {
        self.header("last-modified")
    }
    
    /// Get the Cache-Control header
    pub fn cache_control(&self) -> Option<&String> {
        self.header("cache-control")
    }
    
    /// Get the Location header (for redirects)
    pub fn location(&self) -> Option<&String> {
        self.header("location")
    }
    
    /// Check if the response is successful (2xx status)
    pub fn is_success(&self) -> bool {
        self.status >= 200 && self.status < 300
    }
    
    /// Check if the response is a redirect (3xx status)
    pub fn is_redirect(&self) -> bool {
        self.status >= 300 && self.status < 400
    }
    
    /// Check if the response is a client error (4xx status)
    pub fn is_client_error(&self) -> bool {
        self.status >= 400 && self.status < 500
    }
    
    /// Check if the response is a server error (5xx status)
    pub fn is_server_error(&self) -> bool {
        self.status >= 500 && self.status < 600
    }
    
    /// Check if the response indicates an error (4xx or 5xx)
    pub fn is_error(&self) -> bool {
        self.status >= 400
    }
    
    /// Get the response size in bytes
    pub fn size(&self) -> usize {
        self.body.len()
    }
    
    /// Check if the response body is empty
    pub fn is_empty(&self) -> bool {
        self.body.is_empty()
    }
    
    /// Get the charset from Content-Type header
    pub fn charset(&self) -> Option<String> {
        self.content_type()
            .and_then(|ct| {
                ct.split(';')
                    .find(|part| part.trim().starts_with("charset="))
                    .map(|charset_part| {
                        charset_part.trim()
                            .strip_prefix("charset=")
                            .unwrap_or("")
                            .trim_matches('"')
                            .to_string()
                    })
            })
    }
    
    /// Check if the response is JSON
    pub fn is_json(&self) -> bool {
        self.content_type()
            .map(|ct| ct.contains("application/json") || ct.contains("text/json"))
            .unwrap_or(false)
    }
    
    /// Check if the response is HTML
    pub fn is_html(&self) -> bool {
        self.content_type()
            .map(|ct| ct.contains("text/html"))
            .unwrap_or(false)
    }
    
    /// Check if the response is XML
    pub fn is_xml(&self) -> bool {
        self.content_type()
            .map(|ct| ct.contains("application/xml") || ct.contains("text/xml"))
            .unwrap_or(false)
    }
    
    /// Check if the response is plain text
    pub fn is_text(&self) -> bool {
        self.content_type()
            .map(|ct| ct.contains("text/plain"))
            .unwrap_or(false)
    }
    
    /// Get response as bytes with automatic decompression
    pub fn bytes_decompressed(&self) -> Result<Vec<u8>> {
        if let Some(encoding) = self.header("content-encoding") {
            decompress_response(&self.body, encoding)
        } else {
            Ok(self.body.clone())
        }
    }
    
    /// Save response body to a file
    pub fn save_to_file(&self, path: &str) -> Result<()> {
        use std::fs::File;
        use std::io::Write;
        
        let mut file = File::create(path)
            .map_err(Error::Io)?;
        
        let body = self.bytes_decompressed()?;
        file.write_all(&body)
            .map_err(Error::Io)?;
        
        Ok(())
    }
    
    /// Get response headers as a formatted string
    pub fn headers_string(&self) -> String {
        let mut result = String::new();
        for (key, value) in &self.headers {
            result.push_str(&format!("{key}: {value}\n"));
        }
        result
    }
    
    /// Get a debug representation of the response
    pub fn to_debug_string(&self) -> String {
        let mut debug = format!("HTTP/{} {} {}\n", 
            self.version.as_str(), 
            self.status, 
            self.status_text
        );
        
        debug.push_str(&self.headers_string());
        debug.push('\n');
        
        if self.body.len() > 1000 {
            debug.push_str(&format!("[Body: {} bytes]", self.body.len()));
        } else if let Ok(text) = self.text() {
            debug.push_str(&text);
        } else {
            debug.push_str(&format!("[Binary body: {} bytes]", self.body.len()));
        }
        
        debug
    }
    
    /// Create an error from this response if it's an error status
    pub fn error_for_status(self) -> Result<Self> {
        if self.is_error() {
            let message = if let Ok(text) = self.text() {
                if text.len() > 200 {
                    format!("{}...", &text[..200])
                } else {
                    text
                }
            } else {
                self.status_text.clone()
            };
            
            Err(Error::HttpError(self.status, message))
        } else {
            Ok(self)
        }
    }
    
    /// Get the expires header
    pub fn expires(&self) -> Option<&String> {
        self.header("expires")
    }

    // Security headers
    pub fn content_security_policy(&self) -> Option<&String> {
        self.header("content-security-policy")
    }

    pub fn strict_transport_security(&self) -> Option<&String> {
        self.header("strict-transport-security")
    }

    pub fn x_frame_options(&self) -> Option<&String> {
        self.header("x-frame-options")
    }

    pub fn x_content_type_options(&self) -> Option<&String> {
        self.header("x-content-type-options")
    }

    // CORS headers
    pub fn access_control_allow_origin(&self) -> Option<&String> {
        self.header("access-control-allow-origin")
    }

    pub fn access_control_allow_methods(&self) -> Option<&String> {
        self.header("access-control-allow-methods")
    }

    pub fn access_control_allow_headers(&self) -> Option<&String> {
        self.header("access-control-allow-headers")
    }

    // Server information
    pub fn server(&self) -> Option<&String> {
        self.header("server")
    }

    pub fn powered_by(&self) -> Option<&String> {
        self.header("x-powered-by")
    }

    /// Convert response into its body
    pub fn into_body(self) -> Vec<u8> {
        self.body
    }

    /// Get body length (alias for size)
    pub fn body_len(&self) -> usize {
        self.body.len()
    }

    // Stream-like methods (for future implementation)
    pub fn chunk_size(&self) -> Option<usize> {
        // For chunked transfer encoding
        if self
            .header("transfer-encoding")
            .map(|v| v.to_lowercase().contains("chunked"))
            .unwrap_or(false)
        {
            Some(8192) // Default chunk size
        } else {
            None
        }
    }

    // Response metadata
    pub fn response_time(&self) -> Duration {
        self.elapsed
    }

    pub fn response_time_ms(&self) -> u64 {
        self.elapsed.as_millis() as u64
    }

    // Debug helpers
    pub fn debug_headers(&self) -> String {
        let mut result = String::new();
        for (key, value) in &self.headers {
            result.push_str(&format!("{key}: {value}\n"));
        }
        result
    }

    pub fn debug_summary(&self) -> String {
        format!(
            "HTTP/{} {} {} ({}ms, {} bytes)",
            match self.version {
                Version::Http10 => "1.0",
                Version::Http11 => "1.1",
                Version::Http2 => "2.0",
            },
            self.status,
            self.status_text,
            self.response_time_ms(),
            self.body_len()
        )
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn create_test_response(status: u16, headers: HashMap<String, String>, body: &str) -> Response {
        Response::new(
            status,
            "OK".to_string(),
            headers,
            body.as_bytes().to_vec(),
        )
    }

    #[test]
    fn test_response_creation() {
        let response = create_test_response(200, HashMap::new(), "test body");
        
        assert_eq!(response.status(), 200);
        assert_eq!(response.status_text(), "OK");
        assert_eq!(response.text().unwrap(), "test body");
        assert_eq!(response.size(), 9);
    }

    #[test]
    fn test_response_status_checks() {
        let success = create_test_response(200, HashMap::new(), "");
        assert!(success.is_success());
        assert!(!success.is_error());
        assert!(!success.is_redirect());
        assert!(!success.is_client_error());
        assert!(!success.is_server_error());

        let redirect = create_test_response(301, HashMap::new(), "");
        assert!(!redirect.is_success());
        assert!(!redirect.is_error());
        assert!(redirect.is_redirect());

        let client_error = create_test_response(404, HashMap::new(), "");
        assert!(!client_error.is_success());
        assert!(client_error.is_error());
        assert!(client_error.is_client_error());
        assert!(!client_error.is_server_error());

        let server_error = create_test_response(500, HashMap::new(), "");
        assert!(!server_error.is_success());
        assert!(server_error.is_error());
        assert!(!server_error.is_client_error());
        assert!(server_error.is_server_error());
    }

    #[test]
    fn test_response_headers() {
        let mut headers = HashMap::new();
        headers.insert("Content-Type".to_string(), "application/json; charset=utf-8".to_string());
        headers.insert("Content-Length".to_string(), "100".to_string());
        headers.insert("ETag".to_string(), "\"abc123\"".to_string());
        
        let response = create_test_response(200, headers, "{}");
        
        assert_eq!(response.content_type(), Some(&"application/json; charset=utf-8".to_string()));
        assert_eq!(response.content_length(), Some(100));
        assert_eq!(response.etag(), Some(&"\"abc123\"".to_string()));
        assert_eq!(response.charset(), Some("utf-8".to_string()));
    }

    #[test]
    fn test_response_content_type_checks() {
        let mut json_headers = HashMap::new();
        json_headers.insert("Content-Type".to_string(), "application/json".to_string());
        let json_response = create_test_response(200, json_headers, "{}");
        assert!(json_response.is_json());
        assert!(!json_response.is_html());
        assert!(!json_response.is_xml());
        assert!(!json_response.is_text());

        let mut html_headers = HashMap::new();
        html_headers.insert("Content-Type".to_string(), "text/html".to_string());
        let html_response = create_test_response(200, html_headers, "<html></html>");
        assert!(!html_response.is_json());
        assert!(html_response.is_html());
        assert!(!html_response.is_xml());
        assert!(!html_response.is_text());

        let mut xml_headers = HashMap::new();
        xml_headers.insert("Content-Type".to_string(), "application/xml".to_string());
        let xml_response = create_test_response(200, xml_headers, "<xml></xml>");
        assert!(!xml_response.is_json());
        assert!(!xml_response.is_html());
        assert!(xml_response.is_xml());
        assert!(!xml_response.is_text());

        let mut text_headers = HashMap::new();
        text_headers.insert("Content-Type".to_string(), "text/plain".to_string());
        let text_response = create_test_response(200, text_headers, "plain text");
        assert!(!text_response.is_json());
        assert!(!text_response.is_html());
        assert!(!text_response.is_xml());
        assert!(text_response.is_text());
    }

    #[test]
    fn test_response_json_parsing() {
        let mut headers = HashMap::new();
        headers.insert("Content-Type".to_string(), "application/json".to_string());
        
        let response = create_test_response(200, headers, r#"{"key": "value", "number": 42}"#);
        let json = response.json().unwrap();
        
        // Basic JSON parsing test - in a real implementation you'd have more sophisticated JSON handling
        assert!(json.to_string().contains("key"));
        assert!(json.to_string().contains("value"));
    }

    #[test]
    fn test_response_error_for_status() {
        let success = create_test_response(200, HashMap::new(), "success");
        assert!(success.error_for_status().is_ok());

        let error = create_test_response(404, HashMap::new(), "Not Found");
        let result = error.error_for_status();
        assert!(result.is_err());
        
        if let Err(Error::HttpError(status, message)) = result {
            assert_eq!(status, 404);
            assert_eq!(message, "Not Found");
        } else {
            panic!("Expected HttpError");
        }
    }

    #[test]
    fn test_response_debug_string() {
        let mut headers = HashMap::new();
        headers.insert("Content-Type".to_string(), "text/plain".to_string());
        
        let response = create_test_response(200, headers, "test body");
        let debug_str = response.to_debug_string();
        
        assert!(debug_str.contains("HTTP/1.1 200 OK"));
        assert!(debug_str.contains("Content-Type: text/plain"));
        assert!(debug_str.contains("test body"));
    }

    #[test]
    fn test_response_empty_body() {
        let response = create_test_response(204, HashMap::new(), "");
        
        assert!(response.is_empty());
        assert_eq!(response.size(), 0);
        assert_eq!(response.text().unwrap(), "");
    }

    #[test]
    fn test_response_case_insensitive_headers() {
        let mut headers = HashMap::new();
        headers.insert("Content-Type".to_string(), "application/json".to_string());
        
        let response = create_test_response(200, headers, "{}");
        
        assert_eq!(response.header("content-type"), Some(&"application/json".to_string()));
        assert_eq!(response.header("Content-Type"), Some(&"application/json".to_string()));
        assert_eq!(response.header("CONTENT-TYPE"), Some(&"application/json".to_string()));
    }

    #[test]
    fn test_response_builder_methods() {
        let url = Url::parse("https://example.com").unwrap();
        let response = create_test_response(200, HashMap::new(), "test")
            .with_url(url.clone())
            .with_version(Version::Http2)
            .with_remote_addr("192.168.1.1:80".to_string())
            .with_elapsed(Duration::from_millis(500));
        
        assert_eq!(response.url().host, "example.com");
        assert_eq!(response.version(), Version::Http2);
        assert_eq!(response.remote_addr(), Some("192.168.1.1:80"));
        assert_eq!(response.elapsed(), Duration::from_millis(500));
    }
}