use crate::compression::decompress_response;
use crate::json::{parse_json, JsonValue};
use crate::{Cookie, Error, Result, Url, Version};
use std::collections::HashMap;
use std::time::Duration;

#[derive(Debug)]
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

    // Status check methods
    pub fn is_informational(&self) -> bool {
        self.status >= 100 && self.status < 200
    }

    pub fn is_success(&self) -> bool {
        self.status >= 200 && self.status < 300
    }

    pub fn is_redirection(&self) -> bool {
        self.status >= 300 && self.status < 400
    }

    pub fn is_client_error(&self) -> bool {
        self.status >= 400 && self.status < 500
    }

    pub fn is_server_error(&self) -> bool {
        self.status >= 500 && self.status < 600
    }

    pub fn is_error(&self) -> bool {
        self.status >= 400
    }

    // Content methods
    pub fn content_length(&self) -> Option<usize> {
        self.header("content-length").and_then(|v| v.parse().ok())
    }

    pub fn content_type(&self) -> Option<&String> {
        self.header("content-type")
    }

    pub fn content_encoding(&self) -> Option<&String> {
        self.header("content-encoding")
    }

    pub fn charset(&self) -> Option<String> {
        self.content_type().and_then(|ct| {
            ct.split(';')
                .find(|part| part.trim().starts_with("charset="))
                .map(|part| part.trim()[8..].trim_matches('"').to_string())
        })
    }

    // Cookie methods
    pub fn cookies(&self) -> &[Cookie] {
        &self.cookies
    }

    pub fn cookie(&self, name: &str) -> Option<&Cookie> {
        self.cookies.iter().find(|c| c.name == name)
    }

    // Cache methods
    pub fn cache_control(&self) -> Option<&String> {
        self.header("cache-control")
    }

    pub fn etag(&self) -> Option<&String> {
        self.header("etag")
    }

    pub fn last_modified(&self) -> Option<&String> {
        self.header("last-modified")
    }

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

    // Utility methods
    pub fn error_for_status(self) -> Result<Self> {
        if self.is_error() {
            Err(Error::HttpError(self.status, self.status_text.clone()))
        } else {
            Ok(self)
        }
    }

    pub fn into_body(self) -> Vec<u8> {
        self.body
    }

    pub fn body_len(&self) -> usize {
        self.body.len()
    }

    pub fn is_empty(&self) -> bool {
        self.body.is_empty()
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
