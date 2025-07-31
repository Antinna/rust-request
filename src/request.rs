use crate::{Client, Error, Method, Response, Result, Url, Auth, MultipartForm, JsonValue, Cookie};
use crate::redirect::{RedirectHandler, get_redirect_method, is_sensitive_header};
use crate::compression::{Compression, compress_request_body};
use std::collections::HashMap;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpStream;
use std::time::{Duration, Instant};

// Trait to abstract over HTTP and HTTPS streams
trait HttpStream: Read + Write {
    fn set_timeouts(&mut self, read: Option<Duration>, write: Option<Duration>) -> std::io::Result<()>;
}

impl HttpStream for TcpStream {
    fn set_timeouts(&mut self, read: Option<Duration>, write: Option<Duration>) -> std::io::Result<()> {
        if let Some(timeout) = read {
            self.set_read_timeout(Some(timeout))?;
        }
        if let Some(timeout) = write {
            self.set_write_timeout(Some(timeout))?;
        }
        Ok(())
    }
}

impl HttpStream for crate::tls::TlsStream {
    fn set_timeouts(&mut self, _read: Option<Duration>, _write: Option<Duration>) -> std::io::Result<()> {
        // TLS stream timeout handling would be implemented here
        // For now, we'll just return Ok
        Ok(())
    }
}

#[derive(Debug, Clone)]
pub struct Request {
    pub method: Method,
    pub url: Url,
    pub headers: HashMap<String, String>,
    pub body: Option<Vec<u8>>,
}

impl Request {
    pub fn new(method: Method, url: Url) -> Self {
        Request {
            method,
            url,
            headers: HashMap::new(),
            body: None,
        }
    }
    
    /// Get a header value
    pub fn header(&self, name: &str) -> Option<&String> {
        self.headers.get(name)
    }
    
    /// Get a header value (case-insensitive)
    pub fn header_ignore_case(&self, name: &str) -> Option<&String> {
        let name_lower = name.to_lowercase();
        self.headers.iter()
            .find(|(k, _)| k.to_lowercase() == name_lower)
            .map(|(_, v)| v)
    }
    
    /// Check if request has a body
    pub fn has_body(&self) -> bool {
        self.body.is_some() && !self.body.as_ref().unwrap().is_empty()
    }
    
    /// Get body size
    pub fn body_size(&self) -> usize {
        self.body.as_ref().map(|b| b.len()).unwrap_or(0)
    }
    
    /// Get content type
    pub fn content_type(&self) -> Option<&String> {
        self.header_ignore_case("content-type")
    }
    
    /// Check if request is secure (HTTPS)
    pub fn is_secure(&self) -> bool {
        self.url.is_secure()
    }
    
    /// Get the full request line (for debugging)
    pub fn request_line(&self) -> String {
        format!("{} {} HTTP/1.1", self.method.as_str(), self.url.full_path())
    }
    
    /// Convert to a debug-friendly string
    pub fn to_debug_string(&self) -> String {
        let mut debug = format!("{}\n", self.request_line());
        debug.push_str(&format!("Host: {}\n", self.url.host));
        
        for (key, value) in &self.headers {
            debug.push_str(&format!("{key}: {value}\n"));
        }
        
        if let Some(ref body) = self.body {
            debug.push('\n');
            if body.len() > 1000 {
                debug.push_str(&format!("[Body: {} bytes]", body.len()));
            } else {
                debug.push_str(&String::from_utf8_lossy(body));
            }
        }
        
        debug
    }
    
    /// Clone the request
    pub fn try_clone(&self) -> Result<Self> {
        Ok(Request {
            method: self.method,
            url: self.url.clone(),
            headers: self.headers.clone(),
            body: self.body.clone(),
        })
    }
}

#[derive(Debug)]
pub struct RequestBuilder {
    method: Method,
    url: String,
    headers: HashMap<String, String>,
    query_params: HashMap<String, String>,
    body: Option<Vec<u8>>,
    client: Client,
}

impl RequestBuilder {
    pub fn new(method: Method, url: &str, client: Client) -> Self {
        RequestBuilder {
            method,
            url: url.to_string(),
            headers: HashMap::new(),
            query_params: HashMap::new(),
            body: None,
            client,
        }
    }
    
    /// Validate the request before sending
    pub fn validate(&self) -> Result<()> {
        // Validate URL
        Url::parse(&self.url)?;
        
        // Validate headers
        for (key, value) in &self.headers {
            if key.is_empty() {
                return Err(Error::InvalidHeader("Header name cannot be empty".to_string()));
            }
            if value.contains('\n') || value.contains('\r') {
                return Err(Error::InvalidHeader("Header value cannot contain newlines".to_string()));
            }
        }
        
        // Validate body size
        if let Some(ref body) = self.body {
            if let Some(max_size) = self.client.max_response_size {
                if body.len() > max_size {
                    return Err(Error::ValidationError(
                        format!("Request body size {} exceeds maximum {}", body.len(), max_size)
                    ));
                }
            }
        }
        
        Ok(())
    }
    
    /// Get the estimated request size
    pub fn estimated_size(&self) -> usize {
        let mut size = 0;
        
        // Method + URL + HTTP version
        size += self.method.as_str().len() + self.url.len() + 20;
        
        // Headers
        for (key, value) in &self.headers {
            size += key.len() + value.len() + 4; // ": " + "\r\n"
        }
        
        // Body
        if let Some(ref body) = self.body {
            size += body.len();
        }
        
        size
    }
    
    /// Clone the request builder
    pub fn try_clone(&self) -> Result<Self> {
        Ok(RequestBuilder {
            method: self.method,
            url: self.url.clone(),
            headers: self.headers.clone(),
            query_params: self.query_params.clone(),
            body: self.body.clone(),
            client: self.client.clone(),
        })
    }

    pub fn from_request(request: Request, client: Client) -> Self {
        RequestBuilder {
            method: request.method,
            url: format!("{}://{}{}", request.url.scheme, request.url.authority(), request.url.full_path()),
            headers: request.headers,
            query_params: HashMap::new(), // Query params are already in the URL
            body: request.body,
            client,
        }
    }

    pub fn execute_direct(self, start_time: Instant) -> Result<Response> {
        // Parse the URL
        let url = Url::parse(&self.url)?;

        // Create the request
        let mut headers = self.client.default_headers.clone();
        headers.extend(self.headers.clone());

        // Apply client auth if no request-specific auth
        if let Some(ref auth) = self.client.auth {
            if !headers.contains_key("Authorization") {
                auth.apply_to_headers(&mut headers);
            }
        }

        // Add cookies
        if let Some(ref cookie_jar) = self.client.cookie_jar {
            if let Some(cookie_header) = cookie_jar.to_cookie_header(&url.host, &url.path, url.is_secure()) {
                headers.insert("Cookie".to_string(), cookie_header);
            }
        }

        // Add Content-Length if we have a body
        if let Some(ref body) = self.body {
            headers.insert("Content-Length".to_string(), body.len().to_string());
        }

        // Add Host header
        headers.insert("Host".to_string(), url.host.clone());

        let request = Request {
            method: self.method,
            url,
            headers,
            body: self.body.clone(),
        };

        self.execute_single_request(&request, start_time)
    }

    pub fn header<K, V>(mut self, key: K, value: V) -> Self
    where
        K: Into<String>,
        V: Into<String>,
    {
        self.headers.insert(key.into(), value.into());
        self
    }

    pub fn headers(mut self, headers: HashMap<String, String>) -> Self {
        self.headers.extend(headers);
        self
    }

    pub fn query<K, V>(mut self, key: K, value: V) -> Self
    where
        K: Into<String>,
        V: Into<String>,
    {
        self.query_params.insert(key.into(), value.into());
        self
    }

    pub fn body<T: Into<Vec<u8>>>(mut self, body: T) -> Self {
        self.body = Some(body.into());
        self
    }

    pub fn json_str(mut self, json: &str) -> Self {
        self.headers.insert("Content-Type".to_string(), "application/json".to_string());
        self.body = Some(json.as_bytes().to_vec());
        self
    }

    pub fn json_value(mut self, json: &JsonValue) -> Self {
        self.headers.insert("Content-Type".to_string(), "application/json".to_string());
        let json_str = json.to_string();
        self.body = Some(json_str.into_bytes());
        self
    }

    pub fn multipart(mut self, form: MultipartForm) -> Self {
        self.headers.insert("Content-Type".to_string(), form.content_type());
        self.body = Some(form.to_bytes());
        self
    }

    pub fn auth(mut self, auth: Auth) -> Self {
        auth.apply_to_headers(&mut self.headers);
        self
    }

    pub fn basic_auth<U, P>(mut self, username: U, password: P) -> Self
    where
        U: Into<String>,
        P: Into<String>,
    {
        let auth = Auth::basic(&username.into(), &password.into());
        auth.apply_to_headers(&mut self.headers);
        self
    }

    pub fn bearer_auth<T: Into<String>>(mut self, token: T) -> Self {
        let auth = Auth::bearer(&token.into());
        auth.apply_to_headers(&mut self.headers);
        self
    }

    pub fn timeout(mut self, timeout: std::time::Duration) -> Self {
        // Create a new client with the specific timeout for this request
        let mut client = self.client.clone();
        client.timeout = Some(timeout);
        self.client = client;
        self
    }
    
    pub fn connect_timeout(mut self, timeout: std::time::Duration) -> Self {
        let mut client = self.client.clone();
        client.connect_timeout = Some(timeout);
        self.client = client;
        self
    }
    
    pub fn read_timeout(mut self, timeout: std::time::Duration) -> Self {
        let mut client = self.client.clone();
        client.read_timeout = Some(timeout);
        self.client = client;
        self
    }

    pub fn compress_with(mut self, compression: Compression) -> Self {
        if let Some(ref body) = self.body {
            if let Ok(compressed) = compress_request_body(body, compression) {
                self.body = Some(compressed);
                self.headers.insert("Content-Encoding".to_string(), compression.as_str().to_string());
            }
        }
        self
    }

    pub fn form<K, V>(mut self, form: &HashMap<K, V>) -> Self
    where
        K: AsRef<str>,
        V: AsRef<str>,
    {
        let form_data = form
            .iter()
            .map(|(k, v)| {
                format!(
                    "{}={}",
                    urlencoding::encode(k.as_ref()),
                    urlencoding::encode(v.as_ref())
                )
            })
            .collect::<Vec<_>>()
            .join("&");

        self.headers.insert(
            "Content-Type".to_string(),
            "application/x-www-form-urlencoded".to_string(),
        );
        self.body = Some(form_data.into_bytes());
        self
    }
    
    pub fn query_params(mut self, params: HashMap<String, String>) -> Self {
        self.query_params.extend(params);
        self
    }
    
    pub fn user_agent<S: Into<String>>(mut self, user_agent: S) -> Self {
        self.headers.insert("User-Agent".to_string(), user_agent.into());
        self
    }
    
    pub fn accept<S: Into<String>>(mut self, accept: S) -> Self {
        self.headers.insert("Accept".to_string(), accept.into());
        self
    }
    
    pub fn content_type<S: Into<String>>(mut self, content_type: S) -> Self {
        self.headers.insert("Content-Type".to_string(), content_type.into());
        self
    }
    
    pub fn if_none_match<S: Into<String>>(mut self, etag: S) -> Self {
        self.headers.insert("If-None-Match".to_string(), etag.into());
        self
    }
    
    pub fn if_modified_since<S: Into<String>>(mut self, date: S) -> Self {
        self.headers.insert("If-Modified-Since".to_string(), date.into());
        self
    }
    
    pub fn range<S: Into<String>>(mut self, range: S) -> Self {
        self.headers.insert("Range".to_string(), range.into());
        self
    }
    
    pub fn referer<S: Into<String>>(mut self, referer: S) -> Self {
        self.headers.insert("Referer".to_string(), referer.into());
        self
    }
    
    pub fn origin<S: Into<String>>(mut self, origin: S) -> Self {
        self.headers.insert("Origin".to_string(), origin.into());
        self
    }

    pub fn send(self) -> Result<Response> {
        let start_time = Instant::now();
        
        // Build the final URL with query parameters
        let mut final_url = self.url.clone();
        if !self.query_params.is_empty() {
            let query_string = self
                .query_params
                .iter()
                .map(|(k, v)| format!("{}={}", urlencoding::encode(k), urlencoding::encode(v)))
                .collect::<Vec<_>>()
                .join("&");

            if final_url.contains('?') {
                final_url.push('&');
                final_url.push_str(&query_string);
            } else {
                final_url.push('?');
                final_url.push_str(&query_string);
            }
        }

        let url = Url::parse(&final_url)?;

        // Merge headers
        let mut headers = self.client.default_headers.clone();
        headers.extend(self.headers.clone());

        // Apply client auth if no request-specific auth
        if let Some(ref auth) = self.client.auth {
            if !headers.contains_key("Authorization") {
                auth.apply_to_headers(&mut headers);
            }
        }

        // Add cookies
        if let Some(ref cookie_jar) = self.client.cookie_jar {
            if let Some(cookie_header) = cookie_jar.to_cookie_header(&url.host, &url.path, url.is_secure()) {
                headers.insert("Cookie".to_string(), cookie_header);
            }
        }

        // Add Content-Length if we have a body
        if let Some(ref body) = self.body {
            headers.insert("Content-Length".to_string(), body.len().to_string());
        }

        // Add Host header
        headers.insert("Host".to_string(), url.host.clone());

        let mut request = Request {
            method: self.method,
            url: url.clone(),
            headers,
            body: self.body.clone(),
        };

        // Handle redirects
        let mut redirect_handler = RedirectHandler::new(self.client.redirect_policy.clone());
        let current_method = request.method;
        let current_body = request.body.clone();

        loop {
            let response = self.execute_single_request(&request, start_time)?;
            
            // Handle cookies from response
            if let Some(ref mut cookie_jar) = self.client.cookie_jar.clone() {
                for (key, value) in &response.headers {
                    if key.to_lowercase() == "set-cookie" {
                        cookie_jar.add_cookie_str(value, &request.url.host);
                    }
                }
            }

            // Check for redirects
            if let Some(location) = response.header("location") {
                if let Ok(Some(redirect_info)) = redirect_handler.should_redirect(
                    response.status, 
                    location, 
                    &request.url
                ) {
                    // Update request for redirect
                    request.url = redirect_info.url;
                    request.method = if redirect_info.preserve_method {
                        current_method
                    } else {
                        get_redirect_method(current_method, redirect_info.status)
                    };

                    if redirect_info.remove_body {
                        request.body = None;
                        request.headers.remove("Content-Length");
                        request.headers.remove("Content-Type");
                    } else {
                        request.body = current_body.clone();
                    }

                    // Remove sensitive headers for cross-origin redirects
                    if !redirect_handler.should_send_sensitive_headers(&url, &request.url) {
                        request.headers.retain(|k, _| !is_sensitive_header(k));
                    }

                    // Update Host header
                    request.headers.insert("Host".to_string(), request.url.host.clone());

                    continue;
                }
            }

            return Ok(response);
        }
    }

    fn execute_single_request(&self, request: &Request, start_time: Instant) -> Result<Response> {
        // Connect to the server
        let addr = request.url.socket_addr();
        let tcp_stream = TcpStream::connect(&addr).map_err(|e| {
            Error::ConnectionFailed(format!("Failed to connect to {addr}: {e}"))
        })?;

        // Handle HTTPS vs HTTP
        let mut stream: Box<dyn HttpStream> = if request.url.scheme == "https" {
            let tls_stream = crate::tls::TlsStream::connect(tcp_stream, &request.url.host, &self.client.tls_config)?;
            Box::new(tls_stream)
        } else if request.url.scheme == "http" {
            Box::new(tcp_stream)
        } else {
            return Err(Error::InvalidUrl(format!("Unsupported scheme: {}", request.url.scheme)));
        };

        // Set timeout if specified
        if let Some(timeout) = self.client.timeout {
            stream.set_timeouts(Some(timeout), Some(timeout))?;
        }

        // Build HTTP request
        let mut http_request = format!(
            "{} {} HTTP/1.1\r\n",
            request.method.as_str(),
            if request.url.query.is_some() {
                format!(
                    "{}?{}",
                    request.url.path,
                    request.url.query.as_ref().unwrap()
                )
            } else {
                request.url.path.clone()
            }
        );

        // Add headers
        for (key, value) in &request.headers {
            http_request.push_str(&format!("{key}: {value}\r\n"));
        }

        http_request.push_str("\r\n");

        // Write request
        stream.write_all(http_request.as_bytes())?;

        // Write body if present
        if let Some(ref body) = request.body {
            stream.write_all(body)?;
        }

        stream.flush()?;

        // Read response
        self.read_response(stream, request, start_time)
    }

    fn read_response(&self, stream: Box<dyn HttpStream>, request: &Request, start_time: Instant) -> Result<Response> {
        let mut reader = BufReader::new(stream);
        let mut status_line = String::new();
        reader.read_line(&mut status_line)?;

        // Parse status line
        let parts: Vec<&str> = status_line.split_whitespace().collect();
        if parts.len() < 3 {
            return Err(Error::InvalidResponse("Invalid status line".to_string()));
        }

        let status: u16 = parts[1]
            .parse()
            .map_err(|_| Error::InvalidResponse("Invalid status code".to_string()))?;
        let status_text = parts[2..].join(" ");

        // Read headers
        let mut headers = HashMap::new();
        let mut line = String::new();
        loop {
            line.clear();
            reader.read_line(&mut line)?;
            let line = line.trim();

            if line.is_empty() {
                break;
            }

            if let Some(pos) = line.find(':') {
                let key = line[..pos].trim().to_string();
                let value = line[pos + 1..].trim().to_string();
                headers.insert(key, value);
            }
        }

        // Read body
        let mut body = Vec::new();

        // Check if we have Content-Length
        if let Some(content_length) = headers
            .get("Content-Length")
            .or_else(|| headers.get("content-length"))
        {
            if let Ok(length) = content_length.parse::<usize>() {
                let mut buffer = vec![0; length];
                reader.read_exact(&mut buffer)?;
                body = buffer;
            }
        } else if headers
            .get("Transfer-Encoding")
            .or_else(|| headers.get("transfer-encoding"))
            .map(|v| v.to_lowercase().contains("chunked"))
            .unwrap_or(false)
        {
            // Handle chunked encoding
            body = self.read_chunked_body(reader)?;
        } else {
            // Read until connection closes
            reader.read_to_end(&mut body)?;
        }

        let elapsed = start_time.elapsed();
        
        // Parse cookies from response
        let mut cookies = Vec::new();
        for (key, value) in &headers {
            if key.to_lowercase() == "set-cookie" {
                if let Some(cookie) = Cookie::parse(value) {
                    cookies.push(cookie);
                }
            }
        }

        let response = Response::new(status, status_text, headers, body)
            .with_url(request.url.clone())
            .with_elapsed(elapsed)
            .with_cookies(cookies);

        // Check for HTTP errors (but don't fail on redirects)
        if !response.is_success() && !response.is_redirect() {
            return Err(Error::HttpError(
                response.status,
                response.status_text.clone(),
            ));
        }

        Ok(response)
    }

    fn read_chunked_body(&self, mut reader: BufReader<Box<dyn HttpStream>>) -> Result<Vec<u8>> {
        let mut body = Vec::new();

        loop {
            let mut size_line = String::new();
            reader.read_line(&mut size_line)?;

            let size_str = size_line.trim().split(';').next().unwrap_or("").trim();
            let chunk_size = usize::from_str_radix(size_str, 16)
                .map_err(|_| Error::InvalidResponse("Invalid chunk size".to_string()))?;

            if chunk_size == 0 {
                // Read trailing headers (if any) and final CRLF
                let mut line = String::new();
                loop {
                    line.clear();
                    reader.read_line(&mut line)?;
                    if line.trim().is_empty() {
                        break;
                    }
                }
                break;
            }

            let mut chunk = vec![0; chunk_size];
            reader.read_exact(&mut chunk)?;
            body.extend_from_slice(&chunk);

            // Read trailing CRLF
            let mut crlf = String::new();
            reader.read_line(&mut crlf)?;
        }

        Ok(body)
    }
}

// Simple URL encoding implementation since we can't use external crates
mod urlencoding {
    pub fn encode(input: &str) -> String {
        let mut result = String::new();
        for byte in input.bytes() {
            match byte {
                b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                    result.push(byte as char);
                }
                _ => {
                    result.push_str(&format!("%{byte:02X}"));
                }
            }
        }
        result
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::Client;

    #[test]
    fn test_request_creation() {
        let url = Url::parse("https://example.com/api").unwrap();
        let request = Request::new(Method::GET, url);
        
        assert_eq!(request.method, Method::GET);
        assert_eq!(request.url.host, "example.com");
        assert!(!request.has_body());
        assert_eq!(request.body_size(), 0);
    }

    #[test]
    fn test_request_headers() {
        let url = Url::parse("https://example.com").unwrap();
        let mut request = Request::new(Method::GET, url);
        
        request.headers.insert("Content-Type".to_string(), "application/json".to_string());
        request.headers.insert("Authorization".to_string(), "Bearer token".to_string());
        
        assert_eq!(request.header("Content-Type"), Some(&"application/json".to_string()));
        assert_eq!(request.header_ignore_case("content-type"), Some(&"application/json".to_string()));
        assert_eq!(request.content_type(), Some(&"application/json".to_string()));
    }

    #[test]
    fn test_request_body() {
        let url = Url::parse("https://example.com").unwrap();
        let mut request = Request::new(Method::POST, url);
        
        let body = b"test body".to_vec();
        request.body = Some(body);
        
        assert!(request.has_body());
        assert_eq!(request.body_size(), 9);
    }

    #[test]
    fn test_request_builder_validation() {
        let client = Client::new();
        let builder = RequestBuilder::new(Method::GET, "https://example.com", client.clone());
        
        assert!(builder.validate().is_ok());
        
        let invalid_builder = RequestBuilder::new(Method::GET, "invalid-url", client);
        assert!(invalid_builder.validate().is_err());
    }

    #[test]
    fn test_request_builder_size_estimation() {
        let client = Client::new();
        let builder = RequestBuilder::new(Method::GET, "https://example.com", client)
            .header("Content-Type", "application/json")
            .body("test body");
        
        let size = builder.estimated_size();
        assert!(size > 0);
        assert!(size > 50); // Should include method, URL, headers, and body
    }

    #[test]
    fn test_request_builder_timeouts() {
        let client = Client::new();
        let builder = RequestBuilder::new(Method::GET, "https://example.com", client)
            .timeout(Duration::from_secs(10))
            .connect_timeout(Duration::from_secs(5))
            .read_timeout(Duration::from_secs(15));
        
        assert_eq!(builder.client.timeout, Some(Duration::from_secs(10)));
        assert_eq!(builder.client.connect_timeout, Some(Duration::from_secs(5)));
        assert_eq!(builder.client.read_timeout, Some(Duration::from_secs(15)));
    }

    #[test]
    fn test_request_builder_headers() {
        let client = Client::new();
        let builder = RequestBuilder::new(Method::GET, "https://example.com", client)
            .user_agent("test-agent")
            .accept("application/json")
            .content_type("text/plain")
            .referer("https://referrer.com")
            .origin("https://origin.com");
        
        assert_eq!(builder.headers.get("User-Agent"), Some(&"test-agent".to_string()));
        assert_eq!(builder.headers.get("Accept"), Some(&"application/json".to_string()));
        assert_eq!(builder.headers.get("Content-Type"), Some(&"text/plain".to_string()));
        assert_eq!(builder.headers.get("Referer"), Some(&"https://referrer.com".to_string()));
        assert_eq!(builder.headers.get("Origin"), Some(&"https://origin.com".to_string()));
    }

    #[test]
    fn test_request_debug_string() {
        let url = Url::parse("https://example.com/api").unwrap();
        let mut request = Request::new(Method::POST, url);
        request.headers.insert("Content-Type".to_string(), "application/json".to_string());
        request.body = Some(b"test".to_vec());
        
        let debug_str = request.to_debug_string();
        assert!(debug_str.contains("POST /api HTTP/1.1"));
        assert!(debug_str.contains("Host: example.com"));
        assert!(debug_str.contains("Content-Type: application/json"));
        assert!(debug_str.contains("test"));
    }

    #[test]
    fn test_request_clone() {
        let url = Url::parse("https://example.com").unwrap();
        let mut request = Request::new(Method::GET, url);
        request.headers.insert("Test".to_string(), "value".to_string());
        request.body = Some(b"body".to_vec());
        
        let cloned = request.try_clone().unwrap();
        assert_eq!(request.method, cloned.method);
        assert_eq!(request.url.host, cloned.url.host);
        assert_eq!(request.headers, cloned.headers);
        assert_eq!(request.body, cloned.body);
    }
}