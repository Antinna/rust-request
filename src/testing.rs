use crate::{Request, Response, Result, Error, Method, Url, Version};
use std::collections::HashMap;
use std::time::Duration;
use std::sync::{Arc, Mutex};

/// Mock HTTP server for testing
#[derive(Debug)]
pub struct MockServer {
    routes: Arc<Mutex<HashMap<String, MockRoute>>>,
    default_response: MockResponse,
    request_history: Arc<Mutex<Vec<Request>>>,
}

impl MockServer {
    pub fn new() -> Self {
        MockServer {
            routes: Arc::new(Mutex::new(HashMap::new())),
            default_response: MockResponse::new(404, "Not Found"),
            request_history: Arc::new(Mutex::new(Vec::new())),
        }
    }

    pub fn route<S: Into<String>>(self, method: Method, path: S, response: MockResponse) -> Self {
        let key = format!("{} {}", method.as_str(), path.into());
        if let Ok(mut routes) = self.routes.lock() {
            routes.insert(key, MockRoute::new(response));
        }
        self
    }

    pub fn get<S: Into<String>>(self, path: S, response: MockResponse) -> Self {
        self.route(Method::GET, path, response)
    }

    pub fn post<S: Into<String>>(self, path: S, response: MockResponse) -> Self {
        self.route(Method::POST, path, response)
    }

    pub fn put<S: Into<String>>(self, path: S, response: MockResponse) -> Self {
        self.route(Method::PUT, path, response)
    }

    pub fn delete<S: Into<String>>(self, path: S, response: MockResponse) -> Self {
        self.route(Method::DELETE, path, response)
    }

    pub fn default_response(mut self, response: MockResponse) -> Self {
        self.default_response = response;
        self
    }
    
    pub fn verify_request_count(&self, method: Method, path: &str, expected_count: usize) -> bool {
        let key = format!("{} {}", method.as_str(), path);
        if let Ok(routes) = self.routes.lock() {
            if let Some(route) = routes.get(&key) {
                route.get_call_count() == expected_count
            } else {
                expected_count == 0
            }
        } else {
            false
        }
    }
    
    pub fn get_request_count(&self, method: Method, path: &str) -> usize {
        let key = format!("{} {}", method.as_str(), path);
        if let Ok(routes) = self.routes.lock() {
            if let Some(route) = routes.get(&key) {
                route.get_call_count()
            } else {
                0
            }
        } else {
            0
        }
    }
    
    pub fn reset_all_counters(&self) {
        if let Ok(routes) = self.routes.lock() {
            for route in routes.values() {
                route.reset_call_count();
            }
        }
    }
    
    pub fn get_all_request_counts(&self) -> HashMap<String, usize> {
        if let Ok(routes) = self.routes.lock() {
            routes.iter()
                .map(|(path, route)| (path.clone(), route.get_call_count()))
                .collect()
        } else {
            HashMap::new()
        }
    }
    
    pub fn verify_no_unexpected_calls(&self, expected_paths: &[(Method, &str)]) -> bool {
        if let Ok(routes) = self.routes.lock() {
            for (path, route) in routes.iter() {
                let is_expected = expected_paths.iter().any(|(method, p)| {
                    format!("{} {}", method.as_str(), p) == *path
                });
                
                if !is_expected && route.was_called() {
                    return false;
                }
            }
        }
        true
    }

    pub fn handle_request(&self, request: Request) -> Result<Response> {
        // Record request in history
        if let Ok(mut history) = self.request_history.lock() {
            history.push(request.clone());
        }

        let key = format!("{} {}", request.method.as_str(), request.url.path);
        
        let mock_response = if let Ok(routes) = self.routes.lock() {
            if let Some(route) = routes.get(&key) {
                route.increment_calls();
                route.response.clone()
            } else {
                self.default_response.clone()
            }
        } else {
            self.default_response.clone()
        };

        // Simulate network delay if specified
        if let Some(delay) = mock_response.delay {
            std::thread::sleep(delay);
        }

        // Check if we should return an error
        if let Some(error) = mock_response.error {
            return Err(error);
        }

        Ok(Response {
            status: mock_response.status,
            status_text: mock_response.status_text,
            headers: mock_response.headers,
            body: mock_response.body,
            version: Version::Http11,
            url: request.url,
            remote_addr: Some("127.0.0.1:8080".to_string()),
            elapsed: Duration::from_millis(10),
            cookies: Vec::new(),
        })
    }

    pub fn request_count(&self) -> usize {
        if let Ok(history) = self.request_history.lock() {
            history.len()
        } else {
            0
        }
    }

    pub fn last_request(&self) -> Option<Request> {
        if let Ok(history) = self.request_history.lock() {
            history.last().cloned()
        } else {
            None
        }
    }

    pub fn requests(&self) -> Vec<Request> {
        if let Ok(history) = self.request_history.lock() {
            history.clone()
        } else {
            Vec::new()
        }
    }

    pub fn clear_history(&self) {
        if let Ok(mut history) = self.request_history.lock() {
            history.clear();
        }
    }

    pub fn verify_request<F>(&self, predicate: F) -> bool
    where
        F: Fn(&Request) -> bool,
    {
        if let Ok(history) = self.request_history.lock() {
            history.iter().any(predicate)
        } else {
            false
        }
    }
}

impl Default for MockServer {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone)]
pub struct MockRoute {
    response: MockResponse,
    call_count: Arc<Mutex<usize>>,
}

impl MockRoute {
    pub fn increment_calls(&self) {
        if let Ok(mut count) = self.call_count.lock() {
            *count += 1;
        }
    }

    pub fn get_call_count(&self) -> usize {
        if let Ok(count) = self.call_count.lock() {
            *count
        } else {
            0
        }
    }
    
    pub fn reset_call_count(&self) {
        if let Ok(mut count) = self.call_count.lock() {
            *count = 0;
        }
    }
    
    pub fn was_called(&self) -> bool {
        self.get_call_count() > 0
    }
    
    pub fn was_called_times(&self, expected: usize) -> bool {
        self.get_call_count() == expected
    }
}

impl MockRoute {
    pub fn new(response: MockResponse) -> Self {
        MockRoute {
            response,
            call_count: Arc::new(Mutex::new(0)),
        }
    }
}

/// Mock HTTP response for testing
#[derive(Debug, Clone)]
pub struct MockResponse {
    status: u16,
    status_text: String,
    headers: HashMap<String, String>,
    body: Vec<u8>,
    delay: Option<Duration>,
    error: Option<Error>,
}

impl MockResponse {
    pub fn new<S: Into<String>>(status: u16, status_text: S) -> Self {
        MockResponse {
            status,
            status_text: status_text.into(),
            headers: HashMap::new(),
            body: Vec::new(),
            delay: None,
            error: None,
        }
    }

    pub fn ok() -> Self {
        Self::new(200, "OK")
    }

    pub fn not_found() -> Self {
        Self::new(404, "Not Found")
    }

    pub fn internal_error() -> Self {
        Self::new(500, "Internal Server Error")
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

    pub fn body<B: Into<Vec<u8>>>(mut self, body: B) -> Self {
        self.body = body.into();
        self
    }

    pub fn json<S: Into<String>>(mut self, json: S) -> Self {
        self.headers.insert("Content-Type".to_string(), "application/json".to_string());
        self.body = json.into().into_bytes();
        self
    }

    pub fn text<S: Into<String>>(mut self, text: S) -> Self {
        self.headers.insert("Content-Type".to_string(), "text/plain".to_string());
        self.body = text.into().into_bytes();
        self
    }

    pub fn html<S: Into<String>>(mut self, html: S) -> Self {
        self.headers.insert("Content-Type".to_string(), "text/html".to_string());
        self.body = html.into().into_bytes();
        self
    }

    pub fn delay(mut self, delay: Duration) -> Self {
        self.delay = Some(delay);
        self
    }

    pub fn error(mut self, error: Error) -> Self {
        self.error = Some(error);
        self
    }

    pub fn timeout(mut self) -> Self {
        self.error = Some(Error::Timeout);
        self
    }

    pub fn connection_error<S: Into<String>>(mut self, message: S) -> Self {
        self.error = Some(Error::ConnectionFailed(message.into()));
        self
    }
}

/// HTTP client test utilities
pub struct TestClient {
    mock_server: MockServer,
}

impl TestClient {
    pub fn new() -> Self {
        TestClient {
            mock_server: MockServer::new(),
        }
    }

    pub fn with_mock_server(mock_server: MockServer) -> Self {
        TestClient { mock_server }
    }

    pub fn mock_server(&self) -> &MockServer {
        &self.mock_server
    }

    pub fn execute_request(&self, request: Request) -> Result<Response> {
        self.mock_server.handle_request(request)
    }
}

impl Default for TestClient {
    fn default() -> Self {
        Self::new()
    }
}

/// Request builder for testing
pub struct TestRequestBuilder {
    method: Method,
    url: String,
    headers: HashMap<String, String>,
    body: Option<Vec<u8>>,
}

impl TestRequestBuilder {
    pub fn new<S: Into<String>>(method: Method, url: S) -> Self {
        TestRequestBuilder {
            method,
            url: url.into(),
            headers: HashMap::new(),
            body: None,
        }
    }

    pub fn get<S: Into<String>>(url: S) -> Self {
        Self::new(Method::GET, url)
    }

    pub fn post<S: Into<String>>(url: S) -> Self {
        Self::new(Method::POST, url)
    }

    pub fn put<S: Into<String>>(url: S) -> Self {
        Self::new(Method::PUT, url)
    }

    pub fn delete<S: Into<String>>(url: S) -> Self {
        Self::new(Method::DELETE, url)
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

    pub fn body<B: Into<Vec<u8>>>(mut self, body: B) -> Self {
        self.body = Some(body.into());
        self
    }

    pub fn json<S: Into<String>>(mut self, json: S) -> Self {
        self.headers.insert("Content-Type".to_string(), "application/json".to_string());
        self.body = Some(json.into().into_bytes());
        self
    }

    pub fn form(mut self, form_data: &HashMap<String, String>) -> Self {
        let body = form_data
            .iter()
            .map(|(k, v)| format!("{}={}", urlencoding::encode(k), urlencoding::encode(v)))
            .collect::<Vec<_>>()
            .join("&");

        self.headers.insert("Content-Type".to_string(), "application/x-www-form-urlencoded".to_string());
        self.body = Some(body.into_bytes());
        self
    }

    pub fn build(self) -> Result<Request> {
        let url = Url::parse(&self.url)?;
        Ok(Request {
            method: self.method,
            url,
            headers: self.headers,
            body: self.body,
        })
    }
}

/// Response assertion utilities
pub struct ResponseAssertions {
    response: Response,
}

impl ResponseAssertions {
    pub fn new(response: Response) -> Self {
        ResponseAssertions { response }
    }

    pub fn status(self, expected_status: u16) -> Self {
        assert_eq!(self.response.status, expected_status, 
            "Expected status {}, got {}", expected_status, self.response.status);
        self
    }

    pub fn status_ok(self) -> Self {
        self.status(200)
    }

    pub fn status_not_found(self) -> Self {
        self.status(404)
    }

    pub fn status_error(self) -> Self {
        assert!(self.response.status >= 400, 
            "Expected error status (>=400), got {}", self.response.status);
        self
    }

    pub fn header<K, V>(self, key: K, expected_value: V) -> Self
    where
        K: AsRef<str>,
        V: AsRef<str>,
    {
        let actual_value = self.response.headers.get(key.as_ref())
            .unwrap_or_else(|| panic!("Header '{}' not found", key.as_ref()));
        assert_eq!(actual_value, expected_value.as_ref(),
            "Expected header '{}' to be '{}', got '{}'", 
            key.as_ref(), expected_value.as_ref(), actual_value);
        self
    }

    pub fn header_exists<K: AsRef<str>>(self, key: K) -> Self {
        assert!(self.response.headers.contains_key(key.as_ref()),
            "Header '{}' not found", key.as_ref());
        self
    }

    pub fn content_type<S: AsRef<str>>(self, expected_type: S) -> Self {
        self.header("Content-Type", expected_type.as_ref())
    }

    pub fn body_contains<S: AsRef<str>>(self, text: S) -> Self {
        let body_str = String::from_utf8_lossy(&self.response.body);
        assert!(body_str.contains(text.as_ref()),
            "Response body does not contain '{}'", text.as_ref());
        self
    }

    pub fn body_equals<B: AsRef<[u8]>>(self, expected_body: B) -> Self {
        assert_eq!(self.response.body, expected_body.as_ref(),
            "Response body does not match expected");
        self
    }

    pub fn body_json(self) -> Result<crate::JsonValue> {
        self.response.json()
    }

    pub fn body_empty(self) -> Self {
        assert!(self.response.body.is_empty(),
            "Expected empty body, got {} bytes", self.response.body.len());
        self
    }

    pub fn body_size(self, expected_size: usize) -> Self {
        assert_eq!(self.response.body.len(), expected_size,
            "Expected body size {}, got {}", expected_size, self.response.body.len());
        self
    }

    pub fn elapsed_less_than(self, max_duration: Duration) -> Self {
        assert!(self.response.elapsed < max_duration,
            "Request took {:?}, expected less than {:?}", 
            self.response.elapsed, max_duration);
        self
    }

    pub fn finish(self) -> Response {
        self.response
    }
}

// URL encoding for form data
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

/// Test utilities for HTTP scenarios
pub struct HttpTestScenario {
    name: String,
    requests: Vec<Request>,
    expected_responses: Vec<MockResponse>,
}

impl HttpTestScenario {
    pub fn new<S: Into<String>>(name: S) -> Self {
        HttpTestScenario {
            name: name.into(),
            requests: Vec::new(),
            expected_responses: Vec::new(),
        }
    }

    pub fn request(mut self, request: Request) -> Self {
        self.requests.push(request);
        self
    }

    pub fn expect_response(mut self, response: MockResponse) -> Self {
        self.expected_responses.push(response);
        self
    }

    pub fn run(self, client: &TestClient) -> Result<Vec<Response>> {
        println!("Running test scenario: {}", self.name);
        let mut responses = Vec::new();
        
        for (i, request) in self.requests.into_iter().enumerate() {
            println!("  Executing request {}: {} {}", i + 1, request.method.as_str(), request.url.full_path());
            let response = client.execute_request(request)?;
            responses.push(response);
        }

        println!("Scenario '{}' completed with {} responses", self.name, responses.len());
        Ok(responses)
    }

    pub fn name(&self) -> &str {
        &self.name
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mock_server() {
        let server = MockServer::new()
            .get("/test", MockResponse::ok().json(r#"{"message": "hello"}"#))
            .post("/data", MockResponse::new(201, "Created"));

        let request = TestRequestBuilder::get("http://example.com/test")
            .build()
            .unwrap();

        let response = server.handle_request(request).unwrap();
        assert_eq!(response.status, 200);
        assert_eq!(server.request_count(), 1);
    }

    #[test]
    fn test_response_assertions() {
        let response = Response {
            status: 200,
            status_text: "OK".to_string(),
            headers: {
                let mut h = HashMap::new();
                h.insert("Content-Type".to_string(), "application/json".to_string());
                h
            },
            body: b"test body".to_vec(),
            version: Version::Http11,
            url: Url::parse("http://example.com").unwrap(),
            remote_addr: None,
            elapsed: Duration::from_millis(100),
            cookies: Vec::new(),
        };

        ResponseAssertions::new(response)
            .status_ok()
            .content_type("application/json")
            .body_contains("test")
            .body_size(9)
            .elapsed_less_than(Duration::from_secs(1));
    }

    #[test]
    fn test_request_builder() {
        let mut form_data = HashMap::new();
        form_data.insert("key".to_string(), "value".to_string());

        let request = TestRequestBuilder::post("http://example.com/form")
            .header("Authorization", "Bearer token")
            .form(&form_data)
            .build()
            .unwrap();

        assert_eq!(request.method, Method::POST);
        assert!(request.headers.contains_key("Content-Type"));
        assert!(request.body.is_some());
    }
}