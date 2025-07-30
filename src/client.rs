use crate::{Method, RequestBuilder};
use std::time::Duration;
use std::collections::HashMap;

#[derive(Debug, Clone)]
pub struct Client {
    pub timeout: Option<Duration>,
    pub default_headers: HashMap<String, String>,
}

impl Client {
    pub fn new() -> Self {
        let mut default_headers = HashMap::new();
        default_headers.insert("User-Agent".to_string(), "rust-http-client/0.1.0".to_string());
        default_headers.insert("Connection".to_string(), "close".to_string());
        
        Client {
            timeout: Some(Duration::from_secs(30)),
            default_headers,
        }
    }

    pub fn builder() -> ClientBuilder {
        ClientBuilder::new()
    }

    pub fn timeout(mut self, timeout: Duration) -> Self {
        self.timeout = Some(timeout);
        self
    }

    pub fn default_headers(mut self, headers: HashMap<String, String>) -> Self {
        self.default_headers.extend(headers);
        self
    }

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

    pub fn request(&self, method: Method, url: &str) -> RequestBuilder {
        RequestBuilder::new(method, url, self.clone())
    }
}

impl Default for Client {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug)]
pub struct ClientBuilder {
    timeout: Option<Duration>,
    default_headers: HashMap<String, String>,
}

impl ClientBuilder {
    pub fn new() -> Self {
        ClientBuilder {
            timeout: Some(Duration::from_secs(30)),
            default_headers: HashMap::new(),
        }
    }

    pub fn timeout(mut self, timeout: Duration) -> Self {
        self.timeout = Some(timeout);
        self
    }

    pub fn default_headers(mut self, headers: HashMap<String, String>) -> Self {
        self.default_headers = headers;
        self
    }

    pub fn build(self) -> Client {
        let mut default_headers = HashMap::new();
        default_headers.insert("User-Agent".to_string(), "rust-http-client/0.1.0".to_string());
        default_headers.insert("Connection".to_string(), "close".to_string());
        default_headers.extend(self.default_headers);

        Client {
            timeout: self.timeout,
            default_headers,
        }
    }
}

impl Default for ClientBuilder {
    fn default() -> Self {
        Self::new()
    }
}