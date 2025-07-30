pub mod client;
pub mod request;
pub mod response;
pub mod error;

pub use client::Client;
pub use request::{Request, RequestBuilder};
pub use response::Response;
pub use error::{Error, Result};

// Re-export common HTTP methods
pub fn get(url: &str) -> RequestBuilder {
    Client::new().get(url)
}

pub fn post(url: &str) -> RequestBuilder {
    Client::new().post(url)
}

pub fn put(url: &str) -> RequestBuilder {
    Client::new().put(url)
}

pub fn delete(url: &str) -> RequestBuilder {
    Client::new().delete(url)
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Method {
    GET,
    POST,
    PUT,
    DELETE,
    HEAD,
    PATCH,
}

impl Method {
    pub fn as_str(&self) -> &'static str {
        match self {
            Method::GET => "GET",
            Method::POST => "POST",
            Method::PUT => "PUT",
            Method::DELETE => "DELETE",
            Method::HEAD => "HEAD",
            Method::PATCH => "PATCH",
        }
    }
}

#[derive(Debug, Clone)]
pub struct Url {
    pub scheme: String,
    pub host: String,
    pub port: Option<u16>,
    pub path: String,
    pub query: Option<String>,
}

impl Url {
    pub fn parse(url: &str) -> Result<Self> {
        let url = url.trim();
        
        // Parse scheme
        let (scheme, rest) = if let Some(pos) = url.find("://") {
            let scheme = url[..pos].to_lowercase();
            let rest = &url[pos + 3..];
            (scheme, rest)
        } else {
            return Err(Error::InvalidUrl("Missing scheme".to_string()));
        };

        // Parse host, port, path, and query
        let (host_port, path_query) = if let Some(pos) = rest.find('/') {
            (&rest[..pos], &rest[pos..])
        } else {
            (rest, "/")
        };

        let (host, port) = if let Some(pos) = host_port.find(':') {
            let host = host_port[..pos].to_string();
            let port_str = &host_port[pos + 1..];
            let port = port_str.parse().map_err(|_| Error::InvalidUrl("Invalid port".to_string()))?;
            (host, Some(port))
        } else {
            let default_port = match scheme.as_str() {
                "http" => Some(80),
                "https" => Some(443),
                _ => None,
            };
            (host_port.to_string(), default_port)
        };

        let (path, query) = if let Some(pos) = path_query.find('?') {
            let path = path_query[..pos].to_string();
            let query = Some(path_query[pos + 1..].to_string());
            (path, query)
        } else {
            (path_query.to_string(), None)
        };

        Ok(Url {
            scheme,
            host,
            port,
            path,
            query,
        })
    }

    pub fn socket_addr(&self) -> String {
        match self.port {
            Some(port) => format!("{}:{}", self.host, port),
            None => match self.scheme.as_str() {
                "http" => format!("{}:80", self.host),
                "https" => format!("{}:443", self.host),
                _ => self.host.clone(),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_url_parsing() {
        let url = Url::parse("http://example.com/path?query=value").unwrap();
        assert_eq!(url.scheme, "http");
        assert_eq!(url.host, "example.com");
        assert_eq!(url.port, Some(80));
        assert_eq!(url.path, "/path");
        assert_eq!(url.query, Some("query=value".to_string()));
    }

    #[test]
    fn test_url_with_port() {
        let url = Url::parse("http://example.com:8080/path").unwrap();
        assert_eq!(url.host, "example.com");
        assert_eq!(url.port, Some(8080));
        assert_eq!(url.path, "/path");
    }

    #[test]
    fn test_method_as_str() {
        assert_eq!(Method::GET.as_str(), "GET");
        assert_eq!(Method::POST.as_str(), "POST");
        assert_eq!(Method::PUT.as_str(), "PUT");
        assert_eq!(Method::DELETE.as_str(), "DELETE");
    }

    #[test]
    fn test_client_creation() {
        let client = Client::new();
        assert!(client.timeout.is_some());
        assert!(!client.default_headers.is_empty());
    }
}