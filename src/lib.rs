pub mod client;
pub mod request;
pub mod response;
pub mod error;
pub mod cookie;
pub mod auth;
pub mod proxy;
pub mod multipart;
pub mod compression;
pub mod redirect;
pub mod json;
pub mod tls;
pub mod http2;
pub mod websocket;
pub mod dns;

pub use client::{Client, ClientBuilder};
pub use request::{Request, RequestBuilder};
pub use response::Response;
pub use error::{Error, Result};
pub use cookie::{Cookie, CookieJar};
pub use auth::{Auth, BasicAuth, BearerAuth};
pub use proxy::Proxy;
pub use multipart::{MultipartForm, Part};
pub use json::{JsonValue, JsonParser};

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

pub fn head(url: &str) -> RequestBuilder {
    Client::new().head(url)
}

pub fn patch(url: &str) -> RequestBuilder {
    Client::new().patch(url)
}

pub fn options(url: &str) -> RequestBuilder {
    Client::new().options(url)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Method {
    GET,
    POST,
    PUT,
    DELETE,
    HEAD,
    PATCH,
    OPTIONS,
    TRACE,
    CONNECT,
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
            Method::OPTIONS => "OPTIONS",
            Method::TRACE => "TRACE",
            Method::CONNECT => "CONNECT",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        match s.to_uppercase().as_str() {
            "GET" => Some(Method::GET),
            "POST" => Some(Method::POST),
            "PUT" => Some(Method::PUT),
            "DELETE" => Some(Method::DELETE),
            "HEAD" => Some(Method::HEAD),
            "PATCH" => Some(Method::PATCH),
            "OPTIONS" => Some(Method::OPTIONS),
            "TRACE" => Some(Method::TRACE),
            "CONNECT" => Some(Method::CONNECT),
            _ => None,
        }
    }

    pub fn is_safe(&self) -> bool {
        matches!(self, Method::GET | Method::HEAD | Method::OPTIONS | Method::TRACE)
    }

    pub fn is_idempotent(&self) -> bool {
        matches!(self, Method::GET | Method::HEAD | Method::PUT | Method::DELETE | Method::OPTIONS | Method::TRACE)
    }
}

impl std::str::FromStr for Method {
    type Err = ();

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        Self::parse(s).ok_or(())
    }
}

#[derive(Debug, Clone)]
pub struct Url {
    pub scheme: String,
    pub host: String,
    pub port: Option<u16>,
    pub path: String,
    pub query: Option<String>,
    pub fragment: Option<String>,
    pub username: Option<String>,
    pub password: Option<String>,
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

        // Parse fragment first
        let (rest, fragment) = if let Some(pos) = rest.find('#') {
            let fragment = Some(rest[pos + 1..].to_string());
            let rest = &rest[..pos];
            (rest, fragment)
        } else {
            (rest, None)
        };

        // Parse query
        let (rest, query) = if let Some(pos) = rest.find('?') {
            let query = Some(rest[pos + 1..].to_string());
            let rest = &rest[..pos];
            (rest, query)
        } else {
            (rest, None)
        };

        // Parse path
        let (host_part, path) = if let Some(pos) = rest.find('/') {
            let host_part = &rest[..pos];
            let path = rest[pos..].to_string();
            (host_part, path)
        } else {
            (rest, "/".to_string())
        };

        // Parse user info (username:password@)
        let (username, password, host_port) = if let Some(pos) = host_part.find('@') {
            let user_info = &host_part[..pos];
            let host_port = &host_part[pos + 1..];
            
            if let Some(colon_pos) = user_info.find(':') {
                let username = Some(user_info[..colon_pos].to_string());
                let password = Some(user_info[colon_pos + 1..].to_string());
                (username, password, host_port)
            } else {
                let username = Some(user_info.to_string());
                (username, None, host_port)
            }
        } else {
            (None, None, host_part)
        };

        // Parse host and port
        let (host, port) = if host_port.starts_with('[') {
            // IPv6 address
            if let Some(pos) = host_port.find("]:") {
                let host = host_port[1..pos].to_string();
                let port_str = &host_port[pos + 2..];
                let port = port_str.parse().map_err(|_| Error::InvalidUrl("Invalid port".to_string()))?;
                (host, Some(port))
            } else if host_port.ends_with(']') {
                let host = host_port[1..host_port.len()-1].to_string();
                let default_port = match scheme.as_str() {
                    "http" => Some(80),
                    "https" => Some(443),
                    _ => None,
                };
                (host, default_port)
            } else {
                return Err(Error::InvalidUrl("Invalid IPv6 address".to_string()));
            }
        } else if let Some(pos) = host_port.find(':') {
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

        Ok(Url {
            scheme,
            host,
            port,
            path,
            query,
            fragment,
            username,
            password,
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

    pub fn is_secure(&self) -> bool {
        self.scheme == "https"
    }

    pub fn authority(&self) -> String {
        let mut auth = String::new();
        if let Some(ref username) = self.username {
            auth.push_str(username);
            if let Some(ref password) = self.password {
                auth.push(':');
                auth.push_str(password);
            }
            auth.push('@');
        }
        auth.push_str(&self.host);
        if let Some(port) = self.port {
            let default_port = match self.scheme.as_str() {
                "http" => 80,
                "https" => 443,
                _ => 0,
            };
            if port != default_port {
                auth.push(':');
                auth.push_str(&port.to_string());
            }
        }
        auth
    }

    pub fn full_path(&self) -> String {
        let mut path = self.path.clone();
        if let Some(ref query) = self.query {
            path.push('?');
            path.push_str(query);
        }
        path
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Version {
    Http10,
    Http11,
    Http2,
}

impl Version {
    pub fn as_str(&self) -> &'static str {
        match self {
            Version::Http10 => "HTTP/1.0",
            Version::Http11 => "HTTP/1.1",
            Version::Http2 => "HTTP/2.0",
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
    fn test_url_with_auth() {
        let url = Url::parse("http://user:pass@example.com/path").unwrap();
        assert_eq!(url.username, Some("user".to_string()));
        assert_eq!(url.password, Some("pass".to_string()));
        assert_eq!(url.host, "example.com");
    }

    #[test]
    fn test_method_as_str() {
        assert_eq!(Method::GET.as_str(), "GET");
        assert_eq!(Method::POST.as_str(), "POST");
        assert_eq!(Method::PUT.as_str(), "PUT");
        assert_eq!(Method::DELETE.as_str(), "DELETE");
    }

    #[test]
    fn test_method_properties() {
        assert!(Method::GET.is_safe());
        assert!(!Method::POST.is_safe());
        assert!(Method::GET.is_idempotent());
        assert!(!Method::POST.is_idempotent());
    }

    #[test]
    fn test_client_creation() {
        let client = Client::new();
        assert!(client.timeout.is_some());
        assert!(!client.default_headers.is_empty());
    }
}