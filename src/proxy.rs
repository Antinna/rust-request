use crate::{Auth, Url, Result};

#[derive(Debug, Clone)]
pub struct Proxy {
    pub url: Url,
    pub auth: Option<Auth>,
    pub no_proxy: Vec<String>,
}

impl Proxy {
    pub fn new(proxy_url: &str) -> Result<Self> {
        let url = Url::parse(proxy_url)?;
        Ok(Proxy {
            url,
            auth: None,
            no_proxy: Vec::new(),
        })
    }

    pub fn with_auth(mut self, auth: Auth) -> Self {
        self.auth = Some(auth);
        self
    }

    pub fn with_no_proxy(mut self, no_proxy: Vec<String>) -> Self {
        self.no_proxy = no_proxy;
        self
    }

    pub fn should_use_proxy(&self, target_url: &Url) -> bool {
        // Check if target is in no_proxy list
        for pattern in &self.no_proxy {
            if self.matches_no_proxy_pattern(pattern, &target_url.host) {
                return false;
            }
        }
        true
    }

    fn matches_no_proxy_pattern(&self, pattern: &str, host: &str) -> bool {
        if pattern == "*" {
            return true;
        }
        
        if pattern.starts_with('.') {
            // Domain suffix match
            return host.ends_with(pattern) || host == &pattern[1..];
        }
        
        if pattern.contains('*') {
            // Simple wildcard matching
            return self.wildcard_match(pattern, host);
        }
        
        // Exact match
        pattern == host
    }

    fn wildcard_match(&self, pattern: &str, text: &str) -> bool {
        let pattern_parts: Vec<&str> = pattern.split('*').collect();
        if pattern_parts.len() == 1 {
            return pattern == text;
        }

        let mut text_pos = 0;
        for (i, part) in pattern_parts.iter().enumerate() {
            if part.is_empty() {
                continue;
            }

            if i == 0 {
                // First part must match from the beginning
                if !text[text_pos..].starts_with(part) {
                    return false;
                }
                text_pos += part.len();
            } else if i == pattern_parts.len() - 1 {
                // Last part must match at the end
                return text[text_pos..].ends_with(part);
            } else {
                // Middle parts
                if let Some(pos) = text[text_pos..].find(part) {
                    text_pos += pos + part.len();
                } else {
                    return false;
                }
            }
        }
        true
    }

    pub fn connect_string(&self, target_url: &Url) -> String {
        format!("CONNECT {}:{} HTTP/1.1\r\n\r\n", 
            target_url.host, 
            target_url.port.unwrap_or(if target_url.is_secure() { 443 } else { 80 })
        )
    }

    pub fn proxy_type(&self) -> ProxyType {
        ProxyType::from_scheme(&self.url.scheme).unwrap_or(ProxyType::Http)
    }

    pub fn connect_through_proxy(&self, target_url: &Url) -> Result<Vec<u8>> {
        match self.proxy_type() {
            ProxyType::Http | ProxyType::Https => {
                Ok(self.connect_string(target_url).into_bytes())
            },
            ProxyType::Socks4 => {
                self.create_socks4_connect(target_url)
            },
            ProxyType::Socks5 => {
                self.create_socks5_connect(target_url)
            },
        }
    }

    fn create_socks4_connect(&self, target_url: &Url) -> Result<Vec<u8>> {
        let mut request = Vec::new();
        
        // SOCKS4 request
        request.push(0x04); // Version
        request.push(0x01); // Connect command
        
        // Port (big-endian)
        let port = target_url.port.unwrap_or(if target_url.is_secure() { 443 } else { 80 });
        request.extend_from_slice(&port.to_be_bytes());
        
        // IP address (try to resolve hostname to IP)
        let ip = resolve_hostname(&target_url.host)?;
        request.extend_from_slice(&ip);
        
        // User ID (empty)
        request.push(0x00);
        
        Ok(request)
    }

    fn create_socks5_connect(&self, _target_url: &Url) -> Result<Vec<u8>> {
        // SOCKS5 greeting
        let request = vec![
            0x05, // Version
            0x01, // Number of methods
            0x00, // No authentication
        ];
        
        Ok(request)
    }

    pub fn create_socks5_connect_request(&self, target_url: &Url) -> Result<Vec<u8>> {
        let mut request = Vec::new();
        
        // SOCKS5 connect request
        request.push(0x05); // Version
        request.push(0x01); // Connect command
        request.push(0x00); // Reserved
        
        // Address type and address
        if target_url.host.parse::<std::net::Ipv4Addr>().is_ok() {
            // IPv4 address
            request.push(0x01);
            let ip: std::net::Ipv4Addr = target_url.host.parse().unwrap();
            request.extend_from_slice(&ip.octets());
        } else if target_url.host.parse::<std::net::Ipv6Addr>().is_ok() {
            // IPv6 address
            request.push(0x04);
            let ip: std::net::Ipv6Addr = target_url.host.parse().unwrap();
            request.extend_from_slice(&ip.octets());
        } else {
            // Domain name
            request.push(0x03);
            request.push(target_url.host.len() as u8);
            request.extend_from_slice(target_url.host.as_bytes());
        }
        
        // Port
        let port = target_url.port.unwrap_or(if target_url.is_secure() { 443 } else { 80 });
        request.extend_from_slice(&port.to_be_bytes());
        
        Ok(request)
    }
}

#[derive(Debug, Clone)]
pub enum ProxyType {
    Http,
    Https,
    Socks4,
    Socks5,
}

impl ProxyType {
    pub fn from_scheme(scheme: &str) -> Option<Self> {
        match scheme.to_lowercase().as_str() {
            "http" => Some(ProxyType::Http),
            "https" => Some(ProxyType::Https),
            "socks4" => Some(ProxyType::Socks4),
            "socks5" => Some(ProxyType::Socks5),
            _ => None,
        }
    }
}

fn resolve_hostname(hostname: &str) -> Result<[u8; 4]> {
    // Simple hostname resolution
    // In a real implementation, you'd use proper DNS resolution
    if let Ok(ip) = hostname.parse::<std::net::Ipv4Addr>() {
        Ok(ip.octets())
    } else {
        // For demo purposes, return localhost IP
        // Real implementation would do DNS lookup
        match hostname {
            "localhost" => Ok([127, 0, 0, 1]),
            "example.com" => Ok([93, 184, 216, 34]),
            "httpbin.org" => Ok([54, 236, 246, 173]),
            _ => Ok([127, 0, 0, 1]), // Default to localhost
        }
    }
}

pub fn parse_proxy_env() -> Option<Proxy> {
    use std::env;
    
    // Check environment variables in order of preference
    let proxy_vars = ["HTTPS_PROXY", "https_proxy", "HTTP_PROXY", "http_proxy"];
    
    for var in &proxy_vars {
        if let Ok(proxy_url) = env::var(var) {
            if !proxy_url.is_empty() {
                if let Ok(proxy) = Proxy::new(&proxy_url) {
                    let mut proxy = proxy;
                    
                    // Parse NO_PROXY environment variable
                    if let Ok(no_proxy) = env::var("NO_PROXY").or_else(|_| env::var("no_proxy")) {
                        let no_proxy_list: Vec<String> = no_proxy
                            .split(',')
                            .map(|s| s.trim().to_string())
                            .filter(|s| !s.is_empty())
                            .collect();
                        proxy = proxy.with_no_proxy(no_proxy_list);
                    }
                    
                    return Some(proxy);
                }
            }
        }
    }
    
    None
}