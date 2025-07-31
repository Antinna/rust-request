use crate::{Auth, Error, Url, Result};

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

// Enhanced SOCKS proxy implementation
pub struct SocksConnector {
    proxy: Proxy,
}

impl SocksConnector {
    pub fn new(proxy: Proxy) -> Self {
        SocksConnector { proxy }
    }

    pub fn connect_socks4(&self, target_host: &str, target_port: u16) -> Result<Vec<u8>> {
        let mut request = Vec::new();
        
        // SOCKS4 request format:
        // VER | CMD | DSTPORT | DSTIP | USERID | NULL
        request.push(0x04); // Version 4
        request.push(0x01); // CONNECT command
        
        // Destination port (2 bytes, big-endian)
        request.extend_from_slice(&target_port.to_be_bytes());
        
        // Destination IP (4 bytes)
        let target_ip = resolve_hostname(target_host)?;
        request.extend_from_slice(&target_ip);
        
        // User ID (empty for now)
        request.push(0x00); // NULL terminator
        
        Ok(request)
    }

    pub fn connect_socks5(&self, target_host: &str, target_port: u16) -> Result<Vec<u8>> {
        let mut request = Vec::new();
        
        // SOCKS5 connect request:
        // VER | CMD | RSV | ATYP | DST.ADDR | DST.PORT
        request.push(0x05); // Version 5
        request.push(0x01); // CONNECT command
        request.push(0x00); // Reserved
        
        // Address type and address
        if let Ok(ip) = target_host.parse::<std::net::Ipv4Addr>() {
            // IPv4 address
            request.push(0x01); // IPv4
            request.extend_from_slice(&ip.octets());
        } else if let Ok(ip) = target_host.parse::<std::net::Ipv6Addr>() {
            // IPv6 address
            request.push(0x04); // IPv6
            request.extend_from_slice(&ip.octets());
        } else {
            // Domain name
            request.push(0x03); // Domain name
            let hostname_bytes = target_host.as_bytes();
            request.push(hostname_bytes.len() as u8);
            request.extend_from_slice(hostname_bytes);
        }
        
        // Port (2 bytes, big-endian)
        request.extend_from_slice(&target_port.to_be_bytes());
        
        Ok(request)
    }

    pub fn create_socks5_auth_request(&self) -> Vec<u8> {
        let mut request = Vec::new();
        
        // SOCKS5 authentication request:
        // VER | NMETHODS | METHODS
        request.push(0x05); // Version 5
        
        if self.proxy.auth.is_some() {
            // Support both no auth and username/password
            request.push(0x02); // Number of methods
            request.push(0x00); // No authentication
            request.push(0x02); // Username/password authentication
        } else {
            // Only no authentication
            request.push(0x01); // Number of methods
            request.push(0x00); // No authentication
        }
        
        request
    }

    pub fn create_socks5_username_password_auth(&self) -> Result<Vec<u8>> {
        let auth = self.proxy.auth.as_ref()
            .ok_or_else(|| Error::ProxyError("No authentication provided".to_string()))?;

        match auth {
            Auth::Basic(basic_auth) => {
                let mut request = Vec::new();
                
                // Username/password authentication:
                // VER | ULEN | UNAME | PLEN | PASSWD
                request.push(0x01); // Version 1
                
                // Username
                let username = basic_auth.username.as_bytes();
                request.push(username.len() as u8);
                request.extend_from_slice(username);
                
                // Password
                let password = basic_auth.password.as_bytes();
                request.push(password.len() as u8);
                request.extend_from_slice(password);
                
                Ok(request)
            },
            _ => Err(Error::ProxyError("Unsupported authentication type for SOCKS5".to_string())),
        }
    }

    pub fn parse_socks4_response(&self, response: &[u8]) -> Result<bool> {
        if response.len() < 8 {
            return Err(Error::ProxyError("Invalid SOCKS4 response".to_string()));
        }

        let version = response[0];
        let status = response[1];

        if version != 0x00 {
            return Err(Error::ProxyError("Invalid SOCKS4 response version".to_string()));
        }

        match status {
            0x5A => Ok(true), // Request granted
            0x5B => Err(Error::ProxyError("SOCKS4: Request rejected or failed".to_string())),
            0x5C => Err(Error::ProxyError("SOCKS4: Cannot connect to identd".to_string())),
            0x5D => Err(Error::ProxyError("SOCKS4: Different user IDs".to_string())),
            _ => Err(Error::ProxyError("SOCKS4: Unknown error".to_string())),
        }
    }

    pub fn parse_socks5_response(&self, response: &[u8]) -> Result<bool> {
        if response.len() < 4 {
            return Err(Error::ProxyError("Invalid SOCKS5 connect response".to_string()));
        }

        let version = response[0];
        let status = response[1];
        let _reserved = response[2];
        let address_type = response[3];

        if version != 0x05 {
            return Err(Error::ProxyError("Invalid SOCKS5 version".to_string()));
        }

        match status {
            0x00 => {
                // Success - validate the rest of the response
                let expected_len = match address_type {
                    0x01 => 10, // IPv4: 4 + 4 + 2
                    0x03 => {   // Domain name: 4 + 1 + len + 2
                        if response.len() < 5 {
                            return Err(Error::ProxyError("Invalid domain response".to_string()));
                        }
                        5 + response[4] as usize + 2
                    },
                    0x04 => 22, // IPv6: 4 + 16 + 2
                    _ => return Err(Error::ProxyError("Invalid address type".to_string())),
                };

                if response.len() < expected_len {
                    return Err(Error::ProxyError("Incomplete SOCKS5 response".to_string()));
                }

                Ok(true)
            },
            0x01 => Err(Error::ProxyError("SOCKS5: General SOCKS server failure".to_string())),
            0x02 => Err(Error::ProxyError("SOCKS5: Connection not allowed by ruleset".to_string())),
            0x03 => Err(Error::ProxyError("SOCKS5: Network unreachable".to_string())),
            0x04 => Err(Error::ProxyError("SOCKS5: Host unreachable".to_string())),
            0x05 => Err(Error::ProxyError("SOCKS5: Connection refused".to_string())),
            0x06 => Err(Error::ProxyError("SOCKS5: TTL expired".to_string())),
            0x07 => Err(Error::ProxyError("SOCKS5: Command not supported".to_string())),
            0x08 => Err(Error::ProxyError("SOCKS5: Address type not supported".to_string())),
            _ => Err(Error::ProxyError("SOCKS5: Unknown error".to_string())),
        }
    }
}

// Proxy connection manager
pub struct ProxyManager {
    proxy: Proxy,
}

impl ProxyManager {
    pub fn new(proxy: Proxy) -> Self {
        ProxyManager { proxy }
    }

    pub fn get_proxy_type(&self) -> ProxyType {
        ProxyType::from_scheme(&self.proxy.url.scheme).unwrap_or(ProxyType::Http)
    }

    pub fn create_connect_request(&self, target_host: &str, target_port: u16) -> Result<Vec<u8>> {
        match self.get_proxy_type() {
            ProxyType::Http | ProxyType::Https => {
                self.create_http_connect_request(target_host, target_port)
            },
            ProxyType::Socks4 => {
                let connector = SocksConnector::new(self.proxy.clone());
                connector.connect_socks4(target_host, target_port)
            },
            ProxyType::Socks5 => {
                let connector = SocksConnector::new(self.proxy.clone());
                connector.connect_socks5(target_host, target_port)
            },
        }
    }

    fn create_http_connect_request(&self, target_host: &str, target_port: u16) -> Result<Vec<u8>> {
        let mut request = format!(
            "CONNECT {target_host}:{target_port} HTTP/1.1\r\nHost: {target_host}:{target_port}\r\n"
        );

        // Add proxy authentication if needed
        if let Some(Auth::Basic(basic_auth)) = &self.proxy.auth {
            request.push_str(&format!(
                "Proxy-Authorization: {}\r\n",
                basic_auth.to_header_value()
            ));
        }

        request.push_str("\r\n");
        Ok(request.into_bytes())
    }

    pub fn parse_response(&self, response: &[u8]) -> Result<bool> {
        match self.get_proxy_type() {
            ProxyType::Http | ProxyType::Https => {
                let response_str = String::from_utf8_lossy(response);
                Ok(response_str.starts_with("HTTP/1.1 200") || response_str.starts_with("HTTP/1.0 200"))
            },
            ProxyType::Socks4 => {
                let connector = SocksConnector::new(self.proxy.clone());
                connector.parse_socks4_response(response)
            },
            ProxyType::Socks5 => {
                let connector = SocksConnector::new(self.proxy.clone());
                connector.parse_socks5_response(response)
            },
        }
    }
}