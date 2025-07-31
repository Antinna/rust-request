use crate::{Client, CookieJar, Result, Error, Response};
use std::collections::HashMap;
use std::time::{Duration, Instant};
use std::sync::{Arc, Mutex};

/// HTTP session management with automatic cookie handling and state persistence
#[derive(Debug)]
pub struct Session {
    client: Client,
    cookie_jar: CookieJar,
    default_headers: HashMap<String, String>,
    base_url: Option<String>,
    timeout: Option<Duration>,
    max_redirects: usize,
    verify_ssl: bool,
    session_data: Arc<Mutex<HashMap<String, String>>>,
    created_at: Instant,
    last_activity: Arc<Mutex<Instant>>,
}

impl Session {
    pub fn new() -> Self {
        Session {
            client: Client::new(),
            cookie_jar: CookieJar::new(),
            default_headers: HashMap::new(),
            base_url: None,
            timeout: Some(Duration::from_secs(30)),
            max_redirects: 10,
            verify_ssl: true,
            session_data: Arc::new(Mutex::new(HashMap::new())),
            created_at: Instant::now(),
            last_activity: Arc::new(Mutex::new(Instant::now())),
        }
    }

    pub fn with_client(client: Client) -> Self {
        let mut session = Self::new();
        session.client = client;
        session
    }

    pub fn base_url<S: Into<String>>(mut self, url: S) -> Self {
        self.base_url = Some(url.into());
        self
    }

    pub fn timeout(mut self, timeout: Duration) -> Self {
        self.timeout = Some(timeout);
        self
    }

    pub fn max_redirects(mut self, max: usize) -> Self {
        self.max_redirects = max;
        self
    }

    pub fn verify_ssl(mut self, verify: bool) -> Self {
        self.verify_ssl = verify;
        self
    }

    pub fn header<K, V>(mut self, key: K, value: V) -> Self
    where
        K: Into<String>,
        V: Into<String>,
    {
        self.default_headers.insert(key.into(), value.into());
        self
    }

    pub fn headers(mut self, headers: HashMap<String, String>) -> Self {
        self.default_headers.extend(headers);
        self
    }

    pub fn user_agent<S: Into<String>>(mut self, ua: S) -> Self {
        self.default_headers.insert("User-Agent".to_string(), ua.into());
        self
    }

    pub fn auth_basic<U, P>(mut self, username: U, password: P) -> Self
    where
        U: Into<String>,
        P: Into<String>,
    {
        let auth = crate::Auth::basic(&username.into(), &password.into());
        let mut headers = HashMap::new();
        auth.apply_to_headers(&mut headers);
        self.default_headers.extend(headers);
        self
    }

    pub fn auth_bearer<T: Into<String>>(mut self, token: T) -> Self {
        let auth = crate::Auth::bearer(&token.into());
        let mut headers = HashMap::new();
        auth.apply_to_headers(&mut headers);
        self.default_headers.extend(headers);
        self
    }

    // Session data management
    pub fn set_data<K, V>(&self, key: K, value: V)
    where
        K: Into<String>,
        V: Into<String>,
    {
        if let Ok(mut data) = self.session_data.lock() {
            data.insert(key.into(), value.into());
        }
    }

    pub fn get_data(&self, key: &str) -> Option<String> {
        if let Ok(data) = self.session_data.lock() {
            data.get(key).cloned()
        } else {
            None
        }
    }

    pub fn remove_data(&self, key: &str) -> Option<String> {
        if let Ok(mut data) = self.session_data.lock() {
            data.remove(key)
        } else {
            None
        }
    }

    pub fn clear_data(&self) {
        if let Ok(mut data) = self.session_data.lock() {
            data.clear();
        }
    }

    // Cookie management
    pub fn set_cookie(&mut self, name: &str, value: &str, domain: Option<&str>, path: Option<&str>) {
        let mut cookie = crate::Cookie::new(name.to_string(), value.to_string());
        if let Some(domain) = domain {
            cookie.domain = Some(domain.to_string());
        }
        if let Some(path) = path {
            cookie.path = Some(path.to_string());
        }
        self.cookie_jar.add_cookie(cookie);
    }

    pub fn get_cookie(&self, _name: &str) -> Option<String> {
        // Simple implementation - in practice you'd iterate through cookies
        None
    }

    pub fn remove_cookie(&mut self, name: &str) {
        self.cookie_jar.remove_cookie(name, None);
    }

    pub fn clear_cookies(&mut self) {
        self.cookie_jar = CookieJar::new();
    }

    // HTTP methods with session context
    pub fn get(&self, url: &str) -> Result<Response> {
        self.request("GET", url, None)
    }

    pub fn post(&self, url: &str, body: Option<Vec<u8>>) -> Result<Response> {
        self.request("POST", url, body)
    }

    pub fn put(&self, url: &str, body: Option<Vec<u8>>) -> Result<Response> {
        self.request("PUT", url, body)
    }

    pub fn delete(&self, url: &str) -> Result<Response> {
        self.request("DELETE", url, None)
    }

    pub fn patch(&self, url: &str, body: Option<Vec<u8>>) -> Result<Response> {
        self.request("PATCH", url, body)
    }

    pub fn head(&self, url: &str) -> Result<Response> {
        self.request("HEAD", url, None)
    }

    pub fn options(&self, url: &str) -> Result<Response> {
        self.request("OPTIONS", url, None)
    }

    // JSON convenience methods
    pub fn get_json(&self, url: &str) -> Result<crate::JsonValue> {
        let response = self.get(url)?;
        response.json()
    }

    pub fn post_json(&self, url: &str, json: &crate::JsonValue) -> Result<Response> {
        let body = json.to_string().into_bytes();
        let mut headers = HashMap::new();
        headers.insert("Content-Type".to_string(), "application/json".to_string());
        self.request_with_headers("POST", url, Some(body), headers)
    }

    pub fn put_json(&self, url: &str, json: &crate::JsonValue) -> Result<Response> {
        let body = json.to_string().into_bytes();
        let mut headers = HashMap::new();
        headers.insert("Content-Type".to_string(), "application/json".to_string());
        self.request_with_headers("PUT", url, Some(body), headers)
    }

    // Form data methods
    pub fn post_form(&self, url: &str, form_data: &HashMap<String, String>) -> Result<Response> {
        let body = form_data
            .iter()
            .map(|(k, v)| format!("{}={}", urlencoding::encode(k), urlencoding::encode(v)))
            .collect::<Vec<_>>()
            .join("&")
            .into_bytes();

        let mut headers = HashMap::new();
        headers.insert("Content-Type".to_string(), "application/x-www-form-urlencoded".to_string());
        self.request_with_headers("POST", url, Some(body), headers)
    }

    // Core request method
    fn request(&self, method: &str, url: &str, body: Option<Vec<u8>>) -> Result<Response> {
        self.request_with_headers(method, url, body, HashMap::new())
    }

    fn request_with_headers(&self, method: &str, url: &str, body: Option<Vec<u8>>, extra_headers: HashMap<String, String>) -> Result<Response> {
        // Update last activity
        if let Ok(mut last_activity) = self.last_activity.lock() {
            *last_activity = Instant::now();
        }

        // Build full URL
        let full_url = if let Some(ref base) = self.base_url {
            if url.starts_with("http://") || url.starts_with("https://") {
                url.to_string()
            } else {
                format!("{}/{}", base.trim_end_matches('/'), url.trim_start_matches('/'))
            }
        } else {
            url.to_string()
        };

        // Parse method
        let http_method = crate::Method::parse(method)
            .ok_or_else(|| Error::InvalidUrl(format!("Invalid HTTP method: {method}")))?;

        // Build request
        let mut request_builder = self.client.request(http_method, &full_url);

        // Add default headers
        for (key, value) in &self.default_headers {
            request_builder = request_builder.header(key, value);
        }

        // Add extra headers
        for (key, value) in extra_headers {
            request_builder = request_builder.header(key, value);
        }

        // Add body if present
        if let Some(body) = body {
            request_builder = request_builder.body(body);
        }

        // Execute request
        let response = request_builder.send()?;

        // Update cookies from response
        self.update_cookies_from_response(&response);

        Ok(response)
    }

    fn update_cookies_from_response(&self, response: &Response) {
        // Extract Set-Cookie headers and update cookie jar
        for _cookie in &response.cookies {
            // In a real implementation, we would update the session's cookie jar
            // For now, this is a placeholder for the cookie update logic
        }
    }

    // Session info
    pub fn age(&self) -> Duration {
        self.created_at.elapsed()
    }

    pub fn last_activity(&self) -> Duration {
        if let Ok(last_activity) = self.last_activity.lock() {
            last_activity.elapsed()
        } else {
            Duration::from_secs(0)
        }
    }

    pub fn is_expired(&self, max_age: Duration) -> bool {
        self.age() > max_age
    }

    pub fn is_idle(&self, max_idle: Duration) -> bool {
        self.last_activity() > max_idle
    }

    // Session persistence (simplified)
    pub fn save_to_file(&self, path: &str) -> Result<()> {
        use std::fs::File;
        use std::io::Write;

        let session_data = SessionData {
            cookies: format!("{:?}", self.cookie_jar),
            headers: self.default_headers.clone(),
            base_url: self.base_url.clone(),
            created_at: self.created_at,
            custom_data: if let Ok(data) = self.session_data.lock() {
                data.clone()
            } else {
                HashMap::new()
            },
        };

        let json_data = serde_json::to_string(&session_data)
            .map_err(|_| Error::JsonSerializeError("Failed to serialize session".to_string()))?;

        let mut file = File::create(path)
            .map_err(Error::Io)?;

        file.write_all(json_data.as_bytes())
            .map_err(Error::Io)?;

        Ok(())
    }

    pub fn load_from_file(path: &str) -> Result<Self> {
        use std::fs::File;
        use std::io::Read;

        let mut file = File::open(path)
            .map_err(Error::Io)?;

        let mut contents = String::new();
        file.read_to_string(&mut contents)
            .map_err(Error::Io)?;

        let session_data: SessionData = serde_json::from_str(&contents)
            .map_err(|_| Error::JsonParseError("Failed to parse session file".to_string()))?;

        let mut session = Session::new();
        session.default_headers = session_data.headers;
        session.base_url = session_data.base_url;
        session.created_at = session_data.created_at;

        // Restore custom data
        if let Ok(mut data) = session.session_data.lock() {
            *data = session_data.custom_data;
        }

        // TODO: Restore cookies from string representation

        Ok(session)
    }
}

impl Default for Session {
    fn default() -> Self {
        Self::new()
    }
}

impl Clone for Session {
    fn clone(&self) -> Self {
        let custom_data = if let Ok(data) = self.session_data.lock() {
            data.clone()
        } else {
            HashMap::new()
        };

        let last_activity = if let Ok(activity) = self.last_activity.lock() {
            *activity
        } else {
            Instant::now()
        };

        Session {
            client: self.client.clone(),
            cookie_jar: self.cookie_jar.clone(),
            default_headers: self.default_headers.clone(),
            base_url: self.base_url.clone(),
            timeout: self.timeout,
            max_redirects: self.max_redirects,
            verify_ssl: self.verify_ssl,
            session_data: Arc::new(Mutex::new(custom_data)),
            created_at: self.created_at,
            last_activity: Arc::new(Mutex::new(last_activity)),
        }
    }
}

// Session data structure for persistence
#[derive(Debug)]
struct SessionData {
    cookies: String,
    headers: HashMap<String, String>,
    base_url: Option<String>,
    created_at: Instant,
    custom_data: HashMap<String, String>,
}

// Simple JSON serialization for session data (placeholder)
mod serde_json {
    use super::*;
    use std::fmt::Write;

    pub fn to_string(data: &SessionData) -> std::result::Result<String, ()> {
        let mut json = String::new();
        json.push('{');
        
        // This is a very simplified JSON serialization
        // In a real implementation, you'd use a proper JSON library
        write!(&mut json, "\"cookies\":\"{}\",", escape_json(&data.cookies)).map_err(|_| ())?;
        write!(&mut json, "\"base_url\":{},", 
            if let Some(ref url) = data.base_url {
                format!("\"{}\"", escape_json(url))
            } else {
                "null".to_string()
            }
        ).map_err(|_| ())?;
        
        json.push('}');
        Ok(json)
    }

    pub fn from_str(_s: &str) -> std::result::Result<SessionData, ()> {
        // Simplified deserialization - in practice you'd use a real JSON parser
        Err(())
    }

    fn escape_json(s: &str) -> String {
        s.replace('\\', "\\\\")
         .replace('"', "\\\"")
         .replace('\n', "\\n")
         .replace('\r', "\\r")
         .replace('\t', "\\t")
    }
}

// URL encoding module (simplified)
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

/// Session pool for managing multiple sessions
#[derive(Debug)]
pub struct SessionPool {
    sessions: Arc<Mutex<HashMap<String, Session>>>,
    max_sessions: usize,
    session_timeout: Duration,
}

impl SessionPool {
    pub fn new(max_sessions: usize, session_timeout: Duration) -> Self {
        SessionPool {
            sessions: Arc::new(Mutex::new(HashMap::new())),
            max_sessions,
            session_timeout,
        }
    }

    pub fn get_session(&self, session_id: &str) -> Option<Session> {
        if let Ok(mut sessions) = self.sessions.lock() {
            if let Some(session) = sessions.get(session_id) {
                if !session.is_expired(self.session_timeout) {
                    return Some(session.clone());
                } else {
                    sessions.remove(session_id);
                }
            }
        }
        None
    }

    pub fn create_session(&self, session_id: String) -> Result<Session> {
        if let Ok(mut sessions) = self.sessions.lock() {
            // Clean up expired sessions
            let expired_keys: Vec<String> = sessions
                .iter()
                .filter(|(_, session)| session.is_expired(self.session_timeout))
                .map(|(key, _)| key.clone())
                .collect();

            for key in expired_keys {
                sessions.remove(&key);
            }

            // Check if we're at capacity
            if sessions.len() >= self.max_sessions {
                return Err(Error::ConnectionFailed("Session pool at capacity".to_string()));
            }

            let session = Session::new();
            sessions.insert(session_id, session.clone());
            Ok(session)
        } else {
            Err(Error::ConnectionFailed("Failed to access session pool".to_string()))
        }
    }

    pub fn remove_session(&self, session_id: &str) {
        if let Ok(mut sessions) = self.sessions.lock() {
            sessions.remove(session_id);
        }
    }

    pub fn session_count(&self) -> usize {
        if let Ok(sessions) = self.sessions.lock() {
            sessions.len()
        } else {
            0
        }
    }

    pub fn cleanup_expired(&self) {
        if let Ok(mut sessions) = self.sessions.lock() {
            let expired_keys: Vec<String> = sessions
                .iter()
                .filter(|(_, session)| session.is_expired(self.session_timeout))
                .map(|(key, _)| key.clone())
                .collect();

            for key in expired_keys {
                sessions.remove(&key);
            }
        }
    }
}

impl Default for SessionPool {
    fn default() -> Self {
        Self::new(1000, Duration::from_secs(3600)) // 1000 sessions, 1 hour timeout
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_session_creation() {
        let session = Session::new();
        assert!(session.age() < Duration::from_secs(1));
        assert!(session.last_activity() < Duration::from_secs(1));
    }

    #[test]
    fn test_session_data() {
        let session = Session::new();
        session.set_data("key1", "value1");
        assert_eq!(session.get_data("key1"), Some("value1".to_string()));
        
        session.remove_data("key1");
        assert_eq!(session.get_data("key1"), None);
    }

    #[test]
    fn test_session_pool() {
        let pool = SessionPool::new(10, Duration::from_secs(60));
        
        let _session = pool.create_session("test_session".to_string()).unwrap();
        assert_eq!(pool.session_count(), 1);
        
        let retrieved = pool.get_session("test_session");
        assert!(retrieved.is_some());
        
        pool.remove_session("test_session");
        assert_eq!(pool.session_count(), 0);
    }
}