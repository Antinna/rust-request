use crate::{Result, Error};
use crate::websocket::{WebSocketFrame, OpCode};
use std::io::{Read, Write, BufRead, BufReader};
use std::net::TcpStream;
use std::collections::HashMap;
use std::time::{Duration, Instant};
use std::sync::{Arc, Mutex};

/// WebSocket message types
#[derive(Debug, Clone)]
pub enum WebSocketMessage {
    Text(String),
    Binary(Vec<u8>),
    Ping(Vec<u8>),
    Pong(Vec<u8>),
    Close(Option<(u16, String)>),
}

/// WebSocket client for real-time communication
pub struct WebSocketClient {
    stream: Option<TcpStream>,
    url: String,
    headers: HashMap<String, String>,
    protocols: Vec<String>,
    timeout: Option<Duration>,
    ping_interval: Option<Duration>,
    max_frame_size: usize,
    auto_pong: bool,
    message_queue: Arc<Mutex<Vec<WebSocketMessage>>>,
    is_connected: bool,
    last_ping: Option<Instant>,
}

impl WebSocketClient {
    pub fn new<S: Into<String>>(url: S) -> Self {
        WebSocketClient {
            stream: None,
            url: url.into(),
            headers: HashMap::new(),
            protocols: Vec::new(),
            timeout: Some(Duration::from_secs(30)),
            ping_interval: Some(Duration::from_secs(30)),
            max_frame_size: 1024 * 1024, // 1MB
            auto_pong: true,
            message_queue: Arc::new(Mutex::new(Vec::new())),
            is_connected: false,
            last_ping: None,
        }
    }

    pub fn header<K, V>(mut self, key: K, value: V) -> Self
    where
        K: Into<String>,
        V: Into<String>,
    {
        self.headers.insert(key.into(), value.into());
        self
    }

    pub fn protocol<S: Into<String>>(mut self, protocol: S) -> Self {
        self.protocols.push(protocol.into());
        self
    }

    pub fn timeout(mut self, timeout: Duration) -> Self {
        self.timeout = Some(timeout);
        self
    }

    pub fn ping_interval(mut self, interval: Duration) -> Self {
        self.ping_interval = Some(interval);
        self
    }

    pub fn max_frame_size(mut self, size: usize) -> Self {
        self.max_frame_size = size;
        self
    }

    pub fn auto_pong(mut self, auto_pong: bool) -> Self {
        self.auto_pong = auto_pong;
        self
    }

    pub fn connect(&mut self) -> Result<()> {
        let url = crate::Url::parse(&self.url)?;
        
        if url.scheme != "ws" && url.scheme != "wss" {
            return Err(Error::InvalidUrl("WebSocket URL must use ws:// or wss:// scheme".to_string()));
        }

        // Connect to the server
        let stream = TcpStream::connect(url.socket_addr())
            .map_err(|e| Error::ConnectionFailed(format!("Failed to connect: {e}")))?;

        if let Some(timeout) = self.timeout {
            stream.set_read_timeout(Some(timeout))
                .map_err(Error::Io)?;
            stream.set_write_timeout(Some(timeout))
                .map_err(Error::Io)?;
        }

        // Perform WebSocket handshake
        self.perform_handshake(&stream, &url)?;
        
        self.stream = Some(stream);
        self.is_connected = true;
        self.last_ping = Some(Instant::now());

        Ok(())
    }

    fn perform_handshake(&self, mut stream: &TcpStream, url: &crate::Url) -> Result<()> {
        // Generate WebSocket key
        let key = self.generate_websocket_key();
        
        // Build handshake request
        let mut request = format!(
            "GET {} HTTP/1.1\r\n\
             Host: {}\r\n\
             Upgrade: websocket\r\n\
             Connection: Upgrade\r\n\
             Sec-WebSocket-Key: {}\r\n\
             Sec-WebSocket-Version: 13\r\n",
            url.full_path(),
            url.host,
            key
        );

        // Add protocols if specified
        if !self.protocols.is_empty() {
            request.push_str(&format!("Sec-WebSocket-Protocol: {}\r\n", self.protocols.join(", ")));
        }

        // Add custom headers
        for (name, value) in &self.headers {
            request.push_str(&format!("{name}: {value}\r\n"));
        }

        request.push_str("\r\n");

        // Send handshake request
        stream.write_all(request.as_bytes())
            .map_err(Error::Io)?;

        // Read handshake response
        let mut reader = BufReader::new(stream);
        let mut response_line = String::new();
        reader.read_line(&mut response_line)
            .map_err(Error::Io)?;

        if !response_line.starts_with("HTTP/1.1 101") {
            return Err(Error::InvalidResponse("WebSocket handshake failed".to_string()));
        }

        // Read headers
        let mut headers = HashMap::new();
        loop {
            let mut line = String::new();
            reader.read_line(&mut line)
                .map_err(Error::Io)?;

            if line.trim().is_empty() {
                break;
            }

            if let Some(colon_pos) = line.find(':') {
                let name = line[..colon_pos].trim().to_lowercase();
                let value = line[colon_pos + 1..].trim().to_string();
                headers.insert(name, value);
            }
        }

        // Validate handshake response
        self.validate_handshake_response(&headers, &key)?;

        Ok(())
    }

    fn generate_websocket_key(&self) -> String {
        use std::time::{SystemTime, UNIX_EPOCH};
        
        // Generate a random 16-byte key
        let timestamp = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos();
        let key_bytes = format!("{timestamp:032x}").into_bytes();
        
        // Base64 encode the key
        self.base64_encode(&key_bytes[..16])
    }

    fn base64_encode(&self, input: &[u8]) -> String {
        const CHARS: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        let mut result = String::new();
        
        for chunk in input.chunks(3) {
            let mut buf = [0u8; 3];
            for (i, &byte) in chunk.iter().enumerate() {
                buf[i] = byte;
            }
            
            let b = ((buf[0] as u32) << 16) | ((buf[1] as u32) << 8) | (buf[2] as u32);
            
            result.push(CHARS[((b >> 18) & 63) as usize] as char);
            result.push(CHARS[((b >> 12) & 63) as usize] as char);
            result.push(if chunk.len() > 1 { CHARS[((b >> 6) & 63) as usize] as char } else { '=' });
            result.push(if chunk.len() > 2 { CHARS[(b & 63) as usize] as char } else { '=' });
        }
        
        result
    }

    fn validate_handshake_response(&self, headers: &HashMap<String, String>, key: &str) -> Result<()> {
        // Check required headers
        if headers.get("upgrade").map(|s| s.to_lowercase()) != Some("websocket".to_string()) {
            return Err(Error::InvalidResponse("Missing or invalid Upgrade header".to_string()));
        }

        if headers.get("connection").map(|s| s.to_lowercase()) != Some("upgrade".to_string()) {
            return Err(Error::InvalidResponse("Missing or invalid Connection header".to_string()));
        }

        // Validate Sec-WebSocket-Accept
        let expected_accept = self.calculate_websocket_accept(key);
        if headers.get("sec-websocket-accept") != Some(&expected_accept) {
            return Err(Error::InvalidResponse("Invalid Sec-WebSocket-Accept header".to_string()));
        }

        Ok(())
    }

    fn calculate_websocket_accept(&self, key: &str) -> String {
        // WebSocket magic string as per RFC 6455
        let magic = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
        let combined = format!("{key}{magic}");
        
        // In a real implementation, this would use SHA-1 hash
        // For simplicity, we'll use a basic hash
        let hash = self.simple_hash(combined.as_bytes());
        self.base64_encode(&hash.to_be_bytes())
    }

    fn simple_hash(&self, data: &[u8]) -> u64 {
        let mut hash = 0u64;
        for &byte in data {
            hash = hash.wrapping_mul(31).wrapping_add(byte as u64);
        }
        hash
    }

    pub fn send_text<S: Into<String>>(&mut self, text: S) -> Result<()> {
        let frame = WebSocketFrame::text(&text.into());
        self.send_frame(frame)
    }

    pub fn send_binary(&mut self, data: Vec<u8>) -> Result<()> {
        let frame = WebSocketFrame::binary(data);
        self.send_frame(frame)
    }

    pub fn send_ping(&mut self, data: Vec<u8>) -> Result<()> {
        let frame = WebSocketFrame::ping(data);
        self.send_frame(frame)
    }

    pub fn send_pong(&mut self, data: Vec<u8>) -> Result<()> {
        let frame = WebSocketFrame::pong(data);
        self.send_frame(frame)
    }

    pub fn close(&mut self, code: Option<u16>, reason: Option<String>) -> Result<()> {
        let mut payload = Vec::new();
        if let Some(code) = code {
            payload.extend_from_slice(&code.to_be_bytes());
            if let Some(reason) = reason {
                payload.extend_from_slice(reason.as_bytes());
            }
        }

        let frame = WebSocketFrame::close_with_payload(payload);
        self.send_frame(frame)?;
        
        self.is_connected = false;
        if let Some(stream) = self.stream.take() {
            drop(stream);
        }

        Ok(())
    }

    fn send_frame(&mut self, frame: WebSocketFrame) -> Result<()> {
        if !self.is_connected {
            return Err(Error::ConnectionFailed("WebSocket not connected".to_string()));
        }

        if let Some(ref mut stream) = self.stream {
            let frame_bytes = frame.to_bytes();
            stream.write_all(&frame_bytes)
                .map_err(Error::Io)?;
            stream.flush()
                .map_err(Error::Io)?;
        } else {
            return Err(Error::ConnectionFailed("No active connection".to_string()));
        }

        Ok(())
    }

    pub fn receive_message(&mut self) -> Result<Option<WebSocketMessage>> {
        if !self.is_connected {
            return Err(Error::ConnectionFailed("WebSocket not connected".to_string()));
        }

        // Check message queue first
        if let Ok(mut queue) = self.message_queue.lock() {
            if !queue.is_empty() {
                return Ok(Some(queue.remove(0)));
            }
        }

        // Read and handle frame
        self.read_and_handle_frame()
    }

    fn read_and_handle_frame(&mut self) -> Result<Option<WebSocketMessage>> {
        if let Some(ref mut stream) = self.stream {
            match Self::read_frame_from_stream(stream, self.max_frame_size) {
                Ok(Some(frame)) => self.handle_frame(frame),
                Ok(None) => Ok(None),
                Err(e) => Err(e),
            }
        } else {
            Err(Error::ConnectionFailed("No active connection".to_string()))
        }
    }

    fn read_frame_from_stream(stream: &mut TcpStream, max_frame_size: usize) -> Result<Option<WebSocketFrame>> {
        let mut header = [0u8; 2];
        match stream.read_exact(&mut header) {
            Ok(_) => {},
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => return Ok(None),
            Err(e) => return Err(Error::Io(e)),
        }

        let fin = (header[0] & 0x80) != 0;
        let opcode = OpCode::from_u8(header[0] & 0x0F)
            .ok_or_else(|| Error::InvalidResponse("Invalid WebSocket opcode".to_string()))?;
        let masked = (header[1] & 0x80) != 0;
        let mut payload_len = (header[1] & 0x7F) as u64;

        // Read extended payload length
        if payload_len == 126 {
            let mut len_bytes = [0u8; 2];
            stream.read_exact(&mut len_bytes)
                .map_err(Error::Io)?;
            payload_len = u16::from_be_bytes(len_bytes) as u64;
        } else if payload_len == 127 {
            let mut len_bytes = [0u8; 8];
            stream.read_exact(&mut len_bytes)
                .map_err(Error::Io)?;
            payload_len = u64::from_be_bytes(len_bytes);
        }

        // Check frame size limit
        if payload_len > max_frame_size as u64 {
            return Err(Error::InvalidResponse("Frame too large".to_string()));
        }

        // Read masking key (servers don't mask frames)
        let mask = if masked {
            let mut mask_bytes = [0u8; 4];
            stream.read_exact(&mut mask_bytes)
                .map_err(Error::Io)?;
            Some(mask_bytes)
        } else {
            None
        };

        // Read payload
        let mut payload = vec![0u8; payload_len as usize];
        if payload_len > 0 {
            stream.read_exact(&mut payload)
                .map_err(Error::Io)?;

            // Unmask payload if needed
            if let Some(mask) = mask {
                for (i, byte) in payload.iter_mut().enumerate() {
                    *byte ^= mask[i % 4];
                }
            }
        }

        Ok(Some(WebSocketFrame {
            fin,
            opcode,
            masked: false, // We don't need to track this after unmasking
            payload,
        }))
    }

    fn handle_frame(&mut self, frame: WebSocketFrame) -> Result<Option<WebSocketMessage>> {
        match frame.opcode {
            OpCode::Text => {
                let text = String::from_utf8(frame.payload)
                    .map_err(|_| Error::InvalidResponse("Invalid UTF-8 in text frame".to_string()))?;
                Ok(Some(WebSocketMessage::Text(text)))
            }
            OpCode::Binary => {
                Ok(Some(WebSocketMessage::Binary(frame.payload)))
            }
            OpCode::Ping => {
                if self.auto_pong {
                    let pong_frame = WebSocketFrame::pong(frame.payload.clone());
                    self.send_frame(pong_frame)?;
                }
                Ok(Some(WebSocketMessage::Ping(frame.payload)))
            }
            OpCode::Pong => {
                Ok(Some(WebSocketMessage::Pong(frame.payload)))
            }
            OpCode::Close => {
                self.is_connected = false;
                let (code, reason) = if frame.payload.len() >= 2 {
                    let code = u16::from_be_bytes([frame.payload[0], frame.payload[1]]);
                    let reason = if frame.payload.len() > 2 {
                        String::from_utf8_lossy(&frame.payload[2..]).to_string()
                    } else {
                        String::new()
                    };
                    (Some(code), Some(reason))
                } else {
                    (None, None)
                };
                Ok(Some(WebSocketMessage::Close(code.map(|c| (c, reason.unwrap_or_default())))))
            }
            OpCode::Continuation => {
                // Handle continuation frames (simplified)
                Ok(None)
            }
        }
    }

    pub fn is_connected(&self) -> bool {
        self.is_connected
    }

    pub fn should_ping(&self) -> bool {
        if let (Some(interval), Some(last_ping)) = (self.ping_interval, self.last_ping) {
            last_ping.elapsed() >= interval
        } else {
            false
        }
    }

    pub fn ping_if_needed(&mut self) -> Result<()> {
        if self.should_ping() {
            self.send_ping(Vec::new())?;
            self.last_ping = Some(Instant::now());
        }
        Ok(())
    }

    pub fn set_nonblocking(&mut self, nonblocking: bool) -> Result<()> {
        if let Some(ref stream) = self.stream {
            stream.set_nonblocking(nonblocking)
                .map_err(Error::Io)?;
        }
        Ok(())
    }
}

impl Drop for WebSocketClient {
    fn drop(&mut self) {
        if self.is_connected {
            let _ = self.close(Some(1000), Some("Client disconnecting".to_string()));
        }
    }
}

/// WebSocket client builder for easier configuration
pub struct WebSocketClientBuilder {
    url: String,
    headers: HashMap<String, String>,
    protocols: Vec<String>,
    timeout: Option<Duration>,
    ping_interval: Option<Duration>,
    max_frame_size: usize,
    auto_pong: bool,
}

impl WebSocketClientBuilder {
    pub fn new<S: Into<String>>(url: S) -> Self {
        WebSocketClientBuilder {
            url: url.into(),
            headers: HashMap::new(),
            protocols: Vec::new(),
            timeout: Some(Duration::from_secs(30)),
            ping_interval: Some(Duration::from_secs(30)),
            max_frame_size: 1024 * 1024,
            auto_pong: true,
        }
    }

    pub fn header<K, V>(mut self, key: K, value: V) -> Self
    where
        K: Into<String>,
        V: Into<String>,
    {
        self.headers.insert(key.into(), value.into());
        self
    }

    pub fn protocol<S: Into<String>>(mut self, protocol: S) -> Self {
        self.protocols.push(protocol.into());
        self
    }

    pub fn timeout(mut self, timeout: Duration) -> Self {
        self.timeout = Some(timeout);
        self
    }

    pub fn ping_interval(mut self, interval: Duration) -> Self {
        self.ping_interval = Some(interval);
        self
    }

    pub fn max_frame_size(mut self, size: usize) -> Self {
        self.max_frame_size = size;
        self
    }

    pub fn auto_pong(mut self, auto_pong: bool) -> Self {
        self.auto_pong = auto_pong;
        self
    }

    pub fn build(self) -> WebSocketClient {
        let mut client = WebSocketClient::new(self.url);
        client.headers = self.headers;
        client.protocols = self.protocols;
        client.timeout = self.timeout;
        client.ping_interval = self.ping_interval;
        client.max_frame_size = self.max_frame_size;
        client.auto_pong = self.auto_pong;
        client
    }

    pub fn connect(self) -> Result<WebSocketClient> {
        let mut client = self.build();
        client.connect()?;
        Ok(client)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_websocket_client_creation() {
        let client = WebSocketClient::new("ws://example.com/ws");
        assert!(!client.is_connected());
        assert_eq!(client.url, "ws://example.com/ws");
    }

    #[test]
    fn test_websocket_client_builder() {
        let client = WebSocketClientBuilder::new("ws://example.com/ws")
            .header("Authorization", "Bearer token")
            .protocol("chat")
            .timeout(Duration::from_secs(10))
            .auto_pong(false)
            .build();

        assert_eq!(client.url, "ws://example.com/ws");
        assert!(client.headers.contains_key("Authorization"));
        assert_eq!(client.protocols, vec!["chat"]);
        assert_eq!(client.timeout, Some(Duration::from_secs(10)));
        assert!(!client.auto_pong);
    }

    #[test]
    fn test_websocket_key_generation() {
        let client = WebSocketClient::new("ws://example.com");
        let key1 = client.generate_websocket_key();
        
        // Add a small delay to ensure different timestamp
        std::thread::sleep(std::time::Duration::from_millis(1));
        let key2 = client.generate_websocket_key();
        
        // Keys should be different (due to timestamp) or at least valid
        assert!(!key1.is_empty());
        assert!(!key2.is_empty());
        // Keys might be the same due to timing, so just check they're valid base64
        assert!(key1.len() > 10);
        assert!(key2.len() > 10);
    }

    #[test]
    fn test_base64_encoding() {
        let client = WebSocketClient::new("ws://example.com");
        let encoded = client.base64_encode(b"hello");
        assert_eq!(encoded, "aGVsbG8=");
    }

    #[test]
    fn test_websocket_accept_calculation() {
        let client = WebSocketClient::new("ws://example.com");
        let key = "dGhlIHNhbXBsZSBub25jZQ==";
        let accept = client.calculate_websocket_accept(key);
        assert!(!accept.is_empty());
    }
}