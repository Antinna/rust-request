use crate::{Result, Error};
use std::io::{Read, Write};
use std::net::TcpStream;

// WebSocket frame opcodes
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum OpCode {
    Continuation = 0x0,
    Text = 0x1,
    Binary = 0x2,
    Close = 0x8,
    Ping = 0x9,
    Pong = 0xA,
}

impl OpCode {
    pub fn from_u8(value: u8) -> Option<Self> {
        match value & 0x0F {
            0x0 => Some(OpCode::Continuation),
            0x1 => Some(OpCode::Text),
            0x2 => Some(OpCode::Binary),
            0x8 => Some(OpCode::Close),
            0x9 => Some(OpCode::Ping),
            0xA => Some(OpCode::Pong),
            _ => None,
        }
    }
}

// WebSocket frame structure
#[derive(Debug, Clone)]
pub struct WebSocketFrame {
    pub fin: bool,
    pub opcode: OpCode,
    pub masked: bool,
    pub payload: Vec<u8>,
}

impl WebSocketFrame {
    pub fn new(opcode: OpCode, payload: Vec<u8>) -> Self {
        WebSocketFrame {
            fin: true,
            opcode,
            masked: true, // Client frames should be masked
            payload,
        }
    }

    pub fn text(text: &str) -> Self {
        Self::new(OpCode::Text, text.as_bytes().to_vec())
    }

    pub fn binary(data: Vec<u8>) -> Self {
        Self::new(OpCode::Binary, data)
    }

    pub fn close() -> Self {
        Self::new(OpCode::Close, Vec::new())
    }

    pub fn close_with_payload(payload: Vec<u8>) -> Self {
        Self::new(OpCode::Close, payload)
    }

    pub fn ping(data: Vec<u8>) -> Self {
        Self::new(OpCode::Ping, data)
    }

    pub fn pong(data: Vec<u8>) -> Self {
        Self::new(OpCode::Pong, data)
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut frame = Vec::new();

        // First byte: FIN + RSV + Opcode
        let mut first_byte = self.opcode as u8;
        if self.fin {
            first_byte |= 0x80;
        }
        frame.push(first_byte);

        // Second byte: MASK + Payload length
        let payload_len = self.payload.len();
        let mut second_byte = 0u8;
        if self.masked {
            second_byte |= 0x80;
        }

        if payload_len < 126 {
            second_byte |= payload_len as u8;
            frame.push(second_byte);
        } else if payload_len < 65536 {
            second_byte |= 126;
            frame.push(second_byte);
            frame.extend_from_slice(&(payload_len as u16).to_be_bytes());
        } else {
            second_byte |= 127;
            frame.push(second_byte);
            frame.extend_from_slice(&(payload_len as u64).to_be_bytes());
        }

        // Masking key (if masked)
        let mask_key = if self.masked {
            let key = generate_mask_key();
            frame.extend_from_slice(&key);
            Some(key)
        } else {
            None
        };

        // Payload (masked if necessary)
        if let Some(key) = mask_key {
            let masked_payload: Vec<u8> = self.payload
                .iter()
                .enumerate()
                .map(|(i, &byte)| byte ^ key[i % 4])
                .collect();
            frame.extend_from_slice(&masked_payload);
        } else {
            frame.extend_from_slice(&self.payload);
        }

        frame
    }

    pub fn from_bytes(data: &[u8]) -> Result<(Self, usize)> {
        if data.len() < 2 {
            return Err(Error::InvalidResponse("WebSocket frame too short".to_string()));
        }

        let first_byte = data[0];
        let second_byte = data[1];

        let fin = (first_byte & 0x80) != 0;
        let opcode = OpCode::from_u8(first_byte)
            .ok_or_else(|| Error::InvalidResponse("Invalid WebSocket opcode".to_string()))?;
        let masked = (second_byte & 0x80) != 0;

        let mut pos = 2;
        let payload_len = match second_byte & 0x7F {
            126 => {
                if data.len() < pos + 2 {
                    return Err(Error::InvalidResponse("WebSocket frame incomplete".to_string()));
                }
                let len = u16::from_be_bytes([data[pos], data[pos + 1]]) as usize;
                pos += 2;
                len
            },
            127 => {
                if data.len() < pos + 8 {
                    return Err(Error::InvalidResponse("WebSocket frame incomplete".to_string()));
                }
                let len = u64::from_be_bytes([
                    data[pos], data[pos + 1], data[pos + 2], data[pos + 3],
                    data[pos + 4], data[pos + 5], data[pos + 6], data[pos + 7],
                ]) as usize;
                pos += 8;
                len
            },
            len => len as usize,
        };

        let mask_key = if masked {
            if data.len() < pos + 4 {
                return Err(Error::InvalidResponse("WebSocket frame incomplete".to_string()));
            }
            let key = [data[pos], data[pos + 1], data[pos + 2], data[pos + 3]];
            pos += 4;
            Some(key)
        } else {
            None
        };

        if data.len() < pos + payload_len {
            return Err(Error::InvalidResponse("WebSocket frame incomplete".to_string()));
        }

        let payload = if let Some(key) = mask_key {
            data[pos..pos + payload_len]
                .iter()
                .enumerate()
                .map(|(i, &byte)| byte ^ key[i % 4])
                .collect()
        } else {
            data[pos..pos + payload_len].to_vec()
        };

        let frame = WebSocketFrame {
            fin,
            opcode,
            masked,
            payload,
        };

        Ok((frame, pos + payload_len))
    }
}

// WebSocket connection state
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum WebSocketState {
    Connecting,
    Open,
    Closing,
    Closed,
}

// WebSocket connection
pub struct WebSocketConnection {
    stream: TcpStream,
    state: WebSocketState,
}

impl WebSocketConnection {
    pub fn connect(mut stream: TcpStream, host: &str, path: &str) -> Result<Self> {
        // Send WebSocket handshake
        let key = generate_websocket_key();
        let handshake = format!(
            "GET {path} HTTP/1.1\r\n\
             Host: {host}\r\n\
             Upgrade: websocket\r\n\
             Connection: Upgrade\r\n\
             Sec-WebSocket-Key: {key}\r\n\
             Sec-WebSocket-Version: 13\r\n\
             \r\n"
        );

        stream.write_all(handshake.as_bytes())?;
        stream.flush()?;

        // Read handshake response
        let mut response = Vec::new();
        let mut buffer = [0u8; 1024];
        
        loop {
            let bytes_read = stream.read(&mut buffer)?;
            response.extend_from_slice(&buffer[..bytes_read]);
            
            if response.windows(4).any(|w| w == b"\r\n\r\n") {
                break;
            }
        }

        let response_str = String::from_utf8_lossy(&response);
        
        // Verify handshake response
        if !response_str.contains("HTTP/1.1 101") {
            return Err(Error::WebSocketError("WebSocket handshake failed".to_string()));
        }

        if !response_str.to_lowercase().contains("upgrade: websocket") {
            return Err(Error::WebSocketError("Invalid WebSocket upgrade".to_string()));
        }

        // Verify Sec-WebSocket-Accept
        let expected_accept = calculate_websocket_accept(&key);
        if !response_str.contains(&format!("Sec-WebSocket-Accept: {expected_accept}")) {
            return Err(Error::WebSocketError("Invalid WebSocket accept key".to_string()));
        }

        Ok(WebSocketConnection {
            stream,
            state: WebSocketState::Open,
        })
    }

    pub fn send_frame(&mut self, frame: WebSocketFrame) -> Result<()> {
        if self.state != WebSocketState::Open {
            return Err(Error::WebSocketError("WebSocket connection not open".to_string()));
        }

        let frame_bytes = frame.to_bytes();
        self.stream.write_all(&frame_bytes)?;
        self.stream.flush()?;

        if frame.opcode == OpCode::Close {
            self.state = WebSocketState::Closing;
        }

        Ok(())
    }

    pub fn send_text(&mut self, text: &str) -> Result<()> {
        self.send_frame(WebSocketFrame::text(text))
    }

    pub fn send_binary(&mut self, data: Vec<u8>) -> Result<()> {
        self.send_frame(WebSocketFrame::binary(data))
    }

    pub fn send_ping(&mut self, data: Vec<u8>) -> Result<()> {
        self.send_frame(WebSocketFrame::ping(data))
    }

    pub fn send_pong(&mut self, data: Vec<u8>) -> Result<()> {
        self.send_frame(WebSocketFrame::pong(data))
    }

    pub fn close(&mut self) -> Result<()> {
        self.send_frame(WebSocketFrame::close())?;
        self.state = WebSocketState::Closed;
        Ok(())
    }

    pub fn read_frame(&mut self) -> Result<WebSocketFrame> {
        if self.state == WebSocketState::Closed {
            return Err(Error::WebSocketError("WebSocket connection closed".to_string()));
        }

        let mut buffer = vec![0u8; 8192];
        let bytes_read = self.stream.read(&mut buffer)?;
        buffer.truncate(bytes_read);

        let (frame, _) = WebSocketFrame::from_bytes(&buffer)?;

        match frame.opcode {
            OpCode::Close => {
                self.state = WebSocketState::Closed;
            },
            OpCode::Ping => {
                // Automatically respond to ping with pong
                self.send_pong(frame.payload.clone())?;
            },
            _ => {}
        }

        Ok(frame)
    }

    pub fn read_text(&mut self) -> Result<String> {
        let frame = self.read_frame()?;
        match frame.opcode {
            OpCode::Text => {
                String::from_utf8(frame.payload)
                    .map_err(|_| Error::WebSocketError("Invalid UTF-8 in text frame".to_string()))
            },
            _ => Err(Error::WebSocketError("Expected text frame".to_string())),
        }
    }

    pub fn read_binary(&mut self) -> Result<Vec<u8>> {
        let frame = self.read_frame()?;
        match frame.opcode {
            OpCode::Binary => Ok(frame.payload),
            _ => Err(Error::WebSocketError("Expected binary frame".to_string())),
        }
    }

    pub fn state(&self) -> WebSocketState {
        self.state
    }
}

// Helper functions
fn generate_mask_key() -> [u8; 4] {
    use std::time::{SystemTime, UNIX_EPOCH};
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos() as u32;
    
    [
        (timestamp >> 24) as u8,
        (timestamp >> 16) as u8,
        (timestamp >> 8) as u8,
        timestamp as u8,
    ]
}

fn generate_websocket_key() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    
    let mut key_bytes = [0u8; 16];
    for (i, byte) in key_bytes.iter_mut().enumerate() {
        *byte = ((timestamp >> (i * 8)) & 0xFF) as u8;
    }
    
    base64_encode(&key_bytes)
}

fn calculate_websocket_accept(key: &str) -> String {
    const WEBSOCKET_GUID: &str = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
    let combined = format!("{key}{WEBSOCKET_GUID}");
    
    // Calculate SHA-1 hash
    let hash = sha1_hash(combined.as_bytes());
    base64_encode(&hash)
}

fn base64_encode(input: &[u8]) -> String {
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

fn sha1_hash(input: &[u8]) -> [u8; 20] {
    // Simplified SHA-1 implementation
    let mut h = [
        0x67452301u32,
        0xEFCDAB89u32,
        0x98BADCFEu32,
        0x10325476u32,
        0xC3D2E1F0u32,
    ];

    // Pre-processing
    let mut message = input.to_vec();
    let original_len = message.len();
    
    // Append the '1' bit
    message.push(0x80);
    
    // Append 0 bits until message length ≡ 448 (mod 512)
    while (message.len() % 64) != 56 {
        message.push(0);
    }
    
    // Append original length as 64-bit big-endian integer
    let bit_len = (original_len as u64) * 8;
    message.extend_from_slice(&bit_len.to_be_bytes());

    // Process message in 512-bit chunks
    for chunk in message.chunks_exact(64) {
        let mut w = [0u32; 80];
        
        // Break chunk into sixteen 32-bit big-endian words
        for (i, word) in chunk.chunks_exact(4).enumerate() {
            w[i] = u32::from_be_bytes([word[0], word[1], word[2], word[3]]);
        }
        
        // Extend the sixteen 32-bit words into eighty 32-bit words
        for i in 16..80 {
            w[i] = left_rotate(w[i-3] ^ w[i-8] ^ w[i-14] ^ w[i-16], 1);
        }

        // Initialize hash value for this chunk
        let mut a = h[0];
        let mut b = h[1];
        let mut c = h[2];
        let mut d = h[3];
        let mut e = h[4];

        // Main loop
        for (i, &w_val) in w.iter().enumerate().take(80) {
            let (f, k) = match i {
                0..=19 => ((b & c) | ((!b) & d), 0x5A827999),
                20..=39 => (b ^ c ^ d, 0x6ED9EBA1),
                40..=59 => ((b & c) | (b & d) | (c & d), 0x8F1BBCDC),
                60..=79 => (b ^ c ^ d, 0xCA62C1D6),
                _ => unreachable!(),
            };

            let temp = left_rotate(a, 5)
                .wrapping_add(f)
                .wrapping_add(e)
                .wrapping_add(k)
                .wrapping_add(w_val);
            
            e = d;
            d = c;
            c = left_rotate(b, 30);
            b = a;
            a = temp;
        }

        // Add this chunk's hash to result so far
        h[0] = h[0].wrapping_add(a);
        h[1] = h[1].wrapping_add(b);
        h[2] = h[2].wrapping_add(c);
        h[3] = h[3].wrapping_add(d);
        h[4] = h[4].wrapping_add(e);
    }

    // Produce the final hash value as a 160-bit number (20 bytes)
    let mut result = [0u8; 20];
    for (i, &word) in h.iter().enumerate() {
        let bytes = word.to_be_bytes();
        result[i * 4..(i + 1) * 4].copy_from_slice(&bytes);
    }

    result
}

fn left_rotate(value: u32, amount: u32) -> u32 {
    (value << amount) | (value >> (32 - amount))
}