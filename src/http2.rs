use crate::{Error, Result};
use std::collections::HashMap;

// HTTP/2 frame types
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum FrameType {
    Data = 0x0,
    Headers = 0x1,
    Priority = 0x2,
    RstStream = 0x3,
    Settings = 0x4,
    PushPromise = 0x5,
    Ping = 0x6,
    GoAway = 0x7,
    WindowUpdate = 0x8,
    Continuation = 0x9,
}

impl FrameType {
    pub fn from_u8(value: u8) -> Option<Self> {
        match value {
            0x0 => Some(FrameType::Data),
            0x1 => Some(FrameType::Headers),
            0x2 => Some(FrameType::Priority),
            0x3 => Some(FrameType::RstStream),
            0x4 => Some(FrameType::Settings),
            0x5 => Some(FrameType::PushPromise),
            0x6 => Some(FrameType::Ping),
            0x7 => Some(FrameType::GoAway),
            0x8 => Some(FrameType::WindowUpdate),
            0x9 => Some(FrameType::Continuation),
            _ => None,
        }
    }
}

// HTTP/2 frame flags
#[derive(Debug, Clone, Copy)]
pub struct FrameFlags(pub u8);

impl Default for FrameFlags {
    fn default() -> Self {
        Self::new()
    }
}

impl FrameFlags {
    pub const END_STREAM: u8 = 0x1;
    pub const END_HEADERS: u8 = 0x4;
    pub const PADDED: u8 = 0x8;
    pub const PRIORITY: u8 = 0x20;

    pub fn new() -> Self {
        FrameFlags(0)
    }

    pub fn with_flag(mut self, flag: u8) -> Self {
        self.0 |= flag;
        self
    }

    pub fn has_flag(&self, flag: u8) -> bool {
        self.0 & flag != 0
    }
}

// HTTP/2 frame structure
#[derive(Debug, Clone)]
pub struct Frame {
    pub frame_type: FrameType,
    pub flags: FrameFlags,
    pub stream_id: u32,
    pub payload: Vec<u8>,
}

impl Frame {
    pub fn new(frame_type: FrameType, flags: FrameFlags, stream_id: u32, payload: Vec<u8>) -> Self {
        Frame {
            frame_type,
            flags,
            stream_id,
            payload,
        }
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();

        // Length (24 bits)
        let length = self.payload.len() as u32;
        bytes.push((length >> 16) as u8);
        bytes.push((length >> 8) as u8);
        bytes.push(length as u8);

        // Type
        bytes.push(self.frame_type as u8);

        // Flags
        bytes.push(self.flags.0);

        // Stream ID (31 bits, R bit is 0)
        let stream_id = self.stream_id & 0x7FFFFFFF;
        bytes.extend_from_slice(&stream_id.to_be_bytes());

        // Payload
        bytes.extend_from_slice(&self.payload);

        bytes
    }

    pub fn from_bytes(data: &[u8]) -> Result<Self> {
        if data.len() < 9 {
            return Err(Error::InvalidResponse("HTTP/2 frame too short".to_string()));
        }

        let length = ((data[0] as u32) << 16) | ((data[1] as u32) << 8) | (data[2] as u32);
        let frame_type = FrameType::from_u8(data[3])
            .ok_or_else(|| Error::InvalidResponse("Unknown HTTP/2 frame type".to_string()))?;
        let flags = FrameFlags(data[4]);
        let stream_id = u32::from_be_bytes([data[5], data[6], data[7], data[8]]) & 0x7FFFFFFF;

        if data.len() < 9 + length as usize {
            return Err(Error::InvalidResponse(
                "HTTP/2 frame payload incomplete".to_string(),
            ));
        }

        let payload = data[9..9 + length as usize].to_vec();

        Ok(Frame::new(frame_type, flags, stream_id, payload))
    }
}

// HTTP/2 connection management
pub struct Http2Connection {
    settings: HashMap<u16, u32>,
    streams: HashMap<u32, Http2Stream>,
    next_stream_id: u32,
    window_size: u32,
    max_frame_size: u32,
}

impl Default for Http2Connection {
    fn default() -> Self {
        Self::new()
    }
}

impl Http2Connection {
    pub fn new() -> Self {
        let mut settings = HashMap::new();
        settings.insert(SETTINGS_HEADER_TABLE_SIZE, 4096);
        settings.insert(SETTINGS_ENABLE_PUSH, 1);
        settings.insert(SETTINGS_MAX_CONCURRENT_STREAMS, 100);
        settings.insert(SETTINGS_INITIAL_WINDOW_SIZE, 65535);
        settings.insert(SETTINGS_MAX_FRAME_SIZE, 16384);
        settings.insert(SETTINGS_MAX_HEADER_LIST_SIZE, 8192);

        Http2Connection {
            settings,
            streams: HashMap::new(),
            next_stream_id: 1,
            window_size: 65535,
            max_frame_size: 16384,
        }
    }

    pub fn create_connection_preface(&self) -> Vec<u8> {
        // HTTP/2 connection preface
        let mut preface = Vec::new();
        preface.extend_from_slice(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n");

        // Initial SETTINGS frame
        let settings_frame = self.create_settings_frame();
        preface.extend_from_slice(&settings_frame.to_bytes());

        preface
    }

    pub fn create_settings_frame(&self) -> Frame {
        let mut payload = Vec::new();

        for (&id, &value) in &self.settings {
            payload.extend_from_slice(&id.to_be_bytes());
            payload.extend_from_slice(&value.to_be_bytes());
        }

        Frame::new(
            FrameType::Settings,
            FrameFlags::new(),
            0, // Stream ID 0 for connection-level frames
            payload,
        )
    }

    pub fn create_headers_frame(
        &mut self,
        headers: &[(String, String)],
        end_stream: bool,
    ) -> Result<Frame> {
        let stream_id = self.next_stream_id;
        self.next_stream_id += 2; // Client streams are odd-numbered

        let mut flags = FrameFlags::new().with_flag(FrameFlags::END_HEADERS);
        if end_stream {
            flags = flags.with_flag(FrameFlags::END_STREAM);
        }

        // Encode headers using HPACK (simplified)
        let payload = self.encode_headers(headers)?;

        let stream = Http2Stream::new(stream_id);
        self.streams.insert(stream_id, stream);

        Ok(Frame::new(FrameType::Headers, flags, stream_id, payload))
    }

    pub fn create_data_frame(&self, stream_id: u32, data: &[u8], end_stream: bool) -> Frame {
        let mut flags = FrameFlags::new();
        if end_stream {
            flags = flags.with_flag(FrameFlags::END_STREAM);
        }

        // Respect max frame size
        let chunk_size = std::cmp::min(data.len(), self.max_frame_size as usize);
        let frame_data = data[..chunk_size].to_vec();

        Frame::new(FrameType::Data, flags, stream_id, frame_data)
    }

    pub fn process_frame(&mut self, frame: Frame) -> Result<Option<Vec<u8>>> {
        match frame.frame_type {
            FrameType::Settings => {
                self.process_settings_frame(&frame)?;
                // Send SETTINGS ACK
                let ack_frame = Frame::new(
                    FrameType::Settings,
                    FrameFlags::new().with_flag(0x1), // ACK flag
                    0,
                    Vec::new(),
                );
                Ok(Some(ack_frame.to_bytes()))
            }
            FrameType::Headers => {
                self.process_headers_frame(&frame)?;
                Ok(None)
            }
            FrameType::Data => {
                let data = self.process_data_frame(&frame)?;
                Ok(Some(data))
            }
            FrameType::WindowUpdate => {
                self.process_window_update_frame(&frame)?;
                Ok(None)
            }
            FrameType::Ping => {
                // Send PING ACK
                let ack_frame = Frame::new(
                    FrameType::Ping,
                    FrameFlags::new().with_flag(0x1), // ACK flag
                    0,
                    frame.payload,
                );
                Ok(Some(ack_frame.to_bytes()))
            }
            _ => Ok(None),
        }
    }

    fn process_settings_frame(&mut self, frame: &Frame) -> Result<()> {
        if frame.payload.len() % 6 != 0 {
            return Err(Error::InvalidResponse("Invalid SETTINGS frame".to_string()));
        }

        for chunk in frame.payload.chunks_exact(6) {
            let id = u16::from_be_bytes([chunk[0], chunk[1]]);
            let value = u32::from_be_bytes([chunk[2], chunk[3], chunk[4], chunk[5]]);
            self.settings.insert(id, value);
        }

        Ok(())
    }

    fn process_headers_frame(&mut self, frame: &Frame) -> Result<()> {
        let headers = self.decode_headers(&frame.payload)?;
        if let Some(stream) = self.streams.get_mut(&frame.stream_id) {
            stream.response_headers = Some(headers);
        }
        Ok(())
    }

    fn process_data_frame(&mut self, frame: &Frame) -> Result<Vec<u8>> {
        if let Some(stream) = self.streams.get_mut(&frame.stream_id) {
            stream.response_data.extend_from_slice(&frame.payload);
            if frame.flags.has_flag(FrameFlags::END_STREAM) {
                stream.complete = true;
            }
        }
        Ok(frame.payload.clone())
    }

    fn process_window_update_frame(&mut self, frame: &Frame) -> Result<()> {
        if frame.payload.len() != 4 {
            return Err(Error::InvalidResponse(
                "Invalid WINDOW_UPDATE frame".to_string(),
            ));
        }

        let increment = u32::from_be_bytes([
            frame.payload[0],
            frame.payload[1],
            frame.payload[2],
            frame.payload[3],
        ]) & 0x7FFFFFFF;

        if frame.stream_id == 0 {
            self.window_size += increment;
        } else if let Some(stream) = self.streams.get_mut(&frame.stream_id) {
            stream.window_size += increment;
        }

        Ok(())
    }

    fn encode_headers(&self, headers: &[(String, String)]) -> Result<Vec<u8>> {
        // Simplified HPACK encoding
        let mut encoded = Vec::new();

        for (name, value) in headers {
            // Literal header field with incremental indexing
            encoded.push(0x40);

            // Name length and name
            encoded.push(name.len() as u8);
            encoded.extend_from_slice(name.as_bytes());

            // Value length and value
            encoded.push(value.len() as u8);
            encoded.extend_from_slice(value.as_bytes());
        }

        Ok(encoded)
    }

    fn decode_headers(&self, data: &[u8]) -> Result<Vec<(String, String)>> {
        // Simplified HPACK decoding
        let mut headers = Vec::new();
        let mut pos = 0;

        while pos < data.len() {
            if pos + 1 >= data.len() {
                break;
            }

            let first_byte = data[pos];
            pos += 1;

            if first_byte & 0x80 != 0 {
                // Indexed header field
                let index = (first_byte & 0x7F) as usize;
                if let Some((name, value)) = get_static_header(index) {
                    headers.push((name.to_string(), value.to_string()));
                }
            } else if first_byte & 0x40 != 0 {
                // Literal header field with incremental indexing
                if pos >= data.len() {
                    break;
                }

                let name_len = data[pos] as usize;
                pos += 1;

                if pos + name_len >= data.len() {
                    break;
                }

                let name = String::from_utf8_lossy(&data[pos..pos + name_len]).to_string();
                pos += name_len;

                if pos >= data.len() {
                    break;
                }

                let value_len = data[pos] as usize;
                pos += 1;

                if pos + value_len > data.len() {
                    break;
                }

                let value = String::from_utf8_lossy(&data[pos..pos + value_len]).to_string();
                pos += value_len;

                headers.push((name, value));
            } else {
                // Skip unknown header types
                pos += 1;
            }
        }

        Ok(headers)
    }

    pub fn validate_frame_size(&self, frame: &Frame) -> Result<()> {
        if frame.payload.len() > self.max_frame_size as usize {
            return Err(Error::InvalidResponse(
                format!("Frame size {} exceeds maximum {}", frame.payload.len(), self.max_frame_size)
            ));
        }
        Ok(())
    }

    pub fn set_max_frame_size(&mut self, size: u32) {
        if (16384..=16777215).contains(&size) {
            self.max_frame_size = size;
        }
    }

    pub fn get_max_frame_size(&self) -> u32 {
        self.max_frame_size
    }
}

// HTTP/2 stream state
#[derive(Debug)]
pub struct Http2Stream {
    pub id: u32,
    pub state: StreamState,
    pub window_size: u32,
    pub response_headers: Option<Vec<(String, String)>>,
    pub response_data: Vec<u8>,
    pub complete: bool,
}

impl Http2Stream {
    pub fn new(id: u32) -> Self {
        Http2Stream {
            id,
            state: StreamState::Idle,
            window_size: 65535,
            response_headers: None,
            response_data: Vec::new(),
            complete: false,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum StreamState {
    Idle,
    Open,
    HalfClosedLocal,
    HalfClosedRemote,
    Closed,
}

// HTTP/2 settings identifiers
pub const SETTINGS_HEADER_TABLE_SIZE: u16 = 0x1;
pub const SETTINGS_ENABLE_PUSH: u16 = 0x2;
pub const SETTINGS_MAX_CONCURRENT_STREAMS: u16 = 0x3;
pub const SETTINGS_INITIAL_WINDOW_SIZE: u16 = 0x4;
pub const SETTINGS_MAX_FRAME_SIZE: u16 = 0x5;
pub const SETTINGS_MAX_HEADER_LIST_SIZE: u16 = 0x6;

// Static table for HPACK (simplified)
fn get_static_header(index: usize) -> Option<(&'static str, &'static str)> {
    match index {
        1 => Some((":authority", "")),
        2 => Some((":method", "GET")),
        3 => Some((":method", "POST")),
        4 => Some((":path", "/")),
        5 => Some((":path", "/index.html")),
        6 => Some((":scheme", "http")),
        7 => Some((":scheme", "https")),
        8 => Some((":status", "200")),
        9 => Some((":status", "204")),
        10 => Some((":status", "206")),
        11 => Some((":status", "304")),
        12 => Some((":status", "400")),
        13 => Some((":status", "404")),
        14 => Some((":status", "500")),
        15 => Some(("accept-charset", "")),
        16 => Some(("accept-encoding", "gzip, deflate")),
        17 => Some(("accept-language", "")),
        18 => Some(("accept-ranges", "")),
        19 => Some(("accept", "")),
        20 => Some(("access-control-allow-origin", "")),
        21 => Some(("age", "")),
        22 => Some(("allow", "")),
        23 => Some(("authorization", "")),
        24 => Some(("cache-control", "")),
        25 => Some(("content-disposition", "")),
        26 => Some(("content-encoding", "")),
        27 => Some(("content-language", "")),
        28 => Some(("content-length", "")),
        29 => Some(("content-location", "")),
        30 => Some(("content-range", "")),
        31 => Some(("content-type", "")),
        32 => Some(("cookie", "")),
        33 => Some(("date", "")),
        34 => Some(("etag", "")),
        35 => Some(("expect", "")),
        36 => Some(("expires", "")),
        37 => Some(("from", "")),
        38 => Some(("host", "")),
        39 => Some(("if-match", "")),
        40 => Some(("if-modified-since", "")),
        41 => Some(("if-none-match", "")),
        42 => Some(("if-range", "")),
        43 => Some(("if-unmodified-since", "")),
        44 => Some(("last-modified", "")),
        45 => Some(("link", "")),
        46 => Some(("location", "")),
        47 => Some(("max-forwards", "")),
        48 => Some(("proxy-authenticate", "")),
        49 => Some(("proxy-authorization", "")),
        50 => Some(("range", "")),
        51 => Some(("referer", "")),
        52 => Some(("refresh", "")),
        53 => Some(("retry-after", "")),
        54 => Some(("server", "")),
        55 => Some(("set-cookie", "")),
        56 => Some(("strict-transport-security", "")),
        57 => Some(("transfer-encoding", "")),
        58 => Some(("user-agent", "")),
        59 => Some(("vary", "")),
        60 => Some(("via", "")),
        61 => Some(("www-authenticate", "")),
        _ => None,
    }
}
