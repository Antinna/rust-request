use std::collections::HashMap;

#[derive(Debug, Clone)]
pub enum Auth {
    Basic(BasicAuth),
    Bearer(BearerAuth),
    Digest(DigestAuth),
    Custom(String, String), // header name, header value
}

impl Auth {
    pub fn basic(username: &str, password: &str) -> Self {
        Auth::Basic(BasicAuth::new(username, password))
    }

    pub fn bearer(token: &str) -> Self {
        Auth::Bearer(BearerAuth::new(token))
    }

    pub fn digest(username: &str, password: &str) -> Self {
        Auth::Digest(DigestAuth::new(username, password))
    }

    pub fn custom(header_name: &str, header_value: &str) -> Self {
        Auth::Custom(header_name.to_string(), header_value.to_string())
    }

    pub fn apply_to_headers(&self, headers: &mut HashMap<String, String>) {
        match self {
            Auth::Basic(basic) => {
                headers.insert("Authorization".to_string(), basic.to_header_value());
            },
            Auth::Bearer(bearer) => {
                headers.insert("Authorization".to_string(), bearer.to_header_value());
            },
            Auth::Digest(digest) => {
                headers.insert("Authorization".to_string(), digest.to_header_value());
            },
            Auth::Custom(name, value) => {
                headers.insert(name.clone(), value.clone());
            },
        }
    }
}

#[derive(Debug, Clone)]
pub struct BasicAuth {
    pub username: String,
    pub password: String,
}

impl BasicAuth {
    pub fn new(username: &str, password: &str) -> Self {
        BasicAuth {
            username: username.to_string(),
            password: password.to_string(),
        }
    }

    pub fn to_header_value(&self) -> String {
        let credentials = format!("{}:{}", self.username, self.password);
        let encoded = base64_encode(credentials.as_bytes());
        format!("Basic {encoded}")
    }
}

#[derive(Debug, Clone)]
pub struct BearerAuth {
    pub token: String,
}

impl BearerAuth {
    pub fn new(token: &str) -> Self {
        BearerAuth {
            token: token.to_string(),
        }
    }

    pub fn to_header_value(&self) -> String {
        format!("Bearer {}", self.token)
    }
}

#[derive(Debug, Clone)]
pub struct DigestAuth {
    pub username: String,
    pub password: String,
    pub realm: Option<String>,
    pub nonce: Option<String>,
    pub uri: Option<String>,
    pub qop: Option<String>,
    pub nc: Option<String>,
    pub cnonce: Option<String>,
    pub response: Option<String>,
    pub opaque: Option<String>,
}

impl DigestAuth {
    pub fn new(username: &str, password: &str) -> Self {
        DigestAuth {
            username: username.to_string(),
            password: password.to_string(),
            realm: None,
            nonce: None,
            uri: None,
            qop: None,
            nc: None,
            cnonce: None,
            response: None,
            opaque: None,
        }
    }

    pub fn parse_challenge(challenge: &str) -> HashMap<String, String> {
        let mut params = HashMap::new();
        
        // Remove "Digest " prefix
        let challenge = challenge.strip_prefix("Digest ").unwrap_or(challenge);
        
        // Parse key=value pairs
        for part in challenge.split(',') {
            let part = part.trim();
            if let Some(eq_pos) = part.find('=') {
                let key = part[..eq_pos].trim().to_string();
                let value = part[eq_pos + 1..].trim();
                // Remove quotes if present
                let value = if value.starts_with('"') && value.ends_with('"') {
                    value[1..value.len()-1].to_string()
                } else {
                    value.to_string()
                };
                params.insert(key, value);
            }
        }
        
        params
    }

    pub fn update_from_challenge(&mut self, challenge: &str) {
        let params = Self::parse_challenge(challenge);
        
        self.realm = params.get("realm").cloned();
        self.nonce = params.get("nonce").cloned();
        self.qop = params.get("qop").cloned();
        self.opaque = params.get("opaque").cloned();
    }

    pub fn calculate_response(&mut self, method: &str, uri: &str) {
        if let (Some(realm), Some(nonce)) = (&self.realm, &self.nonce) {
            let ha1 = md5_hash(&format!("{}:{}:{}", self.username, realm, self.password));
            let ha2 = md5_hash(&format!("{method}:{uri}"));
            
            let response = if let Some(qop) = &self.qop {
                if qop == "auth" || qop.contains("auth") {
                    let nc = "00000001";
                    let cnonce = generate_cnonce();
                    self.nc = Some(nc.to_string());
                    self.cnonce = Some(cnonce.clone());
                    md5_hash(&format!("{}:{}:{}:{}:{}:{}", ha1, nonce, nc, cnonce, "auth", ha2))
                } else {
                    md5_hash(&format!("{ha1}:{nonce}:{ha2}"))
                }
            } else {
                md5_hash(&format!("{ha1}:{nonce}:{ha2}"))
            };
            
            self.response = Some(response);
            self.uri = Some(uri.to_string());
        }
    }

    pub fn to_header_value(&self) -> String {
        let mut parts = Vec::new();
        
        parts.push(format!("username=\"{}\"", self.username));
        
        if let Some(ref realm) = self.realm {
            parts.push(format!("realm=\"{realm}\""));
        }
        
        if let Some(ref nonce) = self.nonce {
            parts.push(format!("nonce=\"{nonce}\""));
        }
        
        if let Some(ref uri) = self.uri {
            parts.push(format!("uri=\"{uri}\""));
        }
        
        if let Some(ref response) = self.response {
            parts.push(format!("response=\"{response}\""));
        }
        
        if let Some(ref qop) = self.qop {
            parts.push(format!("qop={qop}"));
        }
        
        if let Some(ref nc) = self.nc {
            parts.push(format!("nc={nc}"));
        }
        
        if let Some(ref cnonce) = self.cnonce {
            parts.push(format!("cnonce=\"{cnonce}\""));
        }
        
        if let Some(ref opaque) = self.opaque {
            parts.push(format!("opaque=\"{opaque}\""));
        }
        
        format!("Digest {}", parts.join(", "))
    }
}

// Simple base64 encoding implementation
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

// Complete MD5 hash implementation (RFC 1321)
fn md5_hash(input: &str) -> String {
    let bytes = input.as_bytes();
    let hash = md5_digest(bytes);
    
    // Convert to hex string
    hash.iter()
        .map(|b| format!("{b:02x}"))
        .collect::<String>()
}

fn md5_digest(input: &[u8]) -> [u8; 16] {
    // MD5 constants
    const S: [u32; 64] = [
        7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22,
        5,  9, 14, 20, 5,  9, 14, 20, 5,  9, 14, 20, 5,  9, 14, 20,
        4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23,
        6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21,
    ];

    const K: [u32; 64] = [
        0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee,
        0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501,
        0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be,
        0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821,
        0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa,
        0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8,
        0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed,
        0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a,
        0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c,
        0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70,
        0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05,
        0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665,
        0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039,
        0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
        0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1,
        0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391,
    ];

    // Initialize MD5 state
    let mut h = [0x67452301u32, 0xefcdab89u32, 0x98badcfeu32, 0x10325476u32];

    // Pre-processing: adding padding bits
    let mut message = input.to_vec();
    let original_len = message.len();
    
    // Append the '1' bit (plus zero padding to make it a byte)
    message.push(0x80);
    
    // Append 0 <= k < 512 bits '0', such that the resulting message length in bits
    // is congruent to 448 (mod 512)
    while (message.len() % 64) != 56 {
        message.push(0);
    }
    
    // Append original length in bits mod 2^64 as 64-bit little-endian integer
    let bit_len = (original_len as u64) * 8;
    message.extend_from_slice(&bit_len.to_le_bytes());

    // Process the message in successive 512-bit chunks
    for chunk in message.chunks_exact(64) {
        let mut w = [0u32; 16];
        for (i, word) in chunk.chunks_exact(4).enumerate() {
            w[i] = u32::from_le_bytes([word[0], word[1], word[2], word[3]]);
        }

        // Initialize hash value for this chunk
        let mut a = h[0];
        let mut b = h[1];
        let mut c = h[2];
        let mut d = h[3];

        // Main loop
        for i in 0..64 {
            let (f, g) = match i {
                0..=15 => ((b & c) | ((!b) & d), i),
                16..=31 => ((d & b) | ((!d) & c), (5 * i + 1) % 16),
                32..=47 => (b ^ c ^ d, (3 * i + 5) % 16),
                48..=63 => (c ^ (b | (!d)), (7 * i) % 16),
                _ => unreachable!(),
            };

            let temp = d;
            d = c;
            c = b;
            b = b.wrapping_add(left_rotate(
                a.wrapping_add(f).wrapping_add(K[i]).wrapping_add(w[g]),
                S[i],
            ));
            a = temp;
        }

        // Add this chunk's hash to result so far
        h[0] = h[0].wrapping_add(a);
        h[1] = h[1].wrapping_add(b);
        h[2] = h[2].wrapping_add(c);
        h[3] = h[3].wrapping_add(d);
    }

    // Produce the final hash value as a 128-bit number (16 bytes)
    let mut result = [0u8; 16];
    for (i, &word) in h.iter().enumerate() {
        let bytes = word.to_le_bytes();
        result[i * 4..(i + 1) * 4].copy_from_slice(&bytes);
    }

    result
}

fn left_rotate(value: u32, amount: u32) -> u32 {
    (value << amount) | (value >> (32 - amount))
}

fn generate_cnonce() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    format!("{timestamp:x}")
}