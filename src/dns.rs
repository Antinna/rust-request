use crate::{Error, Result};
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, UdpSocket};
use std::time::{Duration, Instant};

// DNS record types
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum RecordType {
    A = 1,
    NS = 2,
    CNAME = 5,
    SOA = 6,
    PTR = 12,
    MX = 15,
    TXT = 16,
    AAAA = 28,
    SRV = 33,
}

impl RecordType {
    pub fn from_u16(value: u16) -> Option<Self> {
        match value {
            1 => Some(RecordType::A),
            2 => Some(RecordType::NS),
            5 => Some(RecordType::CNAME),
            6 => Some(RecordType::SOA),
            12 => Some(RecordType::PTR),
            15 => Some(RecordType::MX),
            16 => Some(RecordType::TXT),
            28 => Some(RecordType::AAAA),
            33 => Some(RecordType::SRV),
            _ => None,
        }
    }
}

// DNS record class
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum RecordClass {
    IN = 1, // Internet
}

// DNS message structure
#[derive(Debug, Clone)]
pub struct DnsMessage {
    pub header: DnsHeader,
    pub questions: Vec<DnsQuestion>,
    pub answers: Vec<DnsRecord>,
    pub authorities: Vec<DnsRecord>,
    pub additionals: Vec<DnsRecord>,
}

#[derive(Debug, Clone)]
pub struct DnsHeader {
    pub id: u16,
    pub flags: u16,
    pub question_count: u16,
    pub answer_count: u16,
    pub authority_count: u16,
    pub additional_count: u16,
}

#[derive(Debug, Clone)]
pub struct DnsQuestion {
    pub name: String,
    pub record_type: RecordType,
    pub record_class: RecordClass,
}

#[derive(Debug, Clone)]
pub struct DnsRecord {
    pub name: String,
    pub record_type: RecordType,
    pub record_class: RecordClass,
    pub ttl: u32,
    pub data: Vec<u8>,
}

impl DnsRecord {
    pub fn as_ipv4(&self) -> Option<Ipv4Addr> {
        if self.record_type == RecordType::A && self.data.len() == 4 {
            Some(Ipv4Addr::new(
                self.data[0],
                self.data[1],
                self.data[2],
                self.data[3],
            ))
        } else {
            None
        }
    }

    pub fn as_ipv6(&self) -> Option<Ipv6Addr> {
        if self.record_type == RecordType::AAAA && self.data.len() == 16 {
            let mut octets = [0u8; 16];
            octets.copy_from_slice(&self.data);
            Some(Ipv6Addr::from(octets))
        } else {
            None
        }
    }

    pub fn as_string(&self) -> Option<String> {
        match self.record_type {
            RecordType::CNAME | RecordType::NS | RecordType::PTR => {
                decode_domain_name(&self.data, 0).ok().map(|(name, _)| name)
            }
            RecordType::TXT => {
                if !self.data.is_empty() {
                    let len = self.data[0] as usize;
                    if self.data.len() > len {
                        String::from_utf8(self.data[1..len + 1].to_vec()).ok()
                    } else {
                        None
                    }
                } else {
                    None
                }
            }
            _ => None,
        }
    }
}

// DNS resolver with caching
pub struct DnsResolver {
    servers: Vec<SocketAddr>,
    cache: HashMap<String, CacheEntry>,
    timeout: Duration,
}

#[derive(Debug, Clone)]
struct CacheEntry {
    records: Vec<DnsRecord>,
    expires: Instant,
}

impl DnsResolver {
    pub fn new() -> Self {
        DnsResolver {
            servers: vec![
                "8.8.8.8:53".parse().unwrap(), // Google DNS
                "8.8.4.4:53".parse().unwrap(), // Google DNS
                "1.1.1.1:53".parse().unwrap(), // Cloudflare DNS
                "1.0.0.1:53".parse().unwrap(), // Cloudflare DNS
            ],
            cache: HashMap::new(),
            timeout: Duration::from_secs(5),
        }
    }

    pub fn with_servers(servers: Vec<SocketAddr>) -> Self {
        DnsResolver {
            servers,
            cache: HashMap::new(),
            timeout: Duration::from_secs(5),
        }
    }

    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    pub fn resolve_a(&mut self, hostname: &str) -> Result<Vec<Ipv4Addr>> {
        let records = self.query(hostname, RecordType::A)?;
        Ok(records.iter().filter_map(|r| r.as_ipv4()).collect())
    }

    pub fn resolve_aaaa(&mut self, hostname: &str) -> Result<Vec<Ipv6Addr>> {
        let records = self.query(hostname, RecordType::AAAA)?;
        Ok(records.iter().filter_map(|r| r.as_ipv6()).collect())
    }

    pub fn resolve_ip(&mut self, hostname: &str) -> Result<Vec<IpAddr>> {
        let mut ips = Vec::new();

        // Try IPv4 first
        if let Ok(ipv4_addrs) = self.resolve_a(hostname) {
            ips.extend(ipv4_addrs.into_iter().map(IpAddr::V4));
        }

        // Then try IPv6
        if let Ok(ipv6_addrs) = self.resolve_aaaa(hostname) {
            ips.extend(ipv6_addrs.into_iter().map(IpAddr::V6));
        }

        if ips.is_empty() {
            Err(Error::InvalidResponse(format!(
                "No IP addresses found for {hostname}"
            )))
        } else {
            Ok(ips)
        }
    }

    pub fn resolve_cname(&mut self, hostname: &str) -> Result<Vec<String>> {
        let records = self.query(hostname, RecordType::CNAME)?;
        Ok(records.iter().filter_map(|r| r.as_string()).collect())
    }

    pub fn resolve_txt(&mut self, hostname: &str) -> Result<Vec<String>> {
        let records = self.query(hostname, RecordType::TXT)?;
        Ok(records.iter().filter_map(|r| r.as_string()).collect())
    }

    pub fn query(&mut self, hostname: &str, record_type: RecordType) -> Result<Vec<DnsRecord>> {
        // Check cache first
        let cache_key = format!("{hostname}:{record_type:?}");
        if let Some(entry) = self.cache.get(&cache_key) {
            if entry.expires > Instant::now() {
                return Ok(entry.records.clone());
            } else {
                self.cache.remove(&cache_key);
            }
        }

        // Create DNS query
        let query = self.create_query(hostname, record_type)?;

        // Try each DNS server
        for &server in &self.servers {
            match self.send_query(&query, server) {
                Ok(response) => {
                    // Cache the results
                    let min_ttl = response.answers.iter().map(|r| r.ttl).min().unwrap_or(300); // Default 5 minutes

                    let cache_entry = CacheEntry {
                        records: response.answers.clone(),
                        expires: Instant::now() + Duration::from_secs(min_ttl as u64),
                    };

                    self.cache.insert(cache_key, cache_entry);
                    return Ok(response.answers);
                }
                Err(_) => continue, // Try next server
            }
        }

        Err(Error::InvalidResponse("All DNS servers failed".to_string()))
    }

    fn create_query(&self, hostname: &str, record_type: RecordType) -> Result<Vec<u8>> {
        let mut query = Vec::new();

        // Header
        let id = generate_query_id();
        query.extend_from_slice(&id.to_be_bytes());
        query.extend_from_slice(&[0x01, 0x00]); // Standard query, recursion desired
        query.extend_from_slice(&[0x00, 0x01]); // 1 question
        query.extend_from_slice(&[0x00, 0x00]); // 0 answers
        query.extend_from_slice(&[0x00, 0x00]); // 0 authorities
        query.extend_from_slice(&[0x00, 0x00]); // 0 additionals

        // Question
        encode_domain_name(hostname, &mut query);
        query.extend_from_slice(&(record_type as u16).to_be_bytes());
        query.extend_from_slice(&(RecordClass::IN as u16).to_be_bytes());

        Ok(query)
    }

    fn send_query(&self, query: &[u8], server: SocketAddr) -> Result<DnsMessage> {
        let socket = UdpSocket::bind("0.0.0.0:0")?;
        socket.set_read_timeout(Some(self.timeout))?;
        socket.set_write_timeout(Some(self.timeout))?;

        socket.send_to(query, server)?;

        let mut buffer = [0u8; 512];
        let (bytes_received, _) = socket.recv_from(&mut buffer)?;

        self.parse_response(&buffer[..bytes_received])
    }

    fn parse_response(&self, data: &[u8]) -> Result<DnsMessage> {
        if data.len() < 12 {
            return Err(Error::InvalidResponse("DNS response too short".to_string()));
        }

        let header = DnsHeader {
            id: u16::from_be_bytes([data[0], data[1]]),
            flags: u16::from_be_bytes([data[2], data[3]]),
            question_count: u16::from_be_bytes([data[4], data[5]]),
            answer_count: u16::from_be_bytes([data[6], data[7]]),
            authority_count: u16::from_be_bytes([data[8], data[9]]),
            additional_count: u16::from_be_bytes([data[10], data[11]]),
        };

        let mut pos = 12;
        let mut questions = Vec::new();
        let mut answers = Vec::new();
        let mut authorities = Vec::new();
        let mut additionals = Vec::new();

        // Parse questions
        for _ in 0..header.question_count {
            let (name, new_pos) = decode_domain_name(data, pos)?;
            pos = new_pos;

            if pos + 4 > data.len() {
                return Err(Error::InvalidResponse("Invalid DNS question".to_string()));
            }

            let record_type = RecordType::from_u16(u16::from_be_bytes([data[pos], data[pos + 1]]))
                .ok_or_else(|| Error::InvalidResponse("Unknown record type".to_string()))?;
            let record_class = RecordClass::IN; // Assume IN class
            pos += 4;

            questions.push(DnsQuestion {
                name,
                record_type,
                record_class,
            });
        }

        // Parse answers
        for _ in 0..header.answer_count {
            let (record, new_pos) = self.parse_record(data, pos)?;
            pos = new_pos;
            answers.push(record);
        }

        // Parse authorities
        for _ in 0..header.authority_count {
            let (record, new_pos) = self.parse_record(data, pos)?;
            pos = new_pos;
            authorities.push(record);
        }

        // Parse additionals
        for _ in 0..header.additional_count {
            let (record, new_pos) = self.parse_record(data, pos)?;
            pos = new_pos;
            additionals.push(record);
        }

        Ok(DnsMessage {
            header,
            questions,
            answers,
            authorities,
            additionals,
        })
    }

    fn parse_record(&self, data: &[u8], pos: usize) -> Result<(DnsRecord, usize)> {
        let (name, mut pos) = decode_domain_name(data, pos)?;

        if pos + 10 > data.len() {
            return Err(Error::InvalidResponse("Invalid DNS record".to_string()));
        }

        let record_type = RecordType::from_u16(u16::from_be_bytes([data[pos], data[pos + 1]]))
            .ok_or_else(|| Error::InvalidResponse("Unknown record type".to_string()))?;
        let record_class = RecordClass::IN; // Assume IN class
        let ttl = u32::from_be_bytes([data[pos + 4], data[pos + 5], data[pos + 6], data[pos + 7]]);
        let data_len = u16::from_be_bytes([data[pos + 8], data[pos + 9]]) as usize;
        pos += 10;

        if pos + data_len > data.len() {
            return Err(Error::InvalidResponse(
                "Invalid DNS record data".to_string(),
            ));
        }

        let record_data = data[pos..pos + data_len].to_vec();
        pos += data_len;

        let record = DnsRecord {
            name,
            record_type,
            record_class,
            ttl,
            data: record_data,
        };

        Ok((record, pos))
    }

    pub fn clear_cache(&mut self) {
        self.cache.clear();
    }

    pub fn cache_size(&self) -> usize {
        self.cache.len()
    }
}

impl Default for DnsResolver {
    fn default() -> Self {
        Self::new()
    }
}

// Helper functions
fn encode_domain_name(name: &str, buffer: &mut Vec<u8>) {
    for part in name.split('.') {
        if part.is_empty() {
            continue;
        }
        buffer.push(part.len() as u8);
        buffer.extend_from_slice(part.as_bytes());
    }
    buffer.push(0); // Null terminator
}

fn decode_domain_name(data: &[u8], mut pos: usize) -> Result<(String, usize)> {
    let mut name = String::new();
    let mut jumped = false;
    let mut jump_pos = pos;

    loop {
        if pos >= data.len() {
            return Err(Error::InvalidResponse("Invalid domain name".to_string()));
        }

        let len = data[pos];

        if len == 0 {
            pos += 1;
            break;
        }

        if len & 0xC0 == 0xC0 {
            // Compression pointer
            if !jumped {
                jump_pos = pos + 2;
                jumped = true;
            }

            if pos + 1 >= data.len() {
                return Err(Error::InvalidResponse(
                    "Invalid compression pointer".to_string(),
                ));
            }

            let pointer = ((len as u16 & 0x3F) << 8) | (data[pos + 1] as u16);
            pos = pointer as usize;
            continue;
        }

        pos += 1;

        if pos + len as usize > data.len() {
            return Err(Error::InvalidResponse(
                "Invalid domain name length".to_string(),
            ));
        }

        if !name.is_empty() {
            name.push('.');
        }

        name.push_str(&String::from_utf8_lossy(&data[pos..pos + len as usize]));
        pos += len as usize;
    }

    let final_pos = if jumped { jump_pos } else { pos };
    Ok((name, final_pos))
}

fn generate_query_id() -> u16 {
    use std::time::{SystemTime, UNIX_EPOCH};
    
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos() as u16
}

// System DNS resolver fallback
pub fn system_resolve(hostname: &str) -> Result<Vec<IpAddr>> {
    use std::net::ToSocketAddrs;

    let addresses: Vec<IpAddr> = format!("{hostname}:80")
        .to_socket_addrs()
        .map_err(|e| Error::InvalidResponse(format!("DNS resolution failed: {e}")))?
        .map(|addr| addr.ip())
        .collect();

    if addresses.is_empty() {
        Err(Error::InvalidResponse(format!(
            "No addresses found for {hostname}"
        )))
    } else {
        Ok(addresses)
    }
}
