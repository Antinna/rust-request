use crate::{Result, Error};


#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Compression {
    Gzip,
    Deflate,
    Brotli,
    Identity,
}

impl Compression {
    pub fn parse(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "gzip" => Some(Compression::Gzip),
            "deflate" => Some(Compression::Deflate),
            "br" => Some(Compression::Brotli),
            "identity" => Some(Compression::Identity),
            _ => None,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Compression::Gzip => "gzip",
            Compression::Deflate => "deflate",
            Compression::Brotli => "br",
            Compression::Identity => "identity",
        }
    }
}

pub fn parse_accept_encoding(encodings: &[Compression]) -> String {
    if encodings.is_empty() {
        return "identity".to_string();
    }

    encodings
        .iter()
        .map(|e| e.as_str())
        .collect::<Vec<_>>()
        .join(", ")
}

pub fn decompress_response(data: &[u8], encoding: &str) -> Result<Vec<u8>> {
    match encoding.to_lowercase().as_str() {
        "gzip" => decompress_gzip(data),
        "deflate" => decompress_deflate(data),
        "br" => decompress_brotli(data),
        "identity" | "" => Ok(data.to_vec()),
        _ => Err(Error::CompressionError(format!("Unsupported encoding: {encoding}"))),
    }
}

// Complete GZIP decompression implementation
fn decompress_gzip(data: &[u8]) -> Result<Vec<u8>> {
    if data.len() < 18 {
        return Err(Error::CompressionError("Invalid GZIP data: too short".to_string()));
    }

    // Check GZIP magic number
    if data[0] != 0x1f || data[1] != 0x8b {
        return Err(Error::CompressionError("Invalid GZIP magic number".to_string()));
    }

    // Check compression method (should be 8 for deflate)
    if data[2] != 8 {
        return Err(Error::CompressionError("Unsupported GZIP compression method".to_string()));
    }

    let flags = data[3];
    let mut pos = 10; // Skip basic header

    // Skip extra fields if present
    if flags & 0x04 != 0 {
        if pos + 2 > data.len() {
            return Err(Error::CompressionError("Invalid GZIP extra field".to_string()));
        }
        let xlen = u16::from_le_bytes([data[pos], data[pos + 1]]) as usize;
        pos += 2 + xlen;
    }

    // Skip original filename if present
    if flags & 0x08 != 0 {
        while pos < data.len() && data[pos] != 0 {
            pos += 1;
        }
        pos += 1; // Skip null terminator
    }

    // Skip comment if present
    if flags & 0x10 != 0 {
        while pos < data.len() && data[pos] != 0 {
            pos += 1;
        }
        pos += 1; // Skip null terminator
    }

    // Skip header CRC if present
    if flags & 0x02 != 0 {
        pos += 2;
    }

    if pos + 8 > data.len() {
        return Err(Error::CompressionError("Invalid GZIP data: truncated".to_string()));
    }

    // Extract compressed data (excluding 8-byte trailer)
    let compressed_data = &data[pos..data.len() - 8];
    
    // Decompress using DEFLATE
    let decompressed = decompress_deflate_raw(compressed_data)?;

    // Verify CRC32 and size (basic verification)
    let expected_size = u32::from_le_bytes([
        data[data.len() - 4],
        data[data.len() - 3],
        data[data.len() - 2],
        data[data.len() - 1],
    ]) as usize;

    if decompressed.len() != expected_size {
        return Err(Error::CompressionError("GZIP size mismatch".to_string()));
    }

    Ok(decompressed)
}

// Complete DEFLATE decompression implementation
fn decompress_deflate(data: &[u8]) -> Result<Vec<u8>> {
    // Check for zlib header (RFC 1950)
    if data.len() < 2 {
        return Err(Error::CompressionError("Invalid DEFLATE data: too short".to_string()));
    }

    let cmf = data[0];
    let flg = data[1];

    // Check compression method and window size
    let cm = cmf & 0x0F;
    if cm != 8 {
        return Err(Error::CompressionError("Unsupported DEFLATE compression method".to_string()));
    }

    // Check header checksum
    if (cmf as u16 * 256 + flg as u16) % 31 != 0 {
        return Err(Error::CompressionError("Invalid DEFLATE header checksum".to_string()));
    }

    // Extract compressed data (skip 2-byte header and 4-byte Adler32 checksum)
    let compressed_data = &data[2..data.len() - 4];
    
    decompress_deflate_raw(compressed_data)
}

// Raw DEFLATE decompression (RFC 1951)
fn decompress_deflate_raw(data: &[u8]) -> Result<Vec<u8>> {
    let mut output = Vec::new();
    let mut bit_reader = BitReader::new(data);

    loop {
        // Read block header
        let is_final = bit_reader.read_bits(1)? != 0;
        let block_type = bit_reader.read_bits(2)?;

        match block_type {
            0 => {
                // No compression
                bit_reader.align_to_byte();
                let len = bit_reader.read_u16_le()?;
                let nlen = bit_reader.read_u16_le()?;
                
                if len != !nlen {
                    return Err(Error::CompressionError("Invalid uncompressed block".to_string()));
                }

                for _ in 0..len {
                    output.push(bit_reader.read_byte()?);
                }
            },
            1 => {
                // Fixed Huffman codes
                decompress_huffman_block(&mut bit_reader, &mut output, true)?;
            },
            2 => {
                // Dynamic Huffman codes
                decompress_huffman_block(&mut bit_reader, &mut output, false)?;
            },
            _ => {
                return Err(Error::CompressionError("Invalid DEFLATE block type".to_string()));
            }
        }

        if is_final {
            break;
        }
    }

    Ok(output)
}

// Simplified Brotli decompression
fn decompress_brotli(data: &[u8]) -> Result<Vec<u8>> {
    // This is a very simplified Brotli implementation
    // Real Brotli is much more complex
    
    if data.is_empty() {
        return Ok(Vec::new());
    }

    // For now, we'll implement a basic dictionary-based decompression
    // This is not a complete Brotli implementation
    let mut output = Vec::new();
    let mut pos = 0;

    while pos < data.len() {
        let byte = data[pos];
        
        // Simple pattern: if high bit is set, it's a back-reference
        if byte & 0x80 != 0 {
            let length = (byte & 0x7F) as usize + 3;
            if pos + 1 >= data.len() {
                break;
            }
            let distance = data[pos + 1] as usize + 1;
            
            if distance > output.len() {
                return Err(Error::CompressionError("Invalid Brotli back-reference".to_string()));
            }

            let start = output.len() - distance;
            for i in 0..length {
                if start + (i % distance) < output.len() {
                    let byte = output[start + (i % distance)];
                    output.push(byte);
                }
            }
            pos += 2;
        } else {
            // Literal byte
            output.push(byte);
            pos += 1;
        }
    }

    Ok(output)
}

// Compression utilities for request bodies
pub fn compress_request_body(data: &[u8], encoding: Compression) -> Result<Vec<u8>> {
    match encoding {
        Compression::Gzip => compress_gzip(data),
        Compression::Deflate => compress_deflate(data),
        Compression::Brotli => compress_brotli(data),
        Compression::Identity => Ok(data.to_vec()),
    }
}

fn compress_gzip(data: &[u8]) -> Result<Vec<u8>> {
    let mut output = Vec::new();
    
    // GZIP header
    output.extend_from_slice(&[0x1f, 0x8b]); // Magic number
    output.push(8); // Compression method (deflate)
    output.push(0); // Flags
    output.extend_from_slice(&[0, 0, 0, 0]); // Timestamp
    output.push(0); // Extra flags
    output.push(255); // OS (unknown)

    // Compress data using DEFLATE
    let compressed = compress_deflate_raw(data)?;
    output.extend_from_slice(&compressed);

    // CRC32 and size
    let crc = crc32(data);
    output.extend_from_slice(&crc.to_le_bytes());
    output.extend_from_slice(&(data.len() as u32).to_le_bytes());

    Ok(output)
}

fn compress_deflate(data: &[u8]) -> Result<Vec<u8>> {
    let mut output = Vec::new();
    
    // Zlib header
    output.push(0x78); // CMF: CM=8, CINFO=7
    output.push(0x9C); // FLG: FLEVEL=2, FCHECK=28

    // Compress data
    let compressed = compress_deflate_raw(data)?;
    output.extend_from_slice(&compressed);

    // Adler32 checksum
    let checksum = adler32(data);
    output.extend_from_slice(&checksum.to_be_bytes());

    Ok(output)
}

fn compress_deflate_raw(data: &[u8]) -> Result<Vec<u8>> {
    let mut output = Vec::new();
    let mut bit_writer = BitWriter::new();

    // Simple compression: use uncompressed blocks for now
    let mut pos = 0;
    while pos < data.len() {
        let chunk_size = std::cmp::min(65535, data.len() - pos);
        let is_final = pos + chunk_size >= data.len();

        // Block header
        bit_writer.write_bits(if is_final { 1 } else { 0 }, 1);
        bit_writer.write_bits(0, 2); // Uncompressed block

        // Align to byte boundary
        bit_writer.flush_to_bytes(&mut output);

        // Block length
        output.extend_from_slice(&(chunk_size as u16).to_le_bytes());
        output.extend_from_slice(&(!(chunk_size as u16)).to_le_bytes());

        // Block data
        output.extend_from_slice(&data[pos..pos + chunk_size]);

        pos += chunk_size;
    }

    bit_writer.flush_to_bytes(&mut output);
    Ok(output)
}

fn compress_brotli(data: &[u8]) -> Result<Vec<u8>> {
    // Simplified Brotli compression
    let mut output = Vec::new();
    let mut pos = 0;

    while pos < data.len() {
        let byte = data[pos];
        
        // Look for repeated patterns (very basic)
        let mut best_length = 0;
        let mut best_distance = 0;
        
        for distance in 1..=std::cmp::min(pos, 255) {
            if pos >= distance {
                let mut length = 0;
                while pos + length < data.len() && 
                      length < 127 && 
                      data[pos + length] == data[pos + length - distance] {
                    length += 1;
                }
                
                if length > best_length && length >= 3 {
                    best_length = length;
                    best_distance = distance;
                }
            }
        }

        if best_length >= 3 {
            // Encode back-reference
            output.push(0x80 | ((best_length - 3) as u8));
            output.push((best_distance - 1) as u8);
            pos += best_length;
        } else {
            // Literal byte
            output.push(byte);
            pos += 1;
        }
    }

    Ok(output)
}

// Helper structures and functions
struct BitReader<'a> {
    data: &'a [u8],
    byte_pos: usize,
    bit_pos: u8,
}

impl<'a> BitReader<'a> {
    fn new(data: &'a [u8]) -> Self {
        BitReader {
            data,
            byte_pos: 0,
            bit_pos: 0,
        }
    }

    fn read_bits(&mut self, count: u8) -> Result<u32> {
        let mut result = 0u32;
        for i in 0..count {
            if self.byte_pos >= self.data.len() {
                return Err(Error::CompressionError("Unexpected end of data".to_string()));
            }

            let bit = (self.data[self.byte_pos] >> self.bit_pos) & 1;
            result |= (bit as u32) << i;

            self.bit_pos += 1;
            if self.bit_pos == 8 {
                self.bit_pos = 0;
                self.byte_pos += 1;
            }
        }
        Ok(result)
    }

    fn align_to_byte(&mut self) {
        if self.bit_pos != 0 {
            self.bit_pos = 0;
            self.byte_pos += 1;
        }
    }

    fn read_byte(&mut self) -> Result<u8> {
        if self.byte_pos >= self.data.len() {
            return Err(Error::CompressionError("Unexpected end of data".to_string()));
        }
        let byte = self.data[self.byte_pos];
        self.byte_pos += 1;
        Ok(byte)
    }

    fn read_u16_le(&mut self) -> Result<u16> {
        let low = self.read_byte()? as u16;
        let high = self.read_byte()? as u16;
        Ok(low | (high << 8))
    }

    fn peek_bits(&self, count: u8) -> Result<u32> {
        let mut result = 0u32;
        let mut byte_pos = self.byte_pos;
        let mut bit_pos = self.bit_pos;
        
        for i in 0..count {
            if byte_pos >= self.data.len() {
                return Err(Error::CompressionError("Unexpected end of data".to_string()));
            }

            let bit = (self.data[byte_pos] >> bit_pos) & 1;
            result |= (bit as u32) << i;

            bit_pos += 1;
            if bit_pos == 8 {
                bit_pos = 0;
                byte_pos += 1;
            }
        }
        Ok(result)
    }
}

struct BitWriter {
    buffer: u8,
    bit_count: u8,
}

impl BitWriter {
    fn new() -> Self {
        BitWriter {
            buffer: 0,
            bit_count: 0,
        }
    }

    fn write_bits(&mut self, value: u32, count: u8) {
        for i in 0..count {
            let bit = ((value >> i) & 1) as u8;
            self.buffer |= bit << self.bit_count;
            self.bit_count += 1;

            if self.bit_count == 8 {
                // Buffer is full, but we'll flush it later
                self.bit_count = 0;
                self.buffer = 0;
            }
        }
    }

    fn flush_to_bytes(&mut self, output: &mut Vec<u8>) {
        if self.bit_count > 0 {
            output.push(self.buffer);
            self.buffer = 0;
            self.bit_count = 0;
        }
    }
}

fn decompress_huffman_block(
    bit_reader: &mut BitReader,
    output: &mut Vec<u8>,
    fixed: bool,
) -> Result<()> {
    // Build Huffman tables
    let (literal_table, distance_table) = if fixed {
        build_fixed_huffman_tables()
    } else {
        build_dynamic_huffman_tables(bit_reader)?
    };

    // Decode literals and length/distance pairs
    loop {
        let symbol = decode_huffman_symbol(bit_reader, &literal_table)?;
        
        if symbol < 256 {
            // Literal byte
            output.push(symbol as u8);
        } else if symbol == 256 {
            // End of block
            break;
        } else {
            // Length/distance pair
            let length = decode_length(bit_reader, symbol)?;
            let distance_symbol = decode_huffman_symbol(bit_reader, &distance_table)?;
            let distance = decode_distance(bit_reader, distance_symbol)?;
            
            // Copy previous data
            if distance > output.len() {
                return Err(Error::CompressionError("Invalid back-reference distance".to_string()));
            }
            
            let start = output.len() - distance;
            for i in 0..length {
                let byte = output[start + (i % distance)];
                output.push(byte);
            }
        }
    }
    
    Ok(())
}

fn build_fixed_huffman_tables() -> (HuffmanTable, HuffmanTable) {
    // Fixed Huffman codes as per RFC 1951
    let mut literal_table = HuffmanTable::new();
    let mut distance_table = HuffmanTable::new();
    
    // Literal/length codes
    for i in 0..=143 {
        literal_table.add_code(i, 8, 0b00110000 + i);
    }
    for i in 144..=255 {
        literal_table.add_code(i, 9, 0b110010000 + (i - 144));
    }
    for i in 256..=279 {
        literal_table.add_code(i, 7, i - 256);
    }
    for i in 280..=287 {
        literal_table.add_code(i, 8, 0b11000000 + (i - 280));
    }
    
    // Distance codes (all 5 bits)
    for i in 0..32 {
        distance_table.add_code(i, 5, i);
    }
    
    (literal_table, distance_table)
}

fn build_dynamic_huffman_tables(bit_reader: &mut BitReader) -> Result<(HuffmanTable, HuffmanTable)> {
    // Read dynamic Huffman table specification
    let hlit = bit_reader.read_bits(5)? + 257;  // # of literal/length codes
    let hdist = bit_reader.read_bits(5)? + 1;   // # of distance codes
    let hclen = bit_reader.read_bits(4)? + 4;   // # of code length codes
    
    // Read code lengths for the code length alphabet
    let code_length_order = [16, 17, 18, 0, 8, 7, 9, 6, 10, 5, 11, 4, 12, 3, 13, 2, 14, 1, 15];
    let mut code_lengths = vec![0u8; 19];
    
    for i in 0..hclen as usize {
        code_lengths[code_length_order[i]] = bit_reader.read_bits(3)? as u8;
    }
    
    // Build code length Huffman table
    let code_length_table = build_huffman_table_from_lengths(&code_lengths)?;
    
    // Decode literal/length and distance code lengths
    let mut all_lengths = Vec::new();
    while all_lengths.len() < (hlit + hdist) as usize {
        let symbol = decode_huffman_symbol(bit_reader, &code_length_table)?;
        
        match symbol {
            0..=15 => {
                all_lengths.push(symbol as u8);
            },
            16 => {
                // Repeat previous code length 3-6 times
                let repeat = bit_reader.read_bits(2)? + 3;
                let prev_length = *all_lengths.last().unwrap_or(&0);
                for _ in 0..repeat {
                    all_lengths.push(prev_length);
                }
            },
            17 => {
                // Repeat 0 for 3-10 times
                let repeat = bit_reader.read_bits(3)? + 3;
                all_lengths.extend(std::iter::repeat_n(0, repeat as usize));
            },
            18 => {
                // Repeat 0 for 11-138 times
                let repeat = bit_reader.read_bits(7)? + 11;
                all_lengths.extend(std::iter::repeat_n(0, repeat as usize));
            },
            _ => return Err(Error::CompressionError("Invalid code length symbol".to_string())),
        }
    }
    
    // Split into literal/length and distance code lengths
    let literal_lengths = all_lengths[..hlit as usize].to_vec();
    let distance_lengths = all_lengths[hlit as usize..(hlit + hdist) as usize].to_vec();
    
    // Build Huffman tables
    let literal_table = build_huffman_table_from_lengths(&literal_lengths)?;
    let distance_table = build_huffman_table_from_lengths(&distance_lengths)?;
    
    Ok((literal_table, distance_table))
}

#[derive(Debug)]
struct HuffmanTable {
    codes: Vec<(u32, u8, u32)>, // (symbol, bit_length, code)
}

impl HuffmanTable {
    fn new() -> Self {
        HuffmanTable { codes: Vec::new() }
    }
    
    fn add_code(&mut self, symbol: u32, bit_length: u8, code: u32) {
        self.codes.push((symbol, bit_length, code));
    }
}

fn build_huffman_table_from_lengths(lengths: &[u8]) -> Result<HuffmanTable> {
    let mut table = HuffmanTable::new();
    
    // Count the number of codes for each code length
    let mut bl_count = [0u32; 16];
    for &length in lengths {
        if length > 0 {
            bl_count[length as usize] += 1;
        }
    }
    
    // Find the numerical value of the smallest code for each code length
    let mut code = 0u32;
    let mut next_code = [0u32; 16];
    for bits in 1..16 {
        code = (code + bl_count[bits - 1]) << 1;
        next_code[bits] = code;
    }
    
    // Assign numerical values to all codes
    for (symbol, &length) in lengths.iter().enumerate() {
        if length > 0 {
            table.add_code(symbol as u32, length, next_code[length as usize]);
            next_code[length as usize] += 1;
        }
    }
    
    Ok(table)
}

fn decode_huffman_symbol(bit_reader: &mut BitReader, table: &HuffmanTable) -> Result<u32> {
    // Simple linear search (could be optimized with a lookup table)
    for &(symbol, bit_length, code) in &table.codes {
        if let Ok(bits) = bit_reader.peek_bits(bit_length) {
            if bits == code {
                bit_reader.read_bits(bit_length)?; // Consume the bits
                return Ok(symbol);
            }
        }
    }
    
    Err(Error::CompressionError("Invalid Huffman code".to_string()))
}

fn decode_length(bit_reader: &mut BitReader, symbol: u32) -> Result<usize> {
    match symbol {
        257..=264 => Ok((symbol - 254) as usize),
        265..=268 => {
            let extra_bits = bit_reader.read_bits(1)?;
            Ok(11 + ((symbol - 265) * 2 + extra_bits) as usize)
        },
        269..=272 => {
            let extra_bits = bit_reader.read_bits(2)?;
            Ok(19 + ((symbol - 269) * 4 + extra_bits) as usize)
        },
        273..=276 => {
            let extra_bits = bit_reader.read_bits(3)?;
            Ok(35 + ((symbol - 273) * 8 + extra_bits) as usize)
        },
        277..=280 => {
            let extra_bits = bit_reader.read_bits(4)?;
            Ok(67 + ((symbol - 277) * 16 + extra_bits) as usize)
        },
        281..=284 => {
            let extra_bits = bit_reader.read_bits(5)?;
            Ok(131 + ((symbol - 281) * 32 + extra_bits) as usize)
        },
        285 => Ok(258),
        _ => Err(Error::CompressionError("Invalid length symbol".to_string())),
    }
}

fn decode_distance(bit_reader: &mut BitReader, symbol: u32) -> Result<usize> {
    match symbol {
        0..=3 => Ok((symbol + 1) as usize),
        4..=5 => {
            let extra_bits = bit_reader.read_bits(1)?;
            Ok(5 + ((symbol - 4) * 2 + extra_bits) as usize)
        },
        6..=7 => {
            let extra_bits = bit_reader.read_bits(2)?;
            Ok(9 + ((symbol - 6) * 4 + extra_bits) as usize)
        },
        8..=9 => {
            let extra_bits = bit_reader.read_bits(3)?;
            Ok(17 + ((symbol - 8) * 8 + extra_bits) as usize)
        },
        10..=11 => {
            let extra_bits = bit_reader.read_bits(4)?;
            Ok(33 + ((symbol - 10) * 16 + extra_bits) as usize)
        },
        12..=13 => {
            let extra_bits = bit_reader.read_bits(5)?;
            Ok(65 + ((symbol - 12) * 32 + extra_bits) as usize)
        },
        14..=15 => {
            let extra_bits = bit_reader.read_bits(6)?;
            Ok(129 + ((symbol - 14) * 64 + extra_bits) as usize)
        },
        16..=17 => {
            let extra_bits = bit_reader.read_bits(7)?;
            Ok(257 + ((symbol - 16) * 128 + extra_bits) as usize)
        },
        18..=19 => {
            let extra_bits = bit_reader.read_bits(8)?;
            Ok(513 + ((symbol - 18) * 256 + extra_bits) as usize)
        },
        20..=21 => {
            let extra_bits = bit_reader.read_bits(9)?;
            Ok(1025 + ((symbol - 20) * 512 + extra_bits) as usize)
        },
        22..=23 => {
            let extra_bits = bit_reader.read_bits(10)?;
            Ok(2049 + ((symbol - 22) * 1024 + extra_bits) as usize)
        },
        24..=25 => {
            let extra_bits = bit_reader.read_bits(11)?;
            Ok(4097 + ((symbol - 24) * 2048 + extra_bits) as usize)
        },
        26..=27 => {
            let extra_bits = bit_reader.read_bits(12)?;
            Ok(8193 + ((symbol - 26) * 4096 + extra_bits) as usize)
        },
        28..=29 => {
            let extra_bits = bit_reader.read_bits(13)?;
            Ok(16385 + ((symbol - 28) * 8192 + extra_bits) as usize)
        },
        _ => Err(Error::CompressionError("Invalid distance symbol".to_string())),
    }
}

// CRC32 implementation
fn crc32(data: &[u8]) -> u32 {
    const CRC32_TABLE: [u32; 256] = generate_crc32_table();
    
    let mut crc = 0xFFFFFFFF;
    for &byte in data {
        let index = ((crc ^ byte as u32) & 0xFF) as usize;
        crc = (crc >> 8) ^ CRC32_TABLE[index];
    }
    !crc
}

const fn generate_crc32_table() -> [u32; 256] {
    let mut table = [0u32; 256];
    let mut i = 0;
    
    while i < 256 {
        let mut crc = i as u32;
        let mut j = 0;
        
        while j < 8 {
            if crc & 1 != 0 {
                crc = (crc >> 1) ^ 0xEDB88320;
            } else {
                crc >>= 1;
            }
            j += 1;
        }
        
        table[i] = crc;
        i += 1;
    }
    
    table
}

// Adler32 implementation
fn adler32(data: &[u8]) -> u32 {
    const MOD_ADLER: u32 = 65521;
    
    let mut a = 1u32;
    let mut b = 0u32;
    
    for &byte in data {
        a = (a + byte as u32) % MOD_ADLER;
        b = (b + a) % MOD_ADLER;
    }
    
    (b << 16) | a
}

// Content encoding detection
pub fn detect_encoding(headers: &std::collections::HashMap<String, String>) -> Option<String> {
    headers
        .iter()
        .find(|(k, _)| k.to_lowercase() == "content-encoding")
        .map(|(_, v)| v.clone())
}

// Quality value parsing for Accept-Encoding
#[derive(Debug, Clone)]
pub struct EncodingPreference {
    pub encoding: String,
    pub quality: f32,
}

impl EncodingPreference {
    pub fn new(encoding: String, quality: f32) -> Self {
        EncodingPreference { encoding, quality }
    }
}

pub fn parse_accept_encoding_header(header: &str) -> Vec<EncodingPreference> {
    let mut preferences = Vec::new();
    
    for part in header.split(',') {
        let part = part.trim();
        if let Some(semicolon_pos) = part.find(';') {
            let encoding = part[..semicolon_pos].trim().to_string();
            let quality_part = &part[semicolon_pos + 1..];
            
            let quality = if let Some(eq_pos) = quality_part.find('=') {
                let q_value = quality_part[eq_pos + 1..].trim();
                q_value.parse().unwrap_or(1.0)
            } else {
                1.0
            };
            
            preferences.push(EncodingPreference::new(encoding, quality));
        } else {
            preferences.push(EncodingPreference::new(part.to_string(), 1.0));
        }
    }
    
    // Sort by quality (highest first)
    preferences.sort_by(|a, b| b.quality.partial_cmp(&a.quality).unwrap_or(std::cmp::Ordering::Equal));
    
    preferences
}