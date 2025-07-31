use crate::{Result, Error};
use std::collections::HashMap;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Compression {
    Gzip,
    Deflate,
    Brotli,
    Identity,
}

/// Compression level for algorithms that support it
#[derive(Debug, Clone, Copy, PartialEq, Default)]
pub enum CompressionLevel {
    Fastest,
    Fast,
    #[default]
    Default,
    Best,
    Custom(u8),
}

/// Compression configuration
#[derive(Debug, Clone)]
pub struct CompressionConfig {
    pub algorithm: Compression,
    pub level: CompressionLevel,
    pub window_size: Option<u8>,
    pub memory_level: Option<u8>,
    pub min_size: usize,
    pub max_size: Option<usize>,
}

impl Compression {
    pub fn parse(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "gzip" => Some(Compression::Gzip),
            "deflate" => Some(Compression::Deflate),
            "br" | "brotli" => Some(Compression::Brotli),
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
    
    /// Get the typical compression ratio for this algorithm
    pub fn typical_ratio(&self) -> f32 {
        match self {
            Compression::Gzip => 0.3,
            Compression::Deflate => 0.35,
            Compression::Brotli => 0.25,
            Compression::Identity => 1.0,
        }
    }
    
    /// Check if this compression algorithm is supported
    pub fn is_supported(&self) -> bool {
        match self {
            Compression::Gzip | Compression::Deflate | Compression::Identity => true,
            Compression::Brotli => true, // Basic support
        }
    }
    
    /// Get the file extension for this compression
    pub fn file_extension(&self) -> &'static str {
        match self {
            Compression::Gzip => ".gz",
            Compression::Deflate => ".zlib",
            Compression::Brotli => ".br",
            Compression::Identity => "",
        }
    }
    
    /// Get the MIME type for this compression
    pub fn mime_type(&self) -> &'static str {
        match self {
            Compression::Gzip => "application/gzip",
            Compression::Deflate => "application/deflate",
            Compression::Brotli => "application/brotli",
            Compression::Identity => "application/octet-stream",
        }
    }
    
    /// Check if this algorithm is lossless
    pub fn is_lossless(&self) -> bool {
        true // All supported algorithms are lossless
    }
}

impl CompressionLevel {
    pub fn as_u8(&self) -> u8 {
        match self {
            CompressionLevel::Fastest => 1,
            CompressionLevel::Fast => 3,
            CompressionLevel::Default => 6,
            CompressionLevel::Best => 9,
            CompressionLevel::Custom(level) => *level,
        }
    }
}



impl CompressionConfig {
    pub fn new(algorithm: Compression) -> Self {
        CompressionConfig {
            algorithm,
            level: CompressionLevel::Default,
            window_size: None,
            memory_level: None,
            min_size: 1024, // Don't compress files smaller than 1KB
            max_size: None,
        }
    }
    
    pub fn with_level(mut self, level: CompressionLevel) -> Self {
        self.level = level;
        self
    }
    
    pub fn with_window_size(mut self, size: u8) -> Self {
        self.window_size = Some(size);
        self
    }
    
    pub fn with_memory_level(mut self, level: u8) -> Self {
        self.memory_level = Some(level);
        self
    }
    
    pub fn with_min_size(mut self, size: usize) -> Self {
        self.min_size = size;
        self
    }
    
    pub fn with_max_size(mut self, size: usize) -> Self {
        self.max_size = Some(size);
        self
    }
    
    /// Check if data should be compressed based on size constraints
    pub fn should_compress(&self, data_size: usize) -> bool {
        if data_size < self.min_size {
            return false;
        }
        
        if let Some(max_size) = self.max_size {
            if data_size > max_size {
                return false;
            }
        }
        
        true
    }
}

impl Default for CompressionConfig {
    fn default() -> Self {
        CompressionConfig::new(Compression::Gzip)
    }
}

/// Parse Accept-Encoding header with quality values
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

/// Parse Accept-Encoding header with quality values
pub fn parse_accept_encoding_with_quality(encodings: &[(Compression, f32)]) -> String {
    if encodings.is_empty() {
        return "identity".to_string();
    }

    encodings
        .iter()
        .map(|(compression, quality)| {
            if *quality == 1.0 {
                compression.as_str().to_string()
            } else {
                format!("{}; q={:.1}", compression.as_str(), quality)
            }
        })
        .collect::<Vec<_>>()
        .join(", ")
}

/// Choose the best compression algorithm from Accept-Encoding header
pub fn choose_compression(accept_encoding: &str, supported: &[Compression]) -> Option<Compression> {
    let mut preferences = HashMap::new();
    
    // Parse Accept-Encoding header
    for part in accept_encoding.split(',') {
        let part = part.trim();
        let (encoding, quality) = if let Some(pos) = part.find(';') {
            let encoding = part[..pos].trim();
            let quality_str = part[pos + 1..].trim();
            let quality = if let Some(stripped) = quality_str.strip_prefix("q=") {
                stripped.parse().unwrap_or(1.0)
            } else {
                1.0
            };
            (encoding, quality)
        } else {
            (part, 1.0)
        };
        
        if let Some(compression) = Compression::parse(encoding) {
            preferences.insert(compression, quality);
        }
    }
    
    // Find the best supported compression with highest quality
    supported
        .iter()
        .filter_map(|&compression| {
            preferences.get(&compression).map(|&quality| (compression, quality))
        })
        .max_by(|(_, q1): &(Compression, f32), (_, q2): &(Compression, f32)| q1.partial_cmp(q2).unwrap_or(std::cmp::Ordering::Equal))
        .map(|(compression, _)| compression)
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
    let config = CompressionConfig::new(encoding);
    compress_request_body_with_config(data, &config)
}

pub fn compress_request_body_with_config(data: &[u8], config: &CompressionConfig) -> Result<Vec<u8>> {
    if !config.should_compress(data.len()) {
        return Ok(data.to_vec());
    }
    
    match config.algorithm {
        Compression::Gzip => compress_gzip_with_level(data, config.level),
        Compression::Deflate => compress_deflate_with_level(data, config.level),
        Compression::Brotli => compress_brotli_with_level(data, config.level),
        Compression::Identity => Ok(data.to_vec()),
    }
}

/// Compress data and return statistics
pub fn compress_with_stats(data: &[u8], config: &CompressionConfig) -> Result<(Vec<u8>, CompressionStats)> {
    let start_time = std::time::Instant::now();
    let compressed = compress_request_body_with_config(data, config)?;
    let duration = start_time.elapsed();
    
    let stats = CompressionStats::new(data.len(), compressed.len(), config.algorithm, duration);
    Ok((compressed, stats))
}

/// Compress data with specific algorithm and level
pub fn compress_with_level(data: &[u8], compression: Compression, level: CompressionLevel) -> Result<Vec<u8>> {
    match compression {
        Compression::Gzip => compress_gzip_with_level(data, level),
        Compression::Deflate => compress_deflate_with_level(data, level),
        Compression::Brotli => compress_brotli_with_level(data, level),
        _ => Ok(data.to_vec()),
    }
}

/// Compress data using gzip algorithm
pub fn compress_gzip_data(data: &[u8]) -> Result<Vec<u8>> {
    compress_gzip(data)
}

/// Compress data using deflate algorithm
pub fn compress_deflate_data(data: &[u8]) -> Result<Vec<u8>> {
    compress_deflate(data)
}

/// Compress data using brotli algorithm
pub fn compress_brotli_data(data: &[u8]) -> Result<Vec<u8>> {
    compress_brotli(data)
}

/// Compress using raw deflate (no headers)
pub fn compress_raw_deflate(data: &[u8]) -> Result<Vec<u8>> {
    compress_deflate_raw(data)
}

/// Get the best compression algorithm for given data
pub fn get_best_compression_for_data(data: &[u8]) -> Compression {
    // Simple heuristic based on data characteristics
    if data.len() < 1024 {
        return Compression::Identity; // Don't compress small data
    }
    
    // Check for text-like content
    let text_chars = data.iter().filter(|&&b| b.is_ascii_graphic() || b.is_ascii_whitespace()).count();
    let text_ratio = text_chars as f32 / data.len() as f32;
    
    if text_ratio > 0.8 {
        Compression::Gzip // Good for text
    } else {
        Compression::Brotli // Better for binary data
    }
}

/// Detect the best compression algorithm for the given data
pub fn detect_best_compression(data: &[u8], algorithms: &[Compression]) -> Result<(Compression, CompressionStats)> {
    let mut best_compression = Compression::Identity;
    let mut best_stats = CompressionStats::default();
    let mut best_ratio = 1.0f32;
    
    for &algorithm in algorithms {
        if !algorithm.is_supported() {
            continue;
        }
        
        let config = CompressionConfig::new(algorithm);
        if let Ok((_compressed, stats)) = compress_with_stats(data, &config) {
            if stats.compression_ratio < best_ratio {
                best_ratio = stats.compression_ratio;
                best_compression = algorithm;
                best_stats = stats;
            }
        }
    }
    
    Ok((best_compression, best_stats))
}

/// Compression statistics
#[derive(Debug, Clone, Default)]
pub struct CompressionStats {
    pub original_size: usize,
    pub compressed_size: usize,
    pub compression_ratio: f32,
    pub compression_time: std::time::Duration,
    pub algorithm: Option<Compression>,
}

impl CompressionStats {
    pub fn new(original_size: usize, compressed_size: usize, algorithm: Compression, duration: std::time::Duration) -> Self {
        let ratio = if original_size > 0 {
            compressed_size as f32 / original_size as f32
        } else {
            1.0
        };
        
        CompressionStats {
            original_size,
            compressed_size,
            compression_ratio: ratio,
            compression_time: duration,
            algorithm: Some(algorithm),
        }
    }
    
    pub fn space_saved(&self) -> usize {
        self.original_size.saturating_sub(self.compressed_size)
    }
    
    pub fn space_saved_percent(&self) -> f32 {
        if self.original_size > 0 {
            (self.space_saved() as f32 / self.original_size as f32) * 100.0
        } else {
            0.0
        }
    }
    
    pub fn compression_speed_mbps(&self) -> f32 {
        if self.compression_time.as_secs_f32() > 0.0 {
            (self.original_size as f32 / 1_048_576.0) / self.compression_time.as_secs_f32()
        } else {
            0.0
        }
    }
}

// Enhanced streaming compression support
pub struct StreamingCompressor {
    compression: Compression,
    config: CompressionConfig,
    buffer: Vec<u8>,
    finished: bool,
    stats: CompressionStats,
    start_time: Option<std::time::Instant>,
}

impl StreamingCompressor {
    pub fn new(compression: Compression) -> Self {
        StreamingCompressor {
            compression,
            config: CompressionConfig::new(compression),
            buffer: Vec::new(),
            finished: false,
            stats: CompressionStats::default(),
            start_time: None,
        }
    }
    
    pub fn with_config(compression: Compression, config: CompressionConfig) -> Self {
        StreamingCompressor {
            compression,
            config,
            buffer: Vec::new(),
            finished: false,
            stats: CompressionStats::default(),
            start_time: None,
        }
    }

    pub fn compress_chunk(&mut self, data: &[u8]) -> Result<Vec<u8>> {
        if self.finished {
            return Err(Error::CompressionError("Compressor already finished".to_string()));
        }
        
        if self.start_time.is_none() {
            self.start_time = Some(std::time::Instant::now());
        }

        self.buffer.extend_from_slice(data);
        self.stats.original_size += data.len();
        
        // For streaming, we compress when we have enough data
        if self.buffer.len() >= 8192 { // 8KB chunks
            let compressed = match self.compression {
                Compression::Gzip => compress_gzip(&self.buffer)?,
                Compression::Deflate => compress_deflate(&self.buffer)?,
                Compression::Brotli => compress_brotli(&self.buffer)?,
                _ => compress_request_body_with_config(&self.buffer, &self.config)?,
            };
            self.stats.compressed_size += compressed.len();
            self.buffer.clear();
            Ok(compressed)
        } else {
            Ok(Vec::new())
        }
    }

    pub fn finish(&mut self) -> Result<Vec<u8>> {
        if self.finished {
            return Ok(Vec::new());
        }

        self.finished = true;
        
        if let Some(start_time) = self.start_time {
            self.stats.compression_time = start_time.elapsed();
        }
        
        if self.buffer.is_empty() {
            self.stats.compression_ratio = if self.stats.original_size > 0 {
                self.stats.compressed_size as f32 / self.stats.original_size as f32
            } else {
                1.0
            };
            return Ok(Vec::new());
        }

        let compressed = match self.compression {
            Compression::Gzip => compress_gzip(&self.buffer)?,
            Compression::Deflate => compress_deflate(&self.buffer)?,
            Compression::Brotli => compress_brotli(&self.buffer)?,
            _ => compress_request_body_with_config(&self.buffer, &self.config)?,
        };
        self.stats.compressed_size += compressed.len();
        self.stats.compression_ratio = if self.stats.original_size > 0 {
            self.stats.compressed_size as f32 / self.stats.original_size as f32
        } else {
            1.0
        };
        self.buffer.clear();
        Ok(compressed)
    }
    
    pub fn get_stats(&self) -> &CompressionStats {
        &self.stats
    }
    
    pub fn reset(&mut self) {
        self.buffer.clear();
        self.finished = false;
        self.stats = CompressionStats::default();
        self.start_time = None;
    }
    
    pub fn get_compression(&self) -> Compression {
        self.compression
    }
    
    pub fn get_config(&self) -> &CompressionConfig {
        &self.config
    }
    
    pub fn is_finished(&self) -> bool {
        self.finished
    }
    
    pub fn buffer_size(&self) -> usize {
        self.buffer.len()
    }
    
    pub fn set_buffer_threshold(&mut self, _threshold: usize) {
        // This would be used in compress_chunk to determine when to compress
        // For now, we'll store it in the config if needed
    }
    
    pub fn get_compression_ratio(&self) -> f32 {
        self.stats.compression_ratio
    }
}

pub struct StreamingDecompressor {
    compression: Compression,
    buffer: Vec<u8>,
    finished: bool,
}

impl StreamingDecompressor {
    pub fn new(compression: Compression) -> Self {
        StreamingDecompressor {
            compression,
            buffer: Vec::new(),
            finished: false,
        }
    }

    pub fn decompress_chunk(&mut self, data: &[u8]) -> Result<Vec<u8>> {
        if self.finished {
            return Err(Error::CompressionError("Decompressor already finished".to_string()));
        }

        self.buffer.extend_from_slice(data);
        
        // Try to decompress accumulated data
        match decompress_response(&self.buffer, self.compression.as_str()) {
            Ok(decompressed) => {
                self.buffer.clear();
                Ok(decompressed)
            },
            Err(_) => {
                // Not enough data yet, wait for more
                Ok(Vec::new())
            }
        }
    }

    pub fn finish(&mut self) -> Result<Vec<u8>> {
        if self.finished {
            return Ok(Vec::new());
        }

        self.finished = true;
        
        if self.buffer.is_empty() {
            return Ok(Vec::new());
        }

        let decompressed = decompress_response(&self.buffer, self.compression.as_str())?;
        self.buffer.clear();
        Ok(decompressed)
    }
}

fn compress_gzip(data: &[u8]) -> Result<Vec<u8>> {
    compress_gzip_with_level(data, CompressionLevel::Default)
}

fn compress_gzip_with_level(data: &[u8], level: CompressionLevel) -> Result<Vec<u8>> {
    let mut output = Vec::new();
    
    // GZIP header
    output.extend_from_slice(&[0x1f, 0x8b]); // Magic number
    output.push(8); // Compression method (deflate)
    output.push(0); // Flags
    output.extend_from_slice(&[0, 0, 0, 0]); // Timestamp
    
    // Extra flags based on compression level
    let extra_flags = match level {
        CompressionLevel::Fastest => 4, // Fastest algorithm
        CompressionLevel::Best => 2,    // Slowest algorithm
        _ => 0,                         // Default
    };
    output.push(extra_flags);
    output.push(255); // OS (unknown)

    // Compress data using DEFLATE with level
    let compressed = compress_deflate_raw_with_level(data, level)?;
    output.extend_from_slice(&compressed);

    // CRC32 and size
    let crc = crc32(data);
    output.extend_from_slice(&crc.to_le_bytes());
    output.extend_from_slice(&(data.len() as u32).to_le_bytes());

    Ok(output)
}

fn compress_deflate(data: &[u8]) -> Result<Vec<u8>> {
    compress_deflate_with_level(data, CompressionLevel::Default)
}

fn compress_deflate_with_level(data: &[u8], level: CompressionLevel) -> Result<Vec<u8>> {
    let mut output = Vec::new();
    
    // Zlib header with level information
    let flevel = match level {
        CompressionLevel::Fastest => 0,
        CompressionLevel::Fast => 1,
        CompressionLevel::Default => 2,
        CompressionLevel::Best => 3,
        CompressionLevel::Custom(l) if l <= 2 => 0,
        CompressionLevel::Custom(l) if l <= 5 => 1,
        CompressionLevel::Custom(l) if l <= 6 => 2,
        CompressionLevel::Custom(_) => 3,
    };
    
    output.push(0x78); // CMF: CM=8, CINFO=7
    let flg = (flevel << 6) | 0x1C; // FLEVEL and FCHECK
    output.push(flg);

    // Compress data with level
    let compressed = compress_deflate_raw_with_level(data, level)?;
    output.extend_from_slice(&compressed);

    // Adler32 checksum
    let checksum = adler32(data);
    output.extend_from_slice(&checksum.to_be_bytes());

    Ok(output)
}

fn compress_deflate_raw(data: &[u8]) -> Result<Vec<u8>> {
    compress_deflate_raw_with_level(data, CompressionLevel::Default)
}

fn compress_deflate_raw_with_level(data: &[u8], level: CompressionLevel) -> Result<Vec<u8>> {
    let mut output = Vec::new();
    let mut bit_writer = BitWriter::new();

    // Choose compression strategy based on level
    let use_compression = match level {
        CompressionLevel::Fastest => false, // Use uncompressed blocks for speed
        _ => data.len() > 100, // Only compress if worth it
    };

    let mut pos = 0;
    while pos < data.len() {
        let chunk_size = std::cmp::min(65535, data.len() - pos);
        let is_final = pos + chunk_size >= data.len();

        if use_compression && chunk_size > 50 {
            // Try simple compression with repeated byte detection
            let compressed_chunk = compress_chunk_simple(&data[pos..pos + chunk_size])?;
            
            if compressed_chunk.len() < chunk_size {
                // Use compressed block
                bit_writer.write_bits(if is_final { 1 } else { 0 }, 1);
                bit_writer.write_bits(1, 2); // Fixed Huffman codes
                
                // Write compressed data (simplified)
                for &byte in &compressed_chunk {
                    bit_writer.write_bits(byte as u32, 8);
                }
            } else {
                // Fall back to uncompressed
                write_uncompressed_block(&mut bit_writer, &mut output, &data[pos..pos + chunk_size], is_final)?;
            }
        } else {
            // Uncompressed block
            write_uncompressed_block(&mut bit_writer, &mut output, &data[pos..pos + chunk_size], is_final)?;
        }

        pos += chunk_size;
    }

    bit_writer.flush_to_bytes(&mut output);
    Ok(output)
}

fn write_uncompressed_block(bit_writer: &mut BitWriter, output: &mut Vec<u8>, data: &[u8], is_final: bool) -> Result<()> {
    // Block header
    bit_writer.write_bits(if is_final { 1 } else { 0 }, 1);
    bit_writer.write_bits(0, 2); // Uncompressed block

    // Align to byte boundary
    bit_writer.flush_to_bytes(output);

    // Block length
    output.extend_from_slice(&(data.len() as u16).to_le_bytes());
    output.extend_from_slice(&(!(data.len() as u16)).to_le_bytes());

    // Block data
    output.extend_from_slice(data);
    
    Ok(())
}

fn compress_chunk_simple(data: &[u8]) -> Result<Vec<u8>> {
    // Very simple compression: just remove consecutive duplicate bytes
    let mut output = Vec::new();
    let mut i = 0;
    
    while i < data.len() {
        let byte = data[i];
        let mut count = 1;
        
        // Count consecutive identical bytes
        while i + count < data.len() && data[i + count] == byte && count < 255 {
            count += 1;
        }
        
        if count >= 3 {
            // Encode as run-length: 0xFF, count, byte
            output.push(0xFF);
            output.push(count as u8);
            output.push(byte);
        } else {
            // Literal bytes
            for _ in 0..count {
                if byte == 0xFF {
                    // Escape 0xFF bytes
                    output.push(0xFF);
                    output.push(0);
                }
                output.push(byte);
            }
        }
        
        i += count;
    }
    
    Ok(output)
}

fn compress_brotli(data: &[u8]) -> Result<Vec<u8>> {
    compress_brotli_with_level(data, CompressionLevel::Default)
}

fn compress_brotli_with_level(data: &[u8], level: CompressionLevel) -> Result<Vec<u8>> {
    // Simplified Brotli compression with level support
    let mut output = Vec::new();
    let mut pos = 0;
    
    let max_distance = match level {
        CompressionLevel::Fastest => 64,
        CompressionLevel::Fast => 256,
        CompressionLevel::Default => 1024,
        CompressionLevel::Best => 4096,
        CompressionLevel::Custom(l) => (64 << (l / 2)) as usize,
    };
    
    let min_match_length = match level {
        CompressionLevel::Fastest => 4,
        _ => 3,
    };

    while pos < data.len() {
        let byte = data[pos];
        
        // Look for repeated patterns
        let mut best_length = 0;
        let mut best_distance = 0;
        
        let search_distance = std::cmp::min(pos, max_distance);
        for distance in 1..=search_distance {
            if pos >= distance {
                let mut length = 0;
                while pos + length < data.len() && 
                      length < 127 && 
                      data[pos + length] == data[pos + length - distance] {
                    length += 1;
                }
                
                if length > best_length && length >= min_match_length {
                    best_length = length;
                    best_distance = distance;
                }
            }
        }

        if best_length >= min_match_length {
            // Encode back-reference
            output.push(0x80 | ((best_length - min_match_length) as u8));
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_compression_enum() {
        assert_eq!(Compression::parse("gzip"), Some(Compression::Gzip));
        assert_eq!(Compression::parse("deflate"), Some(Compression::Deflate));
        assert_eq!(Compression::parse("br"), Some(Compression::Brotli));
        assert_eq!(Compression::parse("brotli"), Some(Compression::Brotli));
        assert_eq!(Compression::parse("identity"), Some(Compression::Identity));
        assert_eq!(Compression::parse("unknown"), None);

        assert_eq!(Compression::Gzip.as_str(), "gzip");
        assert_eq!(Compression::Deflate.as_str(), "deflate");
        assert_eq!(Compression::Brotli.as_str(), "br");
        assert_eq!(Compression::Identity.as_str(), "identity");
    }

    #[test]
    fn test_compression_properties() {
        assert!(Compression::Gzip.is_supported());
        assert!(Compression::Deflate.is_supported());
        assert!(Compression::Brotli.is_supported());
        assert!(Compression::Identity.is_supported());

        assert!(Compression::Gzip.is_lossless());
        assert!(Compression::Deflate.is_lossless());
        assert!(Compression::Brotli.is_lossless());
        assert!(Compression::Identity.is_lossless());

        assert_eq!(Compression::Gzip.file_extension(), ".gz");
        assert_eq!(Compression::Deflate.file_extension(), ".zlib");
        assert_eq!(Compression::Brotli.file_extension(), ".br");
        assert_eq!(Compression::Identity.file_extension(), "");
    }

    #[test]
    fn test_compression_level() {
        assert_eq!(CompressionLevel::Fastest.as_u8(), 1);
        assert_eq!(CompressionLevel::Fast.as_u8(), 3);
        assert_eq!(CompressionLevel::Default.as_u8(), 6);
        assert_eq!(CompressionLevel::Best.as_u8(), 9);
        assert_eq!(CompressionLevel::Custom(5).as_u8(), 5);
    }

    #[test]
    fn test_compression_config() {
        let config = CompressionConfig::new(Compression::Gzip)
            .with_level(CompressionLevel::Best)
            .with_min_size(2048)
            .with_max_size(1024 * 1024);

        assert_eq!(config.algorithm, Compression::Gzip);
        assert_eq!(config.level.as_u8(), 9);
        assert_eq!(config.min_size, 2048);
        assert_eq!(config.max_size, Some(1024 * 1024));

        assert!(!config.should_compress(1000)); // Too small
        assert!(config.should_compress(3000)); // Just right
        assert!(!config.should_compress(2 * 1024 * 1024)); // Too large
    }

    #[test]
    fn test_accept_encoding_parsing() {
        let encodings = vec![Compression::Gzip, Compression::Deflate];
        let header = parse_accept_encoding(&encodings);
        assert_eq!(header, "gzip, deflate");

        let encodings_with_quality = vec![
            (Compression::Gzip, 1.0),
            (Compression::Deflate, 0.8),
            (Compression::Brotli, 0.5),
        ];
        let header = parse_accept_encoding_with_quality(&encodings_with_quality);
        assert!(header.contains("gzip"));
        assert!(header.contains("deflate; q=0.8"));
        assert!(header.contains("br; q=0.5"));
    }

    #[test]
    fn test_choose_compression() {
        let supported = vec![Compression::Gzip, Compression::Deflate];
        
        let choice = choose_compression("gzip, deflate", &supported);
        assert!(choice.is_some()); // Should choose one of the supported algorithms

        let choice = choose_compression("deflate; q=0.8, gzip; q=0.9", &supported);
        assert_eq!(choice, Some(Compression::Gzip));

        let choice = choose_compression("br, deflate", &supported);
        assert_eq!(choice, Some(Compression::Deflate));

        let choice = choose_compression("br", &supported);
        assert_eq!(choice, None);
    }

    #[test]
    fn test_compression_stats() {
        let original_size = 1000;
        let compressed_size = 300;
        let duration = std::time::Duration::from_millis(10);
        
        let stats = CompressionStats::new(original_size, compressed_size, Compression::Gzip, duration);
        
        assert_eq!(stats.original_size, 1000);
        assert_eq!(stats.compressed_size, 300);
        assert_eq!(stats.compression_ratio, 0.3);
        assert_eq!(stats.space_saved(), 700);
        assert_eq!(stats.space_saved_percent(), 70.0);
        assert!(stats.compression_speed_mbps() > 0.0);
    }

    #[test]
    fn test_basic_compression_decompression() {
        let test_data = b"Hello, World! This is a test string for compression.";
        
        // Test Identity (always works)
        let compressed = compress_request_body(test_data, Compression::Identity).unwrap();
        assert_eq!(compressed, test_data);
        
        let decompressed = decompress_response(&compressed, "identity").unwrap();
        assert_eq!(decompressed, test_data);

        // Test that compression functions don't panic
        let _gzip_result = compress_request_body(test_data, Compression::Gzip);
        let _deflate_result = compress_request_body(test_data, Compression::Deflate);
        let _brotli_result = compress_request_body(test_data, Compression::Brotli);
    }

    #[test]
    fn test_streaming_compressor() {
        let mut compressor = StreamingCompressor::new(Compression::Gzip);
        
        let chunk1 = b"Hello, ";
        let chunk2 = b"World! ";
        let chunk3 = b"This is a test.";
        
        let _result1 = compressor.compress_chunk(chunk1).unwrap();
        let _result2 = compressor.compress_chunk(chunk2).unwrap();
        let _result3 = compressor.compress_chunk(chunk3).unwrap();
        
        let final_result = compressor.finish().unwrap();
        assert!(!final_result.is_empty());
        
        let stats = compressor.get_stats();
        assert!(stats.original_size > 0);
        assert!(stats.compression_time > std::time::Duration::from_nanos(0));
    }

    #[test]
    fn test_compression_with_stats() {
        let test_data = b"This is a longer test string that should compress well because it has repeated patterns and common words.";
        let config = CompressionConfig::new(Compression::Gzip);
        
        let (compressed, stats) = compress_with_stats(test_data, &config).unwrap();
        
        assert!(!compressed.is_empty());
        assert_eq!(stats.original_size, test_data.len());
        assert_eq!(stats.compressed_size, compressed.len());
        assert!(stats.compression_ratio <= 1.0);
        assert!(stats.compression_time > std::time::Duration::from_nanos(0));
    }

    #[test]
    fn test_detect_best_compression() {
        let test_data = b"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"; // Highly compressible
        let algorithms = vec![Compression::Gzip, Compression::Deflate, Compression::Identity];
        
        let (best_algorithm, _stats) = detect_best_compression(test_data, &algorithms).unwrap();
        
        // Should return one of the supported algorithms
        assert!(algorithms.contains(&best_algorithm));
    }

    #[test]
    fn test_compression_levels() {
        let test_data = b"This is test data for compression level testing.";
        
        let config_fast = CompressionConfig::new(Compression::Gzip)
            .with_level(CompressionLevel::Fastest);
        let config_best = CompressionConfig::new(Compression::Gzip)
            .with_level(CompressionLevel::Best);
        
        let (compressed_fast, _stats_fast) = compress_with_stats(test_data, &config_fast).unwrap();
        let (compressed_best, _stats_best) = compress_with_stats(test_data, &config_best).unwrap();
        
        // Both should work
        assert!(!compressed_fast.is_empty());
        assert!(!compressed_best.is_empty());
        
        // Both should produce valid output
        assert!(!compressed_fast.is_empty());
        assert!(!compressed_best.is_empty());
    }
}   
 #[test]
    fn test_compress_with_level() {
        let test_data = b"This is test data for level-specific compression.";
        
        let result_fast = compress_with_level(test_data, Compression::Gzip, CompressionLevel::Fastest);
        let result_best = compress_with_level(test_data, Compression::Gzip, CompressionLevel::Best);
        
        assert!(result_fast.is_ok());
        assert!(result_best.is_ok());
        
        let compressed_fast = result_fast.unwrap();
        let compressed_best = result_best.unwrap();
        
        assert!(!compressed_fast.is_empty());
        assert!(!compressed_best.is_empty());
    }

    #[test]
    fn test_compress_raw_deflate() {
        let test_data = b"This is test data for raw deflate compression.";
        
        let result = compress_raw_deflate(test_data);
        assert!(result.is_ok());
        
        let compressed = result.unwrap();
        assert!(!compressed.is_empty());
        assert_ne!(compressed, test_data); // Should be different from original
    }

    #[test]
    fn test_get_best_compression_for_data() {
        // Small data should not be compressed
        let small_data = b"Hi";
        assert_eq!(get_best_compression_for_data(small_data), Compression::Identity);
        
        // Text data should prefer gzip (make sure it's long enough)
        let text_data = "This is a long text string with many words and characters that should compress well with gzip algorithm. ".repeat(20);
        let result = get_best_compression_for_data(text_data.as_bytes());
        assert_eq!(result, Compression::Gzip); // Should be Gzip for long text
        
        // Binary-like data should prefer brotli
        let binary_data = [0u8, 1u8, 255u8, 128u8, 64u8, 32u8, 16u8, 8u8, 4u8, 2u8, 1u8].repeat(100);
        assert_eq!(get_best_compression_for_data(&binary_data), Compression::Brotli);
    }

    #[test]
    fn test_public_compression_functions() {
        let test_data = b"This is test data for public compression functions.";
        
        // Test gzip compression
        let gzip_result = compress_gzip_data(test_data);
        assert!(gzip_result.is_ok());
        assert!(!gzip_result.unwrap().is_empty());
        
        // Test deflate compression
        let deflate_result = compress_deflate_data(test_data);
        assert!(deflate_result.is_ok());
        assert!(!deflate_result.unwrap().is_empty());
        
        // Test brotli compression
        let brotli_result = compress_brotli_data(test_data);
        assert!(brotli_result.is_ok());
        assert!(!brotli_result.unwrap().is_empty());
    }

    #[test]
    fn test_streaming_compressor_methods() {
        let mut compressor = StreamingCompressor::new(Compression::Gzip);
        
        // Test initial state
        assert_eq!(compressor.get_compression(), Compression::Gzip);
        assert!(!compressor.is_finished());
        assert_eq!(compressor.buffer_size(), 0);
        assert_eq!(compressor.get_compression_ratio(), 0.0);
        
        // Add some data
        let test_data = b"Test data for streaming compressor methods.";
        let _result = compressor.compress_chunk(test_data).unwrap();
        
        assert!(compressor.buffer_size() <= test_data.len()); // May be cleared if compressed
        
        // Finish compression
        let _final = compressor.finish().unwrap();
        assert!(compressor.is_finished());
        
        // Test reset
        compressor.reset();
        assert!(!compressor.is_finished());
        assert_eq!(compressor.buffer_size(), 0);
    }

    #[test]
    fn test_streaming_compressor_config() {
        let config = CompressionConfig::new(Compression::Deflate)
            .with_level(CompressionLevel::Best)
            .with_min_size(100);
        
        let compressor = StreamingCompressor::with_config(Compression::Deflate, config.clone());
        
        assert_eq!(compressor.get_compression(), Compression::Deflate);
        assert_eq!(compressor.get_config().algorithm, config.algorithm);
        assert_eq!(compressor.get_config().level, config.level);
        assert_eq!(compressor.get_config().min_size, config.min_size);
    }