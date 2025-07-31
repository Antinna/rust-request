use crate::{Result, Error};
use std::io::{Read, Write, BufRead, BufWriter};
use std::fs::File;
use std::path::Path;
use std::time::{Duration, Instant};

// Type aliases for complex callback types
type UploadProgressCallback = Box<dyn Fn(u64, u64) + Send + Sync>;
type DownloadProgressCallback = Box<dyn Fn(u64, Option<u64>) + Send + Sync>;

/// Streaming upload handler for large files
pub struct StreamingUpload {
    chunk_size: usize,
    progress_callback: Option<UploadProgressCallback>,
    timeout: Option<Duration>,
}

impl StreamingUpload {
    pub fn new() -> Self {
        StreamingUpload {
            chunk_size: 8192, // 8KB default chunk size
            progress_callback: None,
            timeout: None,
        }
    }

    pub fn chunk_size(mut self, size: usize) -> Self {
        self.chunk_size = size;
        self
    }

    pub fn progress_callback<F>(mut self, callback: F) -> Self
    where
        F: Fn(u64, u64) + Send + Sync + 'static,
    {
        self.progress_callback = Some(Box::new(callback));
        self
    }

    pub fn timeout(mut self, timeout: Duration) -> Self {
        self.timeout = Some(timeout);
        self
    }

    pub fn upload_file<P: AsRef<Path>, W: Write>(&self, file_path: P, writer: &mut W) -> Result<u64> {
        let file = File::open(file_path.as_ref())
            .map_err(Error::Io)?;
        
        let file_size = file.metadata()
            .map_err(Error::Io)?
            .len();

        self.upload_reader(file, file_size, writer)
    }

    pub fn upload_reader<R: Read, W: Write>(&self, mut reader: R, total_size: u64, writer: &mut W) -> Result<u64> {
        let mut buffer = vec![0u8; self.chunk_size];
        let mut total_uploaded = 0u64;
        let start_time = Instant::now();

        loop {
            // Check timeout
            if let Some(timeout) = self.timeout {
                if start_time.elapsed() > timeout {
                    return Err(Error::Timeout);
                }
            }

            let bytes_read = reader.read(&mut buffer)
                .map_err(Error::Io)?;

            if bytes_read == 0 {
                break; // EOF
            }

            writer.write_all(&buffer[..bytes_read])
                .map_err(Error::Io)?;

            total_uploaded += bytes_read as u64;

            // Call progress callback
            if let Some(ref callback) = self.progress_callback {
                callback(total_uploaded, total_size);
            }
        }

        writer.flush().map_err(Error::Io)?;
        Ok(total_uploaded)
    }
}

impl Default for StreamingUpload {
    fn default() -> Self {
        Self::new()
    }
}

/// Streaming download handler for large responses
pub struct StreamingDownload {
    chunk_size: usize,
    progress_callback: Option<DownloadProgressCallback>,
    timeout: Option<Duration>,
    max_size: Option<u64>,
}

impl StreamingDownload {
    pub fn new() -> Self {
        StreamingDownload {
            chunk_size: 8192,
            progress_callback: None,
            timeout: None,
            max_size: None,
        }
    }

    pub fn chunk_size(mut self, size: usize) -> Self {
        self.chunk_size = size;
        self
    }

    pub fn progress_callback<F>(mut self, callback: F) -> Self
    where
        F: Fn(u64, Option<u64>) + Send + Sync + 'static,
    {
        self.progress_callback = Some(Box::new(callback));
        self
    }

    pub fn timeout(mut self, timeout: Duration) -> Self {
        self.timeout = Some(timeout);
        self
    }

    pub fn max_size(mut self, size: u64) -> Self {
        self.max_size = Some(size);
        self
    }

    pub fn download_to_file<R: Read, P: AsRef<Path>>(&self, reader: R, file_path: P, content_length: Option<u64>) -> Result<u64> {
        let file = File::create(file_path.as_ref())
            .map_err(Error::Io)?;
        
        let mut writer = BufWriter::new(file);
        self.download_to_writer(reader, &mut writer, content_length)
    }

    pub fn download_to_writer<R: Read, W: Write>(&self, mut reader: R, writer: &mut W, content_length: Option<u64>) -> Result<u64> {
        let mut buffer = vec![0u8; self.chunk_size];
        let mut total_downloaded = 0u64;
        let start_time = Instant::now();

        loop {
            // Check timeout
            if let Some(timeout) = self.timeout {
                if start_time.elapsed() > timeout {
                    return Err(Error::Timeout);
                }
            }

            // Check max size limit
            if let Some(max_size) = self.max_size {
                if total_downloaded >= max_size {
                    return Err(Error::InvalidResponse("Response too large".to_string()));
                }
            }

            let bytes_read = reader.read(&mut buffer)
                .map_err(Error::Io)?;

            if bytes_read == 0 {
                break; // EOF
            }

            writer.write_all(&buffer[..bytes_read])
                .map_err(Error::Io)?;

            total_downloaded += bytes_read as u64;

            // Call progress callback
            if let Some(ref callback) = self.progress_callback {
                callback(total_downloaded, content_length);
            }
        }

        writer.flush().map_err(Error::Io)?;
        Ok(total_downloaded)
    }

    pub fn download_to_memory<R: Read>(&self, mut reader: R, content_length: Option<u64>) -> Result<Vec<u8>> {
        let initial_capacity = content_length.unwrap_or(1024).min(1024 * 1024) as usize; // Cap at 1MB initial
        let mut buffer = Vec::with_capacity(initial_capacity);
        let mut chunk = vec![0u8; self.chunk_size];
        let mut total_downloaded = 0u64;
        let start_time = Instant::now();

        loop {
            // Check timeout
            if let Some(timeout) = self.timeout {
                if start_time.elapsed() > timeout {
                    return Err(Error::Timeout);
                }
            }

            // Check max size limit
            if let Some(max_size) = self.max_size {
                if total_downloaded >= max_size {
                    return Err(Error::InvalidResponse("Response too large".to_string()));
                }
            }

            let bytes_read = reader.read(&mut chunk)
                .map_err(Error::Io)?;

            if bytes_read == 0 {
                break; // EOF
            }

            buffer.extend_from_slice(&chunk[..bytes_read]);
            total_downloaded += bytes_read as u64;

            // Call progress callback
            if let Some(ref callback) = self.progress_callback {
                callback(total_downloaded, content_length);
            }
        }

        Ok(buffer)
    }
}

impl Default for StreamingDownload {
    fn default() -> Self {
        Self::new()
    }
}

/// Chunked transfer encoding handler
#[derive(Debug)]
pub struct ChunkedTransfer {
    max_chunk_size: usize,
}

impl ChunkedTransfer {
    pub fn new() -> Self {
        ChunkedTransfer {
            max_chunk_size: 8192,
        }
    }

    pub fn max_chunk_size(mut self, size: usize) -> Self {
        self.max_chunk_size = size;
        self
    }

    pub fn encode_chunks<R: Read, W: Write>(&self, mut reader: R, writer: &mut W) -> Result<u64> {
        let mut buffer = vec![0u8; self.max_chunk_size];
        let mut total_written = 0u64;

        loop {
            let bytes_read = reader.read(&mut buffer)
                .map_err(Error::Io)?;

            if bytes_read == 0 {
                // Write final chunk (0-length)
                writer.write_all(b"0\r\n\r\n")
                    .map_err(Error::Io)?;
                break;
            }

            // Write chunk size in hex
            let chunk_size_hex = format!("{bytes_read:X}\r\n");
            writer.write_all(chunk_size_hex.as_bytes())
                .map_err(Error::Io)?;

            // Write chunk data
            writer.write_all(&buffer[..bytes_read])
                .map_err(Error::Io)?;

            // Write chunk trailer
            writer.write_all(b"\r\n")
                .map_err(Error::Io)?;

            total_written += bytes_read as u64;
        }

        writer.flush().map_err(Error::Io)?;
        Ok(total_written)
    }

    pub fn decode_chunks<R: BufRead>(&self, reader: &mut R) -> Result<Vec<u8>> {
        let mut result = Vec::new();

        loop {
            // Read chunk size line
            let mut size_line = String::new();
            reader.read_line(&mut size_line)
                .map_err(Error::Io)?;

            // Parse chunk size (hex)
            let size_str = size_line.trim();
            let chunk_size = usize::from_str_radix(size_str, 16)
                .map_err(|_| Error::InvalidResponse("Invalid chunk size".to_string()))?;

            if chunk_size == 0 {
                // Read final CRLF and any trailers
                let mut final_line = String::new();
                reader.read_line(&mut final_line)
                    .map_err(Error::Io)?;
                break;
            }

            // Read chunk data
            let mut chunk_data = vec![0u8; chunk_size];
            reader.read_exact(&mut chunk_data)
                .map_err(Error::Io)?;

            result.extend_from_slice(&chunk_data);

            // Read trailing CRLF
            let mut crlf = [0u8; 2];
            reader.read_exact(&mut crlf)
                .map_err(Error::Io)?;

            if &crlf != b"\r\n" {
                return Err(Error::InvalidResponse("Invalid chunk format".to_string()));
            }
        }

        Ok(result)
    }
}

impl Default for ChunkedTransfer {
    fn default() -> Self {
        Self::new()
    }
}

/// Range request handler for partial content downloads
#[derive(Debug, Clone)]
pub struct RangeRequest {
    pub start: Option<u64>,
    pub end: Option<u64>,
}

impl RangeRequest {
    pub fn new() -> Self {
        RangeRequest {
            start: None,
            end: None,
        }
    }

    pub fn bytes(start: u64, end: Option<u64>) -> Self {
        RangeRequest {
            start: Some(start),
            end,
        }
    }

    pub fn from_offset(offset: u64) -> Self {
        RangeRequest {
            start: Some(offset),
            end: None,
        }
    }

    pub fn last_bytes(count: u64) -> Self {
        RangeRequest {
            start: None,
            end: Some(count),
        }
    }

    pub fn to_header_value(&self) -> String {
        match (self.start, self.end) {
            (Some(start), Some(end)) => format!("bytes={start}-{end}"),
            (Some(start), None) => format!("bytes={start}-"),
            (None, Some(suffix)) => format!("bytes=-{suffix}"),
            (None, None) => "bytes=0-".to_string(),
        }
    }

    pub fn apply_to_headers(&self, headers: &mut std::collections::HashMap<String, String>) {
        headers.insert("Range".to_string(), self.to_header_value());
    }
}

impl Default for RangeRequest {
    fn default() -> Self {
        Self::new()
    }
}

/// Bandwidth throttling for uploads/downloads
#[derive(Debug)]
pub struct BandwidthThrottle {
    max_bytes_per_second: u64,
    last_check: Instant,
    bytes_transferred: u64,
}

impl BandwidthThrottle {
    pub fn new(max_bytes_per_second: u64) -> Self {
        BandwidthThrottle {
            max_bytes_per_second,
            last_check: Instant::now(),
            bytes_transferred: 0,
        }
    }

    pub fn throttle(&mut self, bytes: u64) -> Duration {
        self.bytes_transferred += bytes;
        let elapsed = self.last_check.elapsed();
        
        if elapsed >= Duration::from_secs(1) {
            // Reset counters every second
            self.bytes_transferred = bytes;
            self.last_check = Instant::now();
            return Duration::from_millis(0);
        }

        let expected_time = Duration::from_secs_f64(self.bytes_transferred as f64 / self.max_bytes_per_second as f64);
        
        if elapsed < expected_time {
            expected_time - elapsed
        } else {
            Duration::from_millis(0)
        }
    }

    pub fn should_sleep(&mut self, bytes: u64) -> Option<Duration> {
        let sleep_duration = self.throttle(bytes);
        if sleep_duration > Duration::from_millis(0) {
            Some(sleep_duration)
        } else {
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn test_streaming_upload() {
        let data = b"Hello, World!";
        let reader = Cursor::new(data);
        let mut writer = Vec::new();

        let uploader = StreamingUpload::new().chunk_size(4);
        let bytes_uploaded = uploader.upload_reader(reader, data.len() as u64, &mut writer).unwrap();

        assert_eq!(bytes_uploaded, data.len() as u64);
        assert_eq!(writer, data);
    }

    #[test]
    fn test_streaming_download() {
        let data = b"Hello, World!";
        let reader = Cursor::new(data);
        let mut writer = Vec::new();

        let downloader = StreamingDownload::new().chunk_size(4);
        let bytes_downloaded = downloader.download_to_writer(reader, &mut writer, Some(data.len() as u64)).unwrap();

        assert_eq!(bytes_downloaded, data.len() as u64);
        assert_eq!(writer, data);
    }

    #[test]
    fn test_range_request() {
        let range = RangeRequest::bytes(100, Some(199));
        assert_eq!(range.to_header_value(), "bytes=100-199");

        let range = RangeRequest::from_offset(500);
        assert_eq!(range.to_header_value(), "bytes=500-");

        let range = RangeRequest::last_bytes(1024);
        assert_eq!(range.to_header_value(), "bytes=-1024");
    }

    #[test]
    fn test_bandwidth_throttle() {
        let mut throttle = BandwidthThrottle::new(10000); // 10KB/s - higher limit
        
        // First small transfer should not throttle much
        let sleep_time = throttle.should_sleep(50); // Very small transfer
        assert!(sleep_time.is_none() || sleep_time.unwrap() < Duration::from_secs(1));
    }
}