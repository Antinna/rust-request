use std::collections::HashMap;
use std::io::Write;

#[derive(Debug, Clone)]
pub struct MultipartForm {
    boundary: String,
    parts: Vec<Part>,
}

impl MultipartForm {
    pub fn new() -> Self {
        MultipartForm {
            boundary: generate_boundary(),
            parts: Vec::new(),
        }
    }

    pub fn with_boundary(boundary: String) -> Self {
        MultipartForm {
            boundary,
            parts: Vec::new(),
        }
    }

    pub fn boundary(&self) -> &str {
        &self.boundary
    }

    pub fn add_text<K, V>(&mut self, name: K, value: V) -> &mut Self
    where
        K: Into<String>,
        V: Into<String>,
    {
        let part = Part::text(name.into(), value.into());
        self.parts.push(part);
        self
    }

    pub fn add_file<K>(&mut self, name: K, filename: String, content_type: String, data: Vec<u8>) -> &mut Self
    where
        K: Into<String>,
    {
        let part = Part::file(name.into(), filename, content_type, data);
        self.parts.push(part);
        self
    }

    pub fn add_part(&mut self, part: Part) -> &mut Self {
        self.parts.push(part);
        self
    }

    pub fn content_type(&self) -> String {
        format!("multipart/form-data; boundary={}", self.boundary)
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buffer = Vec::new();

        for part in &self.parts {
            // Write boundary
            write!(buffer, "--{}\r\n", self.boundary).unwrap();
            
            // Write headers
            for (key, value) in &part.headers {
                write!(buffer, "{key}: {value}\r\n").unwrap();
            }
            
            // Empty line before content
            write!(buffer, "\r\n").unwrap();
            
            // Write content
            buffer.extend_from_slice(&part.data);
            write!(buffer, "\r\n").unwrap();
        }

        // Final boundary
        write!(buffer, "--{}--\r\n", self.boundary).unwrap();

        buffer
    }

    pub fn len(&self) -> usize {
        self.to_bytes().len()
    }

    pub fn is_empty(&self) -> bool {
        self.parts.is_empty()
    }
}

impl Default for MultipartForm {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone)]
pub struct Part {
    headers: HashMap<String, String>,
    data: Vec<u8>,
}

impl Part {
    pub fn new() -> Self {
        Part {
            headers: HashMap::new(),
            data: Vec::new(),
        }
    }

    pub fn text(name: String, value: String) -> Self {
        let mut part = Part::new();
        part.headers.insert(
            "Content-Disposition".to_string(),
            format!("form-data; name=\"{name}\"")
        );
        part.data = value.into_bytes();
        part
    }

    pub fn file(name: String, filename: String, content_type: String, data: Vec<u8>) -> Self {
        let mut part = Part::new();
        part.headers.insert(
            "Content-Disposition".to_string(),
            format!("form-data; name=\"{name}\"; filename=\"{filename}\"")
        );
        part.headers.insert("Content-Type".to_string(), content_type);
        part.data = data;
        part
    }

    pub fn with_header<K, V>(mut self, key: K, value: V) -> Self
    where
        K: Into<String>,
        V: Into<String>,
    {
        self.headers.insert(key.into(), value.into());
        self
    }

    pub fn with_data(mut self, data: Vec<u8>) -> Self {
        self.data = data;
        self
    }

    pub fn headers(&self) -> &HashMap<String, String> {
        &self.headers
    }

    pub fn data(&self) -> &[u8] {
        &self.data
    }
}

impl Default for Part {
    fn default() -> Self {
        Self::new()
    }
}

fn generate_boundary() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    
    format!("----formdata-request-{timestamp:x}")
}

// Helper function to read file contents
pub fn read_file_to_bytes(path: &str) -> std::io::Result<Vec<u8>> {
    use std::fs::File;
    use std::io::Read;
    
    let mut file = File::open(path)?;
    let mut buffer = Vec::new();
    file.read_to_end(&mut buffer)?;
    Ok(buffer)
}

// Helper function to guess content type from file extension
pub fn guess_content_type(filename: &str) -> String {
    let extension = filename
        .rfind('.')
        .map(|i| &filename[i + 1..])
        .unwrap_or("")
        .to_lowercase();

    match extension.as_str() {
        "txt" => "text/plain",
        "html" | "htm" => "text/html",
        "css" => "text/css",
        "js" => "application/javascript",
        "json" => "application/json",
        "xml" => "application/xml",
        "pdf" => "application/pdf",
        "zip" => "application/zip",
        "jpg" | "jpeg" => "image/jpeg",
        "png" => "image/png",
        "gif" => "image/gif",
        "svg" => "image/svg+xml",
        "mp3" => "audio/mpeg",
        "mp4" => "video/mp4",
        "avi" => "video/x-msvideo",
        "mov" => "video/quicktime",
        "doc" => "application/msword",
        "docx" => "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
        "xls" => "application/vnd.ms-excel",
        "xlsx" => "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        "ppt" => "application/vnd.ms-powerpoint",
        "pptx" => "application/vnd.openxmlformats-officedocument.presentationml.presentation",
        _ => "application/octet-stream",
    }.to_string()
}