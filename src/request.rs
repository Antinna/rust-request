use crate::{Client, Error, Method, Response, Result, Url};
use std::collections::HashMap;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpStream;

#[derive(Debug)]
pub struct Request {
    pub method: Method,
    pub url: Url,
    pub headers: HashMap<String, String>,
    pub body: Option<Vec<u8>>,
}

impl Request {
    pub fn new(method: Method, url: Url) -> Self {
        Request {
            method,
            url,
            headers: HashMap::new(),
            body: None,
        }
    }
}

#[derive(Debug)]
pub struct RequestBuilder {
    method: Method,
    url: String,
    headers: HashMap<String, String>,
    query_params: HashMap<String, String>,
    body: Option<Vec<u8>>,
    client: Client,
}

impl RequestBuilder {
    pub fn new(method: Method, url: &str, client: Client) -> Self {
        RequestBuilder {
            method,
            url: url.to_string(),
            headers: HashMap::new(),
            query_params: HashMap::new(),
            body: None,
            client,
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

    pub fn headers(mut self, headers: HashMap<String, String>) -> Self {
        self.headers.extend(headers);
        self
    }

    pub fn query<K, V>(mut self, key: K, value: V) -> Self
    where
        K: Into<String>,
        V: Into<String>,
    {
        self.query_params.insert(key.into(), value.into());
        self
    }

    pub fn body<T: Into<Vec<u8>>>(mut self, body: T) -> Self {
        self.body = Some(body.into());
        self
    }

    // Note: JSON serialization would require serde or manual implementation
    // Users should use .body() with manually serialized JSON string
    // pub fn json<T>(mut self, json: &T) -> Self
    // where
    //     T: serde::Serialize,
    // {
    //     self.headers.insert("Content-Type".to_string(), "application/json".to_string());
    //     self
    // }

    pub fn form<K, V>(mut self, form: &HashMap<K, V>) -> Self
    where
        K: AsRef<str>,
        V: AsRef<str>,
    {
        let form_data = form
            .iter()
            .map(|(k, v)| {
                format!(
                    "{}={}",
                    urlencoding::encode(k.as_ref()),
                    urlencoding::encode(v.as_ref())
                )
            })
            .collect::<Vec<_>>()
            .join("&");

        self.headers.insert(
            "Content-Type".to_string(),
            "application/x-www-form-urlencoded".to_string(),
        );
        self.body = Some(form_data.into_bytes());
        self
    }

    pub fn send(self) -> Result<Response> {
        // Build the final URL with query parameters
        let mut final_url = self.url.clone();
        if !self.query_params.is_empty() {
            let query_string = self
                .query_params
                .iter()
                .map(|(k, v)| format!("{}={}", urlencoding::encode(k), urlencoding::encode(v)))
                .collect::<Vec<_>>()
                .join("&");

            if final_url.contains('?') {
                final_url.push('&');
                final_url.push_str(&query_string);
            } else {
                final_url.push('?');
                final_url.push_str(&query_string);
            }
        }

        let url = Url::parse(&final_url)?;

        // Merge headers
        let mut headers = self.client.default_headers.clone();
        headers.extend(self.headers.clone());

        // Add Content-Length if we have a body
        if let Some(ref body) = self.body {
            headers.insert("Content-Length".to_string(), body.len().to_string());
        }

        // Add Host header
        headers.insert("Host".to_string(), url.host.clone());

        let request = Request {
            method: self.method,
            url,
            headers,
            body: self.body.clone(),
        };

        self.execute_request(request)
    }

    fn execute_request(&self, request: Request) -> Result<Response> {
        // Only support HTTP for now (HTTPS would require TLS implementation)
        if request.url.scheme != "http" {
            return Err(Error::InvalidUrl("Only HTTP is supported".to_string()));
        }

        // Connect to the server
        let addr = request.url.socket_addr();
        let mut stream = TcpStream::connect(&addr).map_err(|e| {
            Error::ConnectionFailed(format!("Failed to connect to {}: {}", addr, e))
        })?;

        // Set timeout if specified
        if let Some(timeout) = self.client.timeout {
            stream.set_read_timeout(Some(timeout))?;
            stream.set_write_timeout(Some(timeout))?;
        }

        // Build HTTP request
        let mut http_request = format!(
            "{} {} HTTP/1.1\r\n",
            request.method.as_str(),
            if request.url.query.is_some() {
                format!(
                    "{}?{}",
                    request.url.path,
                    request.url.query.as_ref().unwrap()
                )
            } else {
                request.url.path.clone()
            }
        );

        // Add headers
        for (key, value) in &request.headers {
            http_request.push_str(&format!("{}: {}\r\n", key, value));
        }

        http_request.push_str("\r\n");

        // Write request
        stream.write_all(http_request.as_bytes())?;

        // Write body if present
        if let Some(ref body) = request.body {
            stream.write_all(body)?;
        }

        stream.flush()?;

        // Read response
        self.read_response(stream)
    }

    fn read_response(&self, stream: TcpStream) -> Result<Response> {
        let mut reader = BufReader::new(stream);
        let mut status_line = String::new();
        reader.read_line(&mut status_line)?;

        // Parse status line
        let parts: Vec<&str> = status_line.trim().split_whitespace().collect();
        if parts.len() < 3 {
            return Err(Error::InvalidResponse("Invalid status line".to_string()));
        }

        let status: u16 = parts[1]
            .parse()
            .map_err(|_| Error::InvalidResponse("Invalid status code".to_string()))?;
        let status_text = parts[2..].join(" ");

        // Read headers
        let mut headers = HashMap::new();
        let mut line = String::new();
        loop {
            line.clear();
            reader.read_line(&mut line)?;
            let line = line.trim();

            if line.is_empty() {
                break;
            }

            if let Some(pos) = line.find(':') {
                let key = line[..pos].trim().to_string();
                let value = line[pos + 1..].trim().to_string();
                headers.insert(key, value);
            }
        }

        // Read body
        let mut body = Vec::new();

        // Check if we have Content-Length
        if let Some(content_length) = headers
            .get("Content-Length")
            .or_else(|| headers.get("content-length"))
        {
            if let Ok(length) = content_length.parse::<usize>() {
                let mut buffer = vec![0; length];
                reader.read_exact(&mut buffer)?;
                body = buffer;
            }
        } else if headers
            .get("Transfer-Encoding")
            .or_else(|| headers.get("transfer-encoding"))
            .map(|v| v.to_lowercase().contains("chunked"))
            .unwrap_or(false)
        {
            // Handle chunked encoding
            body = self.read_chunked_body(reader)?;
        } else {
            // Read until connection closes
            reader.read_to_end(&mut body)?;
        }

        let response = Response::new(status, status_text, headers, body);

        // Check for HTTP errors
        if !response.is_success() {
            return Err(Error::HttpError(
                response.status,
                response.status_text.clone(),
            ));
        }

        Ok(response)
    }

    fn read_chunked_body(&self, mut reader: BufReader<TcpStream>) -> Result<Vec<u8>> {
        let mut body = Vec::new();

        loop {
            let mut size_line = String::new();
            reader.read_line(&mut size_line)?;

            let size_str = size_line.trim().split(';').next().unwrap_or("").trim();
            let chunk_size = usize::from_str_radix(size_str, 16)
                .map_err(|_| Error::InvalidResponse("Invalid chunk size".to_string()))?;

            if chunk_size == 0 {
                // Read trailing headers (if any) and final CRLF
                let mut line = String::new();
                loop {
                    line.clear();
                    reader.read_line(&mut line)?;
                    if line.trim().is_empty() {
                        break;
                    }
                }
                break;
            }

            let mut chunk = vec![0; chunk_size];
            reader.read_exact(&mut chunk)?;
            body.extend_from_slice(&chunk);

            // Read trailing CRLF
            let mut crlf = String::new();
            reader.read_line(&mut crlf)?;
        }

        Ok(body)
    }
}

// Simple URL encoding implementation since we can't use external crates
mod urlencoding {
    pub fn encode(input: &str) -> String {
        let mut result = String::new();
        for byte in input.bytes() {
            match byte {
                b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                    result.push(byte as char);
                }
                _ => {
                    result.push_str(&format!("%{:02X}", byte));
                }
            }
        }
        result
    }
}
