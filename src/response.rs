use crate::{Result, Error};
use std::collections::HashMap;

#[derive(Debug)]
pub struct Response {
    pub status: u16,
    pub status_text: String,
    pub headers: HashMap<String, String>,
    pub body: Vec<u8>,
}

impl Response {
    pub fn new(status: u16, status_text: String, headers: HashMap<String, String>, body: Vec<u8>) -> Self {
        Response {
            status,
            status_text,
            headers,
            body,
        }
    }

    pub fn status(&self) -> u16 {
        self.status
    }

    pub fn status_text(&self) -> &str {
        &self.status_text
    }

    pub fn headers(&self) -> &HashMap<String, String> {
        &self.headers
    }

    pub fn header(&self, name: &str) -> Option<&String> {
        // Case-insensitive header lookup
        self.headers.iter()
            .find(|(k, _)| k.to_lowercase() == name.to_lowercase())
            .map(|(_, v)| v)
    }

    pub fn text(&self) -> Result<String> {
        String::from_utf8(self.body.clone())
            .map_err(|_| Error::InvalidResponse("Invalid UTF-8 in response body".to_string()))
    }

    pub fn bytes(&self) -> &[u8] {
        &self.body
    }

    // Note: JSON parsing would require serde or manual implementation
    // pub fn json<T>(&self) -> Result<T> 
    // where 
    //     T: serde::de::DeserializeOwned,
    // {
    //     Err(Error::InvalidResponse("JSON parsing requires manual implementation or serde dependency".to_string()))
    // }

    pub fn is_success(&self) -> bool {
        self.status >= 200 && self.status < 300
    }

    pub fn is_client_error(&self) -> bool {
        self.status >= 400 && self.status < 500
    }

    pub fn is_server_error(&self) -> bool {
        self.status >= 500 && self.status < 600
    }

    pub fn content_length(&self) -> Option<usize> {
        self.header("content-length")
            .and_then(|v| v.parse().ok())
    }

    pub fn content_type(&self) -> Option<&String> {
        self.header("content-type")
    }
}