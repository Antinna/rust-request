use std::fmt;
use std::io;

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug)]
pub enum Error {
    Io(io::Error),
    InvalidUrl(String),
    InvalidResponse(String),
    Timeout,
    ConnectionFailed(String),
    HttpError(u16, String),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Io(err) => write!(f, "IO error: {}", err),
            Error::InvalidUrl(msg) => write!(f, "Invalid URL: {}", msg),
            Error::InvalidResponse(msg) => write!(f, "Invalid response: {}", msg),
            Error::Timeout => write!(f, "Request timeout"),
            Error::ConnectionFailed(msg) => write!(f, "Connection failed: {}", msg),
            Error::HttpError(code, msg) => write!(f, "HTTP error {}: {}", code, msg),
        }
    }
}

impl std::error::Error for Error {}

impl From<io::Error> for Error {
    fn from(err: io::Error) -> Self {
        Error::Io(err)
    }
}