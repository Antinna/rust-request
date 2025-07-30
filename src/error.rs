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
    TlsError(String),
    ProxyError(String),
    AuthenticationError(String),
    CompressionError(String),
    JsonParseError(String),
    JsonSerializeError(String),
    TooManyRedirects(usize),
    RedirectLoop,
    InvalidHeader(String),
    InvalidCookie(String),
    MultipartError(String),
    EncodingError(String),
    CertificateError(String),
    HostnameVerificationError(String),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Io(err) => write!(f, "IO error: {err}"),
            Error::InvalidUrl(msg) => write!(f, "Invalid URL: {msg}"),
            Error::InvalidResponse(msg) => write!(f, "Invalid response: {msg}"),
            Error::Timeout => write!(f, "Request timeout"),
            Error::ConnectionFailed(msg) => write!(f, "Connection failed: {msg}"),
            Error::HttpError(code, msg) => write!(f, "HTTP error {code}: {msg}"),
            Error::TlsError(msg) => write!(f, "TLS error: {msg}"),
            Error::ProxyError(msg) => write!(f, "Proxy error: {msg}"),
            Error::AuthenticationError(msg) => write!(f, "Authentication error: {msg}"),
            Error::CompressionError(msg) => write!(f, "Compression error: {msg}"),
            Error::JsonParseError(msg) => write!(f, "JSON parse error: {msg}"),
            Error::JsonSerializeError(msg) => write!(f, "JSON serialize error: {msg}"),
            Error::TooManyRedirects(count) => write!(f, "Too many redirects: {count}"),
            Error::RedirectLoop => write!(f, "Redirect loop detected"),
            Error::InvalidHeader(msg) => write!(f, "Invalid header: {msg}"),
            Error::InvalidCookie(msg) => write!(f, "Invalid cookie: {msg}"),
            Error::MultipartError(msg) => write!(f, "Multipart error: {msg}"),
            Error::EncodingError(msg) => write!(f, "Encoding error: {msg}"),
            Error::CertificateError(msg) => write!(f, "Certificate error: {msg}"),
            Error::HostnameVerificationError(msg) => write!(f, "Hostname verification error: {msg}"),
        }
    }
}

impl std::error::Error for Error {}

impl From<io::Error> for Error {
    fn from(err: io::Error) -> Self {
        Error::Io(err)
    }
}