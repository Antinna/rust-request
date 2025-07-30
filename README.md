# Request - A Reqwest-like HTTP Client

A simple HTTP client library built using only Rust's standard library, inspired by the popular `reqwest` crate.

## Features

- ✅ HTTP/1.1 support (HTTP only, no HTTPS yet)
- ✅ GET, POST, PUT, DELETE, HEAD, PATCH methods
- ✅ Custom headers
- ✅ Query parameters
- ✅ Request body support
- ✅ Form data encoding
- ✅ Response parsing
- ✅ Chunked transfer encoding support
- ✅ Timeout configuration
- ✅ Builder pattern API
- ❌ No third-party dependencies
- ❌ No async support (synchronous only)
- ❌ No HTTPS/TLS support
- ❌ No automatic JSON serialization/deserialization

## Quick Start

```rust
use request::Client;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let client = Client::new();
    
    // Simple GET request
    let response = client
        .get("http://httpbin.org/get")
        .send()?;
    
    println!("Status: {}", response.status());
    println!("Body: {}", response.text()?);
    
    Ok(())
}
```

## Usage Examples

### GET Request with Headers and Query Parameters

```rust
let response = client
    .get("http://httpbin.org/get")
    .header("Accept", "application/json")
    .header("User-Agent", "my-app/1.0")
    .query("param1", "value1")
    .query("param2", "value2")
    .send()?;
```

### POST Request with JSON Body

```rust
let json_body = r#"{"name": "John", "age": 30}"#;
let response = client
    .post("http://httpbin.org/post")
    .header("Content-Type", "application/json")
    .body(json_body)
    .send()?;
```

### POST Request with Form Data

```rust
use std::collections::HashMap;

let mut form_data = HashMap::new();
form_data.insert("username", "testuser");
form_data.insert("password", "testpass");

let response = client
    .post("http://httpbin.org/post")
    .form(&form_data)
    .send()?;
```

### Using Convenience Functions

```rust
// These create a default client internally
let response = request::get("http://httpbin.org/get").send()?;
let response = request::post("http://httpbin.org/post").body("data").send()?;
```

### Custom Client Configuration

```rust
use std::time::Duration;
use std::collections::HashMap;

let mut default_headers = HashMap::new();
default_headers.insert("User-Agent".to_string(), "my-app/1.0".to_string());

let client = Client::builder()
    .timeout(Duration::from_secs(10))
    .default_headers(default_headers)
    .build();
```

### Response Handling

```rust
let response = client.get("http://httpbin.org/get").send()?;

// Status information
println!("Status: {}", response.status());
println!("Status text: {}", response.status_text());
println!("Success: {}", response.is_success());

// Headers
if let Some(content_type) = response.header("content-type") {
    println!("Content-Type: {}", content_type);
}

// Body
let text = response.text()?;  // As UTF-8 string
let bytes = response.bytes(); // As raw bytes
```

## Running Examples

```bash
cargo run --example basic_usage
```

## Limitations

- **HTTP Only**: No HTTPS/TLS support (would require implementing TLS or using a TLS library)
- **Synchronous**: No async/await support
- **No JSON**: No automatic JSON serialization/deserialization (would require serde)
- **Basic Error Handling**: Limited error types and handling
- **No Redirects**: Doesn't automatically follow redirects
- **No Cookies**: No cookie jar support
- **No Compression**: No gzip/deflate support

## Architecture

The library is structured into several modules:

- `client.rs` - HTTP client and builder
- `request.rs` - Request building and execution
- `response.rs` - Response parsing and handling  
- `error.rs` - Error types and handling
- `lib.rs` - Public API and common types

The core HTTP implementation uses `std::net::TcpStream` for networking and manual HTTP/1.1 protocol handling.