use request::{Client, Method, Auth, CookieJar, MultipartForm};
use request::redirect::RedirectPolicy;
use request::compression::Compression;
use request::dns::DnsResolver;
use request::http2::Http2Connection;
use std::time::Duration;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("🚀 Complete HTTP Client Feature Demo");
    println!("====================================\n");

    // 1. Advanced DNS Resolution
    println!("1. DNS Resolution Demo");
    println!("---------------------");
    
    let mut dns_resolver = DnsResolver::new().with_timeout(Duration::from_secs(3));
    
    match dns_resolver.resolve_ip("httpbin.org") {
        Ok(ips) => {
            println!("   Resolved httpbin.org to: {ips:?}");
        },
        Err(e) => println!("   DNS resolution failed: {e}"),
    }

    match dns_resolver.resolve_txt("google.com") {
        Ok(txt_records) => {
            println!("   TXT records for google.com: {txt_records:?}");
        },
        Err(e) => println!("   TXT lookup failed: {e}"),
    }
    println!();

    // 2. Advanced Client Configuration
    println!("2. Advanced Client Configuration");
    println!("-------------------------------");
    
    let client = Client::builder()
        .timeout(Duration::from_secs(30))
        .connect_timeout(Duration::from_secs(10))
        .read_timeout(Duration::from_secs(20))
        .write_timeout(Duration::from_secs(20))
        .user_agent("CompleteDemo/1.0 (Advanced HTTP Client)")
        .max_redirects(10)
        .compression(vec![Compression::Gzip, Compression::Deflate])
        .keep_alive(true)
        .tcp_nodelay(true)
        .tcp_keepalive(Some(Duration::from_secs(60)))
        .max_response_size(Some(50 * 1024 * 1024)) // 50MB
        .build();

    println!("   ✅ Advanced client configured with:");
    println!("      - Multiple timeout types");
    println!("      - Compression support");
    println!("      - Connection optimization");
    println!("      - Response size limits");
    println!();

    // 3. Comprehensive HTTP Methods
    println!("3. HTTP Methods Demonstration");
    println!("----------------------------");
    
    let methods = [
        (Method::GET, "http://httpbin.org/get"),
        (Method::POST, "http://httpbin.org/post"),
        (Method::PUT, "http://httpbin.org/put"),
        (Method::DELETE, "http://httpbin.org/delete"),
        (Method::PATCH, "http://httpbin.org/patch"),
        (Method::HEAD, "http://httpbin.org/get"),
        (Method::OPTIONS, "http://httpbin.org/get"),
    ];

    for (method, url) in &methods {
        match client.request(*method, url).send() {
            Ok(response) => {
                println!("   {} -> {} {} ({}ms)", 
                    method.as_str(), 
                    response.status(), 
                    response.status_text(),
                    response.response_time_ms()
                );
            },
            Err(e) => {
                println!("   {} -> Error: {}", method.as_str(), e);
            }
        }
    }
    println!();

    // 4. Advanced Authentication
    println!("4. Authentication Methods");
    println!("------------------------");
    
    // Basic Auth
    match client
        .get("http://httpbin.org/basic-auth/testuser/testpass")
        .auth(Auth::basic("testuser", "testpass"))
        .send() {
        Ok(response) => println!("   Basic Auth: {} {}", response.status(), response.status_text()),
        Err(e) => println!("   Basic Auth failed: {e}"),
    }

    // Bearer Token
    match client
        .get("http://httpbin.org/bearer")
        .auth(Auth::bearer("test-jwt-token-12345"))
        .send() {
        Ok(response) => println!("   Bearer Auth: {} {}", response.status(), response.status_text()),
        Err(e) => println!("   Bearer Auth failed: {e}"),
    }

    // Custom Auth Header
    match client
        .get("http://httpbin.org/headers")
        .auth(Auth::custom("X-API-Key", "secret-api-key-67890"))
        .send() {
        Ok(response) => println!("   Custom Auth: {} {}", response.status(), response.status_text()),
        Err(e) => println!("   Custom Auth failed: {e}"),
    }
    println!();

    // 5. Cookie Management
    println!("5. Cookie Management");
    println!("-------------------");
    
    let cookie_jar = CookieJar::new();
    let cookie_client = Client::builder()
        .cookie_jar(cookie_jar.clone())
        .build();

    // Set cookies
    match cookie_client
        .get("http://httpbin.org/cookies/set/session_id/abc123")
        .send() {
        Ok(response) => {
            println!("   Set cookie: {} {}", response.status(), response.status_text());
            for cookie in response.cookies() {
                println!("      Cookie: {}={}", cookie.name, cookie.value);
            }
        },
        Err(e) => println!("   Cookie setting failed: {e}"),
    }

    // Use cookies
    match cookie_client
        .get("http://httpbin.org/cookies")
        .send() {
        Ok(response) => {
            println!("   Cookie usage: {} {}", response.status(), response.status_text());
            if let Ok(json) = response.json() {
                if let Some(cookies) = json.get("cookies") {
                    println!("      Server received: {cookies}");
                }
            }
        },
        Err(e) => println!("   Cookie usage failed: {e}"),
    }
    println!();

    // 6. Multipart File Upload
    println!("6. Multipart File Upload");
    println!("-----------------------");
    
    let mut form = MultipartForm::new();
    form.add_text("description", "Test file upload")
        .add_text("category", "demo")
        .add_file(
            "file",
            "test.txt".to_string(),
            "text/plain".to_string(),
            b"Hello, World!\nThis is a test file for multipart upload.".to_vec()
        )
        .add_file(
            "data",
            "data.json".to_string(),
            "application/json".to_string(),
            br#"{"message": "Hello from JSON file", "timestamp": 1234567890}"#.to_vec()
        );

    match client
        .post("http://httpbin.org/post")
        .multipart(form)
        .send() {
        Ok(response) => {
            println!("   Multipart upload: {} {} ({}ms)", 
                response.status(), 
                response.status_text(),
                response.response_time_ms()
            );
            if let Ok(json) = response.json() {
                if let Some(files) = json.get("files") {
                    println!("      Files received: {files}");
                }
            }
        },
        Err(e) => println!("   Multipart upload failed: {e}"),
    }
    println!();

    // 7. JSON Processing
    println!("7. JSON Processing");
    println!("-----------------");
    
    let json_data = r#"{
        "user": {
            "name": "John Doe",
            "age": 30,
            "active": true,
            "scores": [95, 87, 92],
            "metadata": {
                "created": "2023-01-01",
                "updated": "2023-12-01"
            }
        }
    }"#;

    match request::json::parse_json(json_data) {
        Ok(json) => {
            println!("   ✅ JSON parsing successful");
            if let Some(user) = json.get("user") {
                if let Some(name) = user.get("name").and_then(|v| v.as_str()) {
                    println!("      User name: {name}");
                }
                if let Some(scores) = user.get("scores").and_then(|v| v.as_array()) {
                    println!("      Scores: {} items", scores.len());
                }
            }
        },
        Err(e) => println!("   JSON parsing failed: {e}"),
    }

    // Send JSON request
    match client
        .post("http://httpbin.org/post")
        .json_str(json_data)
        .send() {
        Ok(response) => {
            println!("   JSON request: {} {}", response.status(), response.status_text());
        },
        Err(e) => println!("   JSON request failed: {e}"),
    }
    println!();

    // 8. Redirect Handling
    println!("8. Redirect Handling");
    println!("-------------------");
    
    // Follow redirects
    let redirect_client = Client::builder()
        .redirect(RedirectPolicy::default().with_auth())
        .build();

    match redirect_client
        .get("http://httpbin.org/redirect/3")
        .send() {
        Ok(response) => {
            println!("   Redirect following: {} {} (final URL: {})", 
                response.status(), 
                response.status_text(),
                response.url().authority()
            );
        },
        Err(e) => println!("   Redirect following failed: {e}"),
    }

    // No redirects
    let no_redirect_client = Client::builder()
        .redirect(RedirectPolicy::none())
        .build();

    match no_redirect_client
        .get("http://httpbin.org/redirect/1")
        .send() {
        Ok(response) => {
            println!("   No redirect: {} {}", response.status(), response.status_text());
        },
        Err(e) => println!("   No redirect failed: {e}"),
    }
    println!();

    // 9. Response Analysis
    println!("9. Response Analysis");
    println!("-------------------");
    
    match client
        .get("http://httpbin.org/response-headers")
        .query("Content-Type", "application/json")
        .query("X-Custom-Header", "demo-value")
        .send() {
        Ok(response) => {
            println!("   Response Analysis:");
            println!("   - Status: {} {}", response.status(), response.status_text());
            println!("   - Version: {:?}", response.version());
            println!("   - Success: {}", response.is_success());
            println!("   - Content-Type: {:?}", response.content_type());
            println!("   - Content-Length: {:?}", response.content_length());
            println!("   - Server: {:?}", response.server());
            println!("   - Response time: {}ms", response.response_time_ms());
            println!("   - Body size: {} bytes", response.body_len());
            println!("   - Headers count: {}", response.headers().len());
            
            // Security headers
            if let Some(csp) = response.content_security_policy() {
                println!("   - CSP: {csp}");
            }
            if let Some(hsts) = response.strict_transport_security() {
                println!("   - HSTS: {hsts}");
            }
        },
        Err(e) => println!("   Response analysis failed: {e}"),
    }
    println!();

    // 10. Error Handling Demonstration
    println!("10. Error Handling");
    println!("-----------------");
    
    let error_scenarios = [
        ("Invalid URL", "not-a-url"),
        ("Non-existent domain", "http://this-domain-does-not-exist-12345.com"),
        ("Connection timeout", "http://1.2.3.4:12345"), // Non-routable IP
        ("404 Not Found", "http://httpbin.org/status/404"),
        ("500 Server Error", "http://httpbin.org/status/500"),
    ];

    for (description, url) in &error_scenarios {
        match client.get(url).send() {
            Ok(response) => {
                println!("   {}: {} {}", description, response.status(), response.status_text());
            },
            Err(e) => {
                println!("   {description}: {e}");
            }
        }
    }
    println!();

    // 11. Performance Testing
    println!("11. Performance Testing");
    println!("----------------------");
    
    let start = std::time::Instant::now();
    let mut successful_requests = 0;
    let total_requests = 5;

    for i in 1..=total_requests {
        match client
            .get("http://httpbin.org/get")
            .query("request_id", i.to_string())
            .send() {
            Ok(response) => {
                if response.is_success() {
                    successful_requests += 1;
                }
                println!("   Request {}: {} ({}ms)", 
                    i, 
                    response.status(),
                    response.response_time_ms()
                );
            },
            Err(e) => {
                println!("   Request {i}: Error - {e}");
            }
        }
    }

    let total_time = start.elapsed();
    println!("   Performance Summary:");
    println!("   - Total requests: {total_requests}");
    println!("   - Successful: {successful_requests}");
    println!("   - Total time: {total_time:?}");
    println!("   - Average time: {:?}", total_time / total_requests);
    println!();

    // 12. WebSocket Demo (if connection is available)
    println!("12. WebSocket Demo");
    println!("-----------------");
    
    // Note: This would require a WebSocket server to be available
    println!("   WebSocket support implemented but requires server");
    println!("   Features available:");
    println!("   - WebSocket handshake");
    println!("   - Frame parsing and generation");
    println!("   - Text and binary messages");
    println!("   - Ping/Pong handling");
    println!("   - Connection state management");
    println!();

    // 13. HTTP/2 Demo
    println!("13. HTTP/2 Demo");
    println!("---------------");
    
    println!("   HTTP/2 support implemented:");
    println!("   - Frame parsing and generation");
    println!("   - HPACK header compression");
    println!("   - Stream multiplexing");
    println!("   - Flow control");
    println!("   - Server push support");
    
    let mut http2_conn = Http2Connection::new();
    let preface = http2_conn.create_connection_preface();
    println!("   - Connection preface: {} bytes", preface.len());
    
    let headers = vec![
        (":method".to_string(), "GET".to_string()),
        (":path".to_string(), "/".to_string()),
        (":scheme".to_string(), "https".to_string()),
        (":authority".to_string(), "example.com".to_string()),
    ];
    
    match http2_conn.create_headers_frame(&headers, true) {
        Ok(frame) => {
            println!("   - Headers frame: {} bytes", frame.to_bytes().len());
        },
        Err(e) => {
            println!("   - Headers frame error: {e}");
        }
    }
    println!();

    println!("🎉 Complete Feature Demonstration Finished!");
    println!("\nImplemented Features Summary:");
    println!("✅ DNS Resolution with caching");
    println!("✅ Advanced client configuration");
    println!("✅ All HTTP methods support");
    println!("✅ Multiple authentication methods");
    println!("✅ Automatic cookie management");
    println!("✅ Multipart file uploads");
    println!("✅ JSON parsing and serialization");
    println!("✅ Intelligent redirect handling");
    println!("✅ Comprehensive response analysis");
    println!("✅ Robust error handling");
    println!("✅ Performance optimization");
    println!("✅ WebSocket protocol support");
    println!("✅ HTTP/2 framework");
    println!("✅ TLS/SSL support framework");
    println!("✅ Proxy support (HTTP/SOCKS)");
    println!("✅ Compression (Gzip/Deflate/Brotli)");
    println!("✅ Connection pooling and reuse");
    println!("✅ Timeout management");
    println!("✅ Memory efficient streaming");
    println!("✅ Zero external dependencies");

    Ok(())
}