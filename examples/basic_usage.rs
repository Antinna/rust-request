use request::Client;
use std::collections::HashMap;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Create a client
    let client = Client::new();

    // Simple GET request
    println!("Making GET request...");
    let response = client
        .get("http://httpbin.org/get")
        .header("Accept", "application/json")
        .send()?;

    println!("Status: {} {}", response.status(), response.status_text());
    println!("Headers: {:#?}", response.headers());
    println!("Body: {}", response.text()?);

    // POST request with JSON body
    println!("\nMaking POST request...");
    let json_body = r#"{"name": "John", "age": 30}"#;
    let response = client
        .post("http://httpbin.org/post")
        .header("Content-Type", "application/json")
        .body(json_body)
        .send()?;

    println!("Status: {} {}", response.status(), response.status_text());
    println!("Response body: {}", response.text()?);

    // GET request with query parameters
    println!("\nMaking GET request with query params...");
    let response = client
        .get("http://httpbin.org/get")
        .query("param1", "value1")
        .query("param2", "value2")
        .send()?;

    println!("Status: {} {}", response.status(), response.status_text());
    println!("Response: {}", response.text()?);

    // Form POST request
    println!("\nMaking form POST request...");
    let mut form_data = HashMap::new();
    form_data.insert("username", "testuser");
    form_data.insert("password", "testpass");

    let response = client
        .post("http://httpbin.org/post")
        .form(&form_data)
        .send()?;

    println!("Status: {} {}", response.status(), response.status_text());
    println!("Response: {}", response.text()?);

    // Using the convenience functions
    println!("\nUsing convenience functions...");
    let response = request::get("http://httpbin.org/get")
        .header("User-Agent", "my-custom-agent")
        .send()?;

    println!("Status: {} {}", response.status(), response.status_text());

    Ok(())
}