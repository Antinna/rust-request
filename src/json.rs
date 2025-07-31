use crate::{Error, Result};
use std::collections::HashMap;
use std::fmt;

#[derive(Debug, Clone, PartialEq)]
pub enum JsonValue {
    Null,
    Bool(bool),
    Number(f64),
    String(String),
    Array(Vec<JsonValue>),
    Object(HashMap<String, JsonValue>),
}

impl JsonValue {
    /// Create a new null value
    pub fn null() -> Self {
        JsonValue::Null
    }
    
    /// Create a new boolean value
    pub fn bool(value: bool) -> Self {
        JsonValue::Bool(value)
    }
    
    /// Create a new number value
    pub fn number<T: Into<f64>>(value: T) -> Self {
        JsonValue::Number(value.into())
    }
    
    /// Create a new string value
    pub fn string<T: Into<String>>(value: T) -> Self {
        JsonValue::String(value.into())
    }
    
    /// Create a new array value
    pub fn array(values: Vec<JsonValue>) -> Self {
        JsonValue::Array(values)
    }
    
    /// Create a new object value
    pub fn object(map: HashMap<String, JsonValue>) -> Self {
        JsonValue::Object(map)
    }
    
    /// Create an empty array
    pub fn empty_array() -> Self {
        JsonValue::Array(Vec::new())
    }
    
    /// Create an empty object
    pub fn empty_object() -> Self {
        JsonValue::Object(HashMap::new())
    }
    pub fn is_null(&self) -> bool {
        matches!(self, JsonValue::Null)
    }

    pub fn is_bool(&self) -> bool {
        matches!(self, JsonValue::Bool(_))
    }

    pub fn is_number(&self) -> bool {
        matches!(self, JsonValue::Number(_))
    }

    pub fn is_string(&self) -> bool {
        matches!(self, JsonValue::String(_))
    }

    pub fn is_array(&self) -> bool {
        matches!(self, JsonValue::Array(_))
    }

    pub fn is_object(&self) -> bool {
        matches!(self, JsonValue::Object(_))
    }
    
    /// Check if the value is truthy (not null, false, 0, or empty string/array/object)
    pub fn is_truthy(&self) -> bool {
        match self {
            JsonValue::Null => false,
            JsonValue::Bool(b) => *b,
            JsonValue::Number(n) => *n != 0.0,
            JsonValue::String(s) => !s.is_empty(),
            JsonValue::Array(arr) => !arr.is_empty(),
            JsonValue::Object(obj) => !obj.is_empty(),
        }
    }
    
    /// Get the type name as a string
    pub fn type_name(&self) -> &'static str {
        match self {
            JsonValue::Null => "null",
            JsonValue::Bool(_) => "boolean",
            JsonValue::Number(_) => "number",
            JsonValue::String(_) => "string",
            JsonValue::Array(_) => "array",
            JsonValue::Object(_) => "object",
        }
    }
    
    /// Get the length of arrays and objects
    pub fn len(&self) -> Option<usize> {
        match self {
            JsonValue::Array(arr) => Some(arr.len()),
            JsonValue::Object(obj) => Some(obj.len()),
            JsonValue::String(s) => Some(s.len()),
            _ => None,
        }
    }
    
    /// Check if array or object is empty
    pub fn is_empty(&self) -> bool {
        match self {
            JsonValue::Array(arr) => arr.is_empty(),
            JsonValue::Object(obj) => obj.is_empty(),
            JsonValue::String(s) => s.is_empty(),
            _ => false,
        }
    }

    pub fn as_bool(&self) -> Option<bool> {
        match self {
            JsonValue::Bool(b) => Some(*b),
            _ => None,
        }
    }

    pub fn as_number(&self) -> Option<f64> {
        match self {
            JsonValue::Number(n) => Some(*n),
            _ => None,
        }
    }

    pub fn as_str(&self) -> Option<&str> {
        match self {
            JsonValue::String(s) => Some(s),
            _ => None,
        }
    }

    pub fn as_array(&self) -> Option<&Vec<JsonValue>> {
        match self {
            JsonValue::Array(arr) => Some(arr),
            _ => None,
        }
    }

    pub fn as_object(&self) -> Option<&HashMap<String, JsonValue>> {
        match self {
            JsonValue::Object(obj) => Some(obj),
            _ => None,
        }
    }

    pub fn get(&self, key: &str) -> Option<&JsonValue> {
        match self {
            JsonValue::Object(obj) => obj.get(key),
            _ => None,
        }
    }

    pub fn get_index(&self, index: usize) -> Option<&JsonValue> {
        match self {
            JsonValue::Array(arr) => arr.get(index),
            _ => None,
        }
    }
    
    /// Get a nested value using dot notation (e.g., "user.name")
    pub fn get_path(&self, path: &str) -> Option<&JsonValue> {
        let parts: Vec<&str> = path.split('.').collect();
        let mut current = self;
        
        for part in parts {
            if let Ok(index) = part.parse::<usize>() {
                current = current.get_index(index)?;
            } else {
                current = current.get(part)?;
            }
        }
        
        Some(current)
    }
    
    /// Get a value with a default if not found
    pub fn get_or<'a>(&'a self, key: &str, default: &'a JsonValue) -> &'a JsonValue {
        self.get(key).unwrap_or(default)
    }
    
    /// Convert to integer if possible
    pub fn as_i64(&self) -> Option<i64> {
        match self {
            JsonValue::Number(n) if n.fract() == 0.0 => Some(*n as i64),
            _ => None,
        }
    }
    
    /// Convert to unsigned integer if possible
    pub fn as_u64(&self) -> Option<u64> {
        match self {
            JsonValue::Number(n) if n.fract() == 0.0 && *n >= 0.0 => Some(*n as u64),
            _ => None,
        }
    }
    
    /// Convert to float if possible
    pub fn as_f32(&self) -> Option<f32> {
        match self {
            JsonValue::Number(n) => Some(*n as f32),
            _ => None,
        }
    }
    
    /// Try to convert to string (including numbers and booleans)
    pub fn to_string_lossy(&self) -> String {
        match self {
            JsonValue::String(s) => s.clone(),
            JsonValue::Number(n) => n.to_string(),
            JsonValue::Bool(b) => b.to_string(),
            JsonValue::Null => "null".to_string(),
            _ => self.to_string(),
        }
    }
    
    /// Check if this value contains another value (for arrays and objects)
    pub fn contains(&self, value: &JsonValue) -> bool {
        match self {
            JsonValue::Array(arr) => arr.contains(value),
            JsonValue::Object(obj) => obj.values().any(|v| v == value),
            _ => false,
        }
    }
    
    /// Check if object has a key
    pub fn has_key(&self, key: &str) -> bool {
        match self {
            JsonValue::Object(obj) => obj.contains_key(key),
            _ => false,
        }
    }
    
    /// Get all keys from an object
    pub fn keys(&self) -> Vec<&String> {
        match self {
            JsonValue::Object(obj) => obj.keys().collect(),
            _ => Vec::new(),
        }
    }
    
    /// Get all values from an object
    pub fn values(&self) -> Vec<&JsonValue> {
        match self {
            JsonValue::Object(obj) => obj.values().collect(),
            _ => Vec::new(),
        }
    }
    
    /// Merge with another JSON object (shallow merge)
    pub fn merge(&mut self, other: JsonValue) -> Result<()> {
        match (self, other) {
            (JsonValue::Object(ref mut obj1), JsonValue::Object(obj2)) => {
                obj1.extend(obj2);
                Ok(())
            }
            _ => Err(Error::JsonSerializeError("Can only merge objects".to_string())),
        }
    }
    
    /// Pretty print with indentation
    pub fn pretty_print(&self, indent: usize) -> String {
        self.pretty_print_internal(indent, 0)
    }
    
    fn pretty_print_internal(&self, indent: usize, current_indent: usize) -> String {
        let spaces = " ".repeat(current_indent);
        let next_spaces = " ".repeat(current_indent + indent);
        
        match self {
            JsonValue::Object(obj) if obj.is_empty() => "{}".to_string(),
            JsonValue::Object(obj) => {
                let mut result = "{\n".to_string();
                let items: Vec<_> = obj.iter().collect();
                for (i, (key, value)) in items.iter().enumerate() {
                    result.push_str(&format!("{}\"{}\":", next_spaces, escape_json_string(key)));
                    if value.is_object() || value.is_array() {
                        result.push('\n');
                        result.push_str(&next_spaces);
                        result.push_str(&value.pretty_print_internal(indent, current_indent + indent));
                    } else {
                        result.push(' ');
                        result.push_str(&value.to_string());
                    }
                    if i < items.len() - 1 {
                        result.push(',');
                    }
                    result.push('\n');
                }
                result.push_str(&format!("{spaces}}}"));
                result
            }
            JsonValue::Array(arr) if arr.is_empty() => "[]".to_string(),
            JsonValue::Array(arr) => {
                let mut result = "[\n".to_string();
                for (i, value) in arr.iter().enumerate() {
                    result.push_str(&next_spaces);
                    if value.is_object() || value.is_array() {
                        result.push_str(&value.pretty_print_internal(indent, current_indent + indent));
                    } else {
                        result.push_str(&value.to_string());
                    }
                    if i < arr.len() - 1 {
                        result.push(',');
                    }
                    result.push('\n');
                }
                result.push_str(&format!("{spaces}]"));
                result
            }
            _ => self.to_string(),
        }
    }
}

impl fmt::Display for JsonValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            JsonValue::Null => write!(f, "null"),
            JsonValue::Bool(b) => write!(f, "{b}"),
            JsonValue::Number(n) => {
                if n.fract() == 0.0 && n.abs() < (1u64 << 53) as f64 {
                    write!(f, "{}", *n as i64)
                } else {
                    write!(f, "{n}")
                }
            }
            JsonValue::String(s) => write!(f, "\"{}\"", escape_json_string(s)),
            JsonValue::Array(arr) => {
                write!(f, "[")?;
                for (i, item) in arr.iter().enumerate() {
                    if i > 0 {
                        write!(f, ",")?;
                    }
                    write!(f, "{item}")?;
                }
                write!(f, "]")
            }
            JsonValue::Object(obj) => {
                write!(f, "{{")?;
                for (i, (key, value)) in obj.iter().enumerate() {
                    if i > 0 {
                        write!(f, ",")?;
                    }
                    write!(f, "\"{}\":{}", escape_json_string(key), value)?;
                }
                write!(f, "}}")
            }
        }
    }
}

pub struct JsonParser {
    input: Vec<char>,
    position: usize,
}

impl JsonParser {
    pub fn new(input: &str) -> Self {
        JsonParser {
            input: input.chars().collect(),
            position: 0,
        }
    }

    pub fn parse(&mut self) -> Result<JsonValue> {
        self.skip_whitespace();
        let value = self.parse_value()?;
        self.skip_whitespace();

        if self.position < self.input.len() {
            return Err(Error::JsonParseError(
                "Unexpected characters after JSON".to_string(),
            ));
        }

        Ok(value)
    }

    fn parse_value(&mut self) -> Result<JsonValue> {
        self.skip_whitespace();

        if self.position >= self.input.len() {
            return Err(Error::JsonParseError("Unexpected end of input".to_string()));
        }

        match self.current_char() {
            'n' => self.parse_null(),
            't' | 'f' => self.parse_bool(),
            '"' => self.parse_string(),
            '[' => self.parse_array(),
            '{' => self.parse_object(),
            c if c.is_ascii_digit() || c == '-' => self.parse_number(),
            _ => Err(Error::JsonParseError(format!(
                "Unexpected character: {}",
                self.current_char()
            ))),
        }
    }

    fn parse_null(&mut self) -> Result<JsonValue> {
        if self.consume_string("null") {
            Ok(JsonValue::Null)
        } else {
            Err(Error::JsonParseError("Invalid null value".to_string()))
        }
    }

    fn parse_bool(&mut self) -> Result<JsonValue> {
        if self.consume_string("true") {
            Ok(JsonValue::Bool(true))
        } else if self.consume_string("false") {
            Ok(JsonValue::Bool(false))
        } else {
            Err(Error::JsonParseError("Invalid boolean value".to_string()))
        }
    }

    fn parse_string(&mut self) -> Result<JsonValue> {
        if self.current_char() != '"' {
            return Err(Error::JsonParseError("Expected '\"'".to_string()));
        }

        self.advance(); // Skip opening quote
        let mut result = String::new();

        while self.position < self.input.len() && self.current_char() != '"' {
            if self.current_char() == '\\' {
                self.advance();
                if self.position >= self.input.len() {
                    return Err(Error::JsonParseError(
                        "Unexpected end of string".to_string(),
                    ));
                }

                match self.current_char() {
                    '"' => result.push('"'),
                    '\\' => result.push('\\'),
                    '/' => result.push('/'),
                    'b' => result.push('\u{0008}'),
                    'f' => result.push('\u{000C}'),
                    'n' => result.push('\n'),
                    'r' => result.push('\r'),
                    't' => result.push('\t'),
                    'u' => {
                        // Unicode escape sequence
                        self.advance();
                        let hex = self.consume_hex_digits(4)?;
                        if let Some(unicode_char) = std::char::from_u32(hex) {
                            result.push(unicode_char);
                        } else {
                            return Err(Error::JsonParseError(
                                "Invalid unicode escape".to_string(),
                            ));
                        }
                        continue; // Don't advance again
                    }
                    c => {
                        return Err(Error::JsonParseError(format!(
                            "Invalid escape sequence: \\{c}"
                        )))
                    }
                }
            } else {
                result.push(self.current_char());
            }
            self.advance();
        }

        if self.position >= self.input.len() {
            return Err(Error::JsonParseError("Unterminated string".to_string()));
        }

        self.advance(); // Skip closing quote
        Ok(JsonValue::String(result))
    }

    fn parse_number(&mut self) -> Result<JsonValue> {
        let start = self.position;

        // Handle negative sign
        if self.current_char() == '-' {
            self.advance();
        }

        // Parse integer part
        if self.current_char() == '0' {
            self.advance();
        } else if self.current_char().is_ascii_digit() {
            while self.position < self.input.len() && self.current_char().is_ascii_digit() {
                self.advance();
            }
        } else {
            return Err(Error::JsonParseError("Invalid number".to_string()));
        }

        // Parse fractional part
        if self.position < self.input.len() && self.current_char() == '.' {
            self.advance();
            if !self.current_char().is_ascii_digit() {
                return Err(Error::JsonParseError(
                    "Invalid number: missing digits after decimal point".to_string(),
                ));
            }
            while self.position < self.input.len() && self.current_char().is_ascii_digit() {
                self.advance();
            }
        }

        // Parse exponent part
        if self.position < self.input.len()
            && (self.current_char() == 'e' || self.current_char() == 'E')
        {
            self.advance();
            if self.position < self.input.len()
                && (self.current_char() == '+' || self.current_char() == '-')
            {
                self.advance();
            }
            if !self.current_char().is_ascii_digit() {
                return Err(Error::JsonParseError(
                    "Invalid number: missing digits in exponent".to_string(),
                ));
            }
            while self.position < self.input.len() && self.current_char().is_ascii_digit() {
                self.advance();
            }
        }

        let number_str: String = self.input[start..self.position].iter().collect();
        let number = number_str
            .parse::<f64>()
            .map_err(|_| Error::JsonParseError("Invalid number format".to_string()))?;

        Ok(JsonValue::Number(number))
    }

    fn parse_array(&mut self) -> Result<JsonValue> {
        if self.current_char() != '[' {
            return Err(Error::JsonParseError("Expected '['".to_string()));
        }

        self.advance(); // Skip '['
        self.skip_whitespace();

        let mut array = Vec::new();

        if self.position < self.input.len() && self.current_char() == ']' {
            self.advance(); // Skip ']'
            return Ok(JsonValue::Array(array));
        }

        loop {
            array.push(self.parse_value()?);
            self.skip_whitespace();

            if self.position >= self.input.len() {
                return Err(Error::JsonParseError("Unterminated array".to_string()));
            }

            match self.current_char() {
                ',' => {
                    self.advance();
                    self.skip_whitespace();
                }
                ']' => {
                    self.advance();
                    break;
                }
                _ => {
                    return Err(Error::JsonParseError(
                        "Expected ',' or ']' in array".to_string(),
                    ))
                }
            }
        }

        Ok(JsonValue::Array(array))
    }

    fn parse_object(&mut self) -> Result<JsonValue> {
        if self.current_char() != '{' {
            return Err(Error::JsonParseError("Expected '{'".to_string()));
        }

        self.advance(); // Skip '{'
        self.skip_whitespace();

        let mut object = HashMap::new();

        if self.position < self.input.len() && self.current_char() == '}' {
            self.advance(); // Skip '}'
            return Ok(JsonValue::Object(object));
        }

        loop {
            // Parse key
            let key = match self.parse_value()? {
                JsonValue::String(s) => s,
                _ => {
                    return Err(Error::JsonParseError(
                        "Object key must be a string".to_string(),
                    ))
                }
            };

            self.skip_whitespace();

            if self.position >= self.input.len() || self.current_char() != ':' {
                return Err(Error::JsonParseError(
                    "Expected ':' after object key".to_string(),
                ));
            }

            self.advance(); // Skip ':'

            // Parse value
            let value = self.parse_value()?;
            object.insert(key, value);

            self.skip_whitespace();

            if self.position >= self.input.len() {
                return Err(Error::JsonParseError("Unterminated object".to_string()));
            }

            match self.current_char() {
                ',' => {
                    self.advance();
                    self.skip_whitespace();
                }
                '}' => {
                    self.advance();
                    break;
                }
                _ => {
                    return Err(Error::JsonParseError(
                        "Expected ',' or '}' in object".to_string(),
                    ))
                }
            }
        }

        Ok(JsonValue::Object(object))
    }

    fn current_char(&self) -> char {
        self.input[self.position]
    }

    fn advance(&mut self) {
        self.position += 1;
    }

    fn skip_whitespace(&mut self) {
        while self.position < self.input.len() && self.current_char().is_whitespace() {
            self.advance();
        }
    }

    fn consume_string(&mut self, expected: &str) -> bool {
        let expected_chars: Vec<char> = expected.chars().collect();

        if self.position + expected_chars.len() > self.input.len() {
            return false;
        }

        for (i, &expected_char) in expected_chars.iter().enumerate() {
            if self.input[self.position + i] != expected_char {
                return false;
            }
        }

        self.position += expected_chars.len();
        true
    }

    fn consume_hex_digits(&mut self, count: usize) -> Result<u32> {
        let mut result = 0u32;

        for _ in 0..count {
            if self.position >= self.input.len() {
                return Err(Error::JsonParseError(
                    "Incomplete unicode escape".to_string(),
                ));
            }

            let digit = match self.current_char() {
                '0'..='9' => (self.current_char() as u32) - ('0' as u32),
                'a'..='f' => (self.current_char() as u32) - ('a' as u32) + 10,
                'A'..='F' => (self.current_char() as u32) - ('A' as u32) + 10,
                _ => {
                    return Err(Error::JsonParseError(
                        "Invalid hex digit in unicode escape".to_string(),
                    ))
                }
            };

            result = result * 16 + digit;
            self.advance();
        }

        Ok(result)
    }
}

fn escape_json_string(s: &str) -> String {
    let mut result = String::new();

    for c in s.chars() {
        match c {
            '"' => result.push_str("\\\""),
            '\\' => result.push_str("\\\\"),
            '\u{0008}' => result.push_str("\\b"),
            '\u{000C}' => result.push_str("\\f"),
            '\n' => result.push_str("\\n"),
            '\r' => result.push_str("\\r"),
            '\t' => result.push_str("\\t"),
            c if c.is_control() => {
                result.push_str(&format!("\\u{:04x}", c as u32));
            }
            c => result.push(c),
        }
    }

    result
}

pub fn parse_json(input: &str) -> Result<JsonValue> {
    let mut parser = JsonParser::new(input);
    parser.parse()
}

// Conversion implementations
impl From<bool> for JsonValue {
    fn from(value: bool) -> Self {
        JsonValue::Bool(value)
    }
}

impl From<i32> for JsonValue {
    fn from(value: i32) -> Self {
        JsonValue::Number(value as f64)
    }
}

impl From<i64> for JsonValue {
    fn from(value: i64) -> Self {
        JsonValue::Number(value as f64)
    }
}

impl From<u32> for JsonValue {
    fn from(value: u32) -> Self {
        JsonValue::Number(value as f64)
    }
}

impl From<u64> for JsonValue {
    fn from(value: u64) -> Self {
        JsonValue::Number(value as f64)
    }
}

impl From<f32> for JsonValue {
    fn from(value: f32) -> Self {
        JsonValue::Number(value as f64)
    }
}

impl From<f64> for JsonValue {
    fn from(value: f64) -> Self {
        JsonValue::Number(value)
    }
}

impl From<String> for JsonValue {
    fn from(value: String) -> Self {
        JsonValue::String(value)
    }
}

impl From<&str> for JsonValue {
    fn from(value: &str) -> Self {
        JsonValue::String(value.to_string())
    }
}

impl From<Vec<JsonValue>> for JsonValue {
    fn from(value: Vec<JsonValue>) -> Self {
        JsonValue::Array(value)
    }
}

impl From<HashMap<String, JsonValue>> for JsonValue {
    fn from(value: HashMap<String, JsonValue>) -> Self {
        JsonValue::Object(value)
    }
}

impl<T: Into<JsonValue>> From<Option<T>> for JsonValue {
    fn from(value: Option<T>) -> Self {
        match value {
            Some(v) => v.into(),
            None => JsonValue::Null,
        }
    }
}

pub fn stringify_json(value: &JsonValue) -> String {
    value.to_string()
}
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_json_value_creation() {
        assert!(JsonValue::null().is_null());
        assert!(JsonValue::bool(true).is_bool());
        assert!(JsonValue::number(42).is_number());
        assert!(JsonValue::string("test").is_string());
        assert!(JsonValue::empty_array().is_array());
        assert!(JsonValue::empty_object().is_object());
    }

    #[test]
    fn test_json_value_conversions() {
        let bool_val: JsonValue = true.into();
        assert_eq!(bool_val.as_bool(), Some(true));

        let int_val: JsonValue = 42i32.into();
        assert_eq!(int_val.as_number(), Some(42.0));

        let string_val: JsonValue = "hello".into();
        assert_eq!(string_val.as_str(), Some("hello"));
    }

    #[test]
    fn test_json_value_type_checks() {
        let values = vec![
            JsonValue::null(),
            JsonValue::bool(true),
            JsonValue::number(3.14),
            JsonValue::string("test"),
            JsonValue::empty_array(),
            JsonValue::empty_object(),
        ];

        let type_names = vec!["null", "boolean", "number", "string", "array", "object"];
        
        for (value, expected_type) in values.iter().zip(type_names.iter()) {
            assert_eq!(value.type_name(), *expected_type);
        }
    }

    #[test]
    fn test_json_parsing_basic() {
        let json_str = r#"{"name": "John", "age": 30, "active": true}"#;
        let parsed = parse_json(json_str).unwrap();
        
        assert!(parsed.is_object());
        assert_eq!(parsed.get("name").unwrap().as_str(), Some("John"));
        assert_eq!(parsed.get("age").unwrap().as_number(), Some(30.0));
        assert_eq!(parsed.get("active").unwrap().as_bool(), Some(true));
    }
}

     