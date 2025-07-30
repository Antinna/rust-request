use crate::{Result, Error};
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
            },
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
            },
            JsonValue::Object(obj) => {
                write!(f, "{{")?;
                for (i, (key, value)) in obj.iter().enumerate() {
                    if i > 0 {
                        write!(f, ",")?;
                    }
                    write!(f, "\"{}\":{}", escape_json_string(key), value)?;
                }
                write!(f, "}}")
            },
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
            return Err(Error::JsonParseError("Unexpected characters after JSON".to_string()));
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
            _ => Err(Error::JsonParseError(format!("Unexpected character: {}", self.current_char()))),
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
                    return Err(Error::JsonParseError("Unexpected end of string".to_string()));
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
                            return Err(Error::JsonParseError("Invalid unicode escape".to_string()));
                        }
                        continue; // Don't advance again
                    },
                    c => return Err(Error::JsonParseError(format!("Invalid escape sequence: \\{c}"))),
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
                return Err(Error::JsonParseError("Invalid number: missing digits after decimal point".to_string()));
            }
            while self.position < self.input.len() && self.current_char().is_ascii_digit() {
                self.advance();
            }
        }
        
        // Parse exponent part
        if self.position < self.input.len() && (self.current_char() == 'e' || self.current_char() == 'E') {
            self.advance();
            if self.position < self.input.len() && (self.current_char() == '+' || self.current_char() == '-') {
                self.advance();
            }
            if !self.current_char().is_ascii_digit() {
                return Err(Error::JsonParseError("Invalid number: missing digits in exponent".to_string()));
            }
            while self.position < self.input.len() && self.current_char().is_ascii_digit() {
                self.advance();
            }
        }
        
        let number_str: String = self.input[start..self.position].iter().collect();
        let number = number_str.parse::<f64>()
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
                },
                ']' => {
                    self.advance();
                    break;
                },
                _ => return Err(Error::JsonParseError("Expected ',' or ']' in array".to_string())),
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
                _ => return Err(Error::JsonParseError("Object key must be a string".to_string())),
            };
            
            self.skip_whitespace();
            
            if self.position >= self.input.len() || self.current_char() != ':' {
                return Err(Error::JsonParseError("Expected ':' after object key".to_string()));
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
                },
                '}' => {
                    self.advance();
                    break;
                },
                _ => return Err(Error::JsonParseError("Expected ',' or '}' in object".to_string())),
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
                return Err(Error::JsonParseError("Incomplete unicode escape".to_string()));
            }
            
            let digit = match self.current_char() {
                '0'..='9' => (self.current_char() as u32) - ('0' as u32),
                'a'..='f' => (self.current_char() as u32) - ('a' as u32) + 10,
                'A'..='F' => (self.current_char() as u32) - ('A' as u32) + 10,
                _ => return Err(Error::JsonParseError("Invalid hex digit in unicode escape".to_string())),
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
            },
            c => result.push(c),
        }
    }
    
    result
}

pub fn parse_json(input: &str) -> Result<JsonValue> {
    let mut parser = JsonParser::new(input);
    parser.parse()
}

pub fn stringify_json(value: &JsonValue) -> String {
    value.to_string()
}