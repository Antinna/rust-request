use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Debug, Clone)]
pub struct Cookie {
    pub name: String,
    pub value: String,
    pub domain: Option<String>,
    pub path: Option<String>,
    pub expires: Option<u64>,
    pub max_age: Option<u64>,
    pub secure: bool,
    pub http_only: bool,
    pub same_site: Option<SameSite>,
}

#[derive(Debug, Clone, PartialEq)]
pub enum SameSite {
    Strict,
    Lax,
    None,
}

impl Cookie {
    pub fn new(name: String, value: String) -> Self {
        Cookie {
            name,
            value,
            domain: None,
            path: None,
            expires: None,
            max_age: None,
            secure: false,
            http_only: false,
            same_site: None,
        }
    }

    pub fn parse(cookie_str: &str) -> Option<Self> {
        let parts: Vec<&str> = cookie_str.split(';').collect();
        if parts.is_empty() {
            return None;
        }

        // Parse name=value
        let name_value = parts[0].trim();
        let (name, value) = if let Some(pos) = name_value.find('=') {
            let name = name_value[..pos].trim().to_string();
            let value = name_value[pos + 1..].trim().to_string();
            (name, value)
        } else {
            return None;
        };

        let mut cookie = Cookie::new(name, value);

        // Parse attributes
        for part in parts.iter().skip(1) {
            let part = part.trim();
            if let Some(pos) = part.find('=') {
                let attr_name = part[..pos].trim().to_lowercase();
                let attr_value = part[pos + 1..].trim();
                
                match attr_name.as_str() {
                    "domain" => cookie.domain = Some(attr_value.to_string()),
                    "path" => cookie.path = Some(attr_value.to_string()),
                    "expires" => {
                        // Parse HTTP date format (RFC 7231 Section 7.1.1.1)
                        cookie.expires = parse_http_date(attr_value);
                    },
                    "max-age" => {
                        if let Ok(max_age) = attr_value.parse::<u64>() {
                            cookie.max_age = Some(max_age);
                        }
                    },
                    "samesite" => {
                        match attr_value.to_lowercase().as_str() {
                            "strict" => cookie.same_site = Some(SameSite::Strict),
                            "lax" => cookie.same_site = Some(SameSite::Lax),
                            "none" => cookie.same_site = Some(SameSite::None),
                            _ => {}
                        }
                    },
                    _ => {}
                }
            } else {
                match part.to_lowercase().as_str() {
                    "secure" => cookie.secure = true,
                    "httponly" => cookie.http_only = true,
                    _ => {}
                }
            }
        }

        Some(cookie)
    }

    pub fn is_expired(&self) -> bool {
        if let Some(max_age) = self.max_age {
            // In a real implementation, you'd track when the cookie was set
            return max_age == 0;
        }
        
        if let Some(expires) = self.expires {
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs();
            return now > expires;
        }
        
        false
    }

    pub fn matches_domain(&self, domain: &str) -> bool {
        if let Some(ref cookie_domain) = self.domain {
            domain.ends_with(cookie_domain) || domain == cookie_domain
        } else {
            true
        }
    }

    pub fn matches_path(&self, path: &str) -> bool {
        if let Some(ref cookie_path) = self.path {
            path.starts_with(cookie_path)
        } else {
            true
        }
    }

    pub fn to_header_value(&self) -> String {
        format!("{}={}", self.name, self.value)
    }
}

#[derive(Debug, Clone)]
pub struct CookieJar {
    cookies: HashMap<String, Cookie>,
}

impl CookieJar {
    pub fn new() -> Self {
        CookieJar {
            cookies: HashMap::new(),
        }
    }

    pub fn add_cookie(&mut self, cookie: Cookie) {
        let key = format!("{}:{}", 
            cookie.domain.as_deref().unwrap_or(""), 
            cookie.name
        );
        self.cookies.insert(key, cookie);
    }

    pub fn add_cookie_str(&mut self, cookie_str: &str, domain: &str) {
        if let Some(mut cookie) = Cookie::parse(cookie_str) {
            if cookie.domain.is_none() {
                cookie.domain = Some(domain.to_string());
            }
            self.add_cookie(cookie);
        }
    }

    pub fn get_cookies_for_request(&self, domain: &str, path: &str, secure: bool) -> Vec<&Cookie> {
        self.cookies
            .values()
            .filter(|cookie| {
                !cookie.is_expired() &&
                cookie.matches_domain(domain) &&
                cookie.matches_path(path) &&
                (!cookie.secure || secure)
            })
            .collect()
    }

    pub fn to_cookie_header(&self, domain: &str, path: &str, secure: bool) -> Option<String> {
        let cookies = self.get_cookies_for_request(domain, path, secure);
        if cookies.is_empty() {
            None
        } else {
            let cookie_str = cookies
                .iter()
                .map(|c| c.to_header_value())
                .collect::<Vec<_>>()
                .join("; ");
            Some(cookie_str)
        }
    }

    pub fn clear(&mut self) {
        self.cookies.clear();
    }

    pub fn remove_cookie(&mut self, name: &str, domain: Option<&str>) {
        let key = format!("{}:{}", domain.unwrap_or(""), name);
        self.cookies.remove(&key);
    }
}

impl Default for CookieJar {
    fn default() -> Self {
        Self::new()
    }
}

// HTTP date parsing (RFC 7231 Section 7.1.1.1)
fn parse_http_date(date_str: &str) -> Option<u64> {

    
    // Common HTTP date formats:
    // "Sun, 06 Nov 1994 08:49:37 GMT" (RFC 822/1123)
    // "Sunday, 06-Nov-94 08:49:37 GMT" (RFC 850)
    // "Sun Nov  6 08:49:37 1994" (ANSI C asctime())
    
    let date_str = date_str.trim();
    
    // Try to parse RFC 1123 format first (most common)
    if let Some(timestamp) = parse_rfc1123_date(date_str) {
        return Some(timestamp);
    }
    
    // Try RFC 850 format
    if let Some(timestamp) = parse_rfc850_date(date_str) {
        return Some(timestamp);
    }
    
    // Try ANSI C asctime format
    if let Some(timestamp) = parse_asctime_date(date_str) {
        return Some(timestamp);
    }
    
    None
}

fn parse_rfc1123_date(date_str: &str) -> Option<u64> {
    // Format: "Sun, 06 Nov 1994 08:49:37 GMT"
    let parts: Vec<&str> = date_str.split_whitespace().collect();
    if parts.len() != 6 {
        return None;
    }
    
    let day: u32 = parts[1].parse().ok()?;
    let month = month_to_number(parts[2])?;
    let year: u32 = parts[3].parse().ok()?;
    
    let time_parts: Vec<&str> = parts[4].split(':').collect();
    if time_parts.len() != 3 {
        return None;
    }
    
    let hour: u32 = time_parts[0].parse().ok()?;
    let minute: u32 = time_parts[1].parse().ok()?;
    let second: u32 = time_parts[2].parse().ok()?;
    
    // Simple timestamp calculation (not accounting for leap years, etc.)
    // This is a simplified implementation
    let days_since_epoch = days_since_unix_epoch(year, month, day)?;
    let seconds_in_day = hour * 3600 + minute * 60 + second;
    
    Some(days_since_epoch * 86400 + seconds_in_day as u64)
}

fn parse_rfc850_date(date_str: &str) -> Option<u64> {
    // Format: "Sunday, 06-Nov-94 08:49:37 GMT"
    let parts: Vec<&str> = date_str.split_whitespace().collect();
    if parts.len() != 3 {
        return None;
    }
    
    let date_part = parts[1];
    let date_components: Vec<&str> = date_part.split('-').collect();
    if date_components.len() != 3 {
        return None;
    }
    
    let day: u32 = date_components[0].parse().ok()?;
    let month = month_to_number(date_components[1])?;
    let mut year: u32 = date_components[2].parse().ok()?;
    
    // Convert 2-digit year to 4-digit
    if year < 50 {
        year += 2000;
    } else if year < 100 {
        year += 1900;
    }
    
    let time_parts: Vec<&str> = parts[2].split(':').collect();
    if time_parts.len() != 3 {
        return None;
    }
    
    let hour: u32 = time_parts[0].parse().ok()?;
    let minute: u32 = time_parts[1].parse().ok()?;
    let second: u32 = time_parts[2].parse().ok()?;
    
    let days_since_epoch = days_since_unix_epoch(year, month, day)?;
    let seconds_in_day = hour * 3600 + minute * 60 + second;
    
    Some(days_since_epoch * 86400 + seconds_in_day as u64)
}

fn parse_asctime_date(date_str: &str) -> Option<u64> {
    // Format: "Sun Nov  6 08:49:37 1994"
    let parts: Vec<&str> = date_str.split_whitespace().collect();
    if parts.len() != 5 {
        return None;
    }
    
    let month = month_to_number(parts[1])?;
    let day: u32 = parts[2].parse().ok()?;
    let year: u32 = parts[4].parse().ok()?;
    
    let time_parts: Vec<&str> = parts[3].split(':').collect();
    if time_parts.len() != 3 {
        return None;
    }
    
    let hour: u32 = time_parts[0].parse().ok()?;
    let minute: u32 = time_parts[1].parse().ok()?;
    let second: u32 = time_parts[2].parse().ok()?;
    
    let days_since_epoch = days_since_unix_epoch(year, month, day)?;
    let seconds_in_day = hour * 3600 + minute * 60 + second;
    
    Some(days_since_epoch * 86400 + seconds_in_day as u64)
}

fn month_to_number(month: &str) -> Option<u32> {
    match month {
        "Jan" => Some(1),
        "Feb" => Some(2),
        "Mar" => Some(3),
        "Apr" => Some(4),
        "May" => Some(5),
        "Jun" => Some(6),
        "Jul" => Some(7),
        "Aug" => Some(8),
        "Sep" => Some(9),
        "Oct" => Some(10),
        "Nov" => Some(11),
        "Dec" => Some(12),
        _ => None,
    }
}

fn days_since_unix_epoch(year: u32, month: u32, day: u32) -> Option<u64> {
    if year < 1970 || !(1..=12).contains(&month) || !(1..=31).contains(&day) {
        return None;
    }
    
    // Simplified calculation (not accounting for all leap year rules)
    let mut days = 0u64;
    
    // Add days for complete years
    for y in 1970..year {
        if is_leap_year(y) {
            days += 366;
        } else {
            days += 365;
        }
    }
    
    // Add days for complete months in the current year
    for m in 1..month {
        days += days_in_month(m, year) as u64;
    }
    
    // Add remaining days
    days += (day - 1) as u64;
    
    Some(days)
}

fn is_leap_year(year: u32) -> bool {
    (year % 4 == 0 && year % 100 != 0) || (year % 400 == 0)
}

fn days_in_month(month: u32, year: u32) -> u32 {
    match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 => if is_leap_year(year) { 29 } else { 28 },
        _ => 0,
    }
}