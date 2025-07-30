use crate::{Method, Url, Result, Error};
use std::collections::HashSet;

#[derive(Debug, Clone)]
pub struct RedirectPolicy {
    pub max_redirects: usize,
    pub follow_redirects: bool,
    pub redirect_auth: bool, // Whether to send auth headers on redirects
    pub redirect_sensitive_headers: bool, // Whether to send sensitive headers on redirects
}

impl RedirectPolicy {
    pub fn new() -> Self {
        RedirectPolicy {
            max_redirects: 10,
            follow_redirects: true,
            redirect_auth: false,
            redirect_sensitive_headers: false,
        }
    }

    pub fn none() -> Self {
        RedirectPolicy {
            max_redirects: 0,
            follow_redirects: false,
            redirect_auth: false,
            redirect_sensitive_headers: false,
        }
    }

    pub fn limited(max_redirects: usize) -> Self {
        RedirectPolicy {
            max_redirects,
            follow_redirects: true,
            redirect_auth: false,
            redirect_sensitive_headers: false,
        }
    }

    pub fn with_auth(mut self) -> Self {
        self.redirect_auth = true;
        self
    }

    pub fn with_sensitive_headers(mut self) -> Self {
        self.redirect_sensitive_headers = true;
        self
    }
}

impl Default for RedirectPolicy {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone)]
pub struct RedirectHandler {
    policy: RedirectPolicy,
    visited_urls: HashSet<String>,
    redirect_count: usize,
}

impl RedirectHandler {
    pub fn new(policy: RedirectPolicy) -> Self {
        RedirectHandler {
            policy,
            visited_urls: HashSet::new(),
            redirect_count: 0,
        }
    }

    pub fn should_redirect(&mut self, status: u16, location: &str, current_url: &Url) -> Result<Option<RedirectInfo>> {
        if !self.policy.follow_redirects {
            return Ok(None);
        }

        if self.redirect_count >= self.policy.max_redirects {
            return Err(Error::TooManyRedirects(self.redirect_count));
        }

        if !is_redirect_status(status) {
            return Ok(None);
        }

        // Parse the location header
        let redirect_url = self.resolve_redirect_url(location, current_url)?;
        let redirect_url_str = self.url_to_string(&redirect_url);

        // Check for redirect loops
        if self.visited_urls.contains(&redirect_url_str) {
            return Err(Error::RedirectLoop);
        }

        self.visited_urls.insert(redirect_url_str);
        self.redirect_count += 1;

        let redirect_info = RedirectInfo {
            url: redirect_url,
            status,
            preserve_method: should_preserve_method(status),
            remove_body: should_remove_body(status),
        };

        Ok(Some(redirect_info))
    }

    fn resolve_redirect_url(&self, location: &str, base_url: &Url) -> Result<Url> {
        if location.starts_with("http://") || location.starts_with("https://") {
            // Absolute URL
            Url::parse(location)
        } else if location.starts_with("//") {
            // Protocol-relative URL
            let full_url = format!("{}:{}", base_url.scheme, location);
            Url::parse(&full_url)
        } else if location.starts_with('/') {
            // Absolute path
            let mut new_url = base_url.clone();
            new_url.path = location.to_string();
            new_url.query = None;
            new_url.fragment = None;
            Ok(new_url)
        } else {
            // Relative path
            let base_path = if base_url.path.ends_with('/') {
                &base_url.path
            } else {
                // Remove the last segment
                if let Some(pos) = base_url.path.rfind('/') {
                    &base_url.path[..pos + 1]
                } else {
                    "/"
                }
            };
            
            let mut new_url = base_url.clone();
            new_url.path = format!("{base_path}{location}");
            new_url.query = None;
            new_url.fragment = None;
            Ok(new_url)
        }
    }

    fn url_to_string(&self, url: &Url) -> String {
        format!("{}://{}{}", url.scheme, url.authority(), url.full_path())
    }

    pub fn should_send_auth(&self, original_url: &Url, redirect_url: &Url) -> bool {
        if !self.policy.redirect_auth {
            return false;
        }

        // Only send auth to the same host by default
        original_url.host == redirect_url.host
    }

    pub fn should_send_sensitive_headers(&self, original_url: &Url, redirect_url: &Url) -> bool {
        if !self.policy.redirect_sensitive_headers {
            return false;
        }

        // Only send sensitive headers to the same host
        original_url.host == redirect_url.host && original_url.scheme == redirect_url.scheme
    }

    pub fn reset(&mut self) {
        self.visited_urls.clear();
        self.redirect_count = 0;
    }
}

#[derive(Debug, Clone)]
pub struct RedirectInfo {
    pub url: Url,
    pub status: u16,
    pub preserve_method: bool,
    pub remove_body: bool,
}

fn is_redirect_status(status: u16) -> bool {
    matches!(status, 301 | 302 | 303 | 307 | 308)
}

fn should_preserve_method(status: u16) -> bool {
    // 307 and 308 preserve the method, others change to GET
    matches!(status, 307 | 308)
}

fn should_remove_body(status: u16) -> bool {
    // Remove body for GET redirects (301, 302, 303)
    matches!(status, 301..=303)
}

pub fn get_redirect_method(original_method: Method, status: u16) -> Method {
    if should_preserve_method(status) {
        original_method
    } else {
        // Change to GET for most redirects
        Method::GET
    }
}

// Sensitive headers that should not be sent on cross-origin redirects
pub fn is_sensitive_header(header_name: &str) -> bool {
    let header_lower = header_name.to_lowercase();
    matches!(header_lower.as_str(),
        "authorization" |
        "cookie" |
        "proxy-authorization" |
        "www-authenticate" |
        "proxy-authenticate"
    )
}