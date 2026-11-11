//! Cookie header splitting and the change log the client records.
//!
//! curl-impersonate's `split_cookies` sends one `Cookie` header per cookie when
//! the request is HTTP/2 or HTTP/3. A combined `Cookie` header is split on
//! `;`, which is how those cookies were joined. HTTP/1.1 keeps one header.
//!
//! [`ChangeLog`] is the cookie store installed on the shipped client. `SET` and
//! `DELETE` lines are what [`crate::Client::cookie_changes`] returns.

use std::sync::Mutex;

use wreq::cookie::{CookieStore, Cookies};
use wreq::header::HeaderValue;
use wreq::{Uri, Version};

use crate::policy::{self, CookieProtocol};

/// Header values for one `Cookie` line.
///
/// When `split` is false the input is one header. When it is true, each
/// semicolon-separated cookie is its own header. Empty pieces are dropped.
pub fn cookie_headers(raw: &str, split: bool) -> Vec<String> {
    if !split {
        return vec![raw.to_string()];
    }
    raw.split(';')
        .map(str::trim)
        .filter(|part| !part.is_empty())
        .map(str::to_string)
        .collect()
}

/// Cookie store the shipped client installs.
///
/// `set_cookies` records `CURLINFO_COOKIECHANGES` lines. `cookies` applies the
/// same HTTP-version split as [`cookie_headers`].
pub struct ChangeLog {
    changes: Mutex<Vec<String>>,
    jar: Mutex<Vec<(String, String)>>,
    /// Preset or caller `split_cookies`. HTTP/2 and HTTP/3 split only when set.
    split_cookies: bool,
}

impl ChangeLog {
    pub(crate) fn new(split_cookies: bool) -> Self {
        Self {
            changes: Mutex::new(Vec::new()),
            jar: Mutex::new(Vec::new()),
            split_cookies,
        }
    }

    pub(crate) fn lines(&self) -> Vec<String> {
        self.changes.lock().expect("cookie changes").clone()
    }
}

impl CookieStore for ChangeLog {
    fn set_cookies(&self, cookie_headers: &mut dyn Iterator<Item = &HeaderValue>, uri: &Uri) {
        for header in cookie_headers {
            let Ok(text) = header.to_str() else {
                continue;
            };
            let Some((action, line, name, value)) = netscape_change(uri, text) else {
                continue;
            };
            self.changes
                .lock()
                .expect("cookie changes")
                .push(policy::cookie_change_line(&action, &line));
            let mut jar = self.jar.lock().expect("cookie jar");
            jar.retain(|(existing, _)| !existing.eq_ignore_ascii_case(&name));
            if action == "SET" {
                jar.push((name, value));
            }
        }
    }

    fn cookies(&self, _uri: &Uri, version: Version) -> Cookies {
        let jar = self.jar.lock().expect("cookie jar");
        if jar.is_empty() {
            return Cookies::Empty;
        }
        let protocol = match version {
            Version::HTTP_2 | Version::HTTP_3 => CookieProtocol::Http2,
            _ => CookieProtocol::Http1,
        };
        let combined = jar
            .iter()
            .map(|(name, value)| format!("{name}={value}"))
            .collect::<Vec<_>>()
            .join("; ");
        let split = policy::split_for(protocol, self.split_cookies);
        let values = cookie_headers(&combined, split);
        if split {
            Cookies::Uncompressed(
                values
                    .into_iter()
                    .filter_map(|value| HeaderValue::from_str(&value).ok())
                    .collect(),
            )
        } else {
            values
                .first()
                .and_then(|value| HeaderValue::from_str(value).ok())
                .map(Cookies::Compressed)
                .unwrap_or(Cookies::Empty)
        }
    }
}

fn netscape_change(uri: &Uri, set_cookie: &str) -> Option<(String, String, String, String)> {
    let (pair, rest) = match set_cookie.split_once(';') {
        Some((pair, rest)) => (pair.trim(), Some(rest)),
        None => (set_cookie.trim(), None),
    };
    let (name, value) = pair.split_once('=')?;
    let name = name.trim();
    if name.is_empty() {
        return None;
    }
    let mut value = value.trim().to_string();
    let mut path = "/".to_string();
    let mut domain = uri.host().unwrap_or("").trim_start_matches('.').to_string();
    let mut secure = false;
    let mut delete = value.is_empty();
    if let Some(rest) = rest {
        for attribute in rest.split(';') {
            let attribute = attribute.trim();
            if attribute.eq_ignore_ascii_case("secure") {
                secure = true;
                continue;
            }
            let Some((key, raw)) = attribute.split_once('=') else {
                continue;
            };
            let key = key.trim();
            let raw = raw.trim();
            if key.eq_ignore_ascii_case("path") {
                path = raw.to_string();
            } else if key.eq_ignore_ascii_case("domain") && !raw.is_empty() {
                domain = raw.trim_start_matches('.').to_string();
            } else if key.eq_ignore_ascii_case("max-age") && raw == "0" {
                delete = true;
                value.clear();
            }
        }
    }
    let tail = "FALSE";
    let secure_flag = if secure { "TRUE" } else { "FALSE" };
    let line = format!("{domain}\t{tail}\t{path}\t{secure_flag}\t0\t{name}\t{value}");
    let action = if delete { "DELETE" } else { "SET" };
    Some((action.to_string(), line, name.to_string(), value))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn split_keeps_each_cookie() {
        assert_eq!(
            cookie_headers("a=1; b=2; c=3", true),
            vec!["a=1".to_string(), "b=2".to_string(), "c=3".to_string()]
        );
    }

    #[test]
    fn unsplit_keeps_one_header() {
        assert_eq!(
            cookie_headers("a=1; b=2", false),
            vec!["a=1; b=2".to_string()]
        );
    }
}
