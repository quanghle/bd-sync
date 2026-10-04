//! `application/x-www-form-urlencoded`: the query strings of the
//! authorization flow's redirects, and the consent form's body.

/// `pairs` as a query string, every byte but the unreserved ones (RFC 3986)
/// percent-encoded.
pub fn encode(pairs: &[(&str, &str)]) -> String {
    let mut out = String::new();
    for (i, (key, value)) in pairs.iter().enumerate() {
        if i > 0 {
            out.push('&');
        }
        escape(key, &mut out);
        out.push('=');
        escape(value, &mut out);
    }
    out
}

fn escape(s: &str, out: &mut String) {
    for b in s.bytes() {
        if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~') {
            out.push(char::from(b));
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
}

/// The pairs of a query string or form body, in order, `+` read as a
/// space; `None` if one is not valid percent-encoded UTF-8. Empty parts
/// (`a=1&&b=2`) are skipped; a part without `=` has an empty value.
pub fn decode(query: &str) -> Option<Vec<(String, String)>> {
    query
        .split('&')
        .filter(|part| !part.is_empty())
        .map(|part| {
            let (key, value) = part.split_once('=').unwrap_or((part, ""));
            Some((unescape(key)?, unescape(value)?))
        })
        .collect()
}

fn unescape(s: &str) -> Option<String> {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'+' => out.push(b' '),
            b'%' => {
                let hex = std::str::from_utf8(bytes.get(i + 1..i + 3)?).ok()?;
                out.push(u8::from_str_radix(hex, 16).ok().filter(|_| hex.bytes().all(|b| b.is_ascii_hexdigit()))?);
                i += 2;
            }
            b => out.push(b),
        }
        i += 1;
    }
    String::from_utf8(out).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pairs_go_through_query_strings_unchanged() {
        let pairs = [("redirect_uri", "https://a.example/cb?x=1&y=2"), ("state", "a b+c/é%"), ("", "")];
        let query = encode(&pairs);
        assert_eq!(query, "redirect_uri=https%3A%2F%2Fa.example%2Fcb%3Fx%3D1%26y%3D2&state=a%20b%2Bc%2F%C3%A9%25&=");
        let back = decode(&query).unwrap();
        let back: Vec<(&str, &str)> = back.iter().map(|(k, v)| (k.as_str(), v.as_str())).collect();
        assert_eq!(back, pairs);
        assert_eq!(
            decode("a=1+2&&b&c=%7e").unwrap(),
            [("a".into(), "1 2".into()), ("b".into(), "".into()), ("c".into(), "~".into())]
        );
        assert_eq!(decode("").unwrap(), []);
        for bad in ["a=%", "a=%4", "a=%zz", "a=%+1", "a=%ff", "%c3=1"] {
            assert_eq!(decode(bad), None, "{bad}");
        }
    }
}
