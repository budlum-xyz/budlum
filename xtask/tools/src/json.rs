//! A small JSON reader.
//!
//! The scripts this crate replaces leaned on `jq`, `python3 -c` and `grep` to
//! read a handful of fields out of RPC replies and the SBOM. This module reads
//! the whole document into a tree, so a field is looked up by name instead of
//! being matched as text. It validates strictly: trailing bytes, a missing
//! comma or an unclosed string is an error, not a partial answer.

/// One parsed JSON value. Numbers keep their source text; nothing here needs
/// arithmetic on them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Value {
    Null,
    Bool(bool),
    Number(String),
    String(String),
    Array(Vec<Value>),
    Object(Vec<(String, Value)>),
}

/// How deep a document may nest before the reader gives up.
const MAX_DEPTH: usize = 256;

impl Value {
    /// The member `key` of an object. `None` for a missing key or a value
    /// that is not an object. With a repeated key the last one wins, as in
    /// `jq` and Python.
    #[must_use]
    pub fn get(&self, key: &str) -> Option<&Value> {
        match self {
            Value::Object(members) => members.iter().rev().find(|(k, _)| k == key).map(|(_, v)| v),
            _ => None,
        }
    }

    /// The text of a string value.
    #[must_use]
    pub fn as_str(&self) -> Option<&str> {
        match self {
            Value::String(s) => Some(s),
            _ => None,
        }
    }

    /// The items of an array value.
    #[must_use]
    pub fn as_array(&self) -> Option<&[Value]> {
        match self {
            Value::Array(items) => Some(items),
            _ => None,
        }
    }
}

/// Parse one complete JSON document.
///
/// # Errors
///
/// If the text is not exactly one valid JSON value.
pub fn parse(text: &str) -> Result<Value, String> {
    let mut reader = Reader {
        bytes: text.as_bytes(),
        pos: 0,
    };
    reader.skip_ws();
    let value = reader.value(0)?;
    reader.skip_ws();
    if reader.pos != reader.bytes.len() {
        return Err(format!("trailing data at byte {}", reader.pos));
    }
    Ok(value)
}

struct Reader<'a> {
    bytes: &'a [u8],
    pos: usize,
}

impl Reader<'_> {
    fn skip_ws(&mut self) {
        while matches!(self.peek(), Some(b' ' | b'\t' | b'\n' | b'\r')) {
            self.pos += 1;
        }
    }

    fn peek(&self) -> Option<u8> {
        self.bytes.get(self.pos).copied()
    }

    fn expect(&mut self, byte: u8) -> Result<(), String> {
        if self.peek() == Some(byte) {
            self.pos += 1;
            Ok(())
        } else {
            Err(format!(
                "expected `{}` at byte {}",
                char::from(byte),
                self.pos
            ))
        }
    }

    fn literal(&mut self, word: &str, value: Value) -> Result<Value, String> {
        if self.bytes[self.pos..].starts_with(word.as_bytes()) {
            self.pos += word.len();
            Ok(value)
        } else {
            Err(format!("invalid literal at byte {}", self.pos))
        }
    }

    fn value(&mut self, depth: usize) -> Result<Value, String> {
        if depth > MAX_DEPTH {
            return Err("nesting is too deep".to_string());
        }
        match self.peek() {
            Some(b'{') => self.object(depth),
            Some(b'[') => self.array(depth),
            Some(b'"') => self.string().map(Value::String),
            Some(b't') => self.literal("true", Value::Bool(true)),
            Some(b'f') => self.literal("false", Value::Bool(false)),
            Some(b'n') => self.literal("null", Value::Null),
            Some(b'-' | b'0'..=b'9') => self.number(),
            Some(other) => Err(format!(
                "unexpected `{}` at byte {}",
                char::from(other),
                self.pos
            )),
            None => Err("the document ended early".to_string()),
        }
    }

    fn object(&mut self, depth: usize) -> Result<Value, String> {
        self.expect(b'{')?;
        let mut members = Vec::new();
        self.skip_ws();
        if self.peek() == Some(b'}') {
            self.pos += 1;
            return Ok(Value::Object(members));
        }
        loop {
            self.skip_ws();
            let key = self.string()?;
            self.skip_ws();
            self.expect(b':')?;
            self.skip_ws();
            let value = self.value(depth + 1)?;
            members.push((key, value));
            self.skip_ws();
            match self.peek() {
                Some(b',') => self.pos += 1,
                Some(b'}') => {
                    self.pos += 1;
                    return Ok(Value::Object(members));
                }
                _ => return Err(format!("expected `,` or `}}` at byte {}", self.pos)),
            }
        }
    }

    fn array(&mut self, depth: usize) -> Result<Value, String> {
        self.expect(b'[')?;
        let mut items = Vec::new();
        self.skip_ws();
        if self.peek() == Some(b']') {
            self.pos += 1;
            return Ok(Value::Array(items));
        }
        loop {
            self.skip_ws();
            items.push(self.value(depth + 1)?);
            self.skip_ws();
            match self.peek() {
                Some(b',') => self.pos += 1,
                Some(b']') => {
                    self.pos += 1;
                    return Ok(Value::Array(items));
                }
                _ => return Err(format!("expected `,` or `]` at byte {}", self.pos)),
            }
        }
    }

    fn number(&mut self) -> Result<Value, String> {
        let start = self.pos;
        if self.peek() == Some(b'-') {
            self.pos += 1;
        }
        match self.peek() {
            Some(b'0') => self.pos += 1,
            Some(b'1'..=b'9') => self.digits(),
            _ => return Err(format!("bad number at byte {start}")),
        }
        if self.peek() == Some(b'.') {
            self.pos += 1;
            if !matches!(self.peek(), Some(b'0'..=b'9')) {
                return Err(format!("bad number at byte {start}"));
            }
            self.digits();
        }
        if matches!(self.peek(), Some(b'e' | b'E')) {
            self.pos += 1;
            if matches!(self.peek(), Some(b'+' | b'-')) {
                self.pos += 1;
            }
            if !matches!(self.peek(), Some(b'0'..=b'9')) {
                return Err(format!("bad number at byte {start}"));
            }
            self.digits();
        }
        let text = String::from_utf8_lossy(&self.bytes[start..self.pos]).into_owned();
        Ok(Value::Number(text))
    }

    fn digits(&mut self) {
        while matches!(self.peek(), Some(b'0'..=b'9')) {
            self.pos += 1;
        }
    }

    fn hex4(&mut self) -> Result<u32, String> {
        let end = self.pos + 4;
        let digits = self
            .bytes
            .get(self.pos..end)
            .and_then(|b| std::str::from_utf8(b).ok())
            .ok_or_else(|| format!("bad \\u escape at byte {}", self.pos))?;
        let code = u32::from_str_radix(digits, 16)
            .map_err(|_| format!("bad \\u escape at byte {}", self.pos))?;
        self.pos = end;
        Ok(code)
    }

    fn unicode_escape(&mut self) -> Result<char, String> {
        let first = self.hex4()?;
        if (0xD800..0xDC00).contains(&first) {
            // A high surrogate has to be followed by a low one.
            if self.bytes[self.pos..].starts_with(b"\\u") {
                self.pos += 2;
                let second = self.hex4()?;
                if (0xDC00..0xE000).contains(&second) {
                    let code = 0x1_0000 + ((first - 0xD800) << 10) + (second - 0xDC00);
                    return Ok(char::from_u32(code).unwrap_or('\u{FFFD}'));
                }
            }
            return Ok('\u{FFFD}');
        }
        Ok(char::from_u32(first).unwrap_or('\u{FFFD}'))
    }

    fn string(&mut self) -> Result<String, String> {
        self.expect(b'"')?;
        let mut out: Vec<u8> = Vec::new();
        loop {
            let Some(byte) = self.peek() else {
                return Err("a string was never closed".to_string());
            };
            self.pos += 1;
            match byte {
                b'"' => break,
                b'\\' => {
                    let Some(esc) = self.peek() else {
                        return Err("a string was never closed".to_string());
                    };
                    self.pos += 1;
                    let ch = match esc {
                        b'"' => '"',
                        b'\\' => '\\',
                        b'/' => '/',
                        b'b' => '\u{8}',
                        b'f' => '\u{C}',
                        b'n' => '\n',
                        b'r' => '\r',
                        b't' => '\t',
                        b'u' => self.unicode_escape()?,
                        _ => return Err(format!("bad escape at byte {}", self.pos - 1)),
                    };
                    let mut buf = [0u8; 4];
                    out.extend_from_slice(ch.encode_utf8(&mut buf).as_bytes());
                }
                0..=0x1F => {
                    return Err(format!("raw control byte in a string at {}", self.pos - 1))
                }
                other => out.push(other),
            }
        }
        String::from_utf8(out).map_err(|_| "a string is not valid UTF-8".to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_a_rpc_reply() {
        let v = parse(r#"{"jsonrpc":"2.0","result":"0xb0ce","id":1}"#).expect("valid");
        assert_eq!(v.get("result").and_then(Value::as_str), Some("0xb0ce"));
        assert!(v.get("error").is_none());
    }

    #[test]
    fn reads_nested_members_and_booleans() {
        let v =
            parse(r#" {"result": {"hash":"0xab","number":"0x0"}, "ok": true} "#).expect("valid");
        let result = v.get("result").expect("result");
        assert_eq!(result.get("hash").and_then(Value::as_str), Some("0xab"));
        assert_eq!(v.get("ok"), Some(&Value::Bool(true)));
    }

    #[test]
    fn counts_array_items() {
        let v = parse(r#"{"components":[{"a":1},{"a":-2.5e3},[],{}]}"#).expect("valid");
        assert_eq!(
            v.get("components")
                .and_then(Value::as_array)
                .map(<[_]>::len),
            Some(4)
        );
    }

    #[test]
    fn decodes_escapes() {
        let v = parse(r#""a\n\"b\" \u00e9 \ud83d\ude00""#).expect("valid");
        assert_eq!(v.as_str(), Some("a\n\"b\" \u{e9} \u{1F600}"));
    }

    #[test]
    fn the_last_duplicate_key_wins() {
        let v = parse(r#"{"a":"1","a":"2"}"#).expect("valid");
        assert_eq!(v.get("a").and_then(Value::as_str), Some("2"));
    }

    #[test]
    fn rejects_broken_documents() {
        for bad in [
            "",
            "{",
            "[1,]",
            "{\"a\":1,}",
            "{\"a\" 1}",
            "tru",
            "01",
            "1.",
            "\"abc",
            "{\"a\":1} x",
            "[1 2]",
            "\"\\q\"",
            "nul",
            "\"a\nb\"",
            "-",
        ] {
            assert!(parse(bad).is_err(), "must reject: {bad:?}");
        }
    }

    #[test]
    fn rejects_runaway_nesting() {
        let deep = "[".repeat(MAX_DEPTH + 10);
        assert!(parse(&deep).is_err());
    }
}
