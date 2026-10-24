//! SecLang transformation functions (`t:`). Values are byte strings, as in
//! ModSecurity, so decoding never fails on invalid UTF-8.

use sha1::{Digest, Sha1};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Transform {
    Lowercase,
    Uppercase,
    UrlDecode,
    UrlDecodeUni,
    UrlEncode,
    HtmlEntityDecode,
    JsDecode,
    CssDecode,
    EscapeSeqDecode,
    RemoveNulls,
    ReplaceNulls,
    RemoveWhitespace,
    CompressWhitespace,
    ReplaceComments,
    RemoveComments,
    RemoveCommentsChar,
    NormalizePath,
    NormalizePathWin,
    CmdLine,
    Length,
    Base64Decode,
    Base64DecodeExt,
    Base64Encode,
    HexDecode,
    HexEncode,
    Sha1,
    Utf8ToUnicode,
    Trim,
    TrimLeft,
    TrimRight,
}

impl Transform {
    /// `Ok(None)` is `t:none` (reset). Unknown names are an error.
    pub fn parse(name: &str) -> Result<Option<Self>, String> {
        Ok(Some(match name.to_ascii_lowercase().as_str() {
            "none" => return Ok(None),
            "lowercase" => Self::Lowercase,
            "uppercase" => Self::Uppercase,
            "urldecode" => Self::UrlDecode,
            "urldecodeuni" => Self::UrlDecodeUni,
            "urlencode" => Self::UrlEncode,
            "htmlentitydecode" => Self::HtmlEntityDecode,
            "jsdecode" => Self::JsDecode,
            "cssdecode" => Self::CssDecode,
            "escapeseqdecode" => Self::EscapeSeqDecode,
            "removenulls" => Self::RemoveNulls,
            "replacenulls" => Self::ReplaceNulls,
            "removewhitespace" => Self::RemoveWhitespace,
            "compresswhitespace" => Self::CompressWhitespace,
            "replacecomments" => Self::ReplaceComments,
            "removecomments" => Self::RemoveComments,
            "removecommentschar" => Self::RemoveCommentsChar,
            "normalizepath" | "normalisepath" => Self::NormalizePath,
            "normalizepathwin" | "normalisepathwin" => Self::NormalizePathWin,
            "cmdline" => Self::CmdLine,
            "length" => Self::Length,
            "base64decode" => Self::Base64Decode,
            "base64decodeext" => Self::Base64DecodeExt,
            "base64encode" => Self::Base64Encode,
            "hexdecode" => Self::HexDecode,
            "hexencode" => Self::HexEncode,
            "sha1" => Self::Sha1,
            "utf8tounicode" => Self::Utf8ToUnicode,
            "trim" => Self::Trim,
            "trimleft" => Self::TrimLeft,
            "trimright" => Self::TrimRight,
            other => return Err(format!("unsupported transformation t:{other}")),
        }))
    }

    pub fn apply(self, input: &[u8]) -> Vec<u8> {
        match self {
            Self::Lowercase => input.to_ascii_lowercase(),
            Self::Uppercase => input.to_ascii_uppercase(),
            Self::UrlDecode => url_decode(input, false),
            Self::UrlDecodeUni => url_decode(input, true),
            Self::UrlEncode => url_encode(input),
            Self::HtmlEntityDecode => html_entity_decode(input),
            Self::JsDecode => js_decode(input),
            Self::CssDecode => css_decode(input),
            Self::EscapeSeqDecode => escape_seq_decode(input),
            Self::RemoveNulls => input.iter().copied().filter(|b| *b != 0).collect(),
            Self::ReplaceNulls => input
                .iter()
                .map(|b| if *b == 0 { b' ' } else { *b })
                .collect(),
            Self::RemoveWhitespace => input.iter().copied().filter(|b| !is_space(*b)).collect(),
            Self::CompressWhitespace => compress_whitespace(input),
            Self::ReplaceComments => replace_comments(input),
            Self::RemoveComments => remove_comments(input),
            Self::RemoveCommentsChar => remove_comment_chars(input),
            Self::NormalizePath => normalize_path(input, false),
            Self::NormalizePathWin => normalize_path(input, true),
            Self::CmdLine => cmd_line(input),
            Self::Length => input.len().to_string().into_bytes(),
            Self::Base64Decode => base64_decode(input, false),
            Self::Base64DecodeExt => base64_decode(input, true),
            Self::Base64Encode => base64_encode(input),
            Self::HexDecode => hex_decode(input),
            Self::HexEncode => hex::encode(input).into_bytes(),
            Self::Sha1 => Sha1::digest(input).to_vec(),
            Self::Utf8ToUnicode => utf8_to_unicode(input),
            Self::Trim => trim(input, true, true),
            Self::TrimLeft => trim(input, true, false),
            Self::TrimRight => trim(input, false, true),
        }
    }
}

fn is_space(b: u8) -> bool {
    matches!(b, b' ' | b'\t' | b'\n' | b'\r' | 0x0b | 0x0c | 0xa0)
}

fn hex_val(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

fn hex_pair(input: &[u8], at: usize) -> Option<u8> {
    Some(hex_val(*input.get(at)?)? << 4 | hex_val(*input.get(at + 1)?)?)
}

fn url_decode(input: &[u8], unicode: bool) -> Vec<u8> {
    let mut out = Vec::with_capacity(input.len());
    let mut i = 0;
    while i < input.len() {
        match input[i] {
            b'%' => {
                if unicode
                    && matches!(input.get(i + 1), Some(b'u' | b'U'))
                    && input.len() >= i + 6
                    && input[i + 2..i + 6].iter().all(|b| hex_val(*b).is_some())
                {
                    // %uXXXX: keep the low byte, mapping full-width ASCII
                    // (U+FF01..U+FF5E) to its ASCII equivalent.
                    let hi = hex_pair(input, i + 2).unwrap_or(0);
                    let lo = hex_pair(input, i + 4).unwrap_or(0);
                    let code = u16::from(hi) << 8 | u16::from(lo);
                    out.push(if (0xff01..=0xff5e).contains(&code) {
                        (code - 0xff01 + 0x21) as u8
                    } else {
                        lo
                    });
                    i += 6;
                } else if let Some(byte) = hex_pair(input, i + 1) {
                    out.push(byte);
                    i += 3;
                } else {
                    out.push(b'%');
                    i += 1;
                }
            }
            b'+' => {
                out.push(b' ');
                i += 1;
            }
            b => {
                out.push(b);
                i += 1;
            }
        }
    }
    out
}

fn url_encode(input: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(input.len());
    for &b in input {
        if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b'~') {
            out.push(b);
        } else if b == b' ' {
            out.push(b'+');
        } else {
            out.extend_from_slice(format!("%{b:02x}").as_bytes());
        }
    }
    out
}

fn html_entity_decode(input: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(input.len());
    let mut i = 0;
    while i < input.len() {
        if input[i] != b'&' {
            out.push(input[i]);
            i += 1;
            continue;
        }
        let rest = &input[i + 1..];
        if rest.first() == Some(&b'#') {
            let (radix, digits_start) = if matches!(rest.get(1), Some(b'x' | b'X')) {
                (16, 2)
            } else {
                (10, 1)
            };
            let digits = rest[digits_start..]
                .iter()
                .take_while(|b| {
                    if radix == 16 {
                        b.is_ascii_hexdigit()
                    } else {
                        b.is_ascii_digit()
                    }
                })
                .count();
            if digits > 0 {
                let text =
                    std::str::from_utf8(&rest[digits_start..digits_start + digits]).unwrap_or("0");
                let code = u32::from_str_radix(text, radix).unwrap_or(0);
                // ModSecurity keeps only the low byte of numeric entities.
                out.push((code & 0xff) as u8);
                i += 1 + digits_start + digits;
                if input.get(i) == Some(&b';') {
                    i += 1;
                }
                continue;
            }
        } else {
            let name_len = rest
                .iter()
                .take_while(|b| b.is_ascii_alphanumeric())
                .count();
            let name = &rest[..name_len];
            let decoded = match name.to_ascii_lowercase().as_slice() {
                b"quot" => Some(b'"'),
                b"amp" => Some(b'&'),
                b"lt" => Some(b'<'),
                b"gt" => Some(b'>'),
                b"nbsp" => Some(0xa0),
                b"apos" => Some(b'\''),
                _ => None,
            };
            if let Some(byte) = decoded {
                out.push(byte);
                i += 1 + name_len;
                if input.get(i) == Some(&b';') {
                    i += 1;
                }
                continue;
            }
        }
        out.push(b'&');
        i += 1;
    }
    out
}

fn js_decode(input: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(input.len());
    let mut i = 0;
    while i < input.len() {
        if input[i] != b'\\' || i + 1 >= input.len() {
            out.push(input[i]);
            i += 1;
            continue;
        }
        let next = input[i + 1];
        if matches!(next, b'u' | b'U')
            && input.len() >= i + 6
            && input[i + 2..i + 6].iter().all(u8::is_ascii_hexdigit)
        {
            let hi = hex_pair(input, i + 2).unwrap_or(0);
            let lo = hex_pair(input, i + 4).unwrap_or(0);
            let code = u16::from(hi) << 8 | u16::from(lo);
            out.push(if (0xff01..=0xff5e).contains(&code) {
                (code - 0xff01 + 0x21) as u8
            } else {
                lo
            });
            i += 6;
        } else if matches!(next, b'x' | b'X') && hex_pair(input, i + 2).is_some() {
            out.push(hex_pair(input, i + 2).unwrap_or(0));
            i += 4;
        } else if (b'0'..=b'7').contains(&next) {
            let digits = input[i + 1..]
                .iter()
                .take(3)
                .take_while(|b| (b'0'..=b'7').contains(*b))
                .count();
            let text = std::str::from_utf8(&input[i + 1..i + 1 + digits]).unwrap_or("0");
            out.push(u32::from_str_radix(text, 8).unwrap_or(0) as u8);
            i += 1 + digits;
        } else {
            out.push(match next {
                b'a' => 0x07,
                b'b' => 0x08,
                b'f' => 0x0c,
                b'n' => b'\n',
                b'r' => b'\r',
                b't' => b'\t',
                b'v' => 0x0b,
                other => other,
            });
            i += 2;
        }
    }
    out
}

fn css_decode(input: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(input.len());
    let mut i = 0;
    while i < input.len() {
        if input[i] != b'\\' {
            out.push(input[i]);
            i += 1;
            continue;
        }
        let digits = input[i + 1..]
            .iter()
            .take(6)
            .take_while(|b| b.is_ascii_hexdigit())
            .count();
        if digits > 0 {
            let text = std::str::from_utf8(&input[i + 1..i + 1 + digits]).unwrap_or("0");
            let code = u32::from_str_radix(text, 16).unwrap_or(0);
            out.push(if (0xff01..=0xff5e).contains(&code) {
                (code - 0xff01 + 0x21) as u8
            } else {
                (code & 0xff) as u8
            });
            i += 1 + digits;
            if input.get(i).is_some_and(|b| is_space(*b)) {
                i += 1;
            }
        } else if input.get(i + 1) == Some(&b'\n') {
            i += 2;
        } else if let Some(&next) = input.get(i + 1) {
            out.push(next);
            i += 2;
        } else {
            i += 1;
        }
    }
    out
}

fn escape_seq_decode(input: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(input.len());
    let mut i = 0;
    while i < input.len() {
        if input[i] != b'\\' || i + 1 >= input.len() {
            out.push(input[i]);
            i += 1;
            continue;
        }
        let next = input[i + 1];
        if matches!(next, b'x' | b'X') {
            if let Some(byte) = hex_pair(input, i + 2) {
                out.push(byte);
                i += 4;
                continue;
            }
        }
        if (b'0'..=b'7').contains(&next) {
            let digits = input[i + 1..]
                .iter()
                .take(3)
                .take_while(|b| (b'0'..=b'7').contains(*b))
                .count();
            let text = std::str::from_utf8(&input[i + 1..i + 1 + digits]).unwrap_or("0");
            out.push(u32::from_str_radix(text, 8).unwrap_or(0) as u8);
            i += 1 + digits;
            continue;
        }
        let decoded = match next {
            b'a' => Some(0x07),
            b'b' => Some(0x08),
            b'f' => Some(0x0c),
            b'n' => Some(b'\n'),
            b'r' => Some(b'\r'),
            b't' => Some(b'\t'),
            b'v' => Some(0x0b),
            b'\\' | b'?' | b'\'' | b'"' => Some(next),
            _ => None,
        };
        match decoded {
            Some(byte) => out.push(byte),
            // Unknown escapes are kept verbatim.
            None => out.extend_from_slice(&[b'\\', next]),
        }
        i += 2;
    }
    out
}

fn compress_whitespace(input: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(input.len());
    let mut in_space = false;
    for &b in input {
        if is_space(b) {
            if !in_space {
                out.push(b' ');
            }
            in_space = true;
        } else {
            out.push(b);
            in_space = false;
        }
    }
    out
}

fn replace_comments(input: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(input.len());
    let mut i = 0;
    while i < input.len() {
        if input[i..].starts_with(b"/*") {
            match input[i + 2..].windows(2).position(|w| w == b"*/") {
                Some(end) => i += 2 + end + 2,
                None => i = input.len(),
            }
            out.push(b' ');
        } else if input[i..].starts_with(b"*/") {
            // A dangling terminator is also replaced, as in ModSecurity.
            out.push(b' ');
            i += 2;
        } else {
            out.push(input[i]);
            i += 1;
        }
    }
    out
}

fn remove_comments(input: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(input.len());
    let mut i = 0;
    while i < input.len() {
        if input[i..].starts_with(b"/*") {
            match input[i + 2..].windows(2).position(|w| w == b"*/") {
                Some(end) => i += 2 + end + 2,
                None => i = input.len(),
            }
        } else if input[i..].starts_with(b"<!--") {
            match input[i + 4..].windows(3).position(|w| w == b"-->") {
                Some(end) => i += 4 + end + 3,
                None => i = input.len(),
            }
        } else if input[i..].starts_with(b"--") || input[i] == b'#' {
            break;
        } else {
            out.push(input[i]);
            i += 1;
        }
    }
    out
}

fn remove_comment_chars(input: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(input.len());
    let mut i = 0;
    while i < input.len() {
        if input[i..].starts_with(b"/*")
            || input[i..].starts_with(b"*/")
            || input[i..].starts_with(b"--")
        {
            i += 2;
        } else if input[i..].starts_with(b"<!--") {
            i += 4;
        } else if input[i..].starts_with(b"-->") {
            i += 3;
        } else if input[i] == b'#' {
            i += 1;
        } else {
            out.push(input[i]);
            i += 1;
        }
    }
    out
}

fn normalize_path(input: &[u8], windows: bool) -> Vec<u8> {
    let converted: Vec<u8> = if windows {
        input
            .iter()
            .map(|b| if *b == b'\\' { b'/' } else { *b })
            .collect()
    } else {
        input.to_vec()
    };
    if converted.is_empty() {
        return converted;
    }
    let absolute = converted[0] == b'/';
    let trailing = converted.ends_with(b"/");
    let mut parts: Vec<&[u8]> = Vec::new();
    for segment in converted.split(|b| *b == b'/') {
        match segment {
            b"" | b"." => {}
            b".." => {
                if parts.last().is_some_and(|last| *last != b"..") {
                    parts.pop();
                } else if !absolute {
                    parts.push(segment);
                }
            }
            _ => parts.push(segment),
        }
    }
    let mut out = Vec::with_capacity(converted.len());
    if absolute {
        out.push(b'/');
    }
    out.extend_from_slice(&parts.join(&b'/'));
    if trailing && !out.ends_with(b"/") {
        out.push(b'/');
    }
    out
}

/// `t:cmdLine`: defeat shell-obfuscation tricks.
fn cmd_line(input: &[u8]) -> Vec<u8> {
    let mut out: Vec<u8> = Vec::with_capacity(input.len());
    let mut space = false;
    for &b in input {
        match b {
            b'"' | b'\'' | b'\\' | b'^' => {}
            b' ' | b',' | b';' | b'\t' | b'\r' | b'\n' => {
                if !space {
                    out.push(b' ');
                    space = true;
                }
            }
            b'/' | b'(' => {
                if space {
                    out.pop();
                }
                space = false;
                out.push(b);
            }
            other => {
                space = false;
                out.push(other.to_ascii_lowercase());
            }
        }
    }
    out
}

fn base64_value(b: u8) -> Option<u8> {
    match b {
        b'A'..=b'Z' => Some(b - b'A'),
        b'a'..=b'z' => Some(b - b'a' + 26),
        b'0'..=b'9' => Some(b - b'0' + 52),
        b'+' | b'-' => Some(62),
        b'/' | b'_' => Some(63),
        _ => None,
    }
}

fn base64_decode(input: &[u8], forgiving: bool) -> Vec<u8> {
    let mut out = Vec::with_capacity(input.len() * 3 / 4);
    let mut buffer = 0u32;
    let mut bits = 0;
    for &b in input {
        if b == b'=' {
            break;
        }
        let Some(value) = base64_value(b) else {
            if forgiving {
                continue;
            }
            break;
        };
        buffer = buffer << 6 | u32::from(value);
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((buffer >> bits) as u8);
        }
    }
    out
}

fn base64_encode(input: &[u8]) -> Vec<u8> {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = Vec::with_capacity(input.len().div_ceil(3) * 4);
    for chunk in input.chunks(3) {
        let mut n = 0u32;
        for (i, b) in chunk.iter().enumerate() {
            n |= u32::from(*b) << (16 - 8 * i);
        }
        for i in 0..4 {
            out.push(if i <= chunk.len() {
                ALPHABET[(n >> (18 - 6 * i) & 63) as usize]
            } else {
                b'='
            });
        }
    }
    out
}

fn hex_decode(input: &[u8]) -> Vec<u8> {
    input
        .chunks(2)
        .filter_map(|pair| Some(hex_val(pair[0])? << 4 | hex_val(*pair.get(1)?)?))
        .collect()
}

fn utf8_to_unicode(input: &[u8]) -> Vec<u8> {
    let text = String::from_utf8_lossy(input);
    let mut out = Vec::with_capacity(input.len());
    for c in text.chars() {
        if c.is_ascii() {
            out.push(c as u8);
        } else {
            out.extend_from_slice(format!("%u{:04x}", c as u32 & 0xffff).as_bytes());
        }
    }
    out
}

fn trim(input: &[u8], left: bool, right: bool) -> Vec<u8> {
    let mut start = 0;
    let mut end = input.len();
    if left {
        while start < end && is_space(input[start]) {
            start += 1;
        }
    }
    if right {
        while end > start && is_space(input[end - 1]) {
            end -= 1;
        }
    }
    input[start..end].to_vec()
}

#[cfg(test)]
mod tests {
    use super::Transform::*;

    fn t(transform: super::Transform, input: &str) -> String {
        String::from_utf8_lossy(&transform.apply(input.as_bytes())).into_owned()
    }

    #[test]
    fn decoders_match_modsecurity_semantics() {
        assert_eq!(t(UrlDecodeUni, "a%20b+%u0041%uff1c"), "a b A<");
        assert_eq!(
            t(HtmlEntityDecode, "&lt;script&gt;&#x41;&#66;&quot"),
            "<script>AB\""
        );
        assert_eq!(t(JsDecode, "\\x3cscript\\u003e\\n"), "<script>\n");
        assert_eq!(t(CssDecode, "\\3c script"), "<script");
        assert_eq!(t(ReplaceComments, "un/**/ion/* x"), "un ion ");
        assert_eq!(t(NormalizePath, "/a/./b/../../etc//passwd"), "/etc/passwd");
        assert_eq!(t(NormalizePathWin, "a\\..\\..\\win.ini"), "../win.ini");
        assert_eq!(t(CmdLine, "C^aT \"/etc/pas\"'swd' ,;x"), "cat/etc/passwd x");
        assert_eq!(t(Base64Decode, "c2VsZWN0"), "select");
        assert_eq!(t(Length, "abcd"), "4");
        assert_eq!(t(CompressWhitespace, "a \t\n b"), "a b");
        assert_eq!(t(Utf8ToUnicode, "aé"), "a%u00e9");
    }
}
