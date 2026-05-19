use soroban_sdk::{Bytes, Env};

/// Advances the cursor past RFC8259 JSON whitespace characters.
///
/// Used by the minimal JSON scanner to normalize parsing around delimiters
/// without allocating intermediate buffers.
fn skip_ws(json: &Bytes, mut i: u32) -> u32 {
    let len = json.len();

    while i < len {
        let c = json.get_unchecked(i);

        if c == b' ' || c == b'\n' || c == b'\r' || c == b'\t' {
            i += 1;
        } else {
            break;
        }
    }

    i
}

/// Performs an exact byte-level comparison between a JSON slice and
/// an expected ASCII byte sequence.
///
/// Returns `false` for invalid ranges or length mismatches.
fn json_slice_equals(json: &Bytes, start: u32, end: u32, expected: &[u8]) -> bool {
    if end < start {
        return false;
    }

    if end - start != expected.len() as u32 {
        return false;
    }

    let mut i = 0;

    while i < expected.len() as u32 {
        if json.get_unchecked(start + i) != expected[i as usize] {
            return false;
        }

        i += 1;
    }

    true
}

/// Converts a static ASCII byte slice into Soroban `Bytes`.
///
/// Primarily used for deterministic on-chain comparison values and
/// protocol constants.
pub fn ascii_bytes(env: &Env, input: &[u8]) -> Bytes {
    let mut out = Bytes::new(env);

    let mut i = 0;
    while i < input.len() {
        out.push_back(input[i]);
        i += 1;
    }

    out
}

/// Decodes and compares a JSON string value against `expected`.
///
/// Supports standard JSON escape sequences except unicode escapes
/// (`\\uXXXX`), which are intentionally rejected to keep parsing logic
/// deterministic and minimal for WebAuthn validation flows.
///
/// Returns `false` on malformed or unsupported encodings.
pub fn json_string_value_equals(env: &Env, json: &Bytes, start: u32, expected: &Bytes) -> bool {
    let mut decoded = Bytes::new(env);
    let len = json.len();
    let mut i = start;

    while i < len {
        let c = json.get_unchecked(i);

        if c == b'"' {
            return decoded == *expected;
        }

        if c == b'\\' {
            if i + 1 >= len {
                return false;
            }

            let esc = json.get_unchecked(i + 1);

            match esc {
                b'"' => decoded.push_back(b'"'),
                b'\\' => decoded.push_back(b'\\'),
                b'/' => decoded.push_back(b'/'),
                b'b' => decoded.push_back(0x08),
                b'f' => decoded.push_back(0x0c),
                b'n' => decoded.push_back(b'\n'),
                b'r' => decoded.push_back(b'\r'),
                b't' => decoded.push_back(b'\t'),
                b'u' => return false,
                _ => return false,
            }

            i += 2;
        } else {
            decoded.push_back(c);
            i += 1;
        }
    }

    false
}

/// Locates the terminating quote of a JSON string.
///
/// Escaped characters are skipped to ensure escaped quotes are not
/// interpreted as string terminators.
pub fn find_json_string_end(json: &Bytes, start: u32) -> Option<u32> {
    let len = json.len();
    let mut i = start;

    while i < len {
        let c = json.get_unchecked(i);

        if c == b'\\' {
            i += 2;
            continue;
        }

        if c == b'"' {
            return Some(i);
        }

        i += 1;
    }

    None
}

/// Scans a JSON object for a matching string field and compares its value
/// against `expected_value`.
///
/// This is a constrained JSON scanner intended specifically for trusted
/// WebAuthn `clientDataJSON` verification flows. It is not a general-purpose
/// JSON parser and intentionally supports only ASCII field names and
/// standard non-unicode string escapes.
///
/// The first matching field encountered is evaluated.
pub fn json_string_field_equals(
    env: &Env,
    json: &Bytes,
    key: &[u8],
    expected_value: &Bytes,
) -> bool {
    let len = json.len();
    let mut i = 0;

    while i < len {
        if json.get_unchecked(i) != b'"' {
            i += 1;
            continue;
        }

        let key_start = i + 1;
        let Some(key_end) = find_json_string_end(json, key_start) else {
            return false;
        };

        if json_slice_equals(json, key_start, key_end, key) {
            let mut p = key_end + 1;

            p = skip_ws(json, p);

            if p >= len || json.get_unchecked(p) != b':' {
                return false;
            }

            p += 1;
            p = skip_ws(json, p);

            if p >= len || json.get_unchecked(p) != b'"' {
                return false;
            }

            return json_string_value_equals(env, json, p + 1, expected_value);
        }

        i = key_end + 1;
    }

    false
}

/// Maps a validated 6-bit Base64URL sextet (`0..=63`) to its ASCII
/// character representation.
///
/// Input bounds are assumed to be enforced by the encoder logic.
pub fn base64url_char(v: u8) -> u8 {
    if v < 26 {
        b'A' + v
    } else if v < 52 {
        b'a' + (v - 26)
    } else if v < 62 {
        b'0' + (v - 52)
    } else if v == 62 {
        b'-'
    } else {
        b'_'
    }
}

/// Encodes input bytes using RFC4648 Base64URL encoding without padding.
///
/// Produces WebAuthn-compatible challenge encoding using the URL-safe
/// alphabet (`A-Z`, `a-z`, `0-9`, `-`, `_`) and omits trailing `=` padding.
pub fn base64url_encode_no_pad(env: &Env, input: &Bytes) -> Bytes {
    let mut out = Bytes::new(env);
    let len = input.len();
    let mut i = 0;

    while i + 3 <= len {
        let b0 = input.get_unchecked(i);
        let b1 = input.get_unchecked(i + 1);
        let b2 = input.get_unchecked(i + 2);

        out.push_back(base64url_char(b0 >> 2));
        out.push_back(base64url_char(((b0 & 0x03) << 4) | (b1 >> 4)));
        out.push_back(base64url_char(((b1 & 0x0f) << 2) | (b2 >> 6)));
        out.push_back(base64url_char(b2 & 0x3f));

        i += 3;
    }

    let rem = len - i;

    if rem == 1 {
        let b0 = input.get_unchecked(i);

        out.push_back(base64url_char(b0 >> 2));
        out.push_back(base64url_char((b0 & 0x03) << 4));
    } else if rem == 2 {
        let b0 = input.get_unchecked(i);
        let b1 = input.get_unchecked(i + 1);

        out.push_back(base64url_char(b0 >> 2));
        out.push_back(base64url_char(((b0 & 0x03) << 4) | (b1 >> 4)));
        out.push_back(base64url_char((b1 & 0x0f) << 2));
    }

    out
}
