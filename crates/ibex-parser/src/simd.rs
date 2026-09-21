//! SIMD-accelerated tokenization and delimiter scanning for HTTP parsers.

use memchr::{memchr, memchr2};

/// High-performance SIMD-accelerated byte scanning primitives.
pub struct SimdScanner;

impl SimdScanner {
    /// Finds the next CRLF (`\r\n`) in the byte stream.
    #[inline(always)]
    pub fn find_crlf(src: &[u8]) -> Option<usize> {
        let mut offset = 0;
        while let Some(pos) = memchr(b'\r', &src[offset..]) {
            let cr_idx = offset + pos;
            if cr_idx + 1 < src.len() && src[cr_idx + 1] == b'\n' {
                return Some(cr_idx);
            }
            offset = cr_idx + 1;
            if offset >= src.len() {
                break;
            }
        }
        None
    }

    /// Finds the next colon separator (`:`) in header line.
    #[inline(always)]
    pub fn find_colon(src: &[u8]) -> Option<usize> {
        memchr(b':', src)
    }

    /// Finds next whitespace (space ` ` or tab `\t`).
    #[inline(always)]
    pub fn find_space_or_tab(src: &[u8]) -> Option<usize> {
        memchr2(b' ', b'\t', src)
    }

    /// Validates whether a byte slice contains valid HTTP token characters.
    #[inline(always)]
    pub fn is_valid_token(src: &[u8]) -> bool {
        for &b in src {
            if !matches!(b, b'!' | b'#' | b'$' | b'%' | b'&' | b'\'' | b'*' | b'+' | b'-' | b'.' | b'^' | b'_' | b'`' | b'|' | b'~' | b'0'..=b'9' | b'a'..=b'z' | b'A'..=b'Z') {
                return false;
            }
        }
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_simd_crlf_search() {
        let data = b"GET /index.html HTTP/1.1\r\nHost: example.com\r\n\r\n";
        let first_crlf = SimdScanner::find_crlf(data).expect("Found crlf");
        assert_eq!(first_crlf, 24);
    }

    #[test]
    fn test_simd_colon_search() {
        let data = b"Host: localhost:8080";
        assert_eq!(SimdScanner::find_colon(data), Some(4));
    }
}
