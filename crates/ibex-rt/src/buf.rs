// SPDX-License-Identifier: GPL-2.0-or-later
// Derived from HAProxy 1.0.2 struct buffer (haproxy.c) and modern src/buf.c.
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! A fixed-capacity byte FIFO.
//!
//! Allocated once at stream setup and never grown, so forwarding never allocates. This
//! is the direct descendant of 1.0's `struct buffer { char *r, *w; int l; ... }`, with
//! the pointer arithmetic replaced by indices.

/// A fixed-capacity FIFO of bytes.
///
/// Data lives in `[head, head+len)`. Rather than a true ring, the buffer compacts when
/// the tail runs out of room, exactly as `HAProxy`'s does: a proxy's access pattern is
/// fill-then-drain, so a compaction is rare and a wrap check on every byte is not.
#[derive(Debug)]
pub struct Buf {
    data: Box<[u8]>,
    head: usize,
    len: usize,
}

impl Buf {
    #[must_use]
    pub fn with_capacity(cap: usize) -> Self {
        Buf {
            data: vec![0u8; cap].into_boxed_slice(),
            head: 0,
            len: 0,
        }
    }

    #[must_use]
    #[inline]
    pub const fn len(&self) -> usize {
        self.len
    }

    #[must_use]
    #[inline]
    pub const fn is_empty(&self) -> bool {
        self.len == 0
    }

    #[must_use]
    #[inline]
    pub fn capacity(&self) -> usize {
        self.data.len()
    }

    #[must_use]
    #[inline]
    pub fn is_full(&self) -> bool {
        self.len == self.data.len()
    }

    /// Bytes available to read.
    #[must_use]
    #[inline]
    pub fn readable(&self) -> &[u8] {
        &self.data[self.head..self.head + self.len]
    }

    /// Moves readable data to index 0 so full remaining capacity is contiguous at the tail.
    pub fn compact(&mut self) {
        if self.head > 0 {
            if self.len > 0 {
                self.data.copy_within(self.head..self.head + self.len, 0);
            }
            self.head = 0;
        }
    }

    /// Contiguous space available to write into, compacting first if that helps.
    pub fn writable(&mut self) -> &mut [u8] {
        if self.head > 0 && self.head + self.len == self.data.len() {
            self.compact();
        }
        let start = self.head + self.len;
        &mut self.data[start..]
    }

    /// Commits `n` bytes written into [`Self::writable`].
    ///
    /// # Panics
    /// If `n` exceeds the space reported by the last `writable()` call.
    pub fn commit(&mut self, n: usize) {
        assert!(
            self.head + self.len + n <= self.data.len(),
            "commit({n}) past end of buffer"
        );
        self.len += n;
    }

    /// Discards `n` bytes from the front.
    pub fn consume(&mut self, n: usize) {
        let n = n.min(self.len);
        self.head += n;
        self.len -= n;
        if self.len == 0 {
            self.head = 0;
        }
    }

    pub fn clear(&mut self) {
        self.head = 0;
        self.len = 0;
    }

    /// Replaces the leading `old_len` bytes in the readable portion of the buffer
    /// with `new_data`.
    pub fn replace_prefix(&mut self, old_len: usize, new_data: &[u8]) {
        let old_len = old_len.min(self.len);
        let rem_len = self.len - old_len;
        let new_total = (new_data.len() + rem_len).min(self.data.len());
        let rem_dest = new_data.len();
        let rem_take = (new_total - rem_dest).min(rem_len);

        if self.head + old_len != rem_dest && rem_take > 0 {
            let src_start = self.head + old_len;
            self.data
                .copy_within(src_start..src_start + rem_take, rem_dest);
        }
        let write_len = new_data.len().min(self.data.len());
        self.data[..write_len].copy_from_slice(&new_data[..write_len]);
        self.head = 0;
        self.len = new_total;
    }

    /// Injects or updates an HTTP header in the readable portion of the buffer.
    ///
    /// Compacts the buffer if necessary so readable data starts at index 0 and maximum
    /// tail capacity is available.
    /// Returns `true` if successful, or `false` if buffer capacity was exceeded or malformed.
    pub fn inject_http_header(&mut self, name: &str, value: &str) -> bool {
        if self.head > 0 {
            self.data.copy_within(self.head..self.head + self.len, 0);
            self.head = 0;
        }
        if let Some(new_len) =
            ibex_proto::inject_http_header_with_len(&mut self.data, self.len, name, value)
        {
            self.len = new_len;
            true
        } else {
            false
        }
    }

    /// Removes all occurrences of an HTTP header from the readable portion of the buffer.
    ///
    /// Returns `true` if successful, or `false` if the buffer is malformed.
    pub fn remove_http_header(&mut self, name: &str) -> bool {
        if self.head > 0 {
            self.data.copy_within(self.head..self.head + self.len, 0);
            self.head = 0;
        }
        if let Some(new_len) =
            ibex_proto::remove_http_header_with_len(&mut self.data, self.len, name)
        {
            self.len = new_len;
            true
        } else {
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::Buf;

    #[test]
    fn fills_drains_and_resets() {
        let mut b = Buf::with_capacity(8);
        assert!(b.is_empty());
        b.writable()[..4].copy_from_slice(b"abcd");
        b.commit(4);
        assert_eq!(b.readable(), b"abcd");
        b.consume(2);
        assert_eq!(b.readable(), b"cd");
        b.consume(2);
        assert!(b.is_empty());
        assert_eq!(b.capacity(), 8, "capacity never changes");
    }

    #[test]
    fn compacts_rather_than_wrapping() {
        let mut b = Buf::with_capacity(8);
        b.writable()[..8].copy_from_slice(b"12345678");
        b.commit(8);
        assert!(b.is_full());
        b.consume(6);
        assert_eq!(b.readable(), b"78");
        // Tail is exhausted; writable() must compact to expose room again.
        let w = b.writable();
        assert_eq!(w.len(), 6, "compaction should free the consumed prefix");
        w[..3].copy_from_slice(b"abc");
        b.commit(3);
        assert_eq!(b.readable(), b"78abc");
    }

    #[test]
    fn partial_consume_preserves_order() {
        let mut b = Buf::with_capacity(16);
        for chunk in [b"aa".as_slice(), b"bb", b"cc"] {
            let w = b.writable();
            w[..chunk.len()].copy_from_slice(chunk);
            b.commit(chunk.len());
        }
        assert_eq!(b.readable(), b"aabbcc");
        b.consume(3);
        assert_eq!(b.readable(), b"bcc");
    }

    #[test]
    fn over_consume_is_clamped_not_a_panic() {
        // Untrusted input drives these lengths indirectly; clamping beats trapping.
        let mut b = Buf::with_capacity(4);
        b.writable()[..2].copy_from_slice(b"hi");
        b.commit(2);
        b.consume(999);
        assert!(b.is_empty());
    }

    #[test]
    fn replace_prefix_shrink_and_grow() {
        let mut b = Buf::with_capacity(32);
        b.writable()[..7].copy_from_slice(b"1234rem");
        b.commit(7);
        assert_eq!(b.readable(), b"1234rem");

        // Grow prefix
        b.replace_prefix(4, b"ABCDE");
        assert_eq!(b.readable(), b"ABCDErem");

        // Shrink prefix
        b.replace_prefix(5, b"XYZ");
        assert_eq!(b.readable(), b"XYZrem");
    }

    #[test]
    fn buf_http_header_injection_and_removal() {
        let mut b = Buf::with_capacity(256);
        let req = b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n";
        b.writable()[..req.len()].copy_from_slice(req);
        b.commit(req.len());

        // Inject new header
        assert!(b.inject_http_header("X-Forwarded-Proto", "https"));
        let readable_str = std::str::from_utf8(b.readable()).unwrap();
        assert!(readable_str.contains("X-Forwarded-Proto: https\r\n"));
        assert!(readable_str.ends_with("\r\n\r\n"));

        // Update existing header
        assert!(b.inject_http_header("Host", "api.example.com"));
        let updated_str = std::str::from_utf8(b.readable()).unwrap();
        assert!(updated_str.contains("Host: api.example.com\r\n"));
        assert!(!updated_str.contains("Host: example.com\r\n"));

        // Remove header
        assert!(b.remove_http_header("X-Forwarded-Proto"));
        let removed_str = std::str::from_utf8(b.readable()).unwrap();
        assert!(!removed_str.contains("X-Forwarded-Proto"));
        assert_eq!(
            removed_str,
            "GET / HTTP/1.1\r\nHost: api.example.com\r\n\r\n"
        );
    }
}
