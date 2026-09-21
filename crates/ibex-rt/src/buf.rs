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
/// the tail runs out of room, exactly as HAProxy's does: a proxy's access pattern is
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

    /// Contiguous space available to write into, compacting first if that helps.
    pub fn writable(&mut self) -> &mut [u8] {
        if self.head + self.len == self.data.len() && self.head > 0 {
            self.data.copy_within(self.head..self.head + self.len, 0);
            self.head = 0;
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
}
