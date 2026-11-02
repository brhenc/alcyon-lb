// SPDX-License-Identifier: MIT
// Copyright (C) 2013-2015 Willy Tarreau <w@1wt.eu>. See crates/slz/LICENSE.

//! A stateless deflate compressor (raw deflate, gzip, zlib), a port of libslz.
//!
//! # Output-buffer contract
//!
//! libslz leaves the output size to the caller: a buffer smaller than the worst case is a
//! buffer overflow in C. This port turns that into an error, `ErrorKind::WriteZero`:
//!
//! * [`Encoder::encode`], [`Encoder::flush`] and [`Encoder::finish`] compute the most the
//!   call can write (the header if not yet sent, the data as stored blocks, the bit-queue
//!   tail, the trailer) and return `Err(WriteZero)` when `out` is shorter, **before**
//!   changing anything. A refused call leaves the encoder as it was, so the same call may be
//!   repeated with a larger buffer. The bound is a worst case, not the actual size: a call
//!   can be refused although the real output would have fitted. Give `out` at least
//!   [`max_compressed_len`] bytes for a one-shot stream.
//! * As a second line of defence, every write the bit writer cannot place sets a flag and the
//!   call fails; if that ever fires the encoder is inconsistent and must be dropped. Never
//!   `Ok` with a stream that lost bytes.
//!
//! The input length counts in `u32` (gzip's ISIZE is modulo 2^32), as in libslz.
//!
//! # Worst-case size
//!
//! libslz's own statement (slz.c, comment of `slz_rfc1951_encode`): the output may be up to
//! 5 bytes larger than the input per 65535 input bytes, plus 2 bytes for the last block's
//! BFINAL+EOB (10 bits), and one call may emit up to 5 bytes more than its share because up
//! to 31 bits stay in the queue between calls; `SLZ_MAX_DEBT` bounds by 25 bytes the excess
//! over stored blocks. Flush needs 10 bytes and finish 6 (slz.c comments); gzip adds a
//! 10-byte header and an 8-byte trailer, zlib 2 and 4. The constants below are those figures
//! rounded up, and the tests decode a stream written into exactly [`max_compressed_len`]
//! bytes for every format and level.

#![forbid(unsafe_code)]

mod tables;
mod crc;
mod encode;

pub use encode::rfc1951_encode;
use encode::BitQueue;
use std::io::{Error, ErrorKind};

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum Format {
    Deflate = 0,
    Gzip = 1,
    Zlib = 2,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum Level {
    NoCompression = 0,
    Compression = 1,
}

#[derive(Copy, Clone)]
pub struct Encoder {
    pub(crate) queue: u64,
    pub(crate) qbits: u32,
    pub(crate) state: u16,
    pub(crate) level: u8,
    pub(crate) format: u8,
    pub(crate) debt: u8,
    pub(crate) crc32: u32,
    pub(crate) ilen: u32,
}

pub(crate) const SLZ_ST_INIT: u16 = 0;
pub(crate) const SLZ_ST_FIXED: u16 = 1;
pub(crate) const SLZ_ST_EOB: u16 = 2;
pub(crate) const SLZ_ST_LAST: u16 = 3;
pub(crate) const SLZ_ST_END: u16 = 4;
pub(crate) const SLZ_ST_DONE: u16 = 5;

pub(crate) const HASH_BITS: usize = 13;
pub(crate) const SLZ_MAX_DEBT: u8 = 200;
pub(crate) const SLZ_SWITCH_COST: u32 = 52;

const GZIP_HDR: &[u8] = &[0x1F, 0x8B, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04, 0x03];
const ZLIB_HDR: &[u8] = &[0x78, 0x01];


/// Extra room each additional `encode`/`flush` call of a multi-call stream can need on top of
/// [`max_compressed_len`] (queue tail, block header, EOB; libslz: "up to 5 bytes more", flush
/// 10 bytes). Add `CALL_OVERHEAD` per extra call.
pub const CALL_OVERHEAD: usize = 16;

const FINISH_TAIL: usize = 6;
const FLUSH_TAIL: usize = 10;
/// Queue tail (5) + last-chunk BFINAL+EOB (2) + debt (25), rounded up.
const BODY_SLACK: usize = 32;

fn header_len(format: u8) -> usize {
    if format == Format::Gzip as u8 {
        GZIP_HDR.len()
    } else if format == Format::Zlib as u8 {
        ZLIB_HDR.len()
    } else {
        0
    }
}

fn trailer_len(format: u8) -> usize {
    if format == Format::Gzip as u8 {
        8
    } else if format == Format::Zlib as u8 {
        4
    } else {
        0
    }
}

fn body_bound(input_len: usize) -> usize {
    input_len.saturating_add(5 * (input_len / 65535 + 1)).saturating_add(BODY_SLACK)
}

pub(crate) fn short_buffer() -> Error {
    Error::new(ErrorKind::WriteZero, "output buffer too small")
}

/// The number of bytes that always suffice for a stream of `input_len` bytes in `format`
/// made of one `encode` call (`more` either way) followed by one `finish`. For more calls
/// add [`CALL_OVERHEAD`] per extra `encode`/`flush`. It saturates instead of overflowing.
pub fn max_compressed_len(input_len: usize, format: Format) -> usize {
    let f = format as u8;
    header_len(f)
        .saturating_add(body_bound(input_len))
        .saturating_add(FINISH_TAIL)
        .saturating_add(trailer_len(f))
}

impl Encoder {
    pub fn new(format: Format, level: Level) -> Self {
        Self {
            queue: 0,
            qbits: 0,
            state: SLZ_ST_INIT,
            level: level as u8,
            format: format as u8,
            debt: 0,
            crc32: if format == Format::Zlib { 1 } else { 0 },
            ilen: 0,
        }
    }

    /// The header still to send (empty once sent), the most the next call may write for it.
    fn pending_header(&self) -> usize {
        if self.state == SLZ_ST_INIT { header_len(self.format) } else { 0 }
    }

    /// Writes the header if it was not sent and moves out of INIT; returns its length.
    /// The caller has checked that it fits.
    fn send_header(&mut self, out: &mut [u8]) -> usize {
        let n = match self.state == SLZ_ST_INIT {
            false => return 0,
            true if self.format == Format::Gzip as u8 => {
                out[..GZIP_HDR.len()].copy_from_slice(GZIP_HDR);
                GZIP_HDR.len()
            }
            true if self.format == Format::Zlib as u8 => {
                out[..ZLIB_HDR.len()].copy_from_slice(ZLIB_HDR);
                ZLIB_HDR.len()
            }
            true => 0,
        };
        self.state = SLZ_ST_EOB;
        n
    }

    /// Compresses `input` into `out` and returns the bytes written. `Err(WriteZero)`, with the
    /// encoder untouched, when `out` is shorter than the call can need (see the crate docs).
    pub fn encode(&mut self, input: &[u8], out: &mut [u8], more: bool) -> Result<usize, Error> {
        let need = self.pending_header().saturating_add(body_bound(input.len()));
        if out.len() < need {
            return Err(short_buffer());
        }
        let mut out_pos = self.send_header(out);

        self.ilen = self.ilen.wrapping_add(input.len() as u32);
        if self.format == Format::Gzip as u8 {
            self.crc32 = crc::crc32_by4(self.crc32, input);
        } else if self.format == Format::Zlib as u8 {
            self.crc32 = crc::adler32_block(self.crc32, input);
        }

        out_pos += rfc1951_encode(self, &mut out[out_pos..], input, more)?;
        Ok(out_pos)
    }

    /// Emits the pending bits and an empty stored block to byte-align the output.
    pub fn flush(&mut self, out: &mut [u8]) -> Result<usize, Error> {
        if out.len() < self.pending_header() + FLUSH_TAIL {
            return Err(short_buffer());
        }
        let mut out_pos = self.send_header(out);

        if self.qbits == 0 && self.state != SLZ_ST_FIXED && self.state != SLZ_ST_LAST && self.state != SLZ_ST_EOB {
            return Ok(out_pos);
        }

        let mut bq = BitQueue {
            outbuf: &mut out[out_pos..],
            out_pos: 0,
            queue: self.queue,
            qbits: self.qbits,
            overflow: false,
        };

        if self.state != SLZ_ST_EOB {
            self.state = if self.state == SLZ_ST_LAST { SLZ_ST_DONE } else { SLZ_ST_EOB };
            bq.send_eob();
        }

        if self.state == SLZ_ST_DONE {
            bq.flush_bits();
        } else {
            bq.enqueue8(0, 3);
            bq.flush_bits();
            bq.copy_16b(0x0000);
            bq.copy_16b(0xFFFF);
        }
        out_pos += bq.commit(self)?;
        Ok(out_pos)
    }

    /// Ends the stream: last block, padding and the format's trailer.
    pub fn finish(&mut self, out: &mut [u8]) -> Result<usize, Error> {
        if out.len() < self.pending_header() + FINISH_TAIL + trailer_len(self.format) {
            return Err(short_buffer());
        }
        let mut out_pos = self.send_header(out);

        let mut bq = BitQueue {
            outbuf: &mut out[out_pos..],
            out_pos: 0,
            queue: self.queue,
            qbits: self.qbits,
            overflow: false,
        };

        if self.state == SLZ_ST_FIXED || self.state == SLZ_ST_LAST {
            self.state = if self.state == SLZ_ST_LAST { SLZ_ST_DONE } else { SLZ_ST_EOB };
            bq.send_eob();
        }

        if self.state != SLZ_ST_DONE {
            bq.enqueue8(3, 3); // BTYPE=1, BFINAL=1
            self.state = SLZ_ST_DONE;
            bq.send_eob(); // EOB
        }

        bq.flush_bits();
        out_pos += bq.commit(self)?;

        if self.format == Format::Gzip as u8 {
            out[out_pos..out_pos + 4].copy_from_slice(&self.crc32.to_le_bytes());
            out[out_pos + 4..out_pos + 8].copy_from_slice(&self.ilen.to_le_bytes());
            out_pos += 8;
        } else if self.format == Format::Zlib as u8 {
            out[out_pos..out_pos + 4].copy_from_slice(&self.crc32.to_be_bytes());
            out_pos += 4;
        }

        self.state = SLZ_ST_END;
        Ok(out_pos)
    }
}
