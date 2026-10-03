// SPDX-License-Identifier: MIT
// Copyright (C) 2013-2015 Willy Tarreau <w@1wt.eu>. See crates/slz/LICENSE.

#![forbid(unsafe_code)]

mod tables;
mod crc;
mod encode;

pub use encode::rfc1951_encode;
use encode::BitQueue;

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

    pub fn encode(&mut self, input: &[u8], out: &mut [u8], more: bool) -> Result<usize, std::io::Error> {
        let mut out_pos = 0;
        
        self.ilen = self.ilen.wrapping_add(input.len() as u32);

        if self.state == SLZ_ST_INIT {
            if self.format == Format::Gzip as u8 {
                if out.len() < out_pos + GZIP_HDR.len() {
                    return Err(std::io::Error::new(std::io::ErrorKind::WriteZero, "buffer too small"));
                }
                out[out_pos..out_pos + GZIP_HDR.len()].copy_from_slice(GZIP_HDR);
                out_pos += GZIP_HDR.len();
                self.state = SLZ_ST_EOB;
            } else if self.format == Format::Zlib as u8 {
                if out.len() < out_pos + ZLIB_HDR.len() {
                    return Err(std::io::Error::new(std::io::ErrorKind::WriteZero, "buffer too small"));
                }
                out[out_pos..out_pos + ZLIB_HDR.len()].copy_from_slice(ZLIB_HDR);
                out_pos += ZLIB_HDR.len();
                self.state = SLZ_ST_EOB;
            } else {
                self.state = SLZ_ST_EOB;
            }
        }

        if self.format == Format::Gzip as u8 {
            self.crc32 = crc::crc32_by4(self.crc32, input);
        } else if self.format == Format::Zlib as u8 {
            self.crc32 = crc::adler32_block(self.crc32, input);
        }

        out_pos += rfc1951_encode(self, &mut out[out_pos..], input, more);
        Ok(out_pos)
    }

    pub fn flush(&mut self, out: &mut [u8]) -> Result<usize, std::io::Error> {
        let mut out_pos = 0;
        if self.state == SLZ_ST_INIT {
            if self.format == Format::Gzip as u8 {
                if out.len() < out_pos + GZIP_HDR.len() {
                    return Err(std::io::Error::new(std::io::ErrorKind::WriteZero, "buffer too small"));
                }
                out[out_pos..out_pos + GZIP_HDR.len()].copy_from_slice(GZIP_HDR);
                out_pos += GZIP_HDR.len();
                self.state = SLZ_ST_EOB;
            } else if self.format == Format::Zlib as u8 {
                if out.len() < out_pos + ZLIB_HDR.len() {
                    return Err(std::io::Error::new(std::io::ErrorKind::WriteZero, "buffer too small"));
                }
                out[out_pos..out_pos + ZLIB_HDR.len()].copy_from_slice(ZLIB_HDR);
                out_pos += ZLIB_HDR.len();
                self.state = SLZ_ST_EOB;
            } else {
                self.state = SLZ_ST_EOB;
            }
        }
        
        if self.qbits == 0 && self.state != SLZ_ST_FIXED && self.state != SLZ_ST_LAST && self.state != SLZ_ST_EOB {
            return Ok(out_pos);
        }
        
        let mut bq = BitQueue {
            outbuf: &mut out[out_pos..],
            out_pos: 0,
            queue: self.queue,
            qbits: self.qbits,
        };

        if self.state != SLZ_ST_EOB {
            self.state = if self.state == SLZ_ST_LAST { SLZ_ST_DONE } else { SLZ_ST_EOB };
            bq.send_eob();
        }

        if self.state == SLZ_ST_DONE {
            bq.flush_bits();
            out_pos += bq.out_pos;
            self.queue = bq.queue;
            self.qbits = bq.qbits;
            return Ok(out_pos);
        }

        bq.enqueue8(0, 3);
        bq.flush_bits();
        bq.copy_16b(0x0000);
        bq.copy_16b(0xFFFF);
        out_pos += bq.out_pos;
        
        self.queue = bq.queue;
        self.qbits = bq.qbits;
        Ok(out_pos)
    }

    pub fn finish(&mut self, out: &mut [u8]) -> Result<usize, std::io::Error> {
        let mut out_pos = 0;
        if self.state == SLZ_ST_INIT {
            if self.format == Format::Gzip as u8 {
                if out.len() < out_pos + GZIP_HDR.len() {
                    return Err(std::io::Error::new(std::io::ErrorKind::WriteZero, "buffer too small"));
                }
                out[out_pos..out_pos + GZIP_HDR.len()].copy_from_slice(GZIP_HDR);
                out_pos += GZIP_HDR.len();
                self.state = SLZ_ST_EOB;
            } else if self.format == Format::Zlib as u8 {
                if out.len() < out_pos + ZLIB_HDR.len() {
                    return Err(std::io::Error::new(std::io::ErrorKind::WriteZero, "buffer too small"));
                }
                out[out_pos..out_pos + ZLIB_HDR.len()].copy_from_slice(ZLIB_HDR);
                out_pos += ZLIB_HDR.len();
                self.state = SLZ_ST_EOB;
            } else {
                self.state = SLZ_ST_EOB;
            }
        }

        let mut bq = BitQueue {
            outbuf: &mut out[out_pos..],
            out_pos: 0,
            queue: self.queue,
            qbits: self.qbits,
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
        out_pos += bq.out_pos;
        
        self.queue = bq.queue;
        self.qbits = bq.qbits;

        // Trailer
        if self.format == Format::Gzip as u8 {
            if out.len() < out_pos + 8 { return Err(std::io::Error::new(std::io::ErrorKind::WriteZero, "buffer too small")); }
            out[out_pos..out_pos+4].copy_from_slice(&self.crc32.to_le_bytes());
            out_pos += 4;
            out[out_pos..out_pos+4].copy_from_slice(&self.ilen.to_le_bytes());
            out_pos += 4;
        } else if self.format == Format::Zlib as u8 {
            if out.len() < out_pos + 4 { return Err(std::io::Error::new(std::io::ErrorKind::WriteZero, "buffer too small")); }
            out[out_pos] = (self.crc32 >> 24) as u8;
            out[out_pos+1] = (self.crc32 >> 16) as u8;
            out[out_pos+2] = (self.crc32 >> 8) as u8;
            out[out_pos+3] = self.crc32 as u8;
            out_pos += 4;
        }

        self.state = SLZ_ST_END;
        Ok(out_pos)
    }
}
