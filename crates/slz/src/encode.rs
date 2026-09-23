use crate::tables::*;
use crate::{Encoder, SLZ_MAX_DEBT, SLZ_SWITCH_COST, HASH_BITS, SLZ_ST_EOB, SLZ_ST_FIXED, SLZ_ST_LAST, SLZ_ST_DONE};

pub const SLZ_LAST_COST: u32 = 42;
pub const SLZ_LAST_COST_EOB: u32 = 32;

#[inline(always)]
fn slz_hash(a: u32) -> u32 {
    a.wrapping_mul(0x1af42f) >> (32 - HASH_BITS)
}

#[inline(always)]
fn memmatch(a: &[u8], b: &[u8], max: usize) -> usize {
    let mut len = 0;
    let max = max.min(a.len()).min(b.len());
    while len + 8 <= max {
        let x = u64::from_le_bytes(a[len..len+8].try_into().unwrap());
        let y = u64::from_le_bytes(b[len..len+8].try_into().unwrap());
        let xor = x ^ y;
        if xor != 0 {
            return len + (xor.trailing_zeros() / 8) as usize;
        }
        len += 8;
    }
    while len < max && a[len] == b[len] {
        len += 1;
    }
    len
}

pub struct BitQueue<'a> {
    pub outbuf: &'a mut [u8],
    pub out_pos: usize,
    pub queue: u64,
    pub qbits: u32,
}

impl<'a> BitQueue<'a> {
    #[inline(always)]
    pub fn enqueue24(&mut self, x: u64, xbits: u32) {
        let mut queue = self.queue + (x << self.qbits);
        let mut qbits = self.qbits + xbits;

        if qbits >= 32 && self.out_pos + 4 <= self.outbuf.len() {
            self.outbuf[self.out_pos..self.out_pos+4].copy_from_slice(&(queue as u32).to_le_bytes());
            queue >>= 32;
            qbits -= 32;
            self.out_pos += 4;
        }
        
        if qbits >= 32 {
            while qbits >= 8 && self.out_pos < self.outbuf.len() {
                self.outbuf[self.out_pos] = queue as u8;
                queue >>= 8;
                qbits -= 8;
                self.out_pos += 1;
            }
        }

        self.queue = queue;
        self.qbits = qbits;
    }
    
    #[inline(always)]
    pub fn enqueue8(&mut self, x: u64, xbits: u32) {
        self.enqueue24(x, xbits);
    }

    #[inline(always)]
    pub fn send_eob(&mut self) {
        self.enqueue8(0, 7);
    }

    #[inline(always)]
    pub fn flush_bits(&mut self) {
        if self.qbits > 0 && self.out_pos < self.outbuf.len() {
            self.outbuf[self.out_pos] = self.queue as u8;
            self.out_pos += 1;
        }
        if self.qbits > 8 && self.out_pos < self.outbuf.len() {
            self.outbuf[self.out_pos] = (self.queue >> 8) as u8;
            self.out_pos += 1;
        }
        if self.qbits > 16 && self.out_pos < self.outbuf.len() {
            self.outbuf[self.out_pos] = (self.queue >> 16) as u8;
            self.out_pos += 1;
        }
        if self.qbits > 24 && self.out_pos < self.outbuf.len() {
            self.outbuf[self.out_pos] = (self.queue >> 24) as u8;
            self.out_pos += 1;
        }
        self.queue = 0;
        self.qbits = 0;
    }

    #[inline(always)]
    pub fn copy_16b(&mut self, word: u16) {
        if self.out_pos + 2 <= self.outbuf.len() {
            self.outbuf[self.out_pos..self.out_pos+2].copy_from_slice(&word.to_le_bytes());
            self.out_pos += 2;
        }
    }

    #[inline(always)]
    pub fn copy_data(&mut self, data: &[u8]) {
        let len = data.len();
        if self.out_pos + len <= self.outbuf.len() {
            self.outbuf[self.out_pos..self.out_pos+len].copy_from_slice(data);
            self.out_pos += len;
        }
    }
}

pub fn copy_lit(strm: &mut Encoder, bq: &mut BitQueue, buf: &[u8], more: bool) {
    let mut len = buf.len() as u32;
    let mut buf_pos = 0;

    loop {
        let mut len2 = len;
        if len2 > 65535 {
            len2 = 65535;
        }
        len -= len2;

        if strm.state != SLZ_ST_EOB {
            bq.send_eob();
        }

        strm.state = if more || len > 0 { SLZ_ST_EOB } else { SLZ_ST_DONE };

        bq.enqueue8(if more || len > 0 { 0 } else { 1 }, 3);
        bq.flush_bits();
        bq.copy_16b(len2 as u16);
        bq.copy_16b(!(len2 as u16));
        bq.copy_data(&buf[buf_pos..buf_pos + len2 as usize]);
        buf_pos += len2 as usize;

        if len == 0 { break; }
    }
}

pub fn copy_lit_huff(strm: &mut Encoder, bq: &mut BitQueue, buf: &[u8], more: bool) {
    if strm.state == SLZ_ST_EOB {
        strm.state = if more { SLZ_ST_FIXED } else { SLZ_ST_LAST };
        bq.enqueue8(if more { 2 } else { 3 }, 3);
    } else if !more {
        bq.send_eob();
        strm.state = SLZ_ST_LAST;
        bq.enqueue8(3, 3);
    }

    for &b in buf {
        let huff = FIXED_HUFF[b as usize] as u64;
        bq.enqueue24(huff >> 4, (huff & 15) as u32);
    }
}

pub fn rfc1951_encode(strm: &mut Encoder, out: &mut [u8], input: &[u8], more: bool) -> usize {
    let mut refs = [(-32769_i64) as u64; 1 << HASH_BITS];
    let mut bq = BitQueue {
        outbuf: out,
        out_pos: 0,
        queue: strm.queue,
        qbits: strm.qbits,
    };
    
    let ilen = input.len();
    let mut rem = ilen;
    let mut pos = 0;
    let mut plit: u32 = 0;
    let mut bit9: u32 = 0;

    if strm.level == 0 {
        plit = ilen as u32;
        pos = ilen;
        bit9 = 52;
        rem = 0;
    } else {
        while rem >= 4 {
            let word = u32::from_le_bytes(input[pos..pos+4].try_into().unwrap());
            let h = slz_hash(word);
            
            let ent = refs[h as usize];
            let last = (ent as u32) as usize;
            
            refs[h as usize] = (pos as u64) | ((word as u64) << 32);
            
            if (ent >> 32) as u32 != word {
                rem -= 1;
                plit += 1;
                bit9 += (input[pos] >= 144) as u32;
                pos += 1;
                continue;
            }

            let dist_offset = pos.wrapping_sub(last).wrapping_sub(1);
            if dist_offset >= 32768 {
                rem -= 1;
                plit += 1;
                bit9 += (input[pos] >= 144) as u32;
                pos += 1;
                continue;
            }
            
            let mlen = memmatch(&input[pos+4..], &input[last+4..], (if rem > 258 { 258 } else { rem }) - 4) + 4;
            
            if bit9 >= 52 && mlen < 6 {
                rem -= 1;
                plit += 1;
                bit9 += (input[pos] >= 144) as u32;
                pos += 1;
                continue;
            }
            
            let code = LEN_FH[mlen];
            let dist = FH_DIST_TABLE[dist_offset];
            
            if (strm.state == SLZ_ST_EOB || strm.debt >= SLZ_MAX_DEBT) &&
               (dist & 0x1f) + (code >> 16) + SLZ_SWITCH_COST > 8 * mlen as u32 {
                rem -= 1;
                plit += 1;
                bit9 += (input[pos] >= 144) as u32;
                pos += 1;
                continue;
            }
            
            if plit > 0 {
                if bit9 >= SLZ_SWITCH_COST || strm.debt >= SLZ_MAX_DEBT {
                    copy_lit(strm, &mut bq, &input[pos - plit as usize..pos], true);
                } else {
                    copy_lit_huff(strm, &mut bq, &input[pos - plit as usize..pos], true);
                    strm.debt = strm.debt.saturating_add(bit9 as u8);
                }
                plit = 0;
            }

            if strm.state == SLZ_ST_EOB {
                strm.state = SLZ_ST_FIXED;
                bq.enqueue8(0x02, 3); // BTYPE = 01, BFINAL = 0
            }

            bq.enqueue24((code & 0xFFFF) as u64, code >> 16);
            bq.enqueue24((dist >> 5) as u64, dist & 0x1F);

            let c = (strm.debt as u32) + (code >> 16) + (dist & 0x1f);
            if c > 8 * (mlen as u32) {
                strm.debt = (c - 8 * (mlen as u32)) as u8;
            } else {
                strm.debt = 0;
            }

            bit9 = 0;
            pos += mlen;
            rem -= mlen;
        }
    }

    while rem > 0 {
        rem -= 1;
        plit += 1;
        bit9 += (input[pos] >= 144) as u32;
        pos += 1;
    }

    if plit > 0 {
        let cost = if more { SLZ_SWITCH_COST } else { if strm.state == SLZ_ST_EOB { SLZ_LAST_COST_EOB } else { SLZ_LAST_COST } };
        if bit9 >= cost || strm.debt >= SLZ_MAX_DEBT {
            copy_lit(strm, &mut bq, &input[pos - plit as usize..pos], more);
        } else {
            copy_lit_huff(strm, &mut bq, &input[pos - plit as usize..pos], more);
        }
    }

    strm.queue = bq.queue;
    strm.qbits = bq.qbits;
    bq.out_pos
}
