use std::ffi::{c_char, c_int, c_uint};
use std::slice;

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct ist {
    pub ptr: *mut c_char,
    pub len: usize,
}

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct http_hdr {
    pub n: ist,
    pub v: ist,
}

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct h1m {
    pub state: c_uint,
    pub flags: u32,
    pub curr_len: u64,
    pub body_len: u64,
    pub next: u32,
    pub err_code: c_uint,
    pub err_pos: c_int,
    pub err_state: c_int,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub union h1_sl {
    pub rq: h1_sl_rq,
    pub st: h1_sl_st,
}

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct h1_sl_rq {
    pub m: ist,
    pub u: ist,
    pub v: ist,
    pub meth: c_uint,
}

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct h1_sl_st {
    pub v: ist,
    pub c: ist,
    pub r: ist,
    pub status: u16,
}

extern "C" {
    fn h1_headers_to_hdr_list(
        start: *mut c_char,
        stop: *const c_char,
        hdr: *mut http_hdr,
        hdr_num: c_uint,
        h1m: *mut h1m,
        slp: *mut h1_sl,
    ) -> c_int;
}

#[derive(Debug)]
pub struct SafeH1m {
    pub state: u32,
    pub flags: u32,
    pub curr_len: u64,
    pub body_len: u64,
    pub next: u32,
    pub err_code: u32,
    pub err_pos: i32,
    pub err_state: i32,
}

#[derive(Debug)]
pub struct SafeSlRq<'a> {
    pub m: &'a [u8],
    pub u: &'a [u8],
    pub v: &'a [u8],
    pub meth: u32,
}

#[derive(Debug)]
pub struct SafeSlSt<'a> {
    pub v: &'a [u8],
    pub c: &'a [u8],
    pub r: &'a [u8],
    pub status: u16,
}

#[derive(Debug)]
pub enum SafeSl<'a> {
    Request(SafeSlRq<'a>),
    Response(SafeSlSt<'a>),
}

#[derive(Debug)]
pub struct SafeHdr<'a> {
    pub n: &'a [u8],
    pub v: &'a [u8],
}

#[derive(Debug)]
pub struct ParseResult<'a> {
    pub ret: i32,
    pub h1m: SafeH1m,
    pub sl: SafeSl<'a>,
    pub headers: Vec<SafeHdr<'a>>,
}

/// Parses HTTP/1 headers from the given mutable input buffer.
pub fn parse_h1<'a>(
    input: &'a mut [u8],
    max_headers: usize,
    is_response: bool,
) -> ParseResult<'a> {
    let mut h1m = h1m {
        state: 0,
        flags: if is_response { 0x00000004 } else { 0 }, // H1_MF_RESP
        curr_len: 0,
        body_len: 0,
        next: 0,
        err_code: 0,
        err_pos: -2,
        err_state: 0,
    };

    let mut slp = std::mem::MaybeUninit::<h1_sl>::uninit();
    let mut hdrs = vec![
        http_hdr {
            n: ist { ptr: std::ptr::null_mut(), len: 0 },
            v: ist { ptr: std::ptr::null_mut(), len: 0 }
        };
        max_headers
    ];

    let start = input.as_mut_ptr() as *mut c_char;
    let stop = unsafe { start.add(input.len()) };

    let ret = unsafe {
        h1_headers_to_hdr_list(
            start,
            stop,
            hdrs.as_mut_ptr(),
            max_headers as c_uint,
            &mut h1m,
            slp.as_mut_ptr(),
        )
    };

    let safe_h1m = SafeH1m {
        state: h1m.state,
        flags: h1m.flags,
        curr_len: h1m.curr_len,
        body_len: h1m.body_len,
        next: h1m.next,
        err_code: h1m.err_code,
        err_pos: h1m.err_pos,
        err_state: h1m.err_state,
    };

    let safe_ist = |i: ist| -> &[u8] {
        if i.ptr.is_null() || i.len == 0 {
            &[]
        } else {
            unsafe { slice::from_raw_parts(i.ptr as *const u8, i.len) }
        }
    };

    let safe_sl = if is_response {
        let st = unsafe { slp.assume_init().st };
        SafeSl::Response(SafeSlSt {
            v: safe_ist(st.v),
            c: safe_ist(st.c),
            r: safe_ist(st.r),
            status: st.status,
        })
    } else {
        let rq = unsafe { slp.assume_init().rq };
        SafeSl::Request(SafeSlRq {
            m: safe_ist(rq.m),
            u: safe_ist(rq.u),
            v: safe_ist(rq.v),
            meth: rq.meth,
        })
    };

    let mut safe_hdrs = Vec::with_capacity(hdrs.len());
    for h in hdrs {
        if h.n.len == 0 {
            break;
        }
        safe_hdrs.push(SafeHdr {
            n: safe_ist(h.n),
            v: safe_ist(h.v),
        });
    }

    ParseResult {
        ret,
        h1m: safe_h1m,
        sl: safe_sl,
        headers: safe_hdrs,
    }
}
