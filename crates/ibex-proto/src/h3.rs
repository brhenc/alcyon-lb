use crate::htx::{HeaderField, HtxBlock, HttpMethod, HttpVersion, RequestLine, ResponseLine};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum H3Error {
    NoError = 0x0100,
    GeneralProtocolError = 0x0101,
    InternalError = 0x0102,
    StreamCreationError = 0x0103,
    ClosedCriticalStream = 0x0104,
    FrameUnexpected = 0x0105,
    FrameError = 0x0106,
    ExcessiveLoad = 0x0107,
    IdError = 0x0108,
    SettingsError = 0x0109,
    MissingSettings = 0x010A,
    RequestRejected = 0x010B,
    RequestCancelled = 0x010C,
    RequestIncomplete = 0x010D,
    MessageError = 0x010E,
    ConnectError = 0x010F,
    VersionFallback = 0x0110,
    QpackDecompressionFailed = 0x0200,
    QpackEncoderStreamError = 0x0201,
    QpackDecoderStreamError = 0x0202,
}

pub fn parse_varint(data: &[u8], offset: &mut usize) -> Result<u64, H3Error> {
    if *offset >= data.len() {
        return Err(H3Error::FrameError);
    }
    let first = data[*offset];
    let len = 1 << (first >> 6);
    if *offset + len > data.len() {
        return Err(H3Error::FrameError);
    }
    let mut val = u64::from(first & 0x3f);
    for i in 1..len {
        val = (val << 8) | u64::from(data[*offset + i]);
    }
    *offset += len;
    Ok(val)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Frame<'a> {
    Data(&'a [u8]),
    Headers(&'a [u8]),
    CancelPush(u64),
    Settings(&'a [u8]),
    PushPromise(u64, &'a [u8]),
    GoAway(u64),
    MaxPushId(u64),
    Unknown(u64, &'a [u8]),
}

pub fn parse_frame<'a>(data: &'a [u8], offset: &mut usize) -> Result<Frame<'a>, H3Error> {
    let frame_type = parse_varint(data, offset)?;
    let length = parse_varint(data, offset)?;
    
    let length_usize = usize::try_from(length).unwrap_or(usize::MAX);
    if length_usize == usize::MAX || *offset + length_usize > data.len() {
        return Err(H3Error::FrameError);
    }
    
    let payload = &data[*offset..*offset + length_usize];
    *offset += length_usize;
    
    match frame_type {
        0x00 => Ok(Frame::Data(payload)),
        0x01 => Ok(Frame::Headers(payload)),
        0x03 => {
            let mut o = 0;
            let push_id = parse_varint(payload, &mut o)?;
            Ok(Frame::CancelPush(push_id))
        },
        0x04 => Ok(Frame::Settings(payload)),
        0x05 => {
            let mut o = 0;
            let push_id = parse_varint(payload, &mut o)?;
            Ok(Frame::PushPromise(push_id, &payload[o..]))
        },
        0x07 => {
            let mut o = 0;
            let stream_id = parse_varint(payload, &mut o)?;
            Ok(Frame::GoAway(stream_id))
        },
        0x0d => {
            let mut o = 0;
            let push_id = parse_varint(payload, &mut o)?;
            Ok(Frame::MaxPushId(push_id))
        },
        _ => Ok(Frame::Unknown(frame_type, payload)),
    }
}

pub fn headers_to_htx(decoded_headers: Vec<HeaderField>) -> Vec<HtxBlock> {
    let mut method = None;
    let mut path = None;
    let mut status = None;
    let mut regular_headers = Vec::new();

    for h in decoded_headers {
        match h.name.as_str() {
            ":method" => method = Some(HttpMethod::from_bytes(h.value.as_bytes())),
            ":path" => path = Some(h.value),
            ":status" => status = h.value.parse::<u16>().ok(),
            _ => regular_headers.push(h),
        }
    }

    let mut blocks = Vec::new();

    if let Some(m) = method {
        let uri = path.unwrap_or_else(|| "/".to_string());
        blocks.push(HtxBlock::ReqLine(RequestLine {
            method: m,
            uri,
            version: HttpVersion::Http20,
        }));
    } else if let Some(st) = status {
        blocks.push(HtxBlock::ResLine(ResponseLine {
            version: HttpVersion::Http20,
            status: st,
            reason: String::new(),
        }));
    }

    for h in regular_headers {
        blocks.push(HtxBlock::Header(h));
    }
    blocks.push(HtxBlock::Eoh);
    
    blocks
}
