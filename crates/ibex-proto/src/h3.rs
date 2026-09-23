use crate::htx::{HeaderField, HttpVersion, HtxBlock};

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

pub fn headers_to_htx(decoded_headers: Vec<HeaderField>) -> Result<Vec<HtxBlock>, H3Error> {
    crate::htx::pseudo_headers_to_htx(decoded_headers, HttpVersion::Http30)
        .map_err(|_| H3Error::MessageError)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::htx::{HttpMethod, Htx};

    #[test]
    fn h3_headers_to_htx_request() {
        let headers = vec![
            HeaderField { name: ":method".into(), value: "GET".into() },
            HeaderField { name: ":scheme".into(), value: "https".into() },
            HeaderField { name: ":path".into(), value: "/quic".into() },
            HeaderField { name: ":authority".into(), value: "h3.example.com".into() },
            HeaderField { name: "user-agent".into(), value: "curl/8.18.0".into() },
        ];
        let blocks = headers_to_htx(headers).expect("valid h3 request");
        let mut htx = Htx::new();
        for b in blocks {
            htx.push(b);
        }
        let req = htx.req_line().expect("req_line");
        assert_eq!(req.method, HttpMethod::Get);
        assert_eq!(req.uri, "/quic");
        assert_eq!(req.version, HttpVersion::Http30);
        assert_eq!(htx.get_header("host"), Some("h3.example.com"));
        assert_eq!(htx.get_header(":scheme"), None);
        assert_eq!(htx.get_header(":authority"), None);

        let wire = htx.to_h1_wire();
        let wire_str = String::from_utf8(wire).expect("utf8");
        assert!(wire_str.starts_with("GET /quic HTTP/1.1\r\n"));
        assert!(wire_str.contains("host: h3.example.com\r\n"));
    }

    #[test]
    fn h3_headers_to_htx_errors() {
        // Unknown pseudo header
        let res = headers_to_htx(vec![
            HeaderField { name: ":custom".into(), value: "bad".into() },
        ]);
        assert_eq!(res, Err(H3Error::MessageError));

        // Pseudo after regular
        let res = headers_to_htx(vec![
            HeaderField { name: ":method".into(), value: "GET".into() },
            HeaderField { name: "host".into(), value: "example.com".into() },
            HeaderField { name: ":path".into(), value: "/".into() },
        ]);
        assert_eq!(res, Err(H3Error::MessageError));

        // Authority and host mismatch
        let res = headers_to_htx(vec![
            HeaderField { name: ":method".into(), value: "GET".into() },
            HeaderField { name: ":authority".into(), value: "example.com".into() },
            HeaderField { name: "host".into(), value: "evil.com".into() },
        ]);
        assert_eq!(res, Err(H3Error::MessageError));
    }
}
