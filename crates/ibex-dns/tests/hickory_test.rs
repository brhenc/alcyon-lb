use hickory_proto::op::Message;
#[test]
fn test_loop() {
    let buf = vec![
        0x12, 0x34, // ID
        0x81, 0x80, // Flags (QR, RD, RA)
        0x00, 0x01, // QDCOUNT=1
        0x00, 0x01, // ANCOUNT=1
        0x00, 0x00, // NSCOUNT=0
        0x00, 0x00, // ARCOUNT=0
        // Question: "www."
        0x03, b'w', b'w', b'w', 0x00, // length 16 bytes: 12 + 5 = 17 => index 17
        0x00, 0x01, // QTYPE=A
        0x00, 0x01, // QCLASS=IN // ends at index 21. Answer starts at 21.
        // Answer with pointer loop pointing to index 21
        0xc0, 21,
        0x00, 0x01, // TYPE=A
        0x00, 0x01, // CLASS=IN
        0x00, 0x00, 0x00, 0x3c, // TTL=60
        0x00, 0x04, // RDLENGTH=4
        0x01, 0x02, 0x03, 0x04, // RDATA=1.2.3.4
    ];
    let res = Message::from_vec(&buf);
    println!("RESULT: {res:?}");
}
