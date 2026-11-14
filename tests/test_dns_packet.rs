use net_autopsy::dns::{DnsPacketBuilder, DnsPacketParser, QueryType};
use std::net::Ipv4Addr;

#[test]
fn test_build_dns_query() {
    let packet = DnsPacketBuilder::build_query(0x1234, "example.com", QueryType::A);

    assert!(packet.len() > 12);
    assert_eq!(&packet[0..2], &[0x12, 0x34]); // TX ID
    assert_eq!(&packet[2..4], &[0x01, 0x00]); // Standard query RD=1
    assert_eq!(&packet[4..6], &[0x00, 0x01]); // 1 question

    // Verify QNAME contains "example" (7 bytes) and "com" (3 bytes)
    assert_eq!(packet[12], 7);
    assert_eq!(&packet[13..20], b"example");
    assert_eq!(packet[20], 3);
    assert_eq!(&packet[21..24], b"com");
    assert_eq!(packet[24], 0); // Null terminator
}

#[test]
fn test_parse_dns_response_ipv4() {
    // Construct mock DNS response: 1 question for example.com, 1 answer with 93.184.216.34
    let mut resp_bytes = Vec::new();
    resp_bytes.extend_from_slice(&[0x12, 0x34]); // ID
    resp_bytes.extend_from_slice(&[0x81, 0x80]); // Flags: QR=1, RD=1, RA=1, RCODE=0
    resp_bytes.extend_from_slice(&[0x00, 0x01]); // QDCOUNT=1
    resp_bytes.extend_from_slice(&[0x00, 0x01]); // ANCOUNT=1
    resp_bytes.extend_from_slice(&[0x00, 0x00]); // NSCOUNT=0
    resp_bytes.extend_from_slice(&[0x00, 0x00]); // ARCOUNT=0

    // Question
    resp_bytes.extend_from_slice(&[7]);
    resp_bytes.extend_from_slice(b"example");
    resp_bytes.extend_from_slice(&[3]);
    resp_bytes.extend_from_slice(b"com");
    resp_bytes.extend_from_slice(&[0]);
    resp_bytes.extend_from_slice(&[0x00, 0x01]); // Type A
    resp_bytes.extend_from_slice(&[0x00, 0x01]); // Class IN

    // Answer (pointer to name at offset 12 -> 0xC00C)
    resp_bytes.extend_from_slice(&[0xC0, 0x0C]);
    resp_bytes.extend_from_slice(&[0x00, 0x01]); // Type A
    resp_bytes.extend_from_slice(&[0x00, 0x01]); // Class IN
    resp_bytes.extend_from_slice(&[0x00, 0x00, 0x01, 0x2C]); // TTL = 300s
    resp_bytes.extend_from_slice(&[0x00, 0x04]); // RDLENGTH = 4
    resp_bytes.extend_from_slice(&[93, 184, 216, 34]); // RDATA: 93.184.216.34

    let parsed = DnsPacketParser::parse(&resp_bytes).expect("Should parse");
    assert_eq!(parsed.rcode, 0);
    assert_eq!(parsed.ipv4_records, vec![Ipv4Addr::new(93, 184, 216, 34)]);
    assert!(!parsed.has_ech);
}

#[test]
fn test_parse_truncated_packet() {
    let short_bytes = vec![0x12, 0x34];
    assert!(DnsPacketParser::parse(&short_bytes).is_err());
}
