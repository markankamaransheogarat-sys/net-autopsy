use net_autopsy::transport::QuicProber;

#[test]
fn test_quic_initial_probe_packet() {
    let packet = QuicProber::build_quic_initial_probe();

    // RFC 9000 specifies minimum Initial packet must be 1200 bytes
    assert_eq!(packet.len(), 1200);

    // Long header Form bit = 1, Fixed bit = 1
    assert_eq!(packet[0] & 0xC0, 0xC0);

    // QUIC version 1: 0x00000001
    assert_eq!(&packet[1..5], &[0x00, 0x00, 0x00, 0x01]);

    // DCID length = 8
    assert_eq!(packet[5], 8);
    // SCID length = 8
    assert_eq!(packet[14], 8);
}
