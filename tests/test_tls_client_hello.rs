use net_autopsy::tls::TlsClientHelloBuilder;

#[test]
fn test_tls_client_hello_structure() {
    let sni = "api.openai.com";
    let packet = TlsClientHelloBuilder::build(sni);

    // Minimum sanity check
    assert!(packet.len() > 100);

    // Record header
    assert_eq!(packet[0], 0x16); // ContentType: Handshake
    assert_eq!(&packet[1..3], &[0x03, 0x01]); // TLS 1.0 record layer

    // Handshake header
    assert_eq!(packet[5], 0x01); // HandshakeType: ClientHello

    // Verify SNI string is present in bytes
    let sni_bytes = sni.as_bytes();
    let has_sni = packet.windows(sni_bytes.len()).any(|w| w == sni_bytes);
    assert!(has_sni, "ClientHello must contain the target SNI string");

    // Verify supported versions extension (0x002B) is present
    let has_sup_versions = packet.windows(2).any(|w| w == [0x00, 0x2B]);
    assert!(has_sup_versions, "ClientHello must contain supported_versions extension");
}
