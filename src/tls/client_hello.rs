pub struct TlsClientHelloBuilder;

impl TlsClientHelloBuilder {
    /// Builds a RFC 8446 compliant TLS 1.3 ClientHello record frame
    pub fn build(sni: &str) -> Vec<u8> {
        let mut handshake = Vec::with_capacity(256);

        // Handshake Version: 0x0303 (TLS 1.2 wire compatibility)
        handshake.extend_from_slice(&[0x03, 0x03]);

        // Client Random: 32 bytes
        let mut random = [0x42u8; 32];
        random[0] = 0xDE;
        random[1] = 0xAD;
        handshake.extend_from_slice(&random);

        // Legacy Session ID: 32 bytes (to support TLS 1.3 middlebox compatibility)
        handshake.push(32);
        handshake.extend_from_slice(&[0xAA; 32]);

        // Cipher Suites: TLS_AES_128_GCM_SHA256 (0x1301), TLS_AES_256_GCM_SHA384 (0x1302), TLS_CHACHA20_POLY1305_SHA256 (0x1303)
        let cipher_suites: [u8; 6] = [0x13, 0x01, 0x13, 0x02, 0x13, 0x03];
        handshake.extend_from_slice(&(cipher_suites.len() as u16).to_be_bytes());
        handshake.extend_from_slice(&cipher_suites);

        // Legacy Compression Methods: 1 byte (0 = null)
        handshake.push(1);
        handshake.push(0x00);

        // Extensions Section
        let mut extensions = Vec::with_capacity(128);

        // 1. Extension: Server Name Indication (SNI) - Type 0x0000
        let sni_bytes = sni.as_bytes();
        let mut sni_ext = Vec::with_capacity(sni_bytes.len() + 5);
        let list_len = (sni_bytes.len() + 3) as u16;
        sni_ext.extend_from_slice(&list_len.to_be_bytes());
        sni_ext.push(0x00); // HostName type
        sni_ext.extend_from_slice(&(sni_bytes.len() as u16).to_be_bytes());
        sni_ext.extend_from_slice(sni_bytes);

        extensions.extend_from_slice(&[0x00, 0x00]); // Type 0 (SNI)
        extensions.extend_from_slice(&(sni_ext.len() as u16).to_be_bytes());
        extensions.extend_from_slice(&sni_ext);

        // 2. Extension: Supported Versions (TLS 1.3 / TLS 1.2) - Type 0x002B
        let versions: [u8; 4] = [0x03, 0x04, 0x03, 0x03];
        extensions.extend_from_slice(&[0x00, 0x2B]);
        extensions.extend_from_slice(&((versions.len() + 1) as u16).to_be_bytes());
        extensions.push(versions.len() as u8);
        extensions.extend_from_slice(&versions);

        // 3. Extension: Supported Groups (x25519) - Type 0x000A
        let groups: [u8; 2] = [0x00, 0x1D]; // x25519
        extensions.extend_from_slice(&[0x00, 0x0A]);
        extensions.extend_from_slice(&((groups.len() + 2) as u16).to_be_bytes());
        extensions.extend_from_slice(&(groups.len() as u16).to_be_bytes());
        extensions.extend_from_slice(&groups);

        // Append Extensions Length and Data to Handshake
        handshake.extend_from_slice(&(extensions.len() as u16).to_be_bytes());
        handshake.extend_from_slice(&extensions);

        // Build TLS Record: Type 0x16 (Handshake), Version 0x0301 (TLS 1.0 record layer)
        let mut record = Vec::with_capacity(handshake.len() + 9);
        record.push(0x16); // ContentType: Handshake
        record.extend_from_slice(&[0x03, 0x01]); // ProtocolVersion: TLS 1.0

        let handshake_len = (handshake.len() + 4) as u16;
        record.extend_from_slice(&handshake_len.to_be_bytes());

        // Handshake Header: Type 0x01 (ClientHello), Length 3 bytes
        record.push(0x01);
        let h_len = handshake.len() as u32;
        record.push(((h_len >> 16) & 0xFF) as u8);
        record.push(((h_len >> 8) & 0xFF) as u8);
        record.push((h_len & 0xFF) as u8);

        record.extend_from_slice(&handshake);
        record
    }
}
