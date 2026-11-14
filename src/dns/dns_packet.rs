use std::net::{Ipv4Addr, Ipv6Addr};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QueryType {
    A = 1,
    AAAA = 28,
    HTTPS = 65,
}

pub struct DnsPacketBuilder;

impl DnsPacketBuilder {
    /// Builds a minimal RFC 1035 DNS query packet
    pub fn build_query(tx_id: u16, domain: &str, qtype: QueryType) -> Vec<u8> {
        let mut packet = Vec::with_capacity(64);

        // Header: Transaction ID
        packet.extend_from_slice(&tx_id.to_be_bytes());
        // Flags: Standard query (RD = 1 Recursion Desired) -> 0x0100
        packet.extend_from_slice(&[0x01, 0x00]);
        // Questions count: 1
        packet.extend_from_slice(&[0x00, 0x01]);
        // Answer RRs: 0
        packet.extend_from_slice(&[0x00, 0x00]);
        // Authority RRs: 0
        packet.extend_from_slice(&[0x00, 0x00]);
        // Additional RRs: 0
        packet.extend_from_slice(&[0x00, 0x00]);

        // Question: QNAME
        for label in domain.trim_end_matches('.').split('.') {
            let len = label.len() as u8;
            packet.push(len);
            packet.extend_from_slice(label.as_bytes());
        }
        packet.push(0); // Root label null terminator

        // QTYPE
        packet.extend_from_slice(&(qtype as u16).to_be_bytes());
        // QCLASS: IN (1)
        packet.extend_from_slice(&[0x00, 0x01]);

        packet
    }
}

#[derive(Debug, Clone, Default)]
pub struct DnsResponse {
    pub ipv4_records: Vec<Ipv4Addr>,
    pub ipv6_records: Vec<Ipv6Addr>,
    pub has_https_rr: bool,
    pub has_ech: bool,
    pub rcode: u8,
}

pub struct DnsPacketParser;

impl DnsPacketParser {
    pub fn parse(bytes: &[u8]) -> Result<DnsResponse, &'static str> {
        if bytes.len() < 12 {
            return Err("DNS packet too short");
        }

        let flags = u16::from_be_bytes([bytes[2], bytes[3]]);
        let rcode = (flags & 0x000F) as u8;
        let qdcount = u16::from_be_bytes([bytes[4], bytes[5]]) as usize;
        let ancount = u16::from_be_bytes([bytes[6], bytes[7]]) as usize;

        let mut offset = 12;

        // Skip questions
        for _ in 0..qdcount {
            offset = Self::skip_name(bytes, offset)?;
            if offset + 4 > bytes.len() {
                return Err("Truncated question section");
            }
            offset += 4; // QTYPE + QCLASS
        }

        let mut resp = DnsResponse {
            ipv4_records: Vec::new(),
            ipv6_records: Vec::new(),
            has_https_rr: false,
            has_ech: false,
            rcode,
        };

        // Parse answers
        for _ in 0..ancount {
            if offset >= bytes.len() {
                break;
            }
            offset = Self::skip_name(bytes, offset)?;
            if offset + 10 > bytes.len() {
                break;
            }

            let rtype = u16::from_be_bytes([bytes[offset], bytes[offset + 1]]);
            let _rclass = u16::from_be_bytes([bytes[offset + 2], bytes[offset + 3]]);
            let _ttl = u32::from_be_bytes([
                bytes[offset + 4],
                bytes[offset + 5],
                bytes[offset + 6],
                bytes[offset + 7],
            ]);
            let rdlength = u16::from_be_bytes([bytes[offset + 8], bytes[offset + 9]]) as usize;
            offset += 10;

            if offset + rdlength > bytes.len() {
                break;
            }

            let rdata = &bytes[offset..offset + rdlength];
            offset += rdlength;

            match rtype {
                1 if rdlength == 4 => {
                    // Type A (IPv4)
                    let ip = Ipv4Addr::new(rdata[0], rdata[1], rdata[2], rdata[3]);
                    resp.ipv4_records.push(ip);
                }
                28 if rdlength == 16 => {
                    // Type AAAA (IPv6)
                    let mut octets = [0u8; 16];
                    octets.copy_from_slice(rdata);
                    resp.ipv6_records.push(Ipv6Addr::from(octets));
                }
                65 => {
                    // Type HTTPS (RFC 9460)
                    resp.has_https_rr = true;
                    // Check if ECH key (key 5 in SvcParam) is present in rdata
                    if rdata.windows(2).any(|w| w == [0x00, 0x05]) {
                        resp.has_ech = true;
                    }
                }
                _ => {}
            }
        }

        Ok(resp)
    }

    fn skip_name(bytes: &[u8], mut offset: usize) -> Result<usize, &'static str> {
        let len = bytes.len();
        while offset < len {
            let label_len = bytes[offset] as usize;
            if label_len == 0 {
                return Ok(offset + 1);
            }
            // Pointer (0xC0 ..)
            if (label_len & 0xC0) == 0xC0 {
                return Ok(offset + 2);
            }
            offset += 1 + label_len;
        }
        Err("Invalid DNS name")
    }
}
