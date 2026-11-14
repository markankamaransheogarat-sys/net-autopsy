use std::net::SocketAddr;
use std::time::{Duration, Instant};
use tokio::net::UdpSocket;
use tokio::time::timeout;

#[derive(Debug, Clone, serde::Serialize)]
pub enum QuicProbeStatus {
    Responsive { rtt_ms: f64 },
    PortUnreachable,
    SilentDrop { timeout_ms: u64 },
    Error(String),
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct QuicProbeResult {
    pub target: SocketAddr,
    pub status: QuicProbeStatus,
    pub is_quic_functional: bool,
}

pub struct QuicProber;

impl QuicProber {
    /// Builds a minimal RFC 9000 QUIC v1 Initial probe packet (1200 bytes with padding)
    pub fn build_quic_initial_probe() -> Vec<u8> {
        let mut packet = Vec::with_capacity(1200);

        // Header byte: Form=1 (Long), Fixed=1, Type=00 (Initial), Reserved=00, Packet Number Length=00 (1 byte)
        packet.push(0xC0);
        // Version 1: 0x00000001
        packet.extend_from_slice(&[0x00, 0x00, 0x00, 0x01]);
        // DCID length: 8
        packet.push(8);
        packet.extend_from_slice(&[0xDE, 0xAD, 0xBE, 0xEF, 0x01, 0x02, 0x03, 0x04]);
        // SCID length: 8
        packet.push(8);
        packet.extend_from_slice(&[0xCA, 0xFE, 0xBA, 0xBE, 0x05, 0x06, 0x07, 0x08]);
        // Token Length: 0
        packet.push(0x00);
        // Length: 1170 bytes
        packet.extend_from_slice(&[0x44, 0x92]);
        // Packet number (1 byte): 0x00
        packet.push(0x00);

        // Pad to minimum QUIC Initial size (1200 bytes)
        packet.resize(1200, 0x00);
        packet
    }

    pub async fn probe(target: SocketAddr, timeout_duration: Duration) -> QuicProbeResult {
        let socket = match UdpSocket::bind("0.0.0.0:0").await {
            Ok(s) => s,
            Err(e) => {
                return QuicProbeResult {
                    target,
                    status: QuicProbeStatus::Error(e.to_string()),
                    is_quic_functional: false,
                };
            }
        };

        let packet = Self::build_quic_initial_probe();
        let start = Instant::now();
        let timeout_ms = timeout_duration.as_millis() as u64;

        if let Err(e) = socket.send_to(&packet, target).await {
            return QuicProbeResult {
                target,
                status: QuicProbeStatus::Error(e.to_string()),
                is_quic_functional: false,
            };
        }

        let mut buf = [0u8; 1500];
        match timeout(timeout_duration, socket.recv_from(&mut buf)).await {
            Ok(Ok((_len, _))) => {
                let rtt = start.elapsed().as_secs_f64() * 1000.0;
                QuicProbeResult {
                    target,
                    status: QuicProbeStatus::Responsive { rtt_ms: rtt },
                    is_quic_functional: true,
                }
            }
            Ok(Err(e)) => {
                if e.kind() == std::io::ErrorKind::ConnectionRefused {
                    QuicProbeResult {
                        target,
                        status: QuicProbeStatus::PortUnreachable,
                        is_quic_functional: false,
                    }
                } else {
                    QuicProbeResult {
                        target,
                        status: QuicProbeStatus::Error(e.to_string()),
                        is_quic_functional: false,
                    }
                }
            }
            Err(_) => QuicProbeResult {
                target,
                status: QuicProbeStatus::SilentDrop { timeout_ms },
                is_quic_functional: false,
            },
        }
    }
}
