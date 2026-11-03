use std::net::SocketAddr;
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;
use super::client_hello::TlsClientHelloBuilder;

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub enum SniOutcome {
    ServerHelloReceived { latency_ms: u64 },
    TlsAlertReceived { alert_code: u8, latency_ms: u64 },
    RstInjected { elapsed_ms: u64 },
    SilentDrop { timeout_ms: u64 },
    ConnectionFailed(String),
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct TlsSniReport {
    pub target_domain: String,
    pub plain_target_outcome: SniOutcome,
    pub neutral_sni_outcome: SniOutcome,
    pub segmented_sni_outcome: SniOutcome,
    pub is_sni_filtered: bool,
    pub is_segmentation_bypass_effective: bool,
}

pub struct SniProber;

impl SniProber {
    pub async fn send_and_await(
        target: SocketAddr,
        payloads: &[&[u8]],
        inter_chunk_delay: Option<Duration>,
        timeout_duration: Duration,
    ) -> SniOutcome {
        let mut stream = match TcpStream::connect(target).await {
            Ok(s) => s,
            Err(e) => return SniOutcome::ConnectionFailed(e.to_string()),
        };

        // Disable Nagle's algorithm so chunks are sent immediately
        let _ = stream.set_nodelay(true);

        let start = Instant::now();

        // Send payload chunk(s)
        for (i, chunk) in payloads.iter().enumerate() {
            if let Err(e) = stream.write_all(chunk).await {
                let elapsed = start.elapsed().as_millis() as u64;
                if e.kind() == std::io::ErrorKind::ConnectionReset || e.kind() == std::io::ErrorKind::BrokenPipe {
                    return SniOutcome::RstInjected { elapsed_ms: elapsed };
                }
                return SniOutcome::ConnectionFailed(e.to_string());
            }
            if let Some(delay) = inter_chunk_delay {
                if i < payloads.len() - 1 {
                    tokio::time::sleep(delay).await;
                }
            }
        }

        let _ = stream.flush().await;

        // Await response
        let mut response_buf = [0u8; 1024];
        match timeout(timeout_duration, stream.read(&mut response_buf)).await {
            Ok(Ok(0)) => {
                let elapsed = start.elapsed().as_millis() as u64;
                SniOutcome::RstInjected { elapsed_ms: elapsed }
            }
            Ok(Ok(n)) => {
                let elapsed = start.elapsed().as_millis() as u64;
                let first_byte = response_buf[0];
                match first_byte {
                    0x16 => SniOutcome::ServerHelloReceived { latency_ms: elapsed },
                    0x15 => {
                        let alert_code = if n > 6 { response_buf[6] } else { 0 };
                        SniOutcome::TlsAlertReceived { alert_code, latency_ms: elapsed }
                    }
                    _ => SniOutcome::ServerHelloReceived { latency_ms: elapsed },
                }
            }
            Ok(Err(e)) => {
                let elapsed = start.elapsed().as_millis() as u64;
                if e.kind() == std::io::ErrorKind::ConnectionReset || e.kind() == std::io::ErrorKind::BrokenPipe {
                    SniOutcome::RstInjected { elapsed_ms: elapsed }
                } else {
                    SniOutcome::ConnectionFailed(e.to_string())
                }
            }
            Err(_) => SniOutcome::SilentDrop {
                timeout_ms: timeout_duration.as_millis() as u64,
            },
        }
    }

    /// Perform a 3-way differential TLS autopsy:
    /// 1. Target SNI in single packet
    /// 2. Neutral SNI (example.com) to same IP
    /// 3. Target SNI split into 2 TCP segments (TCP segmentation)
    pub async fn autopsy(target: SocketAddr, target_domain: &str) -> TlsSniReport {
        let timeout_dur = Duration::from_millis(2500);

        // 1. Plain Target SNI
        let target_hello = TlsClientHelloBuilder::build(target_domain);
        let plain_outcome = Self::send_and_await(target, &[&target_hello], None, timeout_dur).await;

        // 2. Neutral SNI (e.g. example.com) to the same IP
        let neutral_hello = TlsClientHelloBuilder::build("example.com");
        let neutral_outcome = Self::send_and_await(target, &[&neutral_hello], None, timeout_dur).await;

        // 3. Segmented Target SNI (Split at 5 bytes to separate TLS record header from SNI extension)
        let split_pos = 5.min(target_hello.len());
        let chunk1 = &target_hello[..split_pos];
        let chunk2 = &target_hello[split_pos..];
        let segmented_outcome = Self::send_and_await(
            target,
            &[chunk1, chunk2],
            Some(Duration::from_millis(2)),
            timeout_dur,
        )
        .await;

        // Analysis: Is SNI filtered?
        // If neutral SNI succeeds (ServerHello or Alert) while target SNI is dropped/reset
        let target_failed = matches!(plain_outcome, SniOutcome::RstInjected { .. } | SniOutcome::SilentDrop { .. });
        let neutral_succeeded = matches!(neutral_outcome, SniOutcome::ServerHelloReceived { .. } | SniOutcome::TlsAlertReceived { .. });

        let is_sni_filtered = target_failed && neutral_succeeded;

        // Is segmentation effective?
        // If plain target failed, but segmented succeeded
        let segmented_succeeded = matches!(segmented_outcome, SniOutcome::ServerHelloReceived { .. } | SniOutcome::TlsAlertReceived { .. });
        let is_segmentation_bypass_effective = target_failed && segmented_succeeded;

        TlsSniReport {
            target_domain: target_domain.to_string(),
            plain_target_outcome: plain_outcome,
            neutral_sni_outcome: neutral_outcome,
            segmented_sni_outcome: segmented_outcome,
            is_sni_filtered,
            is_segmentation_bypass_effective,
        }
    }
}
