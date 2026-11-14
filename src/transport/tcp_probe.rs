use std::net::SocketAddr;
use std::time::{Duration, Instant};
use tokio::net::TcpStream;
use tokio::time::timeout;

#[derive(Debug, Clone, serde::Serialize)]
pub enum TcpProbeStatus {
    Connected { rtt_ms: f64 },
    Refused { latency_ms: f64 },
    Blackholed { timeout_ms: u64 },
    Unreachable(String),
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct TcpProbeResult {
    pub target: SocketAddr,
    pub status: TcpProbeStatus,
    pub is_reachable: bool,
    pub latency_ms: Option<f64>,
}

pub struct TcpProber;

impl TcpProber {
    pub async fn probe(target: SocketAddr, timeout_duration: Duration) -> TcpProbeResult {
        let start = Instant::now();
        let timeout_ms = timeout_duration.as_millis() as u64;

        match timeout(timeout_duration, TcpStream::connect(target)).await {
            Ok(Ok(_stream)) => {
                let rtt = start.elapsed().as_secs_f64() * 1000.0;
                TcpProbeResult {
                    target,
                    status: TcpProbeStatus::Connected { rtt_ms: rtt },
                    is_reachable: true,
                    latency_ms: Some(rtt),
                }
            }
            Ok(Err(e)) => {
                let elapsed = start.elapsed().as_secs_f64() * 1000.0;
                let kind = e.kind();
                if kind == std::io::ErrorKind::ConnectionRefused {
                    TcpProbeResult {
                        target,
                        status: TcpProbeStatus::Refused {
                            latency_ms: elapsed,
                        },
                        is_reachable: false,
                        latency_ms: Some(elapsed),
                    }
                } else {
                    TcpProbeResult {
                        target,
                        status: TcpProbeStatus::Unreachable(e.to_string()),
                        is_reachable: false,
                        latency_ms: None,
                    }
                }
            }
            Err(_) => TcpProbeResult {
                target,
                status: TcpProbeStatus::Blackholed { timeout_ms },
                is_reachable: false,
                latency_ms: None,
            },
        }
    }
}
