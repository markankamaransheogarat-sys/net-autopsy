//! # net-autopsy
//!
//! High-Precision Network Forensics & Censorship Autopsy Engine (OSI Layers 3-7) in Rust.
//! Diagnoses exactly where, why, and how a connection is tampered with (DNS poisoning, TCP RST, SNI filtering, ECH block, QUIC drop).

pub mod dns;
pub mod transport;
pub mod tls;
pub mod engine;

pub use dns::{DnsResolver, DnsAnalysis, DnsProbeResult, QueryType, DnsResponse};
pub use transport::{TcpProber, TcpProbeResult, TcpProbeStatus, QuicProber, QuicProbeResult, QuicProbeStatus};
pub use tls::{TlsClientHelloBuilder, SniProber, SniOutcome, TlsSniReport};
pub use engine::{AutopsyEngine, AutopsyReport, PrimaryVerdict, ReportFormatter, RemediationRecommendation};
