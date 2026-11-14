//! # net-autopsy
//!
//! High-Precision Network Forensics & Censorship Autopsy Engine (OSI Layers 3-7) in Rust.
//! Diagnoses exactly where, why, and how a connection is tampered with (DNS poisoning, TCP RST, SNI filtering, ECH block, QUIC drop).

pub mod dns;
pub mod engine;
pub mod tls;
pub mod transport;

pub use dns::{DnsAnalysis, DnsProbeResult, DnsResolver, DnsResponse, QueryType};
pub use engine::{
    AutopsyEngine, AutopsyReport, PrimaryVerdict, RemediationRecommendation, ReportFormatter,
};
pub use tls::{SniOutcome, SniProber, TlsClientHelloBuilder, TlsSniReport};
pub use transport::{
    QuicProbeResult, QuicProbeStatus, QuicProber, TcpProbeResult, TcpProbeStatus, TcpProber,
};
