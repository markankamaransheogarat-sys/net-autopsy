use super::dns_packet::{DnsPacketBuilder, DnsPacketParser, DnsResponse, QueryType};
use std::net::{Ipv4Addr, SocketAddr};
use std::time::{Duration, Instant};
use tokio::net::UdpSocket;
use tokio::time::timeout;

#[derive(Debug, Clone, serde::Serialize)]
pub struct DnsProbeResult {
    pub server: String,
    pub latency_ms: f64,
    pub ipv4_records: Vec<String>,
    pub has_https_rr: bool,
    pub has_ech: bool,
    pub rcode: u8,
    pub error: Option<String>,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct DnsAnalysis {
    pub target_domain: String,
    pub system_dns: DnsProbeResult,
    pub trusted_dns: DnsProbeResult,
    pub is_poisoned: bool,
    pub is_nxdomain_hijacked: bool,
    pub is_ech_stripped: bool,
    pub poisoning_reason: Option<String>,
    pub canonical_ips: Vec<String>,
}

pub struct DnsResolver;

impl DnsResolver {
    pub async fn query_server(
        domain: &str,
        server_addr: SocketAddr,
        qtype: QueryType,
        timeout_duration: Duration,
    ) -> Result<(DnsResponse, f64), String> {
        let socket = UdpSocket::bind("0.0.0.0:0")
            .await
            .map_err(|e| format!("Failed to bind UDP socket: {e}"))?;

        let tx_id = 0xA1B2;
        let packet = DnsPacketBuilder::build_query(tx_id, domain, qtype);

        let start = Instant::now();
        socket
            .send_to(&packet, server_addr)
            .await
            .map_err(|e| format!("Failed to send DNS query to {server_addr}: {e}"))?;

        let mut buf = [0u8; 1024];
        let (len, _) = timeout(timeout_duration, socket.recv_from(&mut buf))
            .await
            .map_err(|_| {
                format!(
                    "DNS query to {server_addr} timed out after {:?}",
                    timeout_duration
                )
            })?
            .map_err(|e| format!("Failed to receive DNS response: {e}"))?;

        let elapsed_ms = start.elapsed().as_secs_f64() * 1000.0;
        let response =
            DnsPacketParser::parse(&buf[..len]).map_err(|e| format!("DNS parse error: {e}"))?;

        Ok((response, elapsed_ms))
    }

    /// Read system DNS server from `/etc/resolv.conf`, fallback to 1.1.1.1 or 8.8.8.8
    pub fn get_system_dns() -> SocketAddr {
        if let Ok(content) = std::fs::read_to_string("/etc/resolv.conf") {
            for line in content.lines() {
                let trimmed = line.trim();
                if trimmed.starts_with("nameserver") {
                    if let Some(ip_str) = trimmed.split_whitespace().nth(1) {
                        if let Ok(ip) = ip_str.parse::<std::net::IpAddr>() {
                            return SocketAddr::new(ip, 53);
                        }
                    }
                }
            }
        }
        SocketAddr::from(([1, 1, 1, 1], 53))
    }

    /// Perform dual-stack DNS comparison: System Resolver vs Trusted Cloudflare 1.1.1.1
    pub async fn analyze_domain(domain: &str) -> DnsAnalysis {
        let system_server = Self::get_system_dns();
        let trusted_server: SocketAddr = "1.1.1.1:53".parse().unwrap();

        let timeout_dur = Duration::from_millis(1500);

        // Run A and HTTPS queries concurrently
        let sys_res = Self::query_server(domain, system_server, QueryType::A, timeout_dur).await;
        let trusted_res =
            Self::query_server(domain, trusted_server, QueryType::A, timeout_dur).await;
        let trusted_https =
            Self::query_server(domain, trusted_server, QueryType::HTTPS, timeout_dur).await;

        let sys_probe = match sys_res {
            Ok((resp, lat)) => DnsProbeResult {
                server: system_server.to_string(),
                latency_ms: lat,
                ipv4_records: resp.ipv4_records.iter().map(|ip| ip.to_string()).collect(),
                has_https_rr: resp.has_https_rr,
                has_ech: resp.has_ech,
                rcode: resp.rcode,
                error: None,
            },
            Err(e) => DnsProbeResult {
                server: system_server.to_string(),
                latency_ms: 0.0,
                ipv4_records: Vec::new(),
                has_https_rr: false,
                has_ech: false,
                rcode: 255,
                error: Some(e),
            },
        };

        let trusted_probe = match trusted_res {
            Ok((resp, lat)) => {
                let has_ech = trusted_https
                    .as_ref()
                    .map(|(h, _)| h.has_ech)
                    .unwrap_or(false);
                let has_https = trusted_https
                    .as_ref()
                    .map(|(h, _)| h.has_https_rr)
                    .unwrap_or(false);
                DnsProbeResult {
                    server: trusted_server.to_string(),
                    latency_ms: lat,
                    ipv4_records: resp.ipv4_records.iter().map(|ip| ip.to_string()).collect(),
                    has_https_rr: has_https,
                    has_ech,
                    rcode: resp.rcode,
                    error: None,
                }
            }
            Err(e) => DnsProbeResult {
                server: trusted_server.to_string(),
                latency_ms: 0.0,
                ipv4_records: Vec::new(),
                has_https_rr: false,
                has_ech: false,
                rcode: 255,
                error: Some(e),
            },
        };

        // Analyze poisoning
        let mut is_poisoned = false;
        let mut is_nxdomain_hijacked = false;
        let mut is_ech_stripped = false;
        let mut reason = None;

        // 1. Bogon / Loopback detection in System DNS
        for ip_str in &sys_probe.ipv4_records {
            if let Ok(ip) = ip_str.parse::<Ipv4Addr>() {
                if ip.is_loopback() || ip.is_unspecified() || ip.is_private() {
                    is_poisoned = true;
                    reason = Some(format!(
                        "System DNS returned bogus/private IP: {ip} (ISP redirection stub)"
                    ));
                }
            }
        }

        // 2. NXDOMAIN Hijack: System DNS says non-existent, but Trusted DNS finds IPs
        if !trusted_probe.ipv4_records.is_empty()
            && (sys_probe.rcode == 3 || sys_probe.ipv4_records.is_empty())
        {
            is_nxdomain_hijacked = true;
            is_poisoned = true;
            reason = Some(
                "System DNS returned NXDOMAIN / Empty set while Trusted DNS resolved valid IPs"
                    .to_string(),
            );
        }

        // 3. IP Set Discrepancy (neither set intersects and trusted has valid records)
        if !trusted_probe.ipv4_records.is_empty() && !sys_probe.ipv4_records.is_empty() {
            let has_intersection = sys_probe
                .ipv4_records
                .iter()
                .any(|ip| trusted_probe.ipv4_records.contains(ip));
            if !has_intersection && !is_poisoned {
                // If it's a known ISP block IP
                let first_sys_ip = &sys_probe.ipv4_records[0];
                is_poisoned = true;
                reason = Some(format!("System DNS resolved to unverified IP {first_sys_ip} disjoint from trusted records"));
            }
        }

        // 4. ECH Stripping
        if trusted_probe.has_ech && !sys_probe.has_ech && sys_probe.has_https_rr {
            is_ech_stripped = true;
        }

        let canonical_ips = if !trusted_probe.ipv4_records.is_empty() {
            trusted_probe.ipv4_records.clone()
        } else {
            sys_probe.ipv4_records.clone()
        };

        DnsAnalysis {
            target_domain: domain.to_string(),
            system_dns: sys_probe,
            trusted_dns: trusted_probe,
            is_poisoned,
            is_nxdomain_hijacked,
            is_ech_stripped,
            poisoning_reason: reason,
            canonical_ips,
        }
    }
}
