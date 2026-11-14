use crate::dns::{DnsAnalysis, DnsResolver};
use crate::tls::{SniOutcome, SniProber, TlsSniReport};
use crate::transport::{QuicProbeResult, QuicProber, TcpProbeResult, TcpProber};
use std::net::SocketAddr;
use std::time::Duration;

#[derive(Debug, Clone, serde::Serialize)]
pub enum PrimaryVerdict {
    CleanConnection,
    DnsPoisoning,
    TcpSynBlackhole,
    TlsSniFilterRst,
    TlsSniFilterDrop,
    EchStrippedOrBlocked,
    QuicThrottledOrDropped,
    UnreachableHost,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct RemediationRecommendation {
    pub title: String,
    pub description: String,
    pub tool_suggestion: Option<String>,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct AutopsyReport {
    pub target_domain: String,
    pub target_port: u16,
    pub resolved_ip: Option<String>,
    pub dns_analysis: DnsAnalysis,
    pub tcp_probe: Option<TcpProbeResult>,
    pub quic_probe: Option<QuicProbeResult>,
    pub tls_report: Option<TlsSniReport>,
    pub primary_verdict: PrimaryVerdict,
    pub confidence_score: f64,
    pub recommendations: Vec<RemediationRecommendation>,
}

pub struct AutopsyEngine;

impl AutopsyEngine {
    pub async fn run_autopsy(domain: &str, port: u16) -> AutopsyReport {
        // Step 1: Layer 3/7 DNS Autopsy
        let dns_analysis = DnsResolver::analyze_domain(domain).await;

        let target_ip_str = dns_analysis.canonical_ips.first().cloned();
        let target_addr: Option<SocketAddr> = match &target_ip_str {
            Some(ip) => format!("{ip}:{port}").parse().ok(),
            None => None,
        };

        let mut tcp_probe = None;
        let mut quic_probe = None;
        let mut tls_report = None;
        let mut recommendations = Vec::new();
        let mut primary_verdict = PrimaryVerdict::CleanConnection;
        let mut confidence = 0.95;

        // If DNS is poisoned
        if dns_analysis.is_poisoned {
            primary_verdict = PrimaryVerdict::DnsPoisoning;
            confidence = 0.99;
            recommendations.push(RemediationRecommendation {
                title: "Bypass Local DNS Poisoning".to_string(),
                description: format!(
                    "System DNS returned poisoned/bogus records. {}",
                    dns_analysis.poisoning_reason.as_deref().unwrap_or("")
                ),
                tool_suggestion: Some("Configure DNS-over-HTTPS (DoH) with 1.1.1.1 or 8.8.8.8 in system/browser settings".to_string()),
            });
        }

        // If we have an IP, proceed with L4 and L6 probing
        if let Some(addr) = target_addr {
            // Step 2: Layer 4 TCP Handshake Probe
            let tcp_res = TcpProber::probe(addr, Duration::from_millis(2000)).await;
            let is_tcp_ok = tcp_res.is_reachable;
            tcp_probe = Some(tcp_res);

            // Step 3: Layer 4 QUIC Probe (UDP 443)
            if port == 443 {
                let quic_res = QuicProber::probe(addr, Duration::from_millis(1500)).await;
                quic_probe = Some(quic_res);
            }

            if !is_tcp_ok && !dns_analysis.is_poisoned {
                primary_verdict = PrimaryVerdict::TcpSynBlackhole;
                confidence = 0.90;
                recommendations.push(RemediationRecommendation {
                    title: "Bypass L4 TCP SYN Blackhole / Port Blocking".to_string(),
                    description: "TCP handshake timed out or was refused at IP level. Route or port 443 is blocked by ISP middlebox.".to_string(),
                    tool_suggestion: Some("Use an encrypted tunnel proxy (VLESS / Shadowsocks via nodevortex)".to_string()),
                });
            } else if is_tcp_ok && port == 443 {
                // Step 4: Layer 5/6 TLS SNI Differential Autopsy
                let tls_res = SniProber::autopsy(addr, domain).await;

                if tls_res.is_sni_filtered {
                    match tls_res.plain_target_outcome {
                        SniOutcome::RstInjected { .. } => {
                            primary_verdict = PrimaryVerdict::TlsSniFilterRst;
                            confidence = 0.98;
                        }
                        SniOutcome::SilentDrop { .. } => {
                            primary_verdict = PrimaryVerdict::TlsSniFilterDrop;
                            confidence = 0.95;
                        }
                        _ => {}
                    }

                    if tls_res.is_segmentation_bypass_effective {
                        recommendations.push(RemediationRecommendation {
                            title: "TCP Segmentation Bypass Viable".to_string(),
                            description: "Middlebox (TSPU/DPI) killed plain ClientHello, but passed segmented ClientHello!".to_string(),
                            tool_suggestion: Some("Enable TCP segmentation (split at 5 bytes) in ultradpi or zapret. No VPN needed!".to_string()),
                        });
                    } else {
                        recommendations.push(RemediationRecommendation {
                            title: "DPI SNI Blocking Detected".to_string(),
                            description: "Middlebox filters this domain name. Use Fake SNI or encrypted tunnel.".to_string(),
                            tool_suggestion: Some("Enable Low-TTL Fake SNI in ultradpi or connect via VLESS proxy".to_string()),
                        });
                    }
                } else if dns_analysis.is_ech_stripped {
                    primary_verdict = PrimaryVerdict::EchStrippedOrBlocked;
                    recommendations.push(RemediationRecommendation {
                        title: "Encrypted Client Hello (ECH) Interference".to_string(),
                        description: "Local resolver stripped ECH configurations from HTTPS records.".to_string(),
                        tool_suggestion: Some("Disable ECH in browser flags (chrome://flags or about:config) or use DoH".to_string()),
                    });
                } else if let Some(ref q) = quic_probe {
                    if !q.is_quic_functional && is_tcp_ok {
                        recommendations.push(RemediationRecommendation {
                            title: "QUIC/UDP 443 Throttled".to_string(),
                            description: "TCP works but QUIC (HTTP/3) is swallowed. Modern clients might stall waiting for UDP fallback.".to_string(),
                            tool_suggestion: Some("Block outgoing UDP 443 locally to force instant HTTP/2 fallback".to_string()),
                        });
                    }
                }

                tls_report = Some(tls_res);
            }
        } else if !dns_analysis.is_poisoned {
            primary_verdict = PrimaryVerdict::UnreachableHost;
            confidence = 0.85;
            recommendations.push(RemediationRecommendation {
                title: "Unable to Resolve Target Host".to_string(),
                description: "Neither local nor trusted DNS returned valid IP addresses."
                    .to_string(),
                tool_suggestion: None,
            });
        }

        AutopsyReport {
            target_domain: domain.to_string(),
            target_port: port,
            resolved_ip: target_ip_str,
            dns_analysis,
            tcp_probe,
            quic_probe,
            tls_report,
            primary_verdict,
            confidence_score: confidence,
            recommendations,
        }
    }
}
