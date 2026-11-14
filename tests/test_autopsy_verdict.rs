use net_autopsy::dns::{DnsAnalysis, DnsProbeResult};
use net_autopsy::engine::{
    AutopsyReport, PrimaryVerdict, RemediationRecommendation, ReportFormatter,
};
use net_autopsy::tls::{SniOutcome, TlsSniReport};
use net_autopsy::transport::{QuicProbeResult, QuicProbeStatus, TcpProbeResult, TcpProbeStatus};

#[test]
fn test_report_formatting_and_json() {
    let report = AutopsyReport {
        target_domain: "api.openai.com".to_string(),
        target_port: 443,
        resolved_ip: Some("104.18.7.192".to_string()),
        dns_analysis: DnsAnalysis {
            target_domain: "api.openai.com".to_string(),
            system_dns: DnsProbeResult {
                server: "127.0.0.53:53".to_string(),
                latency_ms: 12.5,
                ipv4_records: vec!["104.18.7.192".to_string()],
                has_https_rr: true,
                has_ech: false,
                rcode: 0,
                error: None,
            },
            trusted_dns: DnsProbeResult {
                server: "1.1.1.1:53".to_string(),
                latency_ms: 8.2,
                ipv4_records: vec!["104.18.7.192".to_string()],
                has_https_rr: true,
                has_ech: true,
                rcode: 0,
                error: None,
            },
            is_poisoned: false,
            is_nxdomain_hijacked: false,
            is_ech_stripped: true,
            poisoning_reason: None,
            canonical_ips: vec!["104.18.7.192".to_string()],
        },
        tcp_probe: Some(TcpProbeResult {
            target: "104.18.7.192:443".parse().unwrap(),
            status: TcpProbeStatus::Connected { rtt_ms: 14.2 },
            is_reachable: true,
            latency_ms: Some(14.2),
        }),
        quic_probe: Some(QuicProbeResult {
            target: "104.18.7.192:443".parse().unwrap(),
            status: QuicProbeStatus::Responsive { rtt_ms: 15.0 },
            is_quic_functional: true,
        }),
        tls_report: Some(TlsSniReport {
            target_domain: "api.openai.com".to_string(),
            plain_target_outcome: SniOutcome::RstInjected { elapsed_ms: 18 },
            neutral_sni_outcome: SniOutcome::ServerHelloReceived { latency_ms: 22 },
            segmented_sni_outcome: SniOutcome::ServerHelloReceived { latency_ms: 24 },
            is_sni_filtered: true,
            is_segmentation_bypass_effective: true,
        }),
        primary_verdict: PrimaryVerdict::TlsSniFilterRst,
        confidence_score: 0.98,
        recommendations: vec![RemediationRecommendation {
            title: "TCP Segmentation Bypass Viable".to_string(),
            description:
                "Middlebox (TSPU/DPI) killed plain ClientHello, but passed segmented ClientHello!"
                    .to_string(),
            tool_suggestion: Some("Enable TCP segmentation in ultradpi or zapret".to_string()),
        }],
    };

    let terminal_output = ReportFormatter::format_terminal(&report);
    assert!(terminal_output.contains("NET-AUTOPSY: FORENSIC NETWORK REPORT FOR api.openai.com"));
    assert!(terminal_output.contains("DPI SNI RESET"));
    assert!(terminal_output.contains("TCP SEGMENTATION BYPASS VIABLE!"));

    let json_output = ReportFormatter::format_json(&report);
    assert!(json_output.contains("\"primary_verdict\": \"TlsSniFilterRst\""));
    assert!(json_output.contains("\"is_segmentation_bypass_effective\": true"));
}
