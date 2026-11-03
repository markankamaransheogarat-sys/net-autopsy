use super::autopsy::{AutopsyReport, PrimaryVerdict};
use crate::tls::SniOutcome;

pub struct ReportFormatter;

impl ReportFormatter {
    pub fn format_terminal(report: &AutopsyReport) -> String {
        let mut out = String::new();

        out.push_str("\n┌─────────────────────────────────────────────────────────────────────────────┐\n");
        out.push_str(&format!("│ 🔬 NET-AUTOPSY: FORENSIC NETWORK REPORT FOR {:<31} │\n", report.target_domain));
        out.push_str("└─────────────────────────────────────────────────────────────────────────────┘\n\n");

        // 1. DNS Layer
        out.push_str("📡 [LAYER 3/7: DNS RESOLUTION]\n");
        let sys = &report.dns_analysis.system_dns;
        let trusted = &report.dns_analysis.trusted_dns;

        let sys_status = if report.dns_analysis.is_poisoned { "POISONED ⚠️" } else { "OK ✓" };
        out.push_str(&format!("  • System DNS ({}) -> {} [{:.1} ms]\n", sys.server, sys_status, sys.latency_ms));
        out.push_str(&format!("    Resolved IPs: {}\n", if sys.ipv4_records.is_empty() { "NONE".to_string() } else { sys.ipv4_records.join(", ") }));

        out.push_str(&format!("  • Trusted DNS ({}) -> OK ✓ [{:.1} ms]\n", trusted.server, trusted.latency_ms));
        out.push_str(&format!("    Canonical IPs: {}\n", if trusted.ipv4_records.is_empty() { "NONE".to_string() } else { trusted.ipv4_records.join(", ") }));

        if report.dns_analysis.is_poisoned {
            if let Some(ref r) = report.dns_analysis.poisoning_reason {
                out.push_str(&format!("    ⚠️  POISONING EVIDENCE: {r}\n"));
            }
        }
        out.push('\n');

        // 2. TCP Layer
        out.push_str("🔌 [LAYER 4: TCP HANDSHAKE]\n");
        if let Some(ref tcp) = report.tcp_probe {
            if tcp.is_reachable {
                out.push_str(&format!("  • SYN-ACK Handshake -> REACHABLE ✓ [{:.2} ms]\n", tcp.latency_ms.unwrap_or(0.0)));
            } else {
                out.push_str(&format!("  • SYN-ACK Handshake -> BLOCKED / TIMEOUT ❌ ({:?})\n", tcp.status));
            }
        } else {
            out.push_str("  • Skipped (no IP resolved)\n");
        }
        out.push('\n');

        // 3. QUIC / UDP Layer
        if let Some(ref q) = report.quic_probe {
            out.push_str("⚡ [LAYER 4: QUIC / UDP 443]\n");
            if q.is_quic_functional {
                out.push_str("  • QUIC Initial Probe -> RESPONSIVE ✓\n");
            } else {
                out.push_str("  • QUIC Initial Probe -> SILENT DROP / THROTTLED ⚠️\n");
            }
            out.push('\n');
        }

        // 4. TLS SNI Layer
        if let Some(ref tls) = report.tls_report {
            out.push_str("🔒 [LAYER 5/6: TLS SNI DIFFERENTIAL AUTOPSY]\n");
            out.push_str(&format!("  • Plain Target SNI  (\"{}\") -> ", tls.target_domain));
            Self::format_sni_outcome(&mut out, &tls.plain_target_outcome);

            out.push_str("  • Neutral SNI Test  (\"example.com\")   -> ");
            Self::format_sni_outcome(&mut out, &tls.neutral_sni_outcome);

            out.push_str("  • Segmented SNI     (Split @ 5B)       -> ");
            Self::format_sni_outcome(&mut out, &tls.segmented_sni_outcome);

            if tls.is_sni_filtered {
                out.push_str("    🚨 Middlebox SNI filtering CONFIRMED (Target killed, Neutral allowed!)\n");
            }
            if tls.is_segmentation_bypass_effective {
                out.push_str("    ✨ TCP SEGMENTATION BYPASS VIABLE! (DPI parser defeated by segment split)\n");
            }
            out.push('\n');
        }

        // 5. Final Diagnostic Verdict
        out.push_str("===============================================================================\n");
        out.push_str("📋 AUTOPSY DIAGNOSTIC VERDICT\n");
        out.push_str("===============================================================================\n");

        let (verdict_str, badge) = match report.primary_verdict {
            PrimaryVerdict::CleanConnection => ("CLEAN CONNECTION: No censorship or packet tampering detected.", "✅ PASS"),
            PrimaryVerdict::DnsPoisoning => ("DNS POISONING: Local ISP resolver is spoofing or suppressing records.", "🛑 BLOCKED (L3/L7)"),
            PrimaryVerdict::TcpSynBlackhole => ("TCP BLACKHOLE: Routing or port 443 is blocked at IP transport level.", "🛑 BLOCKED (L4)"),
            PrimaryVerdict::TlsSniFilterRst => ("DPI SNI RESET: Middlebox injected active TCP RST upon seeing SNI in ClientHello.", "🛑 BLOCKED (L5/L6)"),
            PrimaryVerdict::TlsSniFilterDrop => ("DPI SNI DROP: Middlebox silently swallowed packets containing target SNI.", "🛑 BLOCKED (L5/L6)"),
            PrimaryVerdict::EchStrippedOrBlocked => ("ECH BLOCKAGE: Encrypted Client Hello parameters stripped or blocked.", "⚠️ WARNING"),
            PrimaryVerdict::QuicThrottledOrDropped => ("QUIC THROTTLED: UDP port 443 is blocked/throttled. HTTP/3 impaired.", "⚠️ WARNING"),
            PrimaryVerdict::UnreachableHost => ("HOST UNREACHABLE: Domain could not be resolved by any server.", "❓ UNKNOWN"),
        };

        out.push_str(&format!("  Status:     {} (Confidence: {:.0}%)\n", badge, report.confidence_score * 100.0));
        out.push_str(&format!("  Diagnosis:  {}\n", verdict_str));

        if !report.recommendations.is_empty() {
            out.push_str("\n  🛠️  ACTIONABLE REMEDIATIONS:\n");
            for (idx, rec) in report.recommendations.iter().enumerate() {
                out.push_str(&format!("    {}. {}: {}\n", idx + 1, rec.title, rec.description));
                if let Some(ref tool) = rec.tool_suggestion {
                    out.push_str(&format!("       -> Recommended fix: {}\n", tool));
                }
            }
        }
        out.push_str("===============================================================================\n");

        out
    }

    fn format_sni_outcome(out: &mut String, outcome: &SniOutcome) {
        match outcome {
            SniOutcome::ServerHelloReceived { latency_ms } => {
                out.push_str(&format!("ServerHello Received ✓ [{latency_ms} ms]\n"));
            }
            SniOutcome::TlsAlertReceived { alert_code, latency_ms } => {
                out.push_str(&format!("TLS Alert (Code {alert_code}) Received ✓ [{latency_ms} ms]\n"));
            }
            SniOutcome::RstInjected { elapsed_ms } => {
                out.push_str(&format!("TCP RST INJECTED by Middlebox ❌ [{elapsed_ms} ms]\n"));
            }
            SniOutcome::SilentDrop { timeout_ms } => {
                out.push_str(&format!("SILENT PACKET DROP (Timeout {timeout_ms} ms) ❌\n"));
            }
            SniOutcome::ConnectionFailed(e) => {
                out.push_str(&format!("Connection Failed: {e}\n"));
            }
        }
    }

    pub fn format_json(report: &AutopsyReport) -> String {
        serde_json::to_string_pretty(report).unwrap_or_default()
    }
}
