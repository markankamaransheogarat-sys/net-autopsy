# 🔬 net-autopsy

**High-Precision Network Forensics & Censorship Autopsy Engine (OSI Layers 3–7) in Rust**

[![Rust](https://img.shields.io/badge/rust-1.80%2B-blue.svg)](https://www.rust-lang.org/)
[![License](https://img.shields.io/badge/license-MIT%2FApache--2.0-green.svg)](#license)
[![Zero-Dependency](https://img.shields.io/badge/dependencies-zero%20C%20libs-brightgreen.svg)](#architecture)
[![OSI Layers](https://img.shields.io/badge/layers-3%20%7C%204%20%7C%205%2F6%20%7C%207-orange.svg)](#how-it-works)

---

## ⚡ Why `net-autopsy`?

Every day, developers and power users in restricted network environments (Russia, China, Iran, UAE, corporate enterprise middleboxes) face silent connection failures to critical developer infrastructure: **OpenAI / Claude APIs, Cursor, GitHub, Docker Hub, Telegram, Discord**.

Standard tools like `ping`, `traceroute`, and `curl` only report vague timeouts:
> *`curl: (35) Recv failure: Connection reset by peer`* or *`Operation timed out`*

They cannot tell you **why** or **where** the packet was killed. Is it:
1. **DNS Poisoning?** (System DNS spoofed IP or returned NXDOMAIN)?
2. **TCP SYN Blackholing?** (ISP firewall swallowed SYN packets without response)?
3. **DPI TLS SNI Filtering?** (Middlebox / TSPU inspected `ClientHello` and injected a fake TCP RST)?
4. **Encrypted Client Hello (ECH) Blockage?** (Cloudflare ECH keys stripped or connections dropped)?
5. **QUIC / UDP 443 Throttling?** (UDP port 443 blocked, stalling HTTP/3 negotiations)?

`net-autopsy` runs a **sub-second forensic autopsy** across Layers 3 through 7, pinpointing the exact tampering mechanism and outputting the specific remediation command.

---

## 🏛️ Forensic Architecture

```
                  ┌────────────────────────────────────────────────────────┐
                  │                 net-autopsy <domain>                   │
                  └─────────────────────────┬──────────────────────────────┘
                                            │
               ┌────────────────────────────┴───────────────────────────┐
               │              LAYER 3/7: Dual-Stack DNS                 │
               │  • System Resolver vs Trusted Cloudflare 1.1.1.1       │
               │  • Bogon / ISP Landing Page Detection                  │
               │  • NXDOMAIN Hijack & ECH Parameter Stripping Check     │
               └────────────────────────────┬───────────────────────────┘
                                            │
               ┌────────────────────────────┴───────────────────────────┐
               │              LAYER 4: TCP & QUIC Probing               │
               │  • TCP Handshake RTT vs Instant RST vs Silent Drop     │
               │  • RFC 9000 QUIC v1 Initial Probe (UDP 443 Health)     │
               └────────────────────────────┬───────────────────────────┘
                                            │
               ┌────────────────────────────┴───────────────────────────┐
               │    LAYER 5/6: 3-Way Differential TLS SNI Autopsy       │
               │  1. Plain Target SNI  (e.g. api.openai.com)           │
               │  2. Neutral SNI Test  (e.g. example.com to same IP)   │
               │  3. Segmented SNI     (Split @ 5B record boundary)     │
               └────────────────────────────┬───────────────────────────┘
                                            │
                                            ▼
               ┌────────────────────────────────────────────────────────┐
               │               Actionable Verdict Engine                │
               │  • Root cause classification & confidence score        │
               │  • Precise bypass tool: DoH / ultradpi / VLESS tunnel  │
               └────────────────────────────────────────────────────────┘
```

---

## 🔬 How the Differential Autopsy Works

### 1. 3-Way Differential SNI Testing
To isolate middlebox (TSPU / GFW) SNI filters with 99% confidence:
- **Test A (Target SNI)**: Sends RFC 8446 TLS 1.3 `ClientHello` with the target domain.
- **Test B (Neutral SNI)**: Sends identical `ClientHello` with `example.com` to the exact same IP address.
  - *If Test B succeeds (ServerHello/Alert received) while Test A fails (RST injected or dropped) $\to$ **100% confirmation of SNI-targeted middlebox blocking**.*
- **Test C (Segmented SNI)**: Sends the target `ClientHello` split across two TCP packets (first 5 bytes of record header, followed by handshake body).
  - *If Test C succeeds while Test A failed $\to$ **100% confirmation that TCP segmentation (e.g. via [`ultradpi`](https://github.com/markankamaransheogarat-sys/ultradpi)) bypasses the DPI filter for this host!***

### 2. ECH (Encrypted Client Hello) Forensics
Queries DNS Type 65 (`HTTPS` RR, RFC 9460) from both the local resolver and DoH. Detects if the ISP DNS stripped `echconfig` payloads to prevent users from encrypting the SNI.

### 3. QUIC / UDP 443 Blackhole Detection
Sends a calibrated 1200-byte QUIC Initial packet. Identifies ISPs that selectively drop UDP 443, causing browsers and CLI tools to freeze during HTTP/3 fallback.

---

## 💻 CLI Output Example

```
$ net-autopsy api.openai.com

⚡ net-autopsy: Commencing Layer 3-7 forensic probe on 'api.openai.com:443'...

┌─────────────────────────────────────────────────────────────────────────────┐
│ 🔬 NET-AUTOPSY: FORENSIC NETWORK REPORT FOR api.openai.com                  │
└─────────────────────────────────────────────────────────────────────────────┘

📡 [LAYER 3/7: DNS RESOLUTION]
  • System DNS (192.168.1.1:53) -> POISONED ⚠️ [14.2 ms]
    Resolved IPs: 127.0.0.1
  • Trusted DNS (1.1.1.1:53)    -> OK ✓ [8.4 ms]
    Canonical IPs: 104.18.7.192, 104.18.6.192
    ⚠️  POISONING EVIDENCE: System DNS returned bogus/private IP: 127.0.0.1 (ISP redirection stub)

🔌 [LAYER 4: TCP HANDSHAKE]
  • SYN-ACK Handshake -> REACHABLE ✓ [28.40 ms]

⚡ [LAYER 4: QUIC / UDP 443]
  • QUIC Initial Probe -> SILENT DROP / THROTTLED ⚠️

🔒 [LAYER 5/6: TLS SNI DIFFERENTIAL AUTOPSY]
  • Plain Target SNI  ("api.openai.com") -> TCP RST INJECTED by Middlebox ❌ [16 ms]
  • Neutral SNI Test  ("example.com")   -> ServerHello Received ✓ [29 ms]
  • Segmented SNI     (Split @ 5B)       -> ServerHello Received ✓ [31 ms]
    🚨 Middlebox SNI filtering CONFIRMED (Target killed, Neutral allowed!)
    ✨ TCP SEGMENTATION BYPASS VIABLE! (DPI parser defeated by segment split)

===============================================================================
📋 AUTOPSY DIAGNOSTIC VERDICT
===============================================================================
  Status:     🛑 BLOCKED (L5/L6) (Confidence: 98%)
  Diagnosis:  DPI SNI RESET: Middlebox injected active TCP RST upon seeing SNI in ClientHello.

  🛠️  ACTIONABLE REMEDIATIONS:
    1. Bypass Local DNS Poisoning: System DNS returned poisoned/bogus records.
       -> Recommended fix: Configure DNS-over-HTTPS (DoH) with 1.1.1.1 or 8.8.8.8
    2. TCP Segmentation Bypass Viable: Middlebox killed plain ClientHello, but passed segmented ClientHello!
       -> Recommended fix: Enable TCP segmentation in ultradpi or zapret. No VPN needed!
===============================================================================
```

---

## 🤖 JSON Telemetry Mode

Pass `--json` for integration into CI/CD pipelines, autonomous monitoring agents, and Telegram HUD bots:

```bash
net-autopsy cursor.sh --json
```

```json
{
  "target_domain": "cursor.sh",
  "target_port": 443,
  "resolved_ip": "104.21.32.18",
  "primary_verdict": "TlsSniFilterRst",
  "confidence_score": 0.98,
  "tls_report": {
    "is_sni_filtered": true,
    "is_segmentation_bypass_effective": true
  },
  "recommendations": [
    {
      "title": "TCP Segmentation Bypass Viable",
      "description": "Middlebox (TSPU/DPI) killed plain ClientHello, but passed segmented ClientHello!",
      "tool_suggestion": "Enable TCP segmentation in ultradpi or zapret"
    }
  ]
}
```

---

## 🚀 Quick Start

### Build & Run
```bash
cargo run --release -- <DOMAIN>
```

### Run Tests
```bash
cargo test
```

---

## 📜 License

Licensed under either of:
- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)
- MIT license ([LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT)
at your option.
