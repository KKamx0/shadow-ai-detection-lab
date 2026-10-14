# Shadow AI Detection Lab

A single-host detection engineering lab built around one question: **when a user moves sensitive data into an unsanctioned AI tool, what does that look like in endpoint telemetry, and can you write a rule that catches it?** That question drives about half of the detection set. The other half is a baseline of standard endpoint detections. The detection index marks which is which.

Detections are authored in Sigma, converted to SPL, validated against live Sysmon telemetry in Splunk, and mapped to MITRE ATT&CK. Every detection ships with its false positives and the tuning it took to get there.

**Status:** In progress. See [ROADMAP.md](ROADMAP.md) for what is built and what is not.

---

## Why this lab

Most home SOC labs detect brute force and Mimikatz. Those techniques are well covered by every SIEM vendor on earth. The gap that is not well covered is **data movement into AI services** — a control problem that most organizations currently handle with a policy document and nothing else.

This lab treats shadow AI usage as a detection engineering problem instead of a policy problem, and asks what telemetry would actually be needed to enforce it.

The detection set is deliberately split. The shadow AI and data movement detections are the focus of the lab. The standard endpoint detections (encoded PowerShell, LOLBin tool transfer, browser credential store access, registry persistence, brute force) are included as a baseline, because a detection library that covers only one novel theme says nothing about whether the author can handle ordinary endpoint telemetry. Both are needed, and they serve different purposes.

## Scope and boundaries

- All telemetry is generated on lab-owned hardware using synthetic data.
- All detection logic is derived from public sources: MITRE ATT&CK, SigmaHQ, Splunk security_content, Atomic Red Team, and vendor documentation.
- No employer systems, data, findings, configurations, or internal policy are represented in this repository in any form.

## Architecture

```
                      Host: Windows 11, 16GB
              (VBS active, VirtualBox on Native API)
                                 |
                          VirtualBox 7.x
                                 |
        +------------------------------------------------+
        |   VM: Windows 11 Enterprise LTSC Eval, 6GB     |
        |                                                |
        |   Sysmon 15.22 (SwiftOnSecurity config)        |
        |            |                                   |
        |            v                                   |
        |   Windows Event Log                            |
        |            |                                   |
        |            v                                   |
        |   Splunk Enterprise 10.4.3 (single instance)   |
        |     + Splunk Add-on for Sysmon (app 5709)      |
        |            ^                                   |
        |            |                                   |
        |   Atomic Red Team (attack generation)          |
        +------------------------------------------------+
```

Single VM by design. Attack generation happens on the monitored host, which is exactly how insider and shadow-AI activity actually originates. See [docs/architecture.md](docs/architecture.md) for the reasoning and [docs/lab-build.md](docs/lab-build.md) for the build log.

## Repository layout

| Path | Contents |
| --- | --- |
| `detections/` | One markdown file per detection: hypothesis, logic, telemetry, false positives, tuning history |
| `sigma/` | The Sigma rule for each detection, vendor agnostic |
| `investigations/` | Full incident writeups: alert to timeline to verdict |
| `docs/` | Architecture, build log, and the detection authoring standard |
| `coverage/` | ATT&CK Navigator layer JSON and coverage notes |
| `screenshots/` | Evidence that each detection fired |
| `scripts/` | Setup and validation helpers |

## Detection index

| # | Detection | ATT&CK | Telemetry | Focus | Status |
| --- | --- | --- | --- | --- | --- |
| 01 | Encoded PowerShell command | T1059.001, T1027 | Sysmon EID 1 | Baseline | Validated |
| 02 | Egress to unsanctioned AI service | T1567 | Sysmon EID 1, 3, 22 | Shadow AI | Validated |
| 03 | Archive staging before egress | T1560.001, T1074.001 | Sysmon EID 1, 11 | Shadow AI | Draft |
| 04 | Clipboard capture volume anomaly | T1115 | Sysmon EID 24 | Shadow AI | Planned |
| 05 | Ingress tool transfer via LOLBin | T1105, T1218 | Sysmon EID 1, 3 | Baseline | Planned |
| 06 | Bulk document read burst | T1005 | Sysmon EID 11, WinEvent 4663 | Shadow AI | Planned |
| 07 | Browser credential store access | T1555.003 | Sysmon EID 10 | Baseline | Planned |
| 08 | Registry Run key persistence | T1547.001 | Sysmon EID 12, 13 | Baseline | Planned |
| 09 | Failed logon burst then success | T1110, T1078 | WinEvent 4625, 4624 | Baseline | Planned |
| 10 | Correlated: read burst, archive, egress | T1005 + T1560 + T1567 | Multi-source | Shadow AI | Planned |

Status values: **Planned** means not yet written. **Draft** means written but not run against live telemetry. **Validated** means the detection fired against generated behavior in this lab, with evidence in `screenshots/`, but the false positive and tuning steps of [docs/detection-standard.md](docs/detection-standard.md) are not done. **Complete** means every step of that standard is done. No detection is Complete yet.

## Known limitations

Splunk Free does not support alerting or scheduled searches. Detections in this repo were built and scheduled during the 60-day Enterprise Trial window, with evidence captured in `screenshots/`. After the trial expires the logic remains valid and runnable as ad-hoc searches, but scheduled execution requires a licensed instance. This is documented rather than hidden because it is a real constraint every home lab hits.

## References

- [SigmaHQ/sigma](https://github.com/SigmaHQ/sigma)
- [splunk/security_content](https://github.com/splunk/security_content)
- [splunk/attack_data](https://github.com/splunk/attack_data)
- [redcanaryco/atomic-red-team](https://github.com/redcanaryco/atomic-red-team)
- [olafhartong/sysmon-modular](https://github.com/olafhartong/sysmon-modular)
- [MITRE ATT&CK](https://attack.mitre.org)

## Author

Kamsochi Ekwueme — [LinkedIn](https://linkedin.com/in/kamsochi-ekwueme-7097b0284) — [GitHub](https://github.com/KKamx0)
