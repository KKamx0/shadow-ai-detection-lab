# Roadmap

## Phase 1 — Pipeline (in progress)

- [x] Host prepared. VirtualBox running on Native API execution engine.
- [x] VM built: Windows 11 Enterprise LTSC Evaluation, 80GB, 6GB RAM, 2 vCPU, NAT.
- [x] Guest Additions installed.
- [ ] Windows Defender real-time protection disabled for test execution.
- [x] Sysmon 15.22 installed.
- [x] Sysmon configured with the SwiftOnSecurity sysmon-config. The sysmon-modular default config was tried first and dropped EID 1 and 22. See `docs/lab-build.md`, 2026-09-12.
- [x] Splunk Enterprise installed and indexing the Sysmon channel.
- [x] Splunk Add-on for Sysmon installed and parsing fields.
- [ ] CIM data model mapping verified.
- [x] First search confirms Sysmon events are searchable.

## Phase 2 — Detections

Target: 8 to 10 complete detections. A detection is complete only when it satisfies
every section of `docs/detection-standard.md`, including documented false positives.

- [ ] 01 Encoded PowerShell command (T1059.001, T1027)
- [ ] 02 Egress to unsanctioned AI service (T1567)
- [ ] 03 Archive staging before egress (T1560.001, T1074.001)
- [ ] 04 Clipboard capture volume anomaly (T1115)
- [ ] 05 Ingress tool transfer via LOLBin (T1105, T1218)
- [ ] 06 Bulk document read burst (T1005)
- [ ] 07 Browser credential store access (T1555.003)
- [ ] 08 Registry Run key persistence (T1547.001)
- [ ] 09 Failed logon burst then success (T1110, T1078)
- [ ] 10 Correlated: read burst, archive, egress

## Phase 3 — Portfolio

- [ ] One full investigation writeup in `investigations/`
- [ ] ATT&CK Navigator coverage layer in `coverage/`
- [ ] Architecture diagram in `docs/`
- [ ] Screenshot evidence for every completed detection

## Notes

Splunk Enterprise Trial runs 60 days from install and includes alerting. Scheduled
alerts must be built and evidenced inside that window. After it lapses to Splunk Free,
alerting is unavailable and detections run ad hoc only.

Windows evaluation license is 90 days, extendable twice with `slmgr /rearm`.
