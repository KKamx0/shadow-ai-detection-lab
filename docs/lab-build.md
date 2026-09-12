# Lab Build Log

Dated entries. Record what broke and how it was diagnosed, not just what worked. This file is the reason a reader believes the rest of the repository.

---

## 2026-09-09 — Host preparation

**Host:** Acer Aspire 14, Intel Core 5 120U, 16GB RAM, Windows 11.

**Prior attempt (failed).** An earlier build on this machine used VirtualBox with multiple VMs and Wazuh. It failed with repeated guest freezes and kernel soft-lockups. Root cause was VirtualBox falling back to software emulation because the Windows hypervisor was active, combined with memory pressure from running more guests than 16GB supports.

**Corrective actions:**

- [x] Memory Integrity disabled (Windows Security > Device Security > Core Isolation)
- [x] Hyper-V, Virtual Machine Platform, Windows Hypervisor Platform, WSL, Windows Sandbox unchecked in Windows Features
- [x] `bcdedit /set hypervisorlaunchtype off` and `bcdedit /set vsmlaunchtype off`
- [x] DeviceGuard and Credential Guard disabled via registry
- [x] Fast Startup disabled with `powercfg /hibernate off`
- [x] Reboot
- [x] Intel VT-x confirmed enabled in BIOS

**Verification result:** `msinfo32` continued to report a detected hypervisor after all of the above. Virtualization-based security could not be fully disabled on this hardware and OS build.

**Why this turned out not to matter.** The `msinfo32` line is a proxy signal, not the thing that actually breaks a lab. The real question is which execution engine VirtualBox ends up using. Checked directly via Machine > Session Information > Runtime, which reported **Native API**.

Three possible outcomes were in play:

| Execution engine | Meaning | Viable |
| --- | --- | --- |
| VT-x / AMD-V | Raw hardware virtualization | Yes, fastest |
| Native API | Hardware virtualization routed through the Windows Hypervisor Platform | Yes, roughly 20-40% slower |
| Interpreter / IEM | Software emulation, no hardware acceleration | No, this was the prior failure |

Native API is genuine hardware virtualization. It is not the software emulation path that caused the earlier soft-lockups. Build proceeded on Native API rather than spending further time trying to defeat VBS.

**Lesson:** measure the thing you actually care about. Several hours went into chasing a diagnostic string when a two-minute check of the execution engine would have answered the real question immediately.

**Design change from the failed attempt:** single VM instead of a multi-host range, attack generation on the monitored host, Splunk instead of Wazuh. Rationale in `architecture.md`.

---

## 2026-09-12 — Guest OS build

**Planned:** Windows 10 Enterprise Evaluation, chosen to keep memory footprint low.

**Blocked:** Windows 10 Enterprise Evaluation is no longer distributed. Windows 10 reached end of support on 2025-10-14 and the corporate evaluation images have since been decommissioned. The Evaluation Center download pages redirect to Windows 11.

**Built instead:** Windows 11 Enterprise **LTSC** Evaluation, build 26100.ge_release.240331-1435. LTSC was selected over the 25H2 general release deliberately. It ships without the Store, Cortana, and most bundled modern apps, which means a smaller image, lower memory use, and materially less background process and network noise polluting endpoint telemetry. On a detection lab, a quieter baseline is a feature.

**VM specification:**

| Setting | Value |
| --- | --- |
| Name | soc-lab-win11 |
| Disk | 80 GB VDI, dynamically allocated |
| Memory | 6144 MB |
| vCPU | 2 |
| Chipset | ICH9 |
| Firmware | UEFI, Secure Boot enabled, TPM 2.0 |
| Network | NAT |
| Audio | Disabled |
| Hostname | VICTIM-01 |
| Local account | analyst |

Licence is valid 90 days and extendable twice with `slmgr /rearm`.

**Issues encountered:**

- Out-of-box setup attempted to force a Microsoft account. Resolved via the local account path.
- Mouse input was dead on first boot. Cause was the Pointing Device set to USB Tablet while the USB controller had been disabled as a performance optimisation. Changed to PS/2 Mouse.
- VirtualBox's default host key is Right Ctrl, which does not exist on this keyboard. Remapped in File > Preferences > Input.
- One hang during a post-install reboot, cleared by a VM reset. No recurrence.

**Snapshots taken:** `clean-install`.

---

## 2026-09-12 — Sysmon telemetry gap: EID 1 and 22 missing

**What I was trying to do:** Install Sysmon and confirm the event types required by detections 01 and 02 were being produced, before writing any detection logic against them.

**What happened:** Sysmon 15.22 installed cleanly. Service `Sysmon64` reported Running and the operational log was populating. But the pre-check returned only EID 4, 7, 10, 11, 13, 16, and 17. Launching `notepad.exe` produced no EID 1 (process create). Running `nslookup` resolved successfully but produced no EID 22 (DNS query).

**Why it mattered:** Detection 01 reads `CommandLine` from EID 1. Detection 02 reads `QueryName` from EID 22. Both would have executed without error and returned zero results. A detection with no underlying telemetry is indistinguishable from a detection with no true positives, which is the exact failure the pre-check step in `docs/detection-standard.md` exists to catch.

**How I diagnosed it:** Confirmed the service was running and the log was receiving events, which ruled out the sensor itself. Since some event types were present and others were not, the cause had to be config filtering rather than a broken install. Dumped the running configuration with `Sysmon64.exe -c` to confirm which rule groups were loaded.

**Root cause:** The config in use was sysmon-modular's default assembled `sysmonconfig.xml`. sysmon-modular is a library of rule modules intended to be composed into an environment-specific configuration, and its defaults leave several rule groups disabled. It is not a drop-in config.

**Fix:** Switched to the SwiftOnSecurity `sysmon-config`, which enables EID 1, 3, and 22 by default. Applied with `Sysmon64.exe -c`, which updates a running install without reinstalling the driver.

**What I would do differently:** Run the pre-check before selecting a config, not after. Choosing a Sysmon config is a telemetry decision, and telemetry requirements should be derived from the detections you intend to write.

**Follow-up:** SwiftOnSecurity's config deliberately excludes some PowerShell process creation events to reduce noise. This is the blind spot already flagged in `detections/01-encoded-powershell.md`. Needs tuning, with a documented before/after, once detection 01 is validated.

---

## Entry template

## YYYY-MM-DD — Title

**What I was trying to do:**

**What happened:**

**How I diagnosed it:**

**Fix:**

**What I would do differently:**
