# Lab Build Log

Dated entries. Record what broke and how it was diagnosed, not just what worked. This file is the reason a reader believes the rest of the repository.

---

## 2026-09-09 — Host preparation

**Host:** Acer Aspire 14, Intel Core 5 120U, 16GB RAM, Windows 11.

**Prior attempt (failed).** An earlier build on this machine used VirtualBox with multiple VMs and Wazuh. It failed with repeated guest freezes and kernel soft-lockups. Root cause was VirtualBox falling back to software emulation because the Windows hypervisor was active, combined with memory pressure from running more guests than 16GB supports.

**Corrective actions:**

- [ ] Memory Integrity disabled (Windows Security > Device Security > Core Isolation)
- [ ] Hyper-V, Virtual Machine Platform, Windows Hypervisor Platform, WSL, Windows Sandbox unchecked in Windows Features
- [ ] `bcdedit /set hypervisorlaunchtype off`
- [ ] Reboot
- [ ] `msinfo32` no longer reports a detected hypervisor
- [ ] Task Manager reports Virtualization: Enabled
- [ ] Intel VT-x confirmed enabled in BIOS

**Verification result:**

_Record the msinfo32 output here._

**Design change from the failed attempt:** single VM instead of a multi-host range, attack generation on the monitored host, Splunk instead of Wazuh. Rationale in `architecture.md`.

---

## Entry template

## YYYY-MM-DD — Title

**What I was trying to do:**

**What happened:**

**How I diagnosed it:**

**Fix:**

**What I would do differently:**
