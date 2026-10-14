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

## 2026-10-14 — Splunk pipeline confirmed, detections 01 and 02 validated

**Environment:** Windows 11 Enterprise LTSC VM, hostname DESKTOP-TSIOB4T, user `analyst`. Sysmon 15.22 with the SwiftOnSecurity config. Splunk Enterprise 10.4.3, `index=endpoint`, sourcetype `XmlWinEventLog`.

**Hostname correction.** The VM hostname is DESKTOP-TSIOB4T, not VICTIM-01 as recorded in the 2026-09-12 entry. The intended hostname was never set. Open cosmetic item: rename the host to VICTIM-01, or leave it and treat VICTIM-01 in earlier entries as the intended name. `docs/architecture.md` now records the actual hostname. It has no effect on detection logic.

**What I was trying to do:** Confirm Sysmon events reach Splunk with fields parsed, then validate detections 01 and 02 against live telemetry.

**What happened:**

- Pipeline confirmed end to end. A search for `index=endpoint EventCode=1` over 24 hours returned 8,315 events, with `Computer`, `User`, `process_name`, and `CommandLine` extracted by the Splunk Add-on for Sysmon. Evidence: `screenshots/00-pipeline-sysmon-fields-parsed.png`.
- Detection 01 returned exactly one event for `powershell.exe -enc dwBoAG8AYQBtAGkA`, with the full `CommandLine` and user `DESKTOP-TSIOB4T\analyst`. The screenshot from this run has since been replaced; see the next entry.
- Detection 02: `Resolve-DnsName chatgpt.com` and `Invoke-WebRequest https://chatgpt.com` each produced a Sysmon EID 22 event with `Image` = `powershell.exe` and `QueryName` = `chatgpt.com`. The matching EID 3 event recorded `104.18.32.47:443` with an empty `DestinationHostname`. The screenshots from this run have since been replaced; see the next entry.
- The first detection 02 test used `nslookup chatgpt.com`. It resolved successfully and produced no EID 22 event.

**How I diagnosed it:** `Resolve-DnsName` and `Invoke-WebRequest` against the same domain did produce EID 22 events, so DNS query logging itself was working. The difference was the resolver path. `nslookup.exe` queries the configured DNS server directly and does not use the Windows DNS Client service, which is what Sysmon EID 22 records. `Resolve-DnsName` and `Invoke-WebRequest` both go through the DNS Client service.

**Fix:** No sensor change. This is a property of EID 22, not a misconfiguration. Detection 02 now documents EID 3 as a required second signal, and the gap that remains (EID 3 gives a bare IP with no hostname) is recorded in the detection's coverage layers section.

**What I would do differently:** Run the planned bypass test deliberately, as test 4 in detection 02 specifies, instead of finding the bypass by accident. Also run the documented Logic SPL exactly as written rather than simplified ad hoc queries. See the next entry.

**Follow-up:**

- Detection 02 tests 1 (browser), 3 (`curl.exe`), and 4 (hardcoded IP) have not been run.
- Neither detection has run against normal activity, so no false positive rate has been measured and neither has a tuning history entry.
- The SwiftOnSecurity PowerShell exclusion follow-up from 2026-09-12 is still open.

---

## 2026-10-14 — Documented SPL corrected and re-run as written

**What I was trying to do:** Run the Logic SPL for detections 01 and 02 exactly as written in the detection files, and replace the earlier screenshots, which showed simplified searches.

**What happened:**

- The documented SPL in both detection files filtered on `sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"`. That sourcetype does not exist in this lab. The SPL had never been executed, so the mismatch had gone unnoticed.
- The screenshots from the earlier session showed simplified ad hoc queries, not the documented Logic SPL. They proved the telemetry was present but not that the documented detections worked.
- Detection 02's SPL reduced `QueryName` to its last two labels before the lookup. `api.openai.com` became `openai.com`, which is not a row in `lookups/ai_services.csv`, so the lookup could never match an API domain.
- The lookup table had never been uploaded into Splunk. Without it, detection 02's EID 22 query fails with "The lookup table 'ai_services.csv' does not exist or is not available."

**How I diagnosed it:** `index=endpoint | stats count by sourcetype` returned `XmlWinEventLog` with 7,954 events over 24 hours. The label reduction turned `api.openai.com` into `openai.com`, which has no row in `ai_services.csv`, so API domains could not match. The missing lookup was reported directly by the search error.

**Fix:**

- Changed the sourcetype filter in both detection files, Logic and pre-check queries, to `sourcetype=XmlWinEventLog`.
- Removed the label reduction from detection 02. The lookup now matches on the full `QueryName`.
- Uploaded `lookups/ai_services.csv` through Settings > Lookups > Lookup table files, and documented the upload as a prerequisite in detection 02.
- Added an EID 3 query to detection 02's Logic section. The file already argued that EID 3 is required to cover DNS evasion, but only the EID 22 query was written down.
- Re-ran all three Logic queries as written and replaced the screenshots. Detection 01 returned 1 event with `user`, `host`, `parent_process_name`, and `encoded_len` populated. Detection 02's EID 22 query returned 2 rows, ChatGPT and OpenAI API. The `api.openai.com` query was generated with `Resolve-DnsName api.openai.com` from an admin PowerShell session. Detection 02's EID 3 query returned 1 event to `162.159.140.245:443` with an empty `DestinationHostname`. Evidence: `screenshots/01-encoded-powershell-fired.png`, `screenshots/02-ai-egress-eid22-dns.png`, `screenshots/02-ai-egress-eid3-network.png`.
- Lowercased `QueryName` before the lookup in detection 02. DNS is case-insensitive but Splunk lookups are case-sensitive by default, so a query for `ChatGPT.com` would have silently missed the `chatgpt.com` row. Verified with `Resolve-DnsName ChatGPT.com` and `Resolve-DnsName API.OpenAI.com`: both matched, returning ChatGPT and OpenAI API at 05:42:57. The detection 02 screenshot was replaced with this run. Resolved.
- The EID 3 destination differed from the earlier session (`104.18.32.47`). Both addresses are Cloudflare edge nodes. Recorded in detection 02's coverage layers section as evidence that IP-based attribution needs ASN or threat intelligence data rather than a fixed IP list.

These were documentation and logic errors, not telemetry problems. The sensor and the pipeline were working throughout, and both detections had already fired correctly against the raw events in the earlier session.

**What I would do differently:** Run the documented SPL as written before taking any evidence screenshot, and screenshot only that. A simplified query that works says nothing about whether the documented one does. Upload lookups and check sourcetypes with `stats count by sourcetype` as part of the pipeline check, before any detection is written against them.

**Follow-up:**

- Detection 02 does not match subdomains. The lookup matches the full `QueryName` exactly, so `cdn.chatgpt.com` or `api.chatgpt.com` will not match a CSV row for `chatgpt.com`. Open.
- Detection 02 tests 1 (browser), 3 (`curl.exe`), and 4 (hardcoded IP) have not been run.
- Neither detection has run against normal activity, so no false positive rate has been measured and neither has a tuning history entry. Both remain Validated, not Complete.
- The SwiftOnSecurity PowerShell exclusion follow-up from 2026-09-12 is still open.

---

## 2026-10-14 — Detection 02 tested against four client types

**What I was trying to do:** Test detection 02 against the client types it claims to cover, not only PowerShell: a browser, `curl.exe`, and `nslookup.exe`.

**What happened:**

- **Microsoft Edge.** Ran `Clear-DnsClientCache`, then `Start-Process "https://chatgpt.com"`. Events with `Image` matching `msedge` were EID 1 only, count 2. No EID 22 and no EID 3. Over the same window, every EID 22 event came from `powershell.exe`. Evidence: `screenshots/02-edge-eventcode-1-only.png`, `screenshots/02-eid22-by-process-no-browser.png`, `screenshots/02-browser-no-dns-events.png`.
- **`curl.exe`.** `curl.exe -s -o NUL https://api.openai.com` produced EID 22 with the domain captured, and the lookup resolved it to OpenAI API. `Image` was logged as `<unknown process>`. Evidence: `screenshots/02-curl-unknown-process.png`.
- **`nslookup.exe`.** No EID 22, as recorded in the earlier entry.
- **`Invoke-WebRequest` to an API endpoint.** `Invoke-WebRequest https://api.openai.com` returned the API's welcome JSON. The same approach against the chatgpt.com front end earlier returned a Cloudflare bot challenge.
- **Destination IPs.** A third Cloudflare address, `172.66.0.243`, appeared alongside `104.18.32.47` and `162.159.140.245`.
- **Sysmon config.** `Sysmon64.exe -c` reports "Network connection: enabled", "DNS lookup: enabled", and "Image loading: disabled".

Detection 02 fully works against one of the four client types.

**How I diagnosed it:**

- Browser: clearing the DNS cache first ruled out cached resolution. `Sysmon64.exe -c` showing network and DNS logging enabled ruled out the driver. `swift.xml` line 202 has a process-creation exclusion under a `SECTION: Microsoft:Edge` comment for command lines beginning `"C:\Program Files (x86)\Microsoft\Edge Dev\Application\msedge.exe" --type=`. That path is Edge Dev, not standard Edge, so it may not be the rule in effect. Browser-side DNS over HTTPS has not been ruled out. Cause unconfirmed.
- curl: the domain was captured but the image was not, which points to `curl.exe` exiting before Sysmon resolves the process. Not confirmed.

**Operational note:** `Sysmon64.exe -c` silently produces no output when run without administrator rights. Three config checks returned empty for this reason, which led to an incorrect conclusion that the config contained no browser exclusions. The checks were re-run elevated.

**Fix:** No fix for the browser or curl gaps yet. Recorded them in a new standing document, `docs/telemetry-gaps.md`, with a coverage matrix and one section per gap. Rescoped detection 02's hypothesis to programmatic access from scripted clients and added a Coverage section to it. Linked the gaps document from the README.

**What I would do differently:** Test the browser path first. It is the dominant real-world path for shadow AI, and it was the last client type tested. Run every `Sysmon64.exe -c` check from an elevated prompt, and treat empty output as a failed check rather than an answer.

**Follow-up:**

- Gap 2, browser: confirm whether the SwiftOnSecurity Edge exclusion or browser DNS over HTTPS is responsible. Open.
- Gap 3, short-lived processes: find a way to attribute `<unknown process>` DNS events. Open.
- Gap 6, subdomain matching. Open.
- Detection 02 test 4 (hardcoded IP) has not been run. EID 3 was not tested for `curl.exe` or `nslookup.exe`.
- Neither detection has run against normal activity, so no false positive rate has been measured. Both remain Validated, not Complete.

---

## Entry template

## YYYY-MM-DD — Title

**What I was trying to do:**

**What happened:**

**How I diagnosed it:**

**Fix:**

**What I would do differently:**
