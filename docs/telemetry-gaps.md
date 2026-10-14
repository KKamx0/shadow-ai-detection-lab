# Telemetry Gaps

A standing record of what this lab's sensors cannot see, and what that means for each detection. Read this before trusting any rule in this repository. A detection is only as good as the telemetry under it, and a rule with no data to run against looks identical to a rule with no true positives.

Each gap records what was tested, what was observed, the cause if known, which detection it affects, and whether it is open or resolved. Build history for each test is in [lab-build.md](lab-build.md).

---

## Coverage matrix

Tested on 2026-10-14 on the lab VM (DESKTOP-TSIOB4T, Sysmon 15.22 with the SwiftOnSecurity config), against AI service domains.

| Client | Domain captured (EID 22) | Process attributed | Network connection (EID 3) |
| --- | --- | --- | --- |
| PowerShell (`Resolve-DnsName`, `Invoke-WebRequest`) | Yes | Yes | Yes |
| `curl.exe` | Yes | No, logged as `<unknown process>` | Not tested |
| Microsoft Edge | No | No, only EID 1 | No |
| `nslookup.exe` | No | No | Not tested |

Only one of the four client types is fully covered.

## Gap summary

| # | Gap | Affects | Status |
| --- | --- | --- | --- |
| 1 | `nslookup` produces no DNS telemetry | 02 | Open |
| 2 | Browser-based access produces almost no telemetry | 02 | Open, cause unconfirmed |
| 3 | Process attribution fails for short-lived processes | 02 | Open |
| 4 | TLS hides payload content | 02 | Open, not addressable with endpoint telemetry |
| 5 | Destination IPs are unstable | 02 | Open |
| 6 | Subdomain matching | 02 | Open |
| 7 | Lookup case sensitivity | 02 | Resolved 2026-10-14 |
| 8 | Image loading events are disabled | None currently | Recorded |
| 9 | SwiftOnSecurity config filters some PowerShell process creation | 01 | Open, untested |

---

## Gap 1: `nslookup` produces no DNS telemetry

**Status:** Confirmed. Open.

**Tested:** `nslookup chatgpt.com`.

**Observed:** The lookup resolved successfully. No Sysmon EID 22 event was generated.

**Cause:** `nslookup.exe` queries the configured DNS server directly and bypasses the Windows DNS Client service, which is the component Sysmon EID 22 instruments.

**Affects:** Detection 02. Any tool that performs its own resolution is invisible to a DNS-only detection. This is why EID 3 is required as a second signal.

## Gap 2: Browser-based access produces almost no telemetry

**Status:** Confirmed. Cause partially identified. Open. This is the most serious gap in the project.

**Tested:** `Clear-DnsClientCache`, then `Start-Process "https://chatgpt.com"`, which opened chatgpt.com in Microsoft Edge.

**Observed:** Searching for events with `Image` matching `msedge` returned only EID 1, count 2. No EID 22 and no EID 3. Over the same window, every EID 22 event came from `powershell.exe`. The DNS cache was cleared before the test, so this is not a cached-resolution artifact.

**What is ruled out:** The Sysmon driver. `Sysmon64.exe -c` reports "Network connection: enabled" and "DNS lookup: enabled".

**Candidate causes:**

- `swift.xml` line 202 contains a process-creation exclusion under a `SECTION: Microsoft:Edge` comment, matching command lines beginning with `"C:\Program Files (x86)\Microsoft\Edge Dev\Application\msedge.exe" --type=`. That targets Edge subprocesses. The path is Edge Dev, not the standard Edge install path, so it may not be the rule actually in effect.
- Browser-side DNS over HTTPS, which would resolve names without the Windows DNS Client service. Not ruled out.

The cause is unconfirmed.

**Affects:** Detection 02 does not detect browser-based access to AI services. Browser use is the dominant real-world path for shadow AI, so detection 02 covers programmatic access from scripted clients, not shadow AI generally.

**Evidence:** `screenshots/02-edge-eventcode-1-only.png`, `screenshots/02-eid22-by-process-no-browser.png`, `screenshots/02-browser-no-dns-events.png`.

## Gap 3: Process attribution fails for short-lived processes

**Status:** Confirmed. Open.

**Tested:** `curl.exe -s -o NUL https://api.openai.com`.

**Observed:** EID 22 captured the domain, and the lookup resolved it to OpenAI API. `Image` was logged as `<unknown process>`.

**Likely cause:** `curl.exe` exits before Sysmon resolves the process to an image path. Not confirmed.

**Affects:** Detection 02's severity model depends entirely on the initiating process. Browser-initiated access is a policy conversation, script-initiated access is automated data movement. When `Image` is unresolved, the domain is known but the field that determines what the alert means is lost.

One `curl.exe` invocation produced two EID 22 events one millisecond apart, both for `api.openai.com`, most likely separate A and AAAA lookups. A single client action can produce more than one DNS event, which matters for any count-based threshold.

**Evidence:** `screenshots/02-curl-unknown-process.png`, `screenshots/02-curl-dual-dns-events.png`.

## Gap 4: TLS hides payload content

**Status:** Known by design. Open, and not addressable with endpoint telemetry alone.

EID 22 and EID 3 establish that a connection to a service occurred and from which process. They cannot show what data was sent. Content inspection requires a CASB, a DLP agent, or a TLS-intercepting proxy. None of these exist in this lab.

**Affects:** Detection 02, and any future detection that needs to know what left the host.

## Gap 5: Destination IPs are unstable

**Status:** Confirmed. Open.

**Observed:** Connections to the same services returned `104.18.32.47`, `162.159.140.245`, and `172.66.0.243` across runs. All are Cloudflare edge nodes.

**Affects:** Detection 02, layer 3 (IP-to-service attribution). A static IP allowlist would miss connections and would also match unrelated sites on the same CDN. Attribution would need ASN data or a threat intelligence feed.

## Gap 6: Subdomain matching

**Status:** Open.

The lookup matches the full `QueryName` exactly, so `cdn.chatgpt.com` or `api.chatgpt.com` will not match a CSV row for `chatgpt.com`. Fixing this needs wildcard or regex matching, which changes the detection's behavior and requires its own testing.

**Affects:** Detection 02.

## Gap 7: Lookup case sensitivity

**Status:** Resolved 2026-10-14.

Splunk lookups are case-sensitive by default and DNS is not, so a client sending `ChatGPT.com` would have silently missed the `chatgpt.com` row. Fixed by lowercasing `QueryName` with `eval` before the lookup. Verified with `Resolve-DnsName ChatGPT.com` and `Resolve-DnsName API.OpenAI.com`. Both matched. `screenshots/02-curl-dual-dns-events.png` shows `API.OpenAI.com` logged in mixed case.

**Affects:** Detection 02.

## Gap 8: Image loading events are disabled

**Status:** Confirmed. Not currently affecting any detection.

`Sysmon64.exe -c` reports "Image loading: disabled", so EID 7 is not generated under the current config. No detection in this repository depends on it. Recorded so that a future detection does not assume it is available.

## Gap 9: SwiftOnSecurity config filters some PowerShell process creation

**Status:** Open, untested.

Carried over from the 2026-09-12 entry in [lab-build.md](lab-build.md). The SwiftOnSecurity config deliberately excludes some PowerShell process creation events to reduce noise. Any encoded PowerShell invocation inside those exclusions produces no EID 1, so detection 01 will not see it and will not error. The size of the gap has not been measured.

**Affects:** Detection 01.

---

## What this means for the project

This lab can see programmatic access to AI services from scripted clients that resolve names through the Windows DNS Client service. It cannot see browser-based access. It loses process attribution for short-lived processes. It cannot see payload content under TLS.

Detection 02 should be read with those limits in mind. It covers programmatic access from scripted clients. It is not general shadow AI coverage, and the browser path, which is how most shadow AI use happens, is currently undetected.
