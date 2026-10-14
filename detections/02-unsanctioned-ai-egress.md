# 02 — Egress to Unsanctioned AI Service

## Hypothesis

A user or process on a managed endpoint sends data to a generative AI service that is not on the organization's approved list, either through a browser session, a desktop client, or a script calling the service API directly.

This is the flagship detection of this lab. It is deliberately harder than it looks, and the interesting work is in the parts that fail.

## ATT&CK mapping

| Tactic | Technique | ID |
| --- | --- | --- |
| Exfiltration | Exfiltration Over Web Service | T1567 |
| Command and Control | Application Layer Protocol: Web Protocols | T1071.001 |

The mapping is imperfect and that is worth saying out loud. ATT&CK models adversary behavior, and most shadow AI usage is a well-meaning employee taking a shortcut, not an adversary. T1567 describes the mechanics correctly while describing the intent badly. Detections built for this class of activity should be treated as policy-violation signal feeding a governance process, not as compromise signal feeding an IR process.

## Required telemetry

| Source | Event ID | Notes |
| --- | --- | --- |
| Sysmon | 22 (DNS Query) | The primary signal. Gives `QueryName` and the initiating `Image` |
| Sysmon | 3 (Network Connect) | Destination IP and port, initiating process |
| Sysmon | 1 (Process Create) | Identifies non-browser clients and script-based API calls |

Sysmon config sections required: `DnsQuery` must be enabled and must not be filtered down to a small include list. `NetworkConnect` must be enabled. Both are expensive and both are disabled or heavily filtered in many stock configs. `sysmon-modular` enables them.

**The hard constraint.** Sysmon EID 22 gives you the hostname, not the payload. TLS means the request body is invisible without interception you do not have in this lab. So this detection answers "did this host talk to an AI service, from what process, how often" and it does not answer "what data left." That boundary is a finding, not a shortcoming, and it is the honest version of what endpoint telemetry can do here. Content-level enforcement requires a CASB, a DLP agent, or a TLS-inspecting proxy. Naming that gap is more valuable than pretending the rule closes it.

**Scripted access to consumer front-ends is bot-blocked.** During validation, `Invoke-WebRequest` to `https://chatgpt.com` received a Cloudflare bot challenge instead of the page content. The detection still fired, because DNS resolution and the TLS connection both completed before the challenge was served. The implication is that real bulk data movement to AI services is more likely to go through APIs than through scripted requests to chat front-ends. `lookups/ai_services.csv` should therefore weight API endpoints over chat front-end domains.

**Pre-check query.** DNS logging is the single most commonly missing sensor for this detection.

```spl
index=endpoint sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=22
| stats count by Image
| sort - count
```

If this is empty, `DnsQuery` is off. Nothing below will work.

## Logic

Sigma rule: [`sigma/windows/dns_query/unsanctioned_ai_service_egress.yml`](../sigma/windows/dns_query/unsanctioned_ai_service_egress.yml)

The domain list lives in a lookup, not in the rule, because it changes weekly and a rule that requires editing every time a new service launches will not survive contact with reality.

`lookups/ai_services.csv`:

```
domain,service,sanctioned
api.openai.com,OpenAI API,false
chatgpt.com,ChatGPT,false
claude.ai,Claude,true
api.anthropic.com,Anthropic API,true
gemini.google.com,Gemini,false
...
```

SPL as run in this lab:

```spl
index=endpoint sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=22
| rex field=QueryName "(?<registered_domain>[^\.]+\.[^\.]+)$"
| lookup ai_services.csv domain AS registered_domain OUTPUT service, sanctioned
| where isnotnull(service) AND sanctioned="false"
| stats count AS query_count,
        dc(QueryName) AS distinct_hosts,
        min(_time) AS first_seen,
        max(_time) AS last_seen
        BY host, user, Image, service
| eval duration_min=round((last_seen-first_seen)/60,1)
| convert ctime(first_seen) ctime(last_seen)
| sort - query_count
```

**Why the process matters more than the domain.** A browser hitting an AI service is a policy conversation. `python.exe`, `curl.exe`, or an unsigned binary hitting the same API endpoint is a different conversation entirely, because it means scripted, volume data movement rather than a person typing. Splitting on `Image` is what turns this from a web filter into a detection.

## Validation

Validated 2026-10-14 on host DESKTOP-TSIOB4T, user `analyst`, Sysmon 15.22 with the SwiftOnSecurity config, Splunk Enterprise 10.4.3.

Planned tests and what was actually run:

| # | Planned test | Status |
| --- | --- | --- |
| 1 | Browser session to an unsanctioned service | Not run |
| 2 | Scripted call with `Invoke-WebRequest` | Run once against `https://chatgpt.com`, not an API endpoint and not in a loop |
| 3 | Same call from `curl.exe` | Not run |
| 4 | Bypass DNS-based detection | Not run as planned. A DNS bypass was found by accident with `nslookup`, see Finding 2 |

The queries below are raw event searches, not the lookup-based SPL in the Logic section. The Logic SPL filters on `sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"`, but in this lab the Sysmon events arrive with sourcetype `XmlWinEventLog`, so the Logic SPL needs to be re-run as written before it is relied on.

### Finding 1: the baseline works

Behavior generated by:

```powershell
Resolve-DnsName chatgpt.com
Invoke-WebRequest https://chatgpt.com
```

Query run:

```spl
index=endpoint EventCode=22 QueryName="*chatgpt*"
| table _time, User, Image, QueryName
```

Result: Each command produced one Sysmon EID 22 event with `Image` = `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe` and `QueryName` = `chatgpt.com`, attributed to `DESKTOP-TSIOB4T\analyst`. Two events in total, at 02:35:09.458 and 02:35:11.223.

Evidence: `screenshots/02-ai-egress-eid22-dns.png`

### Finding 2: DNS-only detection has a bypass, demonstrated

The first test used `nslookup chatgpt.com`. It resolved successfully and produced zero Sysmon EID 22 events.

Root cause: `nslookup.exe` sends its query directly to the configured DNS server over the network and does not go through the Windows DNS Client service. Sysmon EID 22 is generated from the DNS Client service, so resolution that bypasses it is not recorded. Any tool that performs its own resolution is invisible to a detection built only on EID 22.

This was discovered by accident during validation, not by the planned bypass test. It is the reason EID 3 is required as a second signal rather than an optional extra.

### Finding 3: EID 3 covers the bypass, but with less information

Query run:

```spl
index=endpoint EventCode=3 Image="*powershell.exe"
| table _time, User, Image, DestinationIp, DestinationPort, DestinationHostname
```

Result: One EID 3 event at 02:35:11.256, 33 ms after the second EID 22 event, with `DestinationIp` = `104.18.32.47`, `DestinationPort` = `443`, `Image` = `powershell.exe`. `DestinationHostname` was empty.

EID 3 confirms that a connection occurred and which process made it, but it does not attribute the connection to a domain. Mapping `104.18.32.47` back to an AI service would need IP range mapping, ASN data, or a threat intelligence feed. This lab has none of these.

Evidence: `screenshots/02-ai-egress-eid3-network.png`

## Detection coverage layers

| Layer | Telemetry | What it covers | What it does not cover |
| --- | --- | --- | --- |
| 1 | Sysmon EID 22 | Normal usage: resolution through the Windows DNS Client service, with domain and process | Tools that perform their own DNS resolution, such as `nslookup`, or connections to a hardcoded IP |
| 2 | Sysmon EID 3 | DNS evasion: the connection is still recorded, with destination IP, port, and process | Which service the IP belongs to. `DestinationHostname` was empty in testing |
| 3 | IP-to-service attribution | Turning a bare IP from layer 2 into a named AI service | Requires IP range mapping, ASN data, or threat intelligence, which are outside this lab's scope |

In this lab, layers 1 and 2 are in place and layer 3 is not. A connection that evades layer 1 is visible only as an outbound connection to an IP address.

## False positives

**Anticipated false positives.** The sources below are expected in an enterprise environment. None were observed in this lab.

| Source | Frequency | Handling |
| --- | --- | --- |
| Sanctioned tools that embed a model provider (IDE assistants, browser features) | High | Maintain the `sanctioned` column properly, review monthly |
| Ad and telemetry domains that resolve near AI domains | Low | Registered-domain extraction rather than substring match |
| Security tooling performing reputation lookups | Occasional | Allowlist by `Image` with signature verification |
| A user reading an article about AI | Routine | This rule fires on DNS to the service, not to news coverage of it. Confirm domain list hygiene |

The lab VM has no endpoint management agents, no developer tooling, and no real user activity. Its benign baseline is not representative of a production endpoint, and no false positive rate has been measured.

The dominant failure mode is not false positives, it is **the domain list going stale**. A rule that was 95 percent accurate in January is 60 percent accurate in June because eleven new services launched. Build the review cadence into the runbook or the rule dies quietly.

## Tuning history

_No entries yet._

## Severity and response

**Severity:** Low for browser-initiated, Medium for script-initiated, High when combined with detection 03 (archive staging) within a 30 minute window.

**Triage steps:**
1. Identify the initiating process. Browser or not. That single fact routes the rest of the investigation.
2. Pivot on `ProcessGuid` to Sysmon EID 11 (FileCreate) and file read activity in the preceding 15 minutes. What was the process touching before it reached out.
3. Establish whether the user has a documented business need. This is a governance question, not a security question, and it should be routed to a person, not escalated to IR.
