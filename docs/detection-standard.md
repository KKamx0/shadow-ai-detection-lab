# Detection Authoring Standard

Every detection in this repository follows this structure. A detection is not considered complete until all sections are filled and the validation loop has been run.

## Required sections

**Hypothesis.** One sentence stating the adversary or insider behavior being detected, in plain language. If you cannot state it in one sentence, the detection is doing too much.

**ATT&CK mapping.** Technique ID and name. Sub-technique where it applies. A detection with no mapping is a search, not a detection.

**Required telemetry.** The exact event sources and event IDs the logic depends on, plus the Sysmon config sections or Windows audit policy settings that must be enabled to produce them. This section is the one most home labs skip and the one that matters most, because a rule that silently has no data to run against looks identical to a rule with no true positives.

**Logic.** The Sigma rule, and the converted SPL as it actually runs in this lab.

**Validation.** How the behavior was generated (Atomic Red Team test number, manual command, or replayed dataset), and confirmation the detection fired.

**False positives.** What benign activity trips this rule in a real environment. Every rule has at least one. Writing "none" means the rule has not been run long enough.

**Tuning history.** What was changed, why, and what it cost in coverage. Dated entries.

**Severity and response.** Suggested alert severity and the first three triage steps an analyst should take.

## Validation loop

No detection is marked complete until this loop closes:

1. Write the hypothesis before writing any logic.
2. Confirm the required telemetry is actually present. Query for the raw event first. If the event is not there, fix the sensor before touching the rule.
3. Write the Sigma rule.
4. Convert to SPL and run it against historical data. Note the baseline hit count.
5. Generate the behavior. Confirm the detection fires.
6. Let it run against normal activity. Record every false positive.
7. Tune. Record what the tuning cost you.

Steps 2 and 6 are the ones that separate this from a tutorial. **Document the failures.** A rule that missed the first time and was diagnosed is worth more in this repository than a rule that worked immediately, because the diagnosis is the skill being demonstrated.

## Severity guidance

| Level | Meaning |
| --- | --- |
| Informational | Useful for hunting and correlation, not for alerting on its own |
| Low | Suspicious in aggregate, expect routine benign hits |
| Medium | Warrants analyst review, benign hits are possible but should be explainable |
| High | Should not occur in normal operation for the monitored population |
| Critical | Reserved for confirmed-malicious-by-definition behavior |

Most rules should be low or medium. A repository where everything is critical demonstrates that the author has never carried a pager.

## Naming

- Detection files: `NN-short-name.md` in `detections/`
- Sigma rules: `sigma/windows/<category>/<short_name>.yml`
- Screenshots: `NN-short-name-<what-it-shows>.png`

## Style

Write for an analyst who has to action this alert at 3am and has never seen the rule before. No emoji in detection logic files. No unexplained acronyms. If a field name is non-obvious, say where it comes from.
