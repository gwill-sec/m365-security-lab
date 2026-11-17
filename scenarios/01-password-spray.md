# Scenario 1 — Password Spray → Account Compromise

**MITRE ATT&CK:** [T1110.003 — Brute Force: Password Spraying](https://attack.mitre.org/techniques/T1110/003/)

---

## Summary

An attacker tried one weak, company-themed password (`Ironclad2026!`) once against several accounts from a single IP in ~90 seconds. Most attempts failed, but **Brandon Hayes** (Warehouse Lead) had that password and **no MFA registered**, so the attacker signed in with the password alone and opened his mailbox ~2 minutes later.

I detected the spray in KQL, confirmed the compromise, contained the account, then turned the hunting query into an automatic **Sentinel detection rule** and triaged the resulting incident end to end.

**Verdict:** True positive — confirmed account compromise via password spray.

---

## What a password spray is

One or two common passwords tried against **many accounts** (vs. brute force = many passwords against one account). Each account sees a single failure, so no lockout and low noise. A leading cause of cloud account takeover.

---

## Detection

### Query A — detect the spray pattern (group by attacking IP)

```kql
SigninLogs
| where TimeGenerated > ago(3h)
| where ResultType == "50126"                 // invalid username or password
| summarize FailedAttempts = count(),
            TargetedUsers = dcount(UserPrincipalName),
            UsersTargeted = make_set(UserPrincipalName),
            FirstSeen = min(TimeGenerated),
            LastSeen = max(TimeGenerated)
            by IPAddress
| where TargetedUsers >= 3                     // one IP hitting many users = spray
| order by TargetedUsers desc
```

**Result:** one IP, failed password attempts against 7 distinct users (including the CEO and CFO) inside ~90 seconds. One failure per user + many users + a tight time window = automated spray, not people mistyping.

### Query B — did any attempt succeed?

The question that decides severity. Detecting the spray is step one; confirming a compromise is what matters.

```kql
let SprayIPs = SigninLogs
    | where TimeGenerated > ago(3h)
    | where ResultType == "50126"
    | summarize TargetedUsers = dcount(UserPrincipalName) by IPAddress
    | where TargetedUsers >= 3
    | project IPAddress;
SigninLogs
| where TimeGenerated > ago(3h)
| where IPAddress in (SprayIPs)
| where ResultType == "0"                      // successful sign-in
| where UserPrincipalName !startswith "admin"  // exclude my own admin (shares the lab IP)
| project TimeGenerated, UserPrincipalName, AppDisplayName, IPAddress, AuthenticationRequirement
| order by TimeGenerated asc
```

**Result:** `bhayes` signed in successfully from the spray IP, ~2 minutes after the spray, with `singleFactorAuthentication` — **a correct password with no MFA in the way.** Confirmed compromise.

| Evidence | Meaning |
|----------|---------|
| Success for bhayes from the spray IP | Password guessed, used by the attacker |
| ~2 min after the spray | Spray → hit → immediate use |
| Outlook / OfficeHome | Went straight for email |
| singleFactorAuthentication | Password only — nothing stopped it |

**Root cause:** Brandon never registered MFA, and Security Defaults only prompts regular users "when necessary." A normal-looking IP + correct password = straight in. (Fixed in [Scenario 4](04-conditional-access.md).)

---

## Response

- **Revoke sessions** (Entra → Users → Revoke sessions) — a password reset alone does **not** end tokens already issued.
- **Reset password**, force change at next sign-in.
- **Scope:** check sent mail, inbox rules, file access, and new MFA methods for attacker persistence.

---

## Detection engineering — Sentinel analytics rule

Turned Query A into a scheduled rule so Sentinel catches this automatically.

| Setting | Value | Why |
|---------|-------|-----|
| Severity | Medium | A spray alone is an attempt; spray + success would be High |
| MITRE | T1110.003 Password Spraying | Accurate coverage mapping |
| Run every | 10 min | Fast detection |
| Lookback | 1 hour | Overlap covers ingestion delay (logs can arrive 5–15 min late) |
| Suppression | 1 hour after an alert | Prevents duplicate alerts from the overlapping lookback (alert fatigue) |
| Entity mapping | IP → Address | IP becomes a clickable entity / attack-graph node |
| Custom details | UsersTargeted, FailedAttempts | Evidence surfaced directly on the alert |

Rule query (no `ago()` — Sentinel applies the lookback):

```kql
SigninLogs
| where ResultType == "50126"
| summarize FailedAttempts = count(),
            TargetedUsers = dcount(UserPrincipalName),
            UsersTargeted = make_set(UserPrincipalName),
            FirstSeen = min(TimeGenerated),
            LastSeen = max(TimeGenerated)
            by IPAddress
| where TargetedUsers >= 3
```

I then triggered the rule with a second spray, and triaged the resulting incident: took ownership, reviewed the evidence (custom details showed the targeted users and failure count), ran Query B to confirm no successful sign-ins that time, documented findings, and closed it **classified as security testing** (authorized activity isn't logged as a true positive — it would distort incident metrics).

---

## Why SIEM detection isn't instant (and why that's fine)

Detection delay = log ingestion (minutes) + waiting for the next scheduled run + alert creation (~10–25 min typical). Attackers usually spend hours-to-days after initial access, so this is fast enough to limit damage. Real-time protection comes from **prevention** (Conditional Access, MFA) and **automation** (playbooks), not the SIEM alone.

---

## Lessons

- Accounts without MFA registered are the first thing attackers find.
- Detecting the spray is step one; **"did any of it succeed?"** is the question that matters.
- Revoke sessions **and** reset the password — one without the other leaves a gap.
- A detection rule isn't trusted until it's tested.
