# Scenario 4 — Hardening with Conditional Access + Attack Replay

**This is the payoff.** All three attacks shared one root cause: **MFA was registered but not enforced** — a correct password alone got the attacker in. Here I replace Security Defaults with four layered Conditional Access (CA) policies, then **re-run all three attacks and prove they now fail.**

---

## What Conditional Access is

Entra's if/then policy engine. After a correct password, every sign-in is evaluated:

> **IF** (who + what app + conditions) → **THEN** (allow / require something / block)

Unlike Security Defaults (a fixed package where Microsoft decides when to prompt), CA lets you decide exactly who/when/what. They can't both run, so Security Defaults is turned **off**.

### Rollout safety rules
1. **Exclude the break-glass account** from every policy — the way back in if a policy locks everyone out.
2. **Never exclude everyday admins** — admins get the *strongest* protection, not an exemption.
3. **Build in Report-only first**, verify against real sign-ins, then enable. Keep the Security-Defaults-off → CA-on gap to minutes.

---

## The four policies

| Policy | Targets | Action | Closes the gap from |
|--------|---------|--------|---------------------|
| **CA001 – Require MFA – All users** | All users, all resources | Require MFA | Password-only access (all 3 scenarios) |
| **CA002 – Block legacy authentication** | Legacy client apps only | Block | #1 MFA bypass (POP/IMAP/SMTP) |
| **CA003 – Require MFA for risky sign-ins** | Sign-in risk High + Medium | Require MFA | Risky/VPN sign-ins (Scenario 2) |
| **CA004 – Secure MFA registration** | *User action:* Register security info, from untrusted locations | Block | MFA registration hijacking (Scenario 2) |

Notes on design choices:
- **CA002** targets only legacy clients (Exchange ActiveSync + "Other clients") — old protocols that can't do MFA and would otherwise bypass CA001 with just a password.
- **CA003** uses Identity Protection (needs **P2**, included in E5 — the capability Security Defaults couldn't provide). Tuned to **Medium+** to avoid alert fatigue from benign low-risk sign-ins.
- **CA004** targets the *Register security information* user action and blocks it everywhere **except** a trusted named location — so an attacker on a VPN can't register their own MFA even with the password.

### Validation method
Each policy was validated with the **What If** simulator (confirming it applies to targets, excludes break-glass, and ignores the cases it shouldn't) and run in **Report-only** before enabling. A troubleshooting note: Security Defaults kept enforcing for several minutes after being disabled — confirmed via a sign-in log's Conditional Access tab (**propagation delay**, ruled out the registration campaign first).

---

## The payoff: re-run all three attacks (now blocked)

Same attacks, same accounts, same VPN. Mirror-image hunts — looking for the **block** instead of the compromise.

### Re-test 1 — Password spray → blocked by CA001

```kql
SigninLogs
| where TimeGenerated > ago(2h)
| where UserPrincipalName startswith "bhayes"
| mv-expand CAPolicy = ConditionalAccessPolicies
| extend PolicyName = tostring(CAPolicy.displayName), PolicyResult = tostring(CAPolicy.result)
| where PolicyResult !in ("notApplied", "reportOnlyNotApplied")
| project TimeGenerated, UserPrincipalName, IPAddress, ResultType, ResultDescription,
          OverallCAStatus = ConditionalAccessStatus, PolicyName, PolicyResult
| order by TimeGenerated desc
```

**Result:** `bhayes`, **ResultType 50072** ("must enroll in MFA"), **CA001**, PolicyResult **failure**. The *same correct password* that walked into his mailbox in Scenario 1 now gets nothing.

### Re-test 2 — VPN sign-in as Sarah → blocked by CA004 (+ CA001)

VPN egress: Lisbon, Portugal (ASN 208172, flagged "VPN Server").

```kql
SigninLogs
| where TimeGenerated > ago(2h)
| where UserPrincipalName startswith "smitchell"
| mv-expand CAPolicy = ConditionalAccessPolicies
| extend PolicyName = tostring(CAPolicy.displayName), PolicyResult = tostring(CAPolicy.result)
| where PolicyResult !in ("notApplied", "reportOnlyNotApplied")
| project TimeGenerated, IPAddress, ResultType, OverallCAStatus = ConditionalAccessStatus,
          RiskLevel = RiskLevelDuringSignIn, PolicyName, PolicyResult
| order by TimeGenerated desc
```

**Result:**
- **ResultType 53003** (hard CA block) → **CA004**: MFA registration from the VPN was **blocked**. The registration-hijack hole is closed.
- **ResultType 50072** → **CA001**: MFA required.
- **RiskLevel: low** → **CA003 did NOT fire.**

> **The most valuable finding in the lab.** Signing in as the CEO from a Portugal VPN datacenter scored only *low* risk (Identity Protection has almost no baseline for a new user, and a lone VPN IP often scores low). CA003 missed it — but **CA001 and CA004, which don't depend on risk scoring, blocked it anyway.** That is the live, evidence-backed argument for **defense-in-depth**: no single control is reliable, but layered controls cover each other's gaps.

### Re-test 3 — BEC sign-in as Maria → blocked by CA001, mailbox untouched

Maria *has* MFA registered, so the attacker hit an **"Approve sign in request"** push to her real phone — unanswerable by the attacker.

```kql
SigninLogs
| where TimeGenerated > ago(2d)
| where UserPrincipalName startswith "mlopez"
| mv-expand CAPolicy = ConditionalAccessPolicies
| extend PolicyName = tostring(CAPolicy.displayName), PolicyResult = tostring(CAPolicy.result)
| where PolicyResult !in ("notApplied", "reportOnlyNotApplied")
| project TimeGenerated, IPAddress, ResultType, OverallCAStatus = ConditionalAccessStatus, PolicyName, PolicyResult
| order by TimeGenerated desc
```
**Result:** `mlopez`, **ResultType 50074** ("Strong Authentication is required"), **CA001**, failure, from the VPN IP.

**The closing proof — mailbox never touched:**
```kql
OfficeActivity
| where TimeGenerated > ago(2d)
| where UserId startswith "mlopez"
| where Operation in~ ("New-InboxRule", "Send", "MailItemsAccessed")
| project TimeGenerated, Operation, ClientIP
| order by TimeGenerated desc
```
**Result: 0 items.** In Scenario 3 this exact query returned the full attack chain (rule → send → access → delete). Now: **nothing.** The attacker never reached Outlook.

---

## Before / After

| Attack | Before (undefended) | After (my CA policies) |
|--------|--------------------|------------------------|
| Password spray | Correct password → into Brandon's mailbox | CA001 → MFA wall (50072), no access |
| VPN sign-in | Password → in as Sarah, could self-register MFA | CA004 → registration blocked (53003); CA001 → MFA (50072) |
| BEC | Password → full fraud chain | CA001 → MFA push to real phone (50074); **mailbox untouched (0 events)** |

### Sign-in result codes
| Code | Meaning |
|------|---------|
| 50072 | Must **enroll** in MFA (no MFA registered) |
| 50074 | **Strong auth required** (has MFA → approve prompt) |
| 53003 | **Access blocked by Conditional Access** (hard block) |
| 50126 | Wrong username/password |

---

## Lessons

- Every scenario's root cause was the same: **MFA registered ≠ enforced.** CA001 fixes it.
- **Layer defenses** — CA003 (risk) missed the low-scored VPN sign-in; CA001 + CA004 caught it.
- Report-only before enforce; exclude break-glass only; block legacy auth; IP-based trust is fragile (dynamic home IPs / IPv6 prefixes — production uses static or VPN-egress ranges).
- Risk scoring is noisy in small/new tenants — tune to Medium+, don't rely on it alone.
- The **empty OfficeActivity result** is the strongest proof of all: the attack chain that existed before is simply gone.
