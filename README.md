# Microsoft 365 Security Lab — Detection, Investigation & Hardening

A hands-on security lab built in a live Microsoft 365 E5 tenant with **Microsoft Sentinel**, demonstrating the full defensive lifecycle: **attack → detect → investigate → respond → harden → verify.**

I built a simulated company ("Ironclad Logistics"), ran realistic identity attacks against it, hunted and investigated each one with **KQL**, performed incident response with **PowerShell / Microsoft Graph**, then hardened the tenant with **Conditional Access** and **re-ran every attack to prove the controls work.**

> **Why this project:** I work in IT at an MSP where I already handle business email compromise response, phishing analysis, and account lockdowns. This lab is me learning and demonstrating the **detection-engineering and identity-security layer underneath** the incidents I respond to day to day.

---

## Contents

| # | Scenario | Techniques | Key skills shown |
|---|----------|-----------|------------------|
| 1 | [Password Spray → Account Compromise](scenarios/01-password-spray.md) | T1110.003 | KQL hunting, building a Sentinel analytics rule, incident triage |
| 2 | [Suspicious Sign-in via VPN (Impossible Travel)](scenarios/02-impossible-travel.md) | T1078.004 | Geo/velocity detection in KQL, Identity Protection risk, ASN analysis |
| 3 | [Business Email Compromise (BEC)](scenarios/03-bec.md) | T1114.002, T1564.008, T1534 | Multi-table joins, parsing nested JSON, PowerShell/Graph IR |
| 4 | [Hardening with Conditional Access + Attack Replay](scenarios/04-conditional-access.md) | Mitigation | CA policy design, defense-in-depth, before/after validation |

- [KQL Query Library](queries/) — every hunting and detection query, commented
- [Lab Architecture](#architecture)
- [Skills Demonstrated](#skills-demonstrated)

---

## Architecture

```
MICROSOFT 365 TENANT (Ironclad Logistics)          AZURE
┌─────────────────────────────────────┐            ┌────────────────────────────────┐
│ 10 users + groups, M365 E5 licenses │            │ Resource group: rg-security-lab│
│ Entra ID (identity / sign-ins)      │   logs     │  └─ Log Analytics workspace    │
│ Exchange / SharePoint / Teams       │ ────────►  │      └─ Microsoft Sentinel     │
│ Defender XDR                        │ connectors │         (SIEM)                 │
│ Purview unified audit log           │            └────────────────────────────────┘
└─────────────────────────────────────┘
```

**Data sources connected to Sentinel:** Entra ID sign-in & audit logs, Microsoft 365 activity (Exchange/SharePoint/Teams), Defender XDR alerts.

**Tooling:** Microsoft Sentinel · Defender XDR Advanced Hunting · KQL · Entra ID Conditional Access & Identity Protection (P2) · Exchange Online PowerShell · Microsoft Graph PowerShell · Microsoft Purview.

---

## The headline result: attacks blocked after hardening

Each attack was run twice — once against the undefended tenant (succeeds), once after building Conditional Access policies (fails). Full detail in [Scenario 4](scenarios/04-conditional-access.md).

| Attack | Before (undefended) | After (my CA policies) |
|--------|--------------------|------------------------|
| **Password spray** | Correct password → attacker in the mailbox | Stopped at MFA (CA001) |
| **VPN sign-in** | Password → signed in, could self-register MFA | MFA registration **blocked** (CA004); MFA required (CA001) |
| **BEC** | Password → full fraud chain (inbox rule, fake invoice email, evidence deleted) | MFA wall (CA001); **mailbox never touched** |

The BEC proof is the strongest: the audit-log query that returned a full attack chain before returns **zero events** after.

---

## Skills demonstrated

- **Threat hunting & investigation** — wrote KQL across `SigninLogs`, `OfficeActivity`, `AuditLogs`, `EmailEvents`; multi-table joins, nested-JSON parsing (`mv-expand`/`make_bag`), geo-velocity math, ASN/infrastructure pivots.
- **Detection engineering** — built and tuned a scheduled Sentinel analytics rule (entity mapping, custom details, lookback/suppression tuning, MITRE ATT&CK mapping).
- **Incident response** — containment and eradication via Exchange Online and Microsoft Graph PowerShell (session revocation, password reset, inbox-rule removal, MFA-method review), with transcript documentation.
- **Identity security engineering** — designed a layered Conditional Access baseline (MFA enforcement, legacy-auth block, risk-based MFA, protected MFA registration), validated with What If and Report-only, then verified by attack replay.
- **Analyst judgment** — distinguished benign anomalies (user on cellular, "Stay signed in?" interrupts) from real incidents; documented why risk scoring under-fired in a low-baseline tenant and how layered controls covered the gap.

---

## Notes

- All data is synthetic. "Ironclad Logistics," its users, and all mailbox content are fabricated for the lab. Real personal identifiers in screenshots (home IP, tenant/subscription GUIDs) are redacted.
- "Attacker" IPs shown in screenshots are my own VPN egress (Proton VPN) used to simulate remote attacker infrastructure.
- Built on Microsoft 365 E5 and Azure free trials.

**Author:** Greggory Williams · U.S. Marine Corps veteran · System Administrator at an MSP, working toward a Microsoft security / SOC specialization (Security+ → SC-200).
LinkedIn: _add your profile URL here_
