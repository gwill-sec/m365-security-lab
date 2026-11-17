# KQL Query Library

Every hunting and detection query from the lab, commented. Run these in **Microsoft Sentinel** or **Defender XDR → Advanced hunting**.

| File | Purpose | Scenario |
|------|---------|----------|
| [`01-signin-overview.kql`](01-signin-overview.kql) | Recent sign-ins: who/where/what app/result | triage |
| [`02-failed-signins-per-user.kql`](02-failed-signins-per-user.kql) | Count failures per user (brute-force logic) | triage |
| [`03-password-spray-detection.kql`](03-password-spray-detection.kql) | One IP failing against many users | 1 |
| [`04-password-spray-success-check.kql`](04-password-spray-success-check.kql) | Did any sprayed account succeed? | 1 |
| [`05-impossible-travel.kql`](05-impossible-travel.kql) | Distance + velocity between sign-ins | 2 |
| [`06-inbox-rule-parsing.kql`](06-inbox-rule-parsing.kql) | Parse inbox-rule JSON into readable columns | 3 |
| [`07-mailbox-activity-by-ip.kql`](07-mailbox-activity-by-ip.kql) | Everything one IP did in a mailbox (pivot) | 3 |
| [`08-signin-to-mailbox-join.kql`](08-signin-to-mailbox-join.kql) | Correlate a sign-in to mailbox actions (join) | 3 |
| [`09-suspicious-asn-hunt.kql`](09-suspicious-asn-hunt.kql) | Hunt attacker infrastructure by ASN | 3 |
| [`10-ca-policy-results.kql`](10-ca-policy-results.kql) | Which CA policy acted on a sign-in | 4 |
| [`11-mfa-not-enforced.kql`](11-mfa-not-enforced.kql) | Users only ever signing in single-factor | audit |

## Tables used
- `SigninLogs` — interactive sign-ins (Entra connector)
- `OfficeActivity` — M365 unified audit log (Exchange/SharePoint/Teams)
- `AuditLogs` — Entra directory changes (roles, MFA registration)
- `EmailEvents` — message trace (Defender for Office 365)
