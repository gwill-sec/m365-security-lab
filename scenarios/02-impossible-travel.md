# Scenario 2 — Suspicious Sign-in via VPN (Impossible Travel)

**MITRE ATT&CK:** [T1078.004 — Valid Accounts: Cloud Accounts](https://attack.mitre.org/techniques/T1078/004/)

---

## Summary

An attacker with **Sarah Mitchell's (CEO)** stolen password signed in through a VPN in another country, minutes after her real sign-in from Texas — the classic **impossible travel** pattern. The password was accepted, but because Sarah had no MFA registered, Microsoft forced MFA registration and the attacker stopped there. **No access gained — but valid credentials were used, so the password is compromised.**

I built a KQL detection that calculates the **distance and velocity** between consecutive sign-ins and flagged Sarah "travelling" ~1,200 miles in 2 minutes (~35,000 mph). Evidence (ASN, ISP, baseline history) identified which of the two sign-ins was the attacker.

**Verdict:** True positive — compromised credentials, sign-in interrupted at MFA. No access gained.

---

## Detection

### Query 1 — the user's sign-in timeline with risk

```kql
SigninLogs
| where TimeGenerated > ago(2d)
| where UserPrincipalName startswith "smitchell"
| extend City = tostring(LocationDetails.city),
         Country = tostring(LocationDetails.countryOrRegion)
| project TimeGenerated, IPAddress, City, Country, AppDisplayName,
          ResultType, RiskLevelDuringSignIn, RiskEventTypes_V2
| order by TimeGenerated asc
```

- `LocationDetails` is a nested (dynamic) field — the dot (`.city`) reaches inside it; `tostring()` makes it readable.
- `RiskLevelDuringSignIn` is Identity Protection's real-time risk score (needs **P2**); `RiskEventTypes_V2` is *why* it was risky (e.g. `anonymizedIPAddress`).

**Result:** Sarah from Texas, then Sarah from a VPN IP minutes later with `ResultType 50072` (correct password → must enroll in MFA). One VPN IP was flagged `anonymizedIPAddress`; another was not — Microsoft's built-in detection was inconsistent.

### Query 2 — impossible-travel detection (distance + velocity)

**Idea:** line up each user's sign-ins in time order, compare each to the previous one, compute miles and mph, flag anything faster than an airliner.

```kql
SigninLogs
| where TimeGenerated > ago(2d)
| where ResultType in ("0", "50072", "50074", "50076", "50079")   // correct password (incl. MFA interrupts)
| extend Lat = toreal(LocationDetails.geoCoordinates.latitude),
         Lon = toreal(LocationDetails.geoCoordinates.longitude),
         City = tostring(LocationDetails.city),
         Country = tostring(LocationDetails.countryOrRegion)
| where isnotnull(Lat) and isnotnull(Lon)
| project TimeGenerated, UserPrincipalName, IPAddress, City, Country, Lat, Lon, ResultType
| sort by UserPrincipalName asc, TimeGenerated asc
| extend PrevUser = prev(UserPrincipalName),
         PrevTime = prev(TimeGenerated),
         PrevIP   = prev(IPAddress),
         PrevCity = prev(City),
         PrevLat  = prev(Lat),
         PrevLon  = prev(Lon)
| where UserPrincipalName == PrevUser and IPAddress != PrevIP
| extend DistanceMiles = round(geo_distance_2points(Lon, Lat, PrevLon, PrevLat) / 1609.34, 0),
         MinutesBetween = datetime_diff('minute', TimeGenerated, PrevTime)
| where DistanceMiles > 100                                        // ignore short cell-tower hops
| extend SpeedMph = iff(MinutesBetween > 0, round(DistanceMiles / (MinutesBetween / 60.0), 0), real(null))
| where SpeedMph > 600 or MinutesBetween == 0                      // faster than a jet = impossible
| project UserPrincipalName, PrevTime, PrevCity, TimeGenerated, City, Country,
          DistanceMiles, MinutesBetween, SpeedMph, ResultType, IPAddress
```

Key techniques:
- `sort` + `prev()` — compares each row to the one before it (window function). Used for anything sequential.
- `geo_distance_2points()` — real-world distance in meters; `/1609.34` → miles.
- `DistanceMiles > 100` and `SpeedMph > 600` — thresholds that tune out known false positives (a user switching to their phone on cellular shows a small, slow "jump").
- **No country filter** — an earlier version keyed on country change and would have *missed* an attacker whose VPN geolocated to the same country. Distance+velocity catches same-country attacks too.

**Result:** Sarah, Texas → VPN city, ~1,192 miles in 2 minutes = **~35,760 mph**. Physically impossible — one of the two sign-ins isn't really Sarah.

---

## Analyst judgment: which sign-in is the attacker?

Impossible travel tells you two sign-ins can't both be the same person — **not which one is fake.** The detection flagged the *second* sign-in, but that was the real Sarah; the attacker came first. Deciding takes evidence:

| Evidence | VPN sign-in (attacker) | Home sign-in (real) |
|----------|------------------------|---------------------|
| User's baseline history | Never seen | All prior sign-ins |
| **ASN / ISP** | Datacamp Limited / M247 (datacenter, VPN) | AT&T (residential) |
| Identity Protection risk | `anonymizedIPAddress` (sometimes) | none |
| Reported travel | None | — |

**The ASN/ISP is the real tell.** IP *location* is only an estimate (one VPN IP geolocated to "Atlanta, US" in Microsoft's data but "West Africa" in a third-party lookup). But the network *owner* — a datacenter vs. a residential ISP — reliably exposes a VPN. Real users come from AT&T/Comcast/T-Mobile, not hosting providers.

**Conclusion:** the datacenter-ASN sign-in is the attacker. Confirm with the user out-of-band. Because both attempts used the correct password, **treat the password as compromised either way.**

---

## Key findings

- **A correct password stopped at MFA is still a compromised password** (ResultType 50072/50074 from an attacker IP → reset it).
- **MFA registration hijacking risk:** the attacker was pushed to *register* MFA. A real attacker could have registered **their own** Authenticator and owned the account. (Closed in [Scenario 4](04-conditional-access.md) with CA004.)
- **Built-in risk scoring is inconsistent and needs a learning period** — "atypical travel" never fired because Sarah was a brand-new account with no baseline. Custom KQL caught what the built-in engine missed. This is *why* SOCs write their own detections.

## Lessons

- IP geolocation is an estimate; the **ASN/ISP** is what reveals VPNs and datacenters.
- Country-based rules can be dodged; **distance + velocity** is stronger.
- The detection identifies the anomaly; the analyst identifies the attacker.
