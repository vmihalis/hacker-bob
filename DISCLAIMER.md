# Disclaimer

Hacker Bob is an autonomous security testing tool. Read this before using it.

## Authorization is your responsibility

Bob will scan, probe, and attempt exploitation of any target you point him at. He does not verify that you have permission. **You are solely responsible for ensuring that:**

1. The target is in scope of an active bug bounty program, a written penetration testing agreement, or a system you own.
2. The bug bounty program's policy permits the kind of testing Bob performs (automated scanning, authenticated testing, chaining, PoC execution).
3. Any third-party assets Bob may touch while chaining or proving an exploit are also covered or are out-of-scope only as observers.

If you do not have explicit written authorization, do not run Bob.

## Bob does not enforce scope for you

Bob has internal scope guards (`scope-guard.sh`, `scope-guard-mcp.sh`, audit logging via `bounty_http_scan`), but these are operational safety nets, not legal authorization. They reduce accidental drift; they do not grant permission. The bug bounty program's policy is the only source of truth.

## Legal context

Unauthorized access to computer systems is a criminal offense in most jurisdictions, including but not limited to:

- **United States** — Computer Fraud and Abuse Act (CFAA), 18 U.S.C. § 1030
- **European Union** — Directive 2013/40/EU on attacks against information systems, transposed nationally
- **United Kingdom** — Computer Misuse Act 1990
- **Most other jurisdictions** — equivalent computer-misuse statutes

Bug bounty safe-harbor language in a program's policy is a contractual authorization, not a legal exemption. It only protects you within its stated scope. Read the safe-harbor clause for every program before testing.

## No warranty, no liability

Hacker Bob is provided "AS IS" under the Apache License, Version 2.0. See [`LICENSE`](LICENSE), Sections 7 and 8.

The authors and contributors are not liable for:

- Damage caused by Bob's scans, probes, or exploit attempts to in-scope, out-of-scope, or third-party systems.
- Service disruption to a target.
- Data loss, integrity issues, or downstream effects.
- Legal action taken against you for unauthorized access.
- Findings that are wrong, fabricated, hallucinated, or misclassified.

## Responsible disclosure norms

If Bob produces a finding that you intend to submit:

1. Verify the finding manually before reporting. Verifier rounds reduce false positives but do not eliminate them.
2. Submit through the program's official channel. Do not publicly disclose, sell, or weaponize.
3. Respect any embargo or coordinated-disclosure timeline the program requests.
4. Do not retain extracted data beyond what is needed to demonstrate impact. Delete it after submission.

## Reporting issues in Bob itself

If you find a security issue in Hacker Bob — for example, a way Bob could be tricked into attacking the operator's own machine or an unintended target — please open a private security advisory on GitHub instead of a public issue.

## Acknowledgement

By installing or running Hacker Bob, you acknowledge that you have read this disclaimer, that you have explicit authorization for any target you scan, and that you accept all risk and legal responsibility for the use of the tool.
