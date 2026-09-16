# Security Policy

Zcash Name Service (ZNS) handles real funds: names are minted as shielded Zcash
transactions and resolved into payment instructions. A bug can cost users money.
This document describes our vulnerability disclosure process and commits us to
the [RD-Crypto-Spec Responsible Disclosure standard](https://github.com/RD-Crypto-Spec/Responsible-Disclosure/blob/d47a5a3dafa5942c8849a93441745fdd186731e6/README.md).

## Supported Projects

The following repositories are in scope for this policy:

| Project | Description |
| --- | --- |
| [zns-mint](https://github.com/zcashme/zns-mint) | Mints ZNS names as shielded transactions (runs in a TEE) |
| [zns-resolver](https://github.com/zcashme/zns-resolver) | Verifies name bindings and maintains the name → UA index |
| [zns-verify](https://github.com/zcashme/zns-verify) | On-chain / cryptographic verification of ZNS records |

## Reporting a Vulnerability

**Please do not open a public GitHub issue for security reports.**

### Preferred contact method

Report vulnerabilities privately via **GitHub Security Advisories**
(“Report a vulnerability” under the **Security** tab of the affected repository):

- [Report a vulnerability in zns-mint](https://github.com/zcashme/zns-mint/security/advisories/new)
- [Report a vulnerability in zns-resolver](https://github.com/zcashme/zns-resolver/security/advisories/new)
- [Report a vulnerability in zns-verify](https://github.com/zcashme/zns-verify/security/advisories/new)

If you are unsure which repository is affected, file against zns-mint and we
will route it.

### How to use this contact method securely

GitHub Security Advisories are private by default: only the reporter and the
maintainers can see the report until we publish it. Nothing is transmitted in
the clear to other parties, so no separate PGP key is required. To use it you
need a (free) GitHub account; if you cannot use GitHub for this purpose, contact
a maintainer through another channel and we will arrange a private exchange
before any technical details are shared.

Please include in your report:

- A description of the suspected vulnerability
- Steps to reproduce the issue (PoC code welcome)
- Your email address or another secure mechanism to contact you
- Your name and/or colleagues, if you wish to be recognized later
- Optionally, a patch and/or suggestions to resolve the vulnerability

## Disclosure Timelines and Acknowledgements

We follow the disclosure timelines defined in the
[RD-Crypto-Spec standard](https://github.com/RD-Crypto-Spec/Responsible-Disclosure/blob/d47a5a3dafa5942c8849a93441745fdd186731e6/README.md),
including its acknowledgement, no-response escalation, and coordinated
release procedures.

Reporters who wish to be recognized are credited after the disclosure
timeout, unless they prefer to remain anonymous.

## Scope

### In scope

- The three repositories listed above (zns-mint, zns-resolver, zns-verify),
  including their cryptographic protocols, transaction construction, TEE
  integration, and deployment configuration in this repository.
- Vulnerabilities in ZNS-forked dependencies (e.g. `zns-zcash_primitives`,
  our `orchard` fork) as they behave in ZNS.

### Out of scope

- Vulnerabilities in unmodified upstream dependencies. We will file these
  **upstream** with the respective maintainers (e.g. Zcash core wallets and
  `librustzcash`/`zcash_primitives` with Electric Coin Co, `zebra` with the
  Zcash Foundation, `orchard` upstream) and coordinate with them; please feel
  free to do the same.
- Denial of service via resource exhaustion against public infrastructure,
  social engineering, phishing, or physical attacks.
- Issues in third-party wallets or services that merely interact with ZNS names.

## Ethical Behavior

By reporting to us you agree to the ethical guidelines of the standard:
do not leverage a vulnerability for financial gain or trading advantage, do not
sell vulnerabilities, do not access or compromise development systems, and do
not perform any illegal acts (phishing, DDoS, unauthorized access). We commit
to the same ethics in handling your report, and to good-faith, good-faith-timed
remediation.

We will not pursue legal action against anyone who researches or reports a
vulnerability in good faith, respecting this policy and the ethical guidelines
of the standard.
