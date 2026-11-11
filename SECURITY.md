# Security policy

## Supported versions

Security fixes target the latest minor release only. Use its latest patch release;
older minor releases are not supported.

## Reporting a vulnerability

Please do not disclose vulnerabilities in public issues or pull requests. Open
this repository's **Security** tab and select **Report a vulnerability** to send a
private report to the maintainers through GitHub's private vulnerability reporting.
Include the affected version, a minimal reproduction, expected and actual behavior,
and the potential impact. Redact submission tokens, private keys, account details,
and private mail; use synthetic examples instead.

The security scope includes:

- Bypassing the gateway's ingress policy.
- DKIM verification/signing and From-alignment flaws.
- Submission-token exposure.
- Evading the attachment type checks.
- Hold or daily-limit bypass on outbound mail.

This is a small project. Reports, investigation, fixes, and coordinated disclosure
are handled on a best-effort basis; there is no guaranteed response or fix deadline.
Please keep details private while maintainers investigate and coordinate disclosure.
