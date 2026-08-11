# Security policy

This repository is an experimental research toolkit, not a hosted service. Its
browser fixtures, publishing clients, undocumented-provider integrations, and
relay are not offered with production security or availability guarantees.

## Supported versions

Security fixes are applied to the current `main` branch only. There are no
maintained release branches or published service commitments.

- Python 3.9 through 3.13 on POSIX systems (macOS and Linux) is the supported
  compatibility range. Windows is not supported because the bundle store uses
  `fcntl` locking.
- The relay and JavaScript test projects require Node.js 20 or later.
- The owner Frame API and standard-chat browser automation are experimental and
  may stop working when provider behavior changes.

Use a Python runtime that still receives security updates from its distributor.
Compatibility with a runtime does not extend that runtime's upstream support
lifetime.

## Report a vulnerability privately

Email [github@peterhanily.com](mailto:github@peterhanily.com). Do not include
credentials, private Artifact contents, personal data, or live exploit targets.
Include the affected commit, impact, a minimal controlled reproduction, and any
suggested remediation. Please allow time for a private assessment before public
discussion; no fixed response or embargo timeline is promised.

Use Anthropic's own reporting channel for vulnerabilities in Anthropic systems.
This address is for vulnerabilities in this repository, not provider account
support or reports against third-party Artifacts.

## Operational boundary

The repository does not promise, operate, or grant access to a public
TURN-shaped metadata endpoint, coturn media relay, or canary logger. Anyone
deploying these components is the operator and is responsible for access
control, abuse handling, updates, logs, credentials, privacy notices, and
applicable law. See [PRIVACY.md](PRIVACY.md) before enabling canary logging.
