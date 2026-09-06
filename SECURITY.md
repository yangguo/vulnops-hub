# Security Policy

## Supported versions

The repository currently publishes an untagged M1 technical preview on `main`.
It is not a supported production release and has no security-fix support window
yet. Tagged versions and their support policy will be listed here when the
first release is published.

## Reporting a vulnerability

Please do **not** open a public issue for a suspected vulnerability in this
repository or its implementation.

Use GitHub's private security advisory/reporting flow for this repository when
available. If that flow is unavailable, contact the repository owner through
GitHub and request a private reporting channel before sharing technical details.
Include a minimal reproduction, affected commit/version, impact, and any
suggested mitigation. Do not include production credentials or customer data.

The project aims to acknowledge a valid report promptly, coordinate a fix
privately when feasible, credit reporters who want credit, and publish a
security advisory after users have a practical upgrade or mitigation path.

## Scope note

Findings in an integrated third-party system such as DefectDojo,
Vulnerability-Lookup, Wazuh, Greenbone, PostgreSQL, or an identity provider
should normally be reported to that project's own security process as well.
Please avoid testing against systems you do not own or have explicit permission
to assess.
