# Contributing to VulnOps Hub

Thank you for considering a contribution. The repository currently contains an
implementation-ready reference design; code contributions should start only
after the MVP contracts and data-ownership decisions are reviewed.

## First principles

- Preserve evidence and source provenance.
- Do not turn an uncertain component/CPE mapping into an automatic ticket or
  closure.
- Prefer integration adapters to reimplementing scanner parsers, endpoint
  agents, or public-feed mirrors.
- Keep external state changes idempotent and auditable.
- Do not add a data source or connector without its license, source of truth,
  replay behavior, failure mode, fixtures, and operational owner.

## Before opening an issue

Use issues for:

- a concrete design ambiguity or contradiction;
- a proposed adapter with documented upstream interface and license;
- a reproducible mapping, lifecycle, security, or documentation defect;
- a scoped MVP implementation task tied to the roadmap.

Do not include real credentials, customer data, unredacted scanner reports,
SBOMs with sensitive repository information, or unannounced vulnerabilities.
Report security issues using [SECURITY.md](SECURITY.md).

## Proposal format

Please include:

1. Problem and affected workflow.
2. Source of truth and external systems involved.
3. Expected evidence and identifiers.
4. Proposed behavior and failure behavior.
5. Lifecycle, security, privacy, and licensing impact.
6. Test fixture or reproducible sanitized example.
7. Documentation that must change.

## Code contribution expectations

Once implementation begins:

1. Start from the approved MVP plan and open an issue for material design
   changes.
2. Add the failing test first; preserve a minimal fixture that reproduces the
   behavior.
3. Make implementation, migration, API contract, observability, and
   documentation changes together.
4. Run focused tests plus the relevant integration/contract suite.
5. Keep commits narrow and do not reformat unrelated files.
6. Describe provider versions, source payload shape, and replay behavior in the
   pull request.

Every new adapter must prove:

- source snapshot capture and content digest;
- idempotent replay;
- cursor/checkpoint behavior;
- rate-limit/error/staleness handling;
- identity-mapping conflict handling;
- no direct mutation of Case workflow;
- sanitized fixtures and contract tests.

## Design decision process

Use an Architecture Decision Record for changes to system-of-record boundaries,
identity model, lifecycle guarantees, license assumptions, or deployment
topology. Decisions must state context, alternatives, consequences, and
guardrails.

## License

By submitting a contribution, you agree that it may be licensed under the
repository's [Apache-2.0 license](LICENSE).
