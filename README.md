# VulnOps Hub

> **Status: design repository — no production application code yet.**

VulnOps Hub is a proposed open-source vulnerability-operations control plane. It
correlates public vulnerability intelligence, asset and software inventories,
SBOMs, and scanner evidence into explainable **exposures** and auditable
**remediation cases**.

中文简介：VulnOps Hub 不是另一个扫描器，也不复制一份 CVE 数据库。它把
公开漏洞情报、本地资产和 SBOM、各类漏扫结果，以及整改工单串成一个可追溯的
生命周期闭环：发现 → 匹配 → 分派 → SLA → 风险接受 → 整改 → 复测 → 关闭或重开。

## Why this project

Most mature open-source tools excel at one part of the problem:

| Capability | Preferred reusable capability | Role in this design |
| --- | --- | --- |
| Scanner report parsing, deduplication, test history | [DefectDojo](https://github.com/DefectDojo/django-DefectDojo) | Ingest and preserve raw scanner findings |
| Multi-source vulnerability intelligence | [Vulnerability-Lookup](https://github.com/vulnerability-lookup/vulnerability-lookup) | Enrich and correlate CVE, KEV, EPSS, VEX, vendor advisories |
| Endpoint inventory and package evidence | [Wazuh](https://documentation.wazuh.com/current/user-manual/capabilities/system-inventory/) | Supply observed host/software state |
| Network vulnerability scanning | [Greenbone Community Edition / OpenVAS](https://greenbone.github.io/docs/latest/) | Supply authenticated and network scan evidence |

The missing layer is reliable correlation:

~~~text
public advisory + component/version + asset context + local evidence
                         ↓
                 explainable exposure
                         ↓
       owner + risk policy + SLA + verification evidence
                         ↓
             auditable remediation lifecycle
~~~

VulnOps Hub is deliberately that layer. It integrates with, rather than forks or
reimplements, the systems above.

## Design principles

1. **Reuse first.** Do not build a new scanner parser library, CVE mirror, or
   endpoint agent when a maintained open-source system already does it well.
2. **Evidence before automation.** A global CVE is not a ticket. A ticket is
   created only after an asset/component match has evidence and a recorded
   confidence.
3. **Stable identities over fuzzy names.** Prefer asset IDs, purls, supplier
   package identifiers, and version ranges. CPE/name heuristics remain
   reviewable candidates, not silent auto-closures.
4. **Lifecycle is a case, not a scanner row.** One remediation case may group
   multiple exposures while retaining each asset-level fact and its provenance.
5. **Never close on missing data.** A failed, partial, or out-of-scope rescan
   cannot prove remediation.
6. **Explain every priority.** Risk score, policy version, source freshness,
   match method, exception decision, and state transition are all auditable.
7. **Keep license boundaries explicit.** External integrations are connected
   through documented APIs and deployment boundaries; no upstream code is copied
   into this project.

## Proposed scope

### In scope

- Scheduled intelligence enrichment from CVE/NVD, CISA KEV, FIRST EPSS, OSV,
  CSAF/VEX, and vendor advisory sources, preferably through
  Vulnerability-Lookup where appropriate.
- Canonical asset, service, component, and SBOM identity.
- Ingestion of scanner/endpoint evidence through DefectDojo, Wazuh, Greenbone,
  and open adapter contracts.
- Deterministic and reviewable vulnerability matching.
- Risk policy evaluation, case grouping, ownership, SLA clocks, approvals,
  risk acceptance, verification, closure, and reopening.
- Immutable audit events and external ticket/notification projections.

### Explicitly out of scope for the MVP

- Writing a new network scanner, endpoint agent, SAST/SCA engine, or universal
  report parser.
- Mirroring every public vulnerability record into a new authoritative CVE
  database.
- Autonomous patch deployment or unreviewed AI remediation advice.
- Multi-tenant SaaS billing and cross-organization data sharing.

## Documentation

- [Architecture](docs/architecture.md) — boundaries, data flow, ownership, and
  failure behavior.
- [Data model](docs/data-model.md) — canonical entities, identities,
  relationships, retention, and state machines.
- [Module design](docs/modules.md) — module responsibilities and adapter
  contracts.
- [API design](docs/api.md) — REST and event interfaces, idempotency, and
  authorization.
- [Deployment design](docs/deployment.md) — local, production, operations, and
  security requirements.
- [MVP and roadmap](docs/mvp-roadmap.md) — scope gates, acceptance criteria,
  and sequenced milestones.
- [Research and architecture decisions](docs/research.md) — evidence behind the
  reuse-first approach and licensing boundaries.
- [Implementation plan](docs/plans/2026-09-05-vulnops-hub-mvp.md) — a
  test-first build plan for the proposed MVP.

## Architecture in one view

~~~mermaid
flowchart LR
  subgraph Sources
    Intel["CVE / NVD / CISA KEV / EPSS / OSV / CSAF"]
    Scan["DefectDojo / Greenbone / other scanners"]
    Inv["Wazuh / CMDB / cloud inventory"]
    SBOM["CycloneDX / SPDX / VEX"]
  end

  Intel --> VL["Vulnerability-Lookup and source adapters"]
  Scan --> Evidence["Evidence adapters"]
  Inv --> Inventory["Asset and inventory adapters"]
  SBOM --> Inventory

  VL --> Match["VulnOps Hub matching and risk policy"]
  Evidence --> Match
  Inventory --> Match

  Match --> Exposure["Exposure graph"]
  Exposure --> Case["Remediation cases, SLA, exceptions"]
  Case --> Verify["Verification and reopen rules"]
  Case --> Work["Jira / ServiceNow / notifications"]
  Verify --> Case
~~~

## What makes an exposure actionable?

An **exposure** is the time-bounded assertion that a particular asset contains
or exposes a vulnerable component. It carries evidence, not just a CVE ID:

- an observed component and version from an SBOM, Wazuh, authenticated scan, or
  trusted scanner report;
- an affected version range or scanner-confirmed detection;
- the asset/service identity, criticality, reachability, and owner;
- source provenance, match method, confidence, and last evaluation time.

The platform can automatically create a remediation case for high-confidence
matches according to policy. Candidate matches stay in a triage queue. A case
can close only with positive verification evidence; it reopens on new
confirming evidence, a failed retest, an expired exception, or a revised
affected-range evaluation.

## Repository status and contribution

This repository starts with an evidence-backed reference design. The first code
milestone is intentionally small: a modular monolith with a stable API and
adapter contracts. See the [MVP roadmap](docs/mvp-roadmap.md) before proposing
new scanners, feeds, or UI features.

Please read [CONTRIBUTING.md](CONTRIBUTING.md) and [SECURITY.md](SECURITY.md)
before opening an issue or pull request.

## License

The documentation and future project code are licensed under
[Apache-2.0](LICENSE). Names and marks of integrated projects belong to their
respective owners; this project is not affiliated with or endorsed by them.
