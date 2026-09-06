# Architecture

> **Document status:** Governing architecture and target-state boundaries. The
> M1 preview implements the modular core and selected adapters; identity/RBAC,
> full operational APIs, and several projections remain open as recorded in
> `acceptance-matrix.md`.

## 1. Decision

VulnOps Hub is a **modular vulnerability-operations control plane**, not a
replacement scanner or a CVE database. It owns correlation and governance:

- canonical asset and component identity;
- exposure evaluation and evidence;
- risk policy and priority explanation;
- remediation cases, SLA clocks, exceptions, verification, and audit events.

It uses external systems through adapters:

- **DefectDojo** owns parsed scan-report history and may remain the familiar
  finding workspace for application-security teams.
- **Vulnerability-Lookup** is a preferred intelligence service for
  cross-source CVE/advisory enrichment.
- **Wazuh** provides endpoint and installed-package evidence.
- **Greenbone/OpenVAS** and other scanners provide network or authenticated
  detection evidence.

The implementation is a modular monolith with asynchronous
workers. This keeps the state model transactional and debuggable while avoiding
microservice coordination before scale proves it necessary.

## 2. Context and container view

~~~mermaid
flowchart TB
  subgraph External["External services and sources"]
    VL["Vulnerability-Lookup"]
    DD["DefectDojo"]
    WZ["Wazuh"]
    GB["Greenbone / OpenVAS"]
    CMDB["CMDB / cloud inventory"]
    Pub["CISA KEV, FIRST EPSS, OSV, NVD, CSAF"]
    ITSM["Jira / ServiceNow / email / chat"]
  end

  subgraph Hub["VulnOps Hub"]
    API["API and policy UI"]
    ADP["Adapter runtime"]
    INV["Inventory and SBOM module"]
    INTEL["Intelligence cache and provenance"]
    MATCH["Matching engine"]
    RISK["Risk policy engine"]
    CASE["Case and SLA workflow"]
    AUDIT["Immutable audit/outbox"]
    DB[("PostgreSQL")]
    OBJ[("Object storage")]
    Q["Durable job queue"]
  end

  DD --> ADP
  WZ --> ADP
  GB --> ADP
  CMDB --> ADP
  VL --> ADP
  Pub --> ADP
  ADP --> Q
  Q --> INV
  Q --> INTEL
  INV --> MATCH
  INTEL --> MATCH
  MATCH --> RISK
  RISK --> CASE
  CASE --> AUDIT
  API --> DB
  INV --> DB
  INTEL --> DB
  MATCH --> DB
  CASE --> DB
  ADP --> OBJ
  AUDIT --> ITSM
~~~

## 3. Data flow

### 3.1 Ingestion and provenance

Every inbound record is stored as an immutable source snapshot before it is
normalized. The snapshot records:

- source, collection method, fetch time, provider timestamp, digest, and cursor;
- schema/version and adapter version;
- tenant or deployment scope;
- validation result and parsing warnings;
- a pointer to the encrypted raw payload in object storage.

The normalized record is never treated as proof without a pointer back to its
source snapshot. This makes feed corrections, parser upgrades, and auditor
questions reproducible.

### 3.2 Asset and component identity

Asset identity resolves CMDB, Wazuh, cloud, scanner, DNS, and manually managed
aliases to one canonical Asset. Components are represented with a preferred
package URL (purl), ecosystem, normalized version, and source-specific aliases
such as CPE, RPM/DPKG name, SWID, or vendor product ID. An SBOM is evidence
about component occurrences on a named release, service, or asset; it is not
silently merged with a newer inventory observation.

### 3.3 Matching

The matching engine consumes a component occurrence, vulnerability range data,
asset context, and optional scanner confirmation. It produces an Exposure with
one of these confidence classes:

| Class | Example | Automatic case creation |
| --- | --- | --- |
| Confirmed | Authenticated scanner reports CVE on the asset; or signed VEX says affected | Yes, subject to policy |
| Deterministic | purl/ecosystem/version falls inside a verified OSV or vendor range | Yes, subject to policy |
| Corroborated | CPE mapping and a second independent inventory signal agree | Triage by default |
| Candidate | Name/CPE heuristic or incomplete version data | Never without review |
| Not affected | Trusted VEX or a reviewed technical determination says not affected | No; retain evidence |

No name-only match can cause an automatic closure, exception, or remediation
ticket.

### 3.4 Risk and workflow

Risk evaluation is deterministic and versioned. Rules first apply hard
escalations (for example, an applicable CISA KEV on an internet-facing critical
service). A configurable, explainable score then combines vulnerability impact,
exploit likelihood, asset criticality, exposure context, remediation state, and
match confidence. The engine stores every input, policy version, rule result,
and final priority with the Exposure and Case.

The workflow groups related exposures into a Remediation Case only when ownership
and remediation action truly align. A case can point to external work items, but
the internal audit timeline remains authoritative for the operating model.

## 4. System of record boundaries

| Data | Authoritative system | Hub behavior |
| --- | --- | --- |
| Raw scanner report / parser semantics | Scanner or DefectDojo | Reference and preserve as evidence |
| Public advisory payload | Original source or Vulnerability-Lookup | Cache a versioned normalized projection |
| Endpoint inventory | Wazuh / CMDB / cloud inventory | Resolve aliases and retain observations |
| Asset ownership and criticality | CMDB initially; Hub after governed override | Track source and approval of overrides |
| SBOM document | Submitting build or supplier | Store immutable document and parsed projection |
| Exposure assertion | VulnOps Hub | Re-evaluate whenever evidence changes |
| Remediation lifecycle / SLA / exception | VulnOps Hub | Project status to DefectDojo and ITSM when configured |
| External ticket | ITSM system | Maintain link, sync state, never overwrite unrelated updates |

## 5. Reliability and failure semantics

### Source freshness

Each adapter reports last successful sync, upstream publication time, cursor,
error, and freshness state. A stale intelligence feed never downgrades an
existing Exposure. It only causes an explicit degraded-data warning and may
block automatic closure if the policy requires fresh intelligence.

### Idempotency and ordering

All ingestion commands require a stable source record ID or idempotency key.
Messages may be delivered at least once; projections are made idempotent using
unique natural keys and an outbox/inbox ledger. Events carry sequence/version
data, and a late event cannot overwrite a more recent asset observation without
an explicit reconciliation rule.

### Rescan and closure safety

Absence from a scanner result means “not detected in this run,” not “fixed.”
Automatic closure requires a successful scan or inventory/SBOM observation that
meets the case verification policy, covers the relevant asset/service scope, and
is newer than the remediation assertion. Failed jobs, changed scan scope, and
missing credentials produce a coverage gap rather than a closure.

### Deletion and corrections

Providers may withdraw or correct advisories. Source snapshots remain immutable;
normalized projections and affected-range decisions are versioned. A correction
triggers reevaluation and may downgrade, reopen, or mark an Exposure as
superseded, with the reason recorded in the audit timeline.

## 6. Security architecture

- OIDC/SAML-compatible authentication for people; scoped, rotated service
  credentials for adapters.
- Role and attribute-based authorization tied to organization, business service,
  asset group, and case scope.
- Encryption in transit and at rest; raw reports/SBOMs in private object storage
  with envelope encryption where available.
- Secrets only through a secret manager or Kubernetes secret integration, never
  in source snapshots or workflow events.
- Audit events are append-only at the application layer; privileged correction
  adds a compensating event instead of rewriting history.
- Egress allowlists and proxy support for public-feed synchronization.
- Adapter payload validation, size limits, malware scanning where uploads are
  accepted, and structured redaction of credentials from logs.

## 7. License and integration boundary

This project may call an external Vulnerability-Lookup instance via its API but
does not copy, link, or embed its AGPLv3 code. DefectDojo is a separate BSD
3-Clause component. Deployers are responsible for evaluating their complete
distribution and hosting model; this document describes a technical boundary,
not legal advice. See [research.md](research.md) for source links and the
decision rationale.
