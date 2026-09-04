# Data Model

## 1. Modeling rule

The model separates five things that are often incorrectly collapsed:

1. **Vulnerability intelligence** — what public sources say about a
   vulnerability and affected versions.
2. **Inventory evidence** — what an organization observed on an asset, service,
   release, or SBOM.
3. **Exposure** — the evaluated assertion that a vulnerability affects a
   concrete asset/component occurrence.
4. **Case** — the governed unit of remediation work, ownership, SLA, approval,
   verification, and closure.
5. **Evidence and events** — immutable facts supporting the assertion or
   lifecycle change.

This separation prevents a global CVE, a scanner row, and a remediation ticket
from being mistaken for the same record.

## 2. Core entity relationship

~~~mermaid
erDiagram
  ORGANIZATION ||--o{ BUSINESS_SERVICE : owns
  ORGANIZATION ||--o{ ASSET : contains
  BUSINESS_SERVICE ||--o{ ASSET : depends_on
  ASSET ||--o{ ASSET_ALIAS : has
  ASSET ||--o{ COMPONENT_OCCURRENCE : hosts
  SBOM ||--o{ COMPONENT_OCCURRENCE : declares
  COMPONENT ||--o{ COMPONENT_OCCURRENCE : materializes_as
  COMPONENT ||--o{ COMPONENT_IDENTIFIER : identified_by
  VULNERABILITY ||--o{ VULNERABILITY_ALIAS : has
  VULNERABILITY ||--o{ AFFECTED_RANGE : defines
  VULNERABILITY ||--o{ ADVISORY_ASSERTION : enriched_by
  COMPONENT_OCCURRENCE ||--o{ MATCH_EVIDENCE : supports
  VULNERABILITY ||--o{ MATCH_EVIDENCE : supports
  MATCH_EVIDENCE ||--o{ EXPOSURE : evaluates
  ASSET ||--o{ EXPOSURE : affected
  COMPONENT_OCCURRENCE ||--o{ EXPOSURE : affected
  VULNERABILITY ||--o{ EXPOSURE : concerns
  REMEDIATION_CASE ||--o{ CASE_EXPOSURE : groups
  EXPOSURE ||--o{ CASE_EXPOSURE : belongs_to
  REMEDIATION_CASE ||--o{ SLA_CLOCK : governed_by
  REMEDIATION_CASE ||--o{ RISK_DECISION : receives
  REMEDIATION_CASE ||--o{ VERIFICATION : verified_by
  REMEDIATION_CASE ||--o{ AUDIT_EVENT : records
  SOURCE_SNAPSHOT ||--o{ EVIDENCE_REF : proves
  EVIDENCE_REF ||--o{ MATCH_EVIDENCE : cited_by
  EVIDENCE_REF ||--o{ AUDIT_EVENT : cited_by
~~~

## 3. Identity and temporal rules

### 3.1 Asset

An Asset is a managed technical target: host, VM, container image, Kubernetes
workload, cloud resource, appliance, application deployment, or SaaS
integration. It has:

- immutable internal ID;
- type, lifecycle state, environment, owner, criticality, data classification,
  internet exposure, and business-service references;
- aliases from CMDB, cloud provider, Wazuh agent, scanner host, DNS, IP,
  hardware UUID, and manually reviewed mappings;
- observed intervals: first seen, last seen, source observation time, and
  validity time.

An IP address is an alias or observation, not the identity of a long-lived
asset. Alias collisions require review rather than a last-write-wins merge.

### 3.2 Component and ComponentOccurrence

A Component is a reusable software identity. Its preferred key is a canonical
purl plus ecosystem and normalized name. A ComponentOccurrence binds that
identity and a version to an Asset, Service, Release, or SBOM document. It
records:

- version and version scheme;
- purl, CPE, OS package name, SWID, vendor product, and raw observed value;
- source, evidence time, confidence, and dependency path where known;
- package status and installed/fixed/update context where the source provides it.

The model must preserve uncertain values. A parser may produce a normalized
candidate but must retain the original string and normalization version.

### 3.3 Vulnerability and advisory assertions

Vulnerability is a canonical record with a stable internal ID and aliases such
as CVE, GHSA, OSV, vendor advisory, and CNA identifiers. It has many
AdvisoryAssertions, each tied to a source snapshot. Assertions may include
description, CVSS vectors, CWE, publication dates, exploit information,
references, remediation, CISA KEV membership, EPSS score/history, VEX status,
and affected ranges.

AffectedRange includes the identifier namespace, version scheme, inclusive or
exclusive boundaries, source, confidence, and parser. It never silently replaces
an older range; a supersession relationship records why a new assessment exists.

### 3.4 Exposure

The natural identity is:

~~~text
(organization, asset, component occurrence, vulnerability, detection context)
~~~

An Exposure stores the current evaluation, first/last observed timestamps,
confidence class, priority, risk-policy version, and lifecycle state:

~~~text
candidate | active | under_review | not_affected | remediated | superseded
~~~

Exposure state is an evidence evaluation, not a work-management state. An
exposure may be remediated while a Case remains open waiting for validation
approval, and a case may cover many active exposures.

### 3.5 RemediationCase

A RemediationCase is the unit assigned to an accountable team. It may group
exposures only if the remediation action, owner, service boundary, and policy
permit grouping. Fields include:

- case key, title, organization, service/asset scope, owner team, assignee;
- priority, policy version, SLA policy, clocks, due date, escalation state;
- status, closure reason, external work-item links;
- exception and approval references;
- summary generated from linked exposures but editable with audit history.

Case status:

~~~mermaid
stateDiagram-v2
  [*] --> New
  New --> Triage
  Triage --> Assigned
  Triage --> NotApplicable: reviewed not affected
  Triage --> RiskAccepted: approved temporary exception
  Assigned --> InProgress
  InProgress --> AwaitingVerification
  AwaitingVerification --> Closed: positive verification
  AwaitingVerification --> InProgress: failed or incomplete verification
  RiskAccepted --> Triage: expiry or new material evidence
  NotApplicable --> Triage: new contradictory evidence
  Closed --> Reopened: new confirming evidence
  Reopened --> Triage
~~~

### 3.6 RiskDecision

A RiskDecision represents a human or policy decision: accepted risk, false
positive, not affected, compensating control, waiver, or severity override. It
requires:

- scope (case and explicitly listed exposures);
- rationale and evidence links;
- requester, approver role, approver, decision time, expiry, and review cadence;
- compensating controls and residual-risk statement;
- a policy version and required number of approvals.

Accepted risk is not a terminal deletion. On expiry it returns the case to
triage and produces an escalation. A decision can be revoked only through a new
event, not by editing history.

## 4. Evidence, events, and provenance

### SourceSnapshot

Every import creates a SourceSnapshot with provider, scope, cursor, retrieval
metadata, cryptographic digest, schema, adapter version, raw object URI, and
validation status. For highly sensitive reports, the URI is access-controlled
and only metadata is exposed to ordinary users.

### EvidenceRef

EvidenceRef points to a source snapshot section, DefectDojo finding, Wazuh
event, scanner report, SBOM component, VEX statement, change record, or manual
attestation. It contains a hash and extraction path where possible.

### AuditEvent

AuditEvent is append-only and records actor, action, prior state, new state,
reason, policy version, correlation ID, and evidence references. Examples:

~~~text
case.created
case.assigned
sla.paused
risk.accepted
verification.failed
exposure.reopened
external_ticket.synchronized
~~~

An outbox event is written in the same database transaction as the state change,
then delivered asynchronously to external tools.

## 5. Key constraints and indexes

- Unique active alias per namespace/scope where the alias is a strong identity
  (for example, cloud resource ARN); ambiguous aliases are explicitly modeled.
- Unique source snapshot by (source, source-record ID, content digest).
- Unique component identifier by (namespace, normalized value, normalization
  version).
- Unique open exposure by its natural identity plus evidence generation.
- One active SLA clock per case/SLA phase.
- One current risk decision per scope/type, while all prior decisions remain
  immutable history.
- Time-oriented indexes for source freshness, last seen, due date, exception
  expiry, and event streams.

## 6. Retention and privacy

Raw scanner reports and SBOMs can include internal topology, usernames, package
paths, or repository URLs. Storage policies must allow configurable retention,
redaction, legal hold, and deletion of raw payloads while keeping a minimal
auditable hash/provenance record. Tenant isolation is deferred from the MVP, but
all primary tables should carry an organization scope to avoid a destructive
future migration.
