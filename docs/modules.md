# Module Design

> **Document status:** Target module boundaries. Rows describe ownership even
> when the corresponding API, worker, or external projection is not yet
> implemented; current coverage is tracked in `acceptance-matrix.md`.

## 1. Module map

The implementation is a modular monolith. Modules communicate through
typed commands, domain events, and stable adapter interfaces; they do not
directly reach into one another's persistence models.

| Module | Responsibility | Does not own |
| --- | --- | --- |
| Identity and authorization | Users, service accounts, teams, roles, scoped access | External IdP credentials |
| Asset graph | Assets, services, aliases, ownership, criticality, observations | Scanner parsing |
| SBOM and component inventory | CycloneDX/SPDX parsing, purl/CPE normalization, component occurrences | Public advisory truth |
| Intelligence | Source snapshots, aliases, CVSS/KEV/EPSS/VEX projections, freshness | Authoritative upstream records |
| Evidence ingestion | Scanner, Wazuh, CMDB, cloud, and manual evidence adapters | Case policy |
| Matching | Component-to-vulnerability evaluation and confidence | Ticket workflow |
| Risk policy | Explainable priority, SLA selection, policy simulation | Human approval |
| Case workflow | Grouping, assignments, state transitions, exceptions, verification | Raw scan storage |
| Integrations | DefectDojo, Vulnerability-Lookup, Wazuh, Greenbone, ITSM, notifications | Core business rules |
| Audit and reporting | Immutable events, outbox, exports, coverage/freshness metrics | Operational source ownership |

## 2. Adapter contract

Every external adapter implements a narrow contract:

~~~text
discover(config, cursor) -> source records
validate(raw) -> validated record | rejection
normalize(validated) -> canonical observations + evidence refs
apply(observations) -> idempotent domain commands
checkpoint(result) -> next cursor and health
~~~

An adapter never updates a Case directly. It emits observations or evidence;
the matching and workflow modules decide the resulting exposure or case action.
This prevents a scanner or feed-specific status from corrupting the governance
model.

All adapter jobs must provide:

- stable idempotency/natural keys;
- source snapshot provenance;
- rate-limit, retry, and backoff policy;
- freshness status and structured failure reason;
- optional dry-run mode;
- metric tags for source, tenant/organization, adapter version, and outcome.

## 3. Intelligence module

### Preferred mode

Use a configured Vulnerability-Lookup instance as the primary correlated
intelligence API. Store only the fields needed for matching, risk, and
traceability, along with retrieval metadata and source links. The Hub never
claims the cache is more authoritative than its originating advisory.

### Fallback and corroboration

Direct source adapters may fetch:

- CVE List/NVD for CVE metadata and CPE/CVSS context;
- CISA KEV for known exploitation and due-date information;
- FIRST EPSS for likelihood scores and history;
- OSV for purl/ecosystem/version-range queries;
- CSAF/vendor advisory feeds for authoritative product status and remediation;
- VEX records for product-specific affected/not-affected assertions.

Feed choice is a deployment policy. A direct source must have a documented
update cursor, legal/operational rate handling, source URL, and record digest.

## 4. Inventory and SBOM module

Input modes:

| Input | MVP support | Normalized output |
| --- | --- | --- |
| CSV/CMDB API | Yes | Asset, owner, criticality, aliases |
| Wazuh inventory and vulnerability indices | Yes | Asset observation, OS/package occurrence, detection evidence |
| CycloneDX JSON | Yes | SBOM, components, services, dependency relations |
| SPDX JSON | Yes | SBOM, package/component occurrences |
| Cloud inventory | Later | Asset observations and exposure context |
| Container registry/OCI attestation | Later | Image/release SBOM occurrence |

Normalization strategy:

1. Preserve the raw identifier and document.
2. Resolve purl first; use namespace-specific package identity next.
3. Store CPE as an alias, not as the sole canonical key.
4. Record version scheme and parser version.
5. Emit an ambiguity instead of guessing when an asset alias collides.

## 5. Matching module

The matching pipeline evaluates, in this order:

1. **Scanner-confirmed evidence.** A valid scanner result with an explicit CVE,
   asset mapping, and current report scope yields Confirmed evidence.
2. **VEX/vendor disposition.** A trusted product-specific assertion can state
   affected, fixed, not affected, or under investigation.
3. **purl/ecosystem range.** OSV or vendor range matches are deterministic when
   version semantics are supported.
4. **Distribution/package range.** Wazuh or vendor package logic may prove
   fixed/affected even when upstream version differs.
5. **CPE/product mapping.** Candidate or corroborated only unless a reviewed
   mapping rule upgrades it.
6. **Human review.** A reviewer can document a mapping decision but cannot
   erase contradictory evidence.

The output contains a MatchExplanation:

~~~json
{
  "decision": "deterministic",
  "confidence": 0.93,
  "matcher_version": "2026.1",
  "component_identity": "pkg:maven/org.apache.tomcat/tomcat-catalina@9.0.80",
  "vulnerability": "CVE-XXXX-YYYY",
  "rules": ["osv.purl-range", "asset.service-context"],
  "evidence_refs": ["evid_01...", "evid_02..."],
  "limitations": []
}
~~~

## 6. Risk policy module

Risk policy is configuration-as-data, versioned and testable. It supports:

- hard escalation rules (KEV, confirmed exploitation, internet exposure);
- score contributions (CVSS, EPSS percentile, asset criticality, reachability,
  data sensitivity, age, confidence);
- overrides with approval requirements;
- priority bands and SLA clocks;
- policy simulation against a historical exposure sample before activation.

An example expression is illustrative only:

~~~text
priority = escalation_rules first
otherwise = weighted_impact + weighted_exploitability
          + weighted_asset_context + confidence_adjustment
~~~

The UI must show each factor and its source; a single opaque number is not
acceptable.

## 7. Case workflow and verification module

Case grouping keys default to owner team, business service, remediation action,
and policy scope. Grouping is conservative: a case is split when an exception,
verification path, or owner differs.

Verification is evidence-driven:

| Evidence | Can close automatically? | Conditions |
| --- | --- | --- |
| Successful reimported scanner result no longer detects issue | Sometimes | Same target/service, complete scan, valid credentials, policy allows |
| Wazuh package inventory shows fixed version | Sometimes | Version mapping is deterministic and observation is recent |
| New signed SBOM excludes/updates component | Sometimes | Release is deployed to the affected scope |
| VEX says not affected | No by itself | Creates review task unless policy trusts issuer/scope |
| Manual attestation | No | Requires approval and evidence link |
| Missing/failed scan output | Never | Creates coverage gap |

## 8. DefectDojo bridge

DefectDojo remains the preferred universal parser and raw-finding history for
supported tools. The bridge:

- ingests DefectDojo findings/tests through its API or receives a webhook/poll;
- maps known DefectDojo asset/product/service identifiers to canonical Assets;
- retains the DefectDojo finding URL/ID as evidence;
- optionally projects case status, owner, and external ticket links back with
  conflict-aware mapping;
- uses DefectDojo reimport semantics for recurring scanner data rather than
  attempting to duplicate scanner-specific deduplication.

The bridge must never enable broad auto-create behavior against a production
DefectDojo instance without a pre-mapped context; wrong asset creation is a data
integrity failure, not a convenience.

## 9. Wazuh and Greenbone bridges

The Wazuh adapter imports managed endpoint identity, package inventory, Windows
patch state where present, and vulnerability detection events. It preserves the
Wazuh agent/index/event identifiers and treats Wazuh status as evidence, not
the overall case state.

The Greenbone adapter should initially consume completed, scoped reports through
DefectDojo or Greenbone's documented management/scanner APIs. Direct scan
initiation is outside the MVP. The adapter records report completeness, target
definition, scan configuration, and credential/permission outcome to make
negative results trustworthy.

## 10. Notification and ITSM module

External work items are projections delivered through an outbox. Each projection
stores remote identifier, sync version, last observed remote state, and mapping
policy. Human edits in Jira or ServiceNow are not overwritten unless the policy
assigns the Hub authority for that field. Delivery failures create visible
integration incidents and never roll back the internal audit event.
