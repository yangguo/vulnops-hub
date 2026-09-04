# Research and Architecture Decisions

**Research date:** 2026-09-05

**Question:** Which mature open-source capabilities should a new vulnerability
operations platform reuse, and what narrow layer is worth building?

## 1. Executive conclusion

No single strictly open-source project is the best answer to public
vulnerability intelligence, diverse scanner ingestion, asset/SBOM correlation,
and a complete enterprise remediation lifecycle at once. The recommended
architecture is therefore a thin orchestration layer:

- use **DefectDojo** for broad scanner ingestion, deduplication, and test
  history;
- use **Vulnerability-Lookup** as a preferred intelligence correlation service;
- use **Wazuh** and **Greenbone/OpenVAS** as evidence producers rather than
  trying to recreate endpoint detection or scanning;
- build only the cross-system asset/component matching, explainable risk policy,
  evidence-safe case workflow, and integration governance that no one upstream
  component owns.

## 2. Evidence reviewed

| Capability / claim | Primary evidence | Design consequence |
| --- | --- | --- |
| DefectDojo describes itself as open-source unified vulnerability management and is BSD 3-Clause | [DefectDojo repository](https://github.com/DefectDojo/django-DefectDojo), [license](https://github.com/DefectDojo/django-DefectDojo/blob/master/LICENSE.md) | Safe to integrate as a separately deployed parser/finding workspace |
| DefectDojo supports 500+ tool imports and provides API/reimport behavior | [official docs](https://docs.defectdojo.com/), [reimport guide](https://docs.defectdojo.com/import_data/import_intro/reimport/), [API guidance](https://docs.defectdojo.com/automation/api/api-v2-docs/) | Do not recreate scanner-specific parser/dedup semantics; bridge to tests/findings |
| Vulnerability-Lookup has modular feeders, KEV, EPSS, VEX, watchlists, and API support | [Vulnerability-Lookup repository](https://github.com/vulnerability-lookup/vulnerability-lookup), [new source guide](https://github.com/vulnerability-lookup/vulnerability-lookup/blob/main/new_source.md) | Prefer as intelligence aggregation service; preserve source metadata |
| Vulnerability-Lookup is AGPLv3 | [Vulnerability-Lookup license declaration](https://github.com/vulnerability-lookup/vulnerability-lookup) | Use independent deployment and API integration; do not copy/embed its code without a licensing review |
| Wazuh agents collect inventory and correlate installed software with vulnerability content | [Wazuh vulnerability detection](https://documentation.wazuh.com/current/user-manual/capabilities/vulnerability-detection/), [how it works](https://documentation.wazuh.com/current/user-manual/capabilities/vulnerability-detection/how-it-works.html) | Ingest endpoint/package observations and detection events as evidence |
| Greenbone/OpenVAS provides scanner/runtime APIs and community feeds | [Greenbone docs](https://greenbone.github.io/docs/latest/), [scanner API](https://greenbone.github.io/scanner-api/) | Treat it as an evidence/scanning system; do not make the Hub a scan engine |
| CISA positions KEV as an input to vulnerability-management prioritization | [CISA KEV catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) | KEV is an explicit policy factor/possible hard escalation, never a match by itself |
| FIRST publishes an EPSS API keyed by CVE and historic date | [FIRST EPSS API](https://api.first.org/epss/) | Store score, percentile, observation date, and source freshness; never treat probability as certainty |
| OSV supports package/version and batched queries | [OSV API](https://google.github.io/osv.dev/api/), [querybatch](https://google.github.io/osv.dev/post-v1-querybatch/) | Use purl/ecosystem/version as a deterministic matching path |
| CSAF/VEX can describe product affected/fixed/not-affected status | [CSAF 2.0](https://docs.oasis-open.org/csaf/csaf/v2.0/csaf-v2.0.html) | VEX feeds evidence/review policy; a product-specific statement has explicit scope |
| CycloneDX represents SBOM components and supports VEX use cases | [CycloneDX specification overview](https://cyclonedx.org/specification/overview/), [SBOM/VEX guide](https://cyclonedx.org/guides/sbom/) | Accept CycloneDX JSON; keep VEX separate and time-versioned |
| OpenCVE is BSL, explicitly not an open-source license | [OpenCVE license](https://github.com/opencve/opencve/blob/master/LICENSE) | Do not make it the foundational reusable OSS dependency for this project |

## 3. Alternatives considered

### A. Build on DefectDojo alone

- **Strengths:** mature scanner parser ecosystem, deduplication, findings,
  workflow, API, reporting.
- **Limit:** it is not designed to be a comprehensive public-intelligence mirror
  or an authoritative asset/SBOM matching engine across sources.
- **Decision:** integrate, do not fork as the primary core.

### B. Use Vulnerability-Lookup alone

- **Strengths:** highly relevant intelligence aggregation, correlation, feeders,
  KEV/EPSS/VEX, API.
- **Limit:** coordinated disclosure and intelligence workflows do not replace
  enterprise scanner normalization or a cross-asset remediation lifecycle.
- **Decision:** prefer as a separately deployed intelligence service.

### C. Use Wazuh/Greenbone as the whole platform

- **Strengths:** real local inventory/detection or network scan evidence.
- **Limit:** their data and workflow are strongest inside their own detection
  domains; neither is the universal case-management and public-intelligence
  correlation layer.
- **Decision:** use both as authoritative observations where deployed.

### D. Extend OpenCVE

- **Strengths:** rich intelligence workflow.
- **Limit:** current BSL 1.1 explicitly says it is not an Open Source license
  and has a commercial security-monitoring/alerting restriction.
- **Decision:** exclude as a foundational dependency; evaluate it only as an
  optional separately licensed integration.

### E. Design an independent thin hub

- **Strengths:** clear system-of-record boundaries, support for heterogeneous
  assets/SBOM/scanners, lifecycle built around actual exposure evidence, and
  upgrades to upstream systems remain tractable.
- **Cost:** requires a disciplined canonical identity model, adapter contracts,
  and integration testing.
- **Decision:** recommended.

## 4. Critical design decisions

### D1 — Exposure is not a CVE

A new public advisory alone creates no case. The platform needs a component
occurrence, asset/service context, match explanation, and evidence. This avoids
turning every newly published CVE into irrelevant operational work.

### D2 — purl first; CPE remains an alias

OSV's package/version API makes purl a strong match anchor for open-source
components. CPE is still necessary for many commercial products and scanner
outputs, but it is frequently incomplete or ambiguous. The model stores both
and requires evidence/confidence for a CPE-driven action.

### D3 — Public intelligence is cached, not re-authored

The Hub stores a versioned projection with source provenance and keeps original
payload/snapshot metadata. This respects corrections, supports re-evaluation,
and avoids presenting a local cache as a new authoritative CVE database.

### D4 — Verification is positive evidence

DefectDojo reimport behavior and scanner output are valuable inputs, but a
missing finding may result from changed scope or failed scan. Case closure
requires evidence of a fixed state plus coverage/freshness conditions.

### D5 — Separate process/API does not settle license questions

Using an external API creates a clear technical boundary and avoids copying
upstream code; it does not replace a deployer's legal review of its complete
distribution or hosting arrangement. The project will document dependencies and
avoid unexamined code reuse.

## 5. Research limitations

- Project capabilities and licenses can change. Consult the linked upstream
  documentation/release before implementation or procurement.
- This research evaluates architecture and integration fit, not a security audit
  of any upstream project.
- Regional source coverage (for example, CNVD/CNNVD or sector-specific vendor
  feeds) needs a separate review of licensing, access method, quality, and
  permissible redistribution before inclusion.
- Risk scoring is a policy decision. KEV, EPSS, and CVSS are inputs, not a
  replacement for business impact assessment.

## 6. Stop condition

Research stopped after primary documentation supported each material reuse,
interface, and license-boundary decision. Additional broad comparison would be
less useful than validating the proposed adapter contracts against a target
DefectDojo/Wazuh/Vulnerability-Lookup deployment during M0.
