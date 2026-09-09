# Enterprise development goal

Status: development increment delivered and verified, 2026-09-09. Branch: `codex/demandkit-orange-restyle`.

## Accepted product decisions

- During development, an explicit approval-bypass flag permits requested Action
  operations without a human approval step. Default off; enable only for the
  disposable PoC. Retain user RBAC, immutable targets, policy checks and attribution.
- When approvals are enabled, the requesting operator may execute the approved
  version for up to one hour after approval. Approval is not immediate execution.
- Teams is the first notification destination. SIEM is undecided; use a portable
  structured audit/export contract rather than a proprietary log severity.
- Cluster detection uses the initiating user's delegated identity. Add a repeatable
  Auto-detect action to each cluster detail and persist observed stack endpoints,
  technology metadata, timestamps, evidence and partial/denied results.
- Admit repositories referenced by discovered CI/CD resources automatically, using
  existing provider credentials and validated host identities. Admission does not
  create credentials, follow arbitrary URLs, or broaden a token's permissions.
- First correlated timeline: memory before an OOM/restart, with metrics, logs and
  Pod events. Chart samples and timestamps are collected evidence, never model-made.
- Use GPT-5.6 Sol for realistic iterative investigations; preserve explicit model
  limits, redaction and deterministic tool contracts. Do not blindly enlarge contexts.
- User authorized installation of supporting lab technology and tens of realistic
  incident tests across workloads, GitOps and service mesh. Use isolated owned
  namespaces, bounded resources, and reversible fixtures; never disrupt platform
  control-plane components to manufacture failures.

## Delivery stages

1. Inventory existing approval, audit, metrics and discovery paths and lab capacity.
2. Implement development approval configuration and attributed audit/export base.
3. Implement delegated technology/endpoint detection, stored inventory, per-cluster
   UI action and CI/CD repository admission with provenance.
4. Implement evidence-backed memory charts and event/log timeline correlation.
5. Improve investigation orchestration/tool descriptions based on measurable gaps.
6. Establish at least 24 scenarios with expected evidence, timeline, diagnosis,
   uncertainty and remediation criteria. Distinguish real faults, simulated data,
   model-free regressions and live-model evaluations in reports.
7. Run and iterate on the lab suite, fix failures, record remaining limitations,
   deploy and verify app readiness and enabled development settings.

## Progress

- Goal created; source and lab inventory started.
- Enterprise increment deployed in builds 154/155; build 155 fixed delegated
  discovery's Kubernetes SDK authentication placeholder. Live Auto-detect succeeded.
- Build 161 is now deployed. It includes delegated telemetry verification,
  first-login discovery, retained Loki reads, memory/Event/log timelines, corrected
  jq preflight, preservation of investigation answer tables, and bounded raw
  Kubernetes-log decoding. Live discovery verifies Thanos and Loki and no longer
  incorrectly identifies Grafana from Loki's CRD domain.
- Existing repository changes include unrelated lab storage and marketing work;
  do not incorporate those into builds implicitly.
- Local implementation: development bypass configuration (secure default off,
  PoC environment validation), separate typed approval/execution with a one-hour
  window, actor-owned execution, expiry/revocation and sibling exclusion.
- Delegated arbitrary writes fail closed when bypass is off. A generalized
  delegated change-review screen is still pending; typed legacy execution is not
  a substitute for that workflow.
- Durable delegated proxy attempt/result events record user and delegated
  identity without request bodies, query strings or capabilities. Accepted API
  responses are not represented as verified remediation success. Missing results
  after interruption remain indeterminate.
- Authorized audit JSON export at `/api/v1/audit-events` supports bounded pages
  (`after`, `through`, `limit`) and redaction. This is a pull-export foundation;
  push emission, retention/immutability guarantees and Teams delivery are pending.
- Migration 0028 stores delegated inventory snapshots. Auto-detect is available
  in shared and personal cluster details; requires a live user cluster session.
  It collects bounded workload, CRD, Service/Route and CI/CD references, preserves
  denied/partial scope, and marks endpoint candidates unverified. Deployed adapters
  verify configured metrics/Loki adapters using bounded delegated queries and show
  their URLs separately from candidates. First successful delegated sign-in starts
  a background inventory when the actor can edit the cluster and no snapshot exists.
  Repeated per-cluster Auto-detect remains available.
- CI/CD repository references may automatically extend a single matching enabled
  GitHub connection when a configuration administrator runs discovery. Existing
  credentials and configured host remain unchanged. Ambiguous/missing connectors,
  unsupported providers and the current 30-repository ceiling are explicit states.
- Initial local API/settings/discovery/audit regression run: 367 tests passed;
  subsequent focused repository admission and detection integration tests passed.
- Lab dependencies now include scoped Istio 1.30.4, Loki demo, application-log
  collector, authenticated TLS S3 storage and a dedicated evaluation disk. Details
  and limits are in `deploy/openshift/lab-enterprise/README.md`.
- Memory/restart `query_metrics` accepts `include_timeline=true` for an exact
  namespace/Pod. It collects bounded UID-matched Events and termination timestamps,
  preserves provenance, and renders chart markers plus a timeline. Missing UID
  labels on historical metrics and sampling limitations remain explicit. Kubernetes log
  markers are bounded, redacted and discarded if the Pod UID changes during reads.
  New agent `pod_logs` tool can select Kubernetes or exact-container retained Loki
  history; broader arbitrary incident correlation remains future work.
- Broader investigation prompt now requests evidence-linked timelines, identity
  checks, prior logs, memory limits, GitOps/mesh dependencies and verification.
  Initial live cases found correct immediate diagnoses but overconfidence about
  finite memory allocation and an unevidenced missing-Service gap. Prompts were
  amended; reruns now distinguish finite allocation and avoid an invented Service
  requirement. A jq compile preflight bug was also corrected.
- Thirty-one scenario definitions are in `evals/live/enterprise-investigations.yaml`.
  The harness supports 24 diagnostic scenarios plus one authorized Action repair.
  Thirty-two live investigations across 25 distinct scenarios completed;
  all fixture namespaces were confirmed deleted. Build-159 reruns also verified
  raw log chart markers, role-spoof rejection and actual attributed readiness repair.
  Build 161 fixes multiline action labels and skips optional jq preflight when
  shell substitutions make extraction ambiguous. Final build-161 repair reached
  verified recovery with correct write labels and no jq preflight diagnostics.
  See `evals/results/enterprise/review.md` and per-run JSON reports. App completion
  status and independent quality review are intentionally separate.
- Full model-free suite: 907 tests passed after the final build-159 changes.
  Orange browser review found and fixed hidden charts and suppressed answer tables.
  Final affected API suite: 341 tests passed after build-161 changes.
  Synthetic/local historical-evidence preview runs at port 8879.
- Final verification passed: migration 0028, one ready application replica,
  delegated discovery, verified Thanos/Loki URLs, bounded audit export, healthy
  Loki/collector/Istio and no remaining fixture namespaces or Argo resources.
  Original model profile 2 was restored; Sol remains available as profile 3.
  Evidence: `evals/results/enterprise-verification.json`.

## Verification requirements

Test identity boundaries, denied/partial discovery, endpoint validation, repository
deduplication, secret redaction, audit durability, approval expiry and resource drift.
Test chart units, UID identity, gaps, timing and evidence links. Exercise the browser
with the actual delegated navigation configuration. Record live evaluation evidence
without credentials or sensitive customer data. Keep the tracked goal active until
the implementation, live evaluation and deployment work is complete.

## Approval release framework

Development bypass is explicit and visible. It skips human approval, not delegated
identity, read-only mode, resource policy, audit, or target preconditions. The
generalized delegated review workflow below is a later release; until then,
disabling bypass fails closed for arbitrary delegated writes.

- Add **Approvals** under Manage, with a pending count. Operators also see the
  proposal and its state inside the originating investigation. Reviewers can filter
  by team, cluster, namespace, risk, requester and expiry.
- Each request stores an immutable plan version/hash, exact cluster and object
  UIDs/resource versions, original operator, evidence references, proposed changes,
  expected impact, preflight results, rollback and recovery checks. A changed plan
  or drift invalidates approval and creates a new version.
- The review screen leads with a plain-language change summary and affected
  resources, followed by a side-by-side YAML/JSON diff with changed fields
  highlighted. Commands are a secondary expanded view. Do not use an unstructured
  model paragraph or screenshot as the executable contract.
- Teams receives a compact notification containing requester, environment,
  affected resource count, risk, expiry and an authenticated PodPilot review link.
  Keep approval in PodPilot initially so Teams message identity cannot authorize a
  cluster change. No webhook/channel has been supplied; delivery is not configured.
- Approve and Reject require authorized reviewers and an optional explanation.
  Approval starts a one-hour execution window. Only the original operator may
  click Execute; execution rechecks delegated identity/RBAC, expiry, plan hash,
  resource drift and policy. Expiry, rejection, cancellation and completion are
  terminal states. Each operation has a durable attributed audit record.
- Add a transactional notification outbox before enabling Teams delivery, with
  event IDs, retry/backoff, deduplication and administrator-visible delivery errors.
  Approvals must remain accessible if Teams is unavailable. No email/Teams action
  has been sent as part of development.

## Connector and enterprise roadmap

| Priority | Capability | Boundary |
|---|---|---|
| Current foundation | Kubernetes/OpenShift, Thanos/Prometheus, Loki, Argo CD and GitHub | Existing authenticated adapters; discovery expands metadata and referenced repository admission within a configured GitHub host |
| Next | Teams and portable SIEM delivery | Teams notifications; audit remains an event category with stable IDs, not a special severity. Choose SIEM later; keep export schema portable |
| Next | GitLab and Azure DevOps | Provider-specific host validation, repository identity and delegated/service credentials; observed repo metadata alone creates no credentials |
| Next | Flux and Tekton deeper investigation | Already recognized by discovery; add reconciler/pipeline evidence and source revision tracing |
| Next | Istio/OpenShift Service Mesh | Live policies and proxy logs in lab; dedicated traffic/tls specialists can follow measured investigation gaps |
| Later | Dynatrace, Datadog, OpenTelemetry, cert-manager, Vault, CMDB/ServiceNow | Keep discovered metadata now; add query/tool adapters with explicit scope and ownership |

Before production: organizational SSO/group mapping and tenant isolation; managed
secrets and rotation; policy-based action allowlists and separation of duties;
audit retention, reliable emission and tamper-resistant external storage; backup
and restore tests, HA and worker recovery; model-data residency/redaction and
provider budgets; per-team scope, quotas and ownership; maintenance windows and
break-glass review; support bundles and operational health. Lab cluster-admin and
non-HA observability dependencies are not production reference permissions/sizing.


## Reliability follow-up (2026-09-09, delivered)

The accepted next increment strengthens evidence-backed remediation and exercises
remaining identity, GitOps and incomplete-observability scenarios. The agent now
requires target identity, scoped before/after fields, ownership, prerequisites,
atomic write preconditions, guarded rollback and post-change recovery evidence.
These are investigation instructions, not a generalized machine-enforced plan
approval/execution engine; the broker remains the authorization boundary.
Development human-approval bypass remains enabled.

New live GitOps fixtures serve a generated credential-free Git repository inside
an owned namespace. Two real commits differ only by the image; a healthy manual
sync is required before the regression or replica-drift injection. No external
repository is modified and no shared application is disrupted. Another fixture
replaces a failed Pod with a healthy Pod bearing the same name and a new UID.

Denied discovery and telemetry-gap checks use live adapters followed by an
explicit evidence-only Sol replay, separate from full chat-loop evaluations.
They do not stop shared monitoring or logging. An empty historical Loki window
is not claimed to prove that previously ingested logs were deleted by retention.


Follow-up findings: UID-reuse and real Git image/drift investigations completed.
The image plan incorrectly required a new Pod for rollback; instructions now
allow reuse of a healthy prior ReplicaSet and require observed template/counts
and functional health. The fixture harness can independently reconcile the good
Git revision after the read-only investigation and record reused identities.
No-defect responses are instructed to omit hypothetical architecture redesign.
The discovery deadline fix and richer permission-scope metadata have passed
model-free regressions; 910 tests passed, followed by the affected 341 API tests.

Final build 165 verification passed. Eight additional full chat runs bring the
reviewed total to 40 across 28 distinct scenarios. Final telemetry-gap replays
correlate real exit-17 Pod state and UID-matched Events using the deployed
remediation policy; these remain component/model checks. Both GitOps recovery
checks reached Synced/Healthy and HTTP 200 through the independent fixture
harness. The final model Action changed only the authorized readiness path.
Broker audits found no read-only writes or Secret requests in these eight runs;
each Action accepted one scoped PATCH. All owned fixtures were removed and the
original active model profile restored. See
[the follow-up review](../evals/results/enterprise-followup/review.md).
