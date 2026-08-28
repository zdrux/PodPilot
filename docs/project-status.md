# PodPilot Project Status

Last reviewed: 2026-08-26
Update when: a milestone is completed, the deployed version changes, a release
gate changes, a material blocker is discovered, or the immediate next work is
selected.

## Resume Here

PodPilot 0.11.0 remains deployed on the disposable SNO lab. The 0.12.0 working tree
is implemented and locally tested at schema head `0013_raw_model_responses`, but has
not been deployed. It adds Ask-only multi-cluster routing, secret-backed cluster
management, immutable one-to-ten-cluster conversation selections, cluster-attributed
evidence, and curated-memory prompt integration governed by explicit cluster targets,
required tags, or global scope. Start a new session by reading this file and
`AGENTS.md`, then verify `git status --short` before making changes.

The product is an OpenShift-first investigation and Day-2 operations companion.
It presents active Alertmanager signals, builds bounded evidence-backed
investigations from live cluster state, adds a schema-validated model
interpretation when the provider is available. Registered remediation lifecycle
records remain, but execution now awaits a separate approval-gated action service.

## Implemented

- Ask PodPilot cluster registry with Approver/Breakglass management, plain-text label and key/value
  tags, connection testing, soft disable, a dedicated resourceName-restricted cluster
  credential Secret, default-on TLS verification, and an explicit visible/audited
  per-cluster insecure exception. The runtime cluster is registered automatically and its
  persisted display name and tags can be changed without modifying its deployment-managed
  identity or connection.
- New Ask conversations select one to ten clusters through a searchable picker. The
  immutable selection is retained in history; changing it starts another conversation.
  One shared 25-unit weighted investigation budget fans out across selected clusters, partial failures remain
  scoped limitations, and all evidence/citations identify their source cluster. Alert,
  investigation, dashboard, remote metrics, and remediation routing are unchanged.
- Curated memory now supports global entries, explicit cluster sets, and all-required
  tag matches with explicit-or-tag OR semantics. Eligible nonrestricted chunks are supplied
  to standalone Ask planning and answers as cluster-labeled guidance, never live evidence,
  tool authority, or current-state citations.

- Curated cluster-memory foundation with immutable versions, heading-aware chunks,
  SQLite FTS5/BM25 search, reviewed/enabled/expiry eligibility, cluster and
  namespace scope, restricted-entry authorization, Approver management controls,
  Investigator retrieval preview, redaction, and content-free audit metadata.
  The 0.12 targeting and Ask augmentation rules above supersede the original
  single-cluster preview-only boundary.

- OpenShift OAuth-protected dashboard with Viewer, Investigator, Approver, and
  Breakglass attribution through disposable htpasswd lab users.
- Standalone Ask now supports a model-directed loop of ten planning rounds within 25 weighted
  investigation units, with no default server-follow-up reserve. The model dynamically selects
  evidence-grounded object, owner, log, Event, metric, probe, and configuration traversal while
  the broker retains all sensitivity, verb, budget, redaction, and RBAC enforcement. It can
  search live API discovery and issue bounded watches against any RBAC-readable non-sensitive
  resource, and shows a transient live investigation journal with hypotheses, next checks, and
  findings grouped into stable chronological phase sections. Repeated progress messages are
  collapsed so each journal line is shown once.
- Model profiles can omit sampling temperature for provider compatibility or set an explicit
  `0`–`2` value. Explicit inventory routes canonicalize model noun variants against fresh live
  discovery and no longer treat a catalog-name miss as proof of an empty cluster inventory.
- Alertmanager queue with expected Watchdog separation and durable
  investigations.
- Bounded Pod status, event, current/previous log, owner-chain, rollout, and node
  scheduling evidence.
- Provider-neutral model boundary with OpenAI Responses and strict-schema Chat
  Completions implementations, capability probing, structured output, redaction,
  and deterministic fallback. Multiple endpoint profiles live in SQLite with one
  tested active profile. Per-profile API tokens remain under opaque keys in the
  fixed OpenShift Secret and are dynamically created, rotated, and removed without
  a Pod restart. Transport modes include system trust, custom CA, a visibly
  insecure HTTPS override, and explicit plain HTTP restricted to Kubernetes
  Service DNS endpoints. Capability probing now validates the live Ask PodPilot
  classification, compact action-selection, grounded follow-up, evidence-citing
  answer, and log-analysis stages with the same modular payload shapes as production,
  and shows an explicit result notification,
  emits sanitized phase/outcome events for provider troubleshooting, and gives
  Chat Completions models one bounded field/type plus static cross-field schema correction attempt.
  Inquiry operations are authoritative over the redundant coarse mode, so defensible
  compound classifications such as investigate+logs normalize to logs instead of
  failing the profile probe or discarding useful production semantics.
  Compact action-selection prompts retain bounded completed-read history and structured
  candidate capability/evidence metadata, prioritize relevant grounded action IDs, and
  explicitly prohibit repeating successful discovery through authored object reads.
  Final-answer adapters recover exact bracketed evidence IDs only from the bounded facts
  supplied to that call when a compatible provider omits the structured citations array;
  unknown inline IDs remain untrusted and final answer validation still rechecks grounding.
  A schema-invalid correction after a valid premature stop may fall back to one exact
  operator-grounded discovery anchor. After successful evidence collection, independently valid action
  selections survive a malformed sibling read, and a fully invalid corrected selection may continue
  with one exact unread broker candidate derived from that evidence. A plan malformed from its first
  response still executes nothing.
  The compatibility boundary safely defaults a missing descriptive plan summary,
  uses a smaller synthetic answer budget during probes, canonicalizes known
  Kubernetes/OpenShift Kind and apiVersion pairs, and keeps model-authored plan
  caveats separate from trusted evidence-collection limitations.
  Model probe diagnostics count only actual provider requests, attach a failed
  capability result to the responsible workflow request, expose redacted provider
  identifiers and response previews, avoid duplicate failure toasts, and use a
  transient dismissible success notice.
  Approvers can delete active or inactive profiles in the GUI. Active deletion
  selects the most recently probed ready fallback when available, otherwise the
  application continues in its deterministic model-free mode.
- Typed remediation for one controller-owned failed Pod replacement and one
  Deployment, StatefulSet, or DaemonSet rollout restart.
- Server dry-run, exact UID/resourceVersion preconditions, ten-minute preview
  expiry, Approver-only two-step confirmation, atomic single execution,
  post-action verification, sibling-action cancellation, and audit events.
- Explicit preview cancellation by the investigation creator or an Approver,
  automatic expiry, source-alert reconciliation from complete Alertmanager
  snapshots, and read-only stale or missing target reconciliation.
- Approval rechecks the source alert immediately before claiming an action. An
  unavailable or truncated Alertmanager snapshot fails closed without
  cancelling or authorizing the preview.
- `TargetDown` investigations with namespace and Service scope receive a
  persisted three-step safe diagnostic plan. An Investigator can run bounded
  passive Thanos rule/scrape correlation, Service/EndpointSlice/Pod topology,
  and recent target-Pod event checks once.
- Check results become confirmed, cited observations and trigger a fresh model
  interpretation when the configured provider is ready. The plan and evidence
  remain useful without the model.
- Investigation-scoped chat persists attributed, redacted messages and labels
  evidence-based, general-guidance, and insufficient-evidence answers. The API
  validates model citations against the investigation's persisted observation
  IDs and withholds uncited factual claims. It now shares the bounded Ask read
  broker, persists alert-scoped resource and Pod-log observations into the
  incident, and audits read targets without evidence bodies.
- Chat may propose only the literal `run_queued_checks` intent while registered
  checks remain queued. The proposal cannot execute anything; an Investigator
  must use the separate existing check control and its CSRF, atomic claim, scope,
  and audit gates.
- Standalone Ask PodPilot conversations can investigate symptoms without an alert.
  Up to ten schema-validated planning rounds spend at most 25 weighted units on adaptive
  discovery, bounded resource/search/watch, ConfigMap, Pod-log, metric, or HTTP-probe reads.
  Earlier observations feed later rounds so
  discovery can lead to exact container logs; a final pass answers from persisted, redacted evidence with
  server-validated citations. HTTP probes are unauthenticated, SNI-aware, TLS-verified,
  response-bounded, and do not follow redirects. Secrets, access reviews, arbitrary
  subresources, commands, authenticated probes, and mutations are denied.
- Unambiguous StorageClass inventory and supported namespaced built-in list
  questions use deterministic read plans. Failed-Job incident questions seed an
  exact `batch/v1` Job read from persisted alert labels before optional follow-up
  planning, preventing empty or malformed model intents from blocking basic work.
- The read broker now builds a five-minute safe catalog from live Kubernetes API
  discovery. Explicit inventory questions compile from that catalog, and model
  planning receives question-relevant plural resource names for core,
  OpenShift, and installed CRD objects. Normal code resolves versions, group
  collisions, scope, and verbs. Lists paginate and persist compact, explicitly
  truncated collection evidence rather than one observation per object.
- Catalog-compiled inventory reads retain the selected API version and Kind instead
  of executing from a plural alone. Kind and API-group wording disambiguates colliding
  lists such as core `Node` versus `NodeMetrics`, and OpenShift versus Cluster API
  `Machine` resources, while the broker revalidates the exact coordinates.
- Ask PodPilot now makes one small model semantic-classification call per user turn, shared by
  every selected cluster. The model identifies coarse inquiry mode, the resource concept, desired
  evidence, and whether names alone are sufficient. Inventory concepts are validated against each
  cluster's live safe catalog before normal code issues a bounded LIST; non-inventory modes guide
  the existing planner. Invalid or unavailable classification falls back to deterministic routing,
  and never changes broker, RBAC, sensitive-kind, or mutation policy.
- Named-object configuration questions now select a generic `configuration_guidance` capability. The
  classifier can recover exact resource coordinates from the last four chat messages, after which normal
  code grounds them in the conversation, resolves the resource through live discovery, and performs the
  same bounded read used for any other object kind. Final answers distinguish unapplied general guidance
  from cited observed state; Kafka-specific keyword projection and answer replacement have been removed.
- Configuration traversal now detects explicit nested ConfigMap references in any observed custom-resource
  spec, offers the exact referenced object ahead of generic discovery candidates, and keeps configuration
  inquiries open for that model-selected read. Exact ConfigMap GET evidence contributes bounded redacted
  `data` to final fact cards, while LIST evidence remains metadata-only. Partial unrelated RBAC failures no
  longer replace an otherwise supported answer with an “Access blocked” headline.
- The relationship graph now exposes opaque forward and reverse semantic targets for observed ownership,
  typed object references, and registered selectors. Machine `status.nodeRef` links, MachineConfigPool
  Node/MachineConfig selectors, common workload selectors, and multi-hop owner chains advance through the
  same bounded planner and broker. The classifier selects a relationship ID while normal code retains names,
  selectors, API resolution, and authorization. Deterministic rendering prefers the classified primary Kind,
  preventing a supporting ConfigMap read from replacing a requested source CR.
- Inventory classification now guarantees the base catalog-resolved LIST on every selected cluster.
  The classifier's detail flag controls only an optional follow-up phase, so it can no longer suppress
  inventory collection or deterministic multi-cluster rendering. Model-authored cluster-wide LIST and
  search reads also normalize the common `namespace: "*"` shorthand to an omitted namespace before
  broker validation.
- Simple inventory turns now finish through the deterministic renderer without a general final-model
  answer/correction pass or unrelated suggested checks. Multi-cluster summaries report matches as
  “X of Y queried clusters,” and absent Ready conditions display as `Unknown` rather than implying
  that a discovered custom resource is running.
- Model planning now infers natural-language goals while the server derives collection
  decisions from typed intents. Unsupported
  operational no-read answers receive one structured repair attempt. If both
  initial plans stop before evidence collection, one exact operator-supplied
  coordinate may seed a single broker-validated discovery read; the model chooses
  all later troubleshooting traversal. The first later evidence-supported stop
  for diagnostic/log/explanation goals receives one model sufficiency review so
  material available reads are attempted instead of merely listed as next checks.
  Generic catalog fallback remains disabled, and recommendation text is never executable.
- Cluster-wide inventory LISTs no longer require the operator to invent a
  namespace. OpenShift API 403 responses identify the investigator ServiceAccount,
  verb, resource, and scope in the answer. List evidence retains all collected
  names separately from compact details, so detail compaction no longer falsely
  claims that additional objects exist; internal observation paths are removed
  from displayed Markdown.
- Ask PodPilot snapshots active model-profile status before its SQLAlchemy
  session closes. A configured but non-ready profile now produces a persisted,
  attributed setup message with its real provider status instead of raising a
  detached-instance error during chat creation.
- Explicit inventory LISTs now default to 500 objects and accept a deployment
  setting up to 1,000. Kubernetes pagination is no longer capped at the old five
  50-object pages. The API renders every collected name into a cited Markdown
  table for list requests and suppresses redundant model-authored completeness
  caveats; the model is not responsible for reproducing the actual inventory.
- Projected resource search can scan beyond the ordinary LIST evidence window while
  returning only a bounded match set. Route URL questions compile to exact `spec.host`
  searches, and planner guidance covers named GETs, label selectors, Route hosts,
  Route backend Services, and follow-up reads from discovered coordinates.
- Cross-group plural collisions use matching `apiVersion`/`Kind` coordinates during
  discovery preflight. OpenShift browser Route questions select
  `routes.route.openshift.io`, never an incidental Knative Route; rejected ambiguity does
  not consume the cluster-read budget.
- Route backend Service references are grounded from projected `spec.to.name` data, allowing
  exact Route-to-Service follow-up reads. Edge, reencrypt, passthrough, and unsecured Route
  behavior has a deterministic cited answer when model follow-up planning is incomplete.
- Route, HTTP-5xx, and connectivity investigations receive a deterministic bounded relationship
  graph covering observed Route, Service, EndpointSlice/Endpoints, Pod, owner, selector, and mount
  edges. The model selects each traversal as a typed read; graph frontier hints never execute.
- Cross-namespace Pod TCP/connectivity questions expose exact Pods, Namespace label sets, and
  NetworkPolicies as evidence-grounded candidates. The model decides which reads discriminate its
  hypothesis, while policy interpretation still separates source egress from destination ingress
  and discloses that configuration alone cannot prove a drop.
- HTTPS troubleshooting probes keep verification enabled by default but may explicitly
  select `tls_verify=false` for private, self-signed, or component-managed certificates.
  SNI is preserved and both evidence and limitations state that server identity was not verified.
- Ask PodPilot can request typed CPU, memory, network, restart, PVC-utilization, and
  readiness trends for exact Pod/namespace/PVC scopes. Server-owned PromQL is sent through
  authenticated Thanos range queries; the model receives bounded normalized samples and
  statistics but never PromQL control or the ServiceAccount token.
- Deployment metric scope aggregates all owned ReplicaSet Pods, including rollout overlap.
  Bounded CPU/memory rankings support cluster, namespace, Deployment, and node scope; pod totals
  aggregate application containers and honor the requested top-N limit. Semantic cluster rankings
  execute once per selected cluster and render as a deterministic multi-cluster table. Common namespace
  ranking questions compile directly to typed metric reads before model planning. Node scope supports
  total workload trends and rankings with
  namespace/Pod/container attribution. Standard monitoring still cannot identify arbitrary
  host processes; that would require separate process-exporter/eBPF or node diagnostics.
  Overall node-exporter CPU/memory utilization can be paired with those rankings to reveal
  pressure not explained by monitored workload containers.
- Ask PodPilot can rank namespaces by application-log payload volume over a bounded period.
  Normal code owns the fixed Loki `bytes_over_time` query, authenticates through the OpenShift
  LokiStack gateway, preserves explicit bounded periods such as `5m`, `2h`, and `today`, persists
  only aggregate namespace bytes/rates, renders multi-cluster tables,
  and never returns log lines or accepts model-authored LogQL. The investigator retains
  `cluster-monitoring-view` and adds the read-only application, infrastructure, and audit
  OpenShift Logging views.
- Ask PodPilot conversations are private to their creating OpenShift user. Users
  can start and delete their own conversations; other users receive a not-found
  response rather than conversation metadata. Questions are unlimited per
  conversation: the model receives the ten most recent messages plus a bounded
  deterministic digest of earlier messages. Per-question collection remains
  bounded to 25 weighted investigation units, and each user is throttled to ten questions per minute.
- The chat UI uses larger operational text, exposes New conversation and Delete
  conversation controls, and submits with Enter while reserving Shift+Enter for
  a newline. The Ask screen now uses one mellow slate-blue surface across its
  header, transcript, and composer. Full-width conversation rows use a dedicated
  metadata column and subtle silver-blue dividers instead of rounded message cards;
  narrow layouts stack that metadata above each response.
- Each Ask question has a default-off **Show raw model response** switch. When enabled,
  the durable run retains up to four redacted, size-bounded final-answer provider bodies,
  including the initial and PodPilot correction attempts. The owner can expand them beneath
  the final reply as escaped, visibly untrusted debug output; they do not bypass validation,
  citation enforcement, fallback behavior, or action policy.
- Ask questions are persisted as recoverable jobs and processed by a configurable bounded pool
  inside the single SQLite replica (three workers and two concurrent runs per user by default).
  SQLite uses WAL plus a 30-second writer wait, and excess work remains durably queued. Submission
  clears the composer immediately and adds an
  optimistic user turn plus pulsating assistant placeholder. Owner-only SSE
  updates report real discovery, planning, collection, and answer phases; reloads
  recover progress from SQLite, and interrupted jobs are requeued on startup.
  Runs have an overall configurable execution deadline; the worker and owner-only
  status streams atomically fail stale jobs, while the browser stops progress
  animation after a bounded delivery grace period.
- Ad-hoc Pod-log reads report authorization, missing-target, and invalid-stream
  failures separately. A missing retained previous container stream falls back to
  bounded current logs and preserves that distinction as a limitation. Evidence
  citations now show the tool, summary, first technical fact, and stable evidence
  ID; they open, focus, highlight, and expand the matching provenance card. Drawer
  cards expose exact OpenShift coordinates, material object fields, probe SNI/TLS
  diagnostics, metric bounds, container identity, bounded excerpts, and the full
  persisted redacted payload. A server-side guard rejects provider claims that a
  TLS-stage certificate failure or sidecar-only logs prove an application backend
  serves plain HTTP.
- Trust-only HTTPS probe failures now receive one deterministic, evidence-visible
  retry with verification disabled while preserving URL, Host, SNI, method, and
  connection override. Unready, restarting, and non-running containers become
  prioritized exact log candidates. Bounded logs from any container are classified
  into general operational findings with occurrence/signature counts, timestamps,
  samples, paths, and endpoints. The model receives findings, optional correlation candidates,
  and completed checks, then dynamically selects any exact Pod, owner, Pod-Event, metric,
  configuration, or applicable previous-log reads inside the existing budget. It must
  distinguish correlation from root cause.
  Missing certificate/key assets are correlated across neighboring traceback lines, so a
  PEM path separated from its `FileNotFoundError` remains a required cited log finding.
- Ask replies now keep confidence as a short hover/focus pill beside the timestamp
  and collapse cited observations into one rounded on-demand vertical timeline; the redundant
  inspected-target disclosure is no longer rendered. Ask session,
  reply, and evidence timestamps display in fixed `EST (-4)` while persistence stays UTC.
- The Ask composer now keeps the question label, cluster picker, and raw-response toggle on one
  row and places the Investigate button inside the text box; the former per-question budget and
  keyboard-hint row is no longer rendered.
- Final-answer evidence is compacted into a provider-only bounded view that prioritizes
  current reads and caps Pod logs, objects, findings, and total bytes without changing
  persisted provenance. Citation-bearing heading-only or extremely brief answers receive
  one bounded correction, as do evidence-based answers missing current Pod-log citations. A
  second failure uses deterministic Route/TLS, inventory, or cited-observation output. Current
  single-line chat-completions answers beginning with a heading are normalized into real block
  structure before validation, so substantive prose is not misclassified as heading-only. Current
  chat-completions answers that misplaced an exact allowlisted evidence ID in prose now recover
  that citation and remove the internal marker; unknown IDs remain rejected. Current structured
  log findings are always composed into the reply with exact coordinates, bounded
  technical details, and citations, so a Route fallback cannot hide them. Equivalent displayed
  limitations are semantically deduplicated.
- Final-answer context is now separately constrained to eight evidence fact cards within a 7.5 KB
  aggregate target, cluster ID/name attribution, three collection issues, and an optional bounded
  prior answer or retry code. Graph, ledger, catalog,
  tool-policy, raw observation envelopes, and domain teaching text are omitted. An empty
  Chat Completions payload receives one schema-only retry. Any later final-answer failure preserves
  successful reads in a cited deterministic Route/resource/inventory or observation summary instead
  of replacing the investigation with an uncited generic error.
- Final-answer validation now detects structured gap JSON embedded in prose and flattened inline
  Markdown tables. It requests clean operator prose plus real top-level gaps, and can recover only
  fixed ledger-actionable capability labels from an explicit recommendation section. Those labels
  return to grounded candidate planning; model-authored coordinates and mutation text are discarded.
- Evidence-follow-up answers now receive ledger-reconciled resolved and remaining gaps, and stale
  “not collected” wording for completed checks is rejected. Internal multi-ID citation markers are
  removed from prose. Exact operator URLs can become grounded Route-probe candidates, while structured
  log gaps can admit exact healthy Running/Ready Pod containers without weakening log target binding.
- Deterministic Route fallback now composes current Service, endpoint, Pod, and live-probe evidence;
  completed structured gaps are removed server-side. Once a TLS probe returns an HTTP response,
  workload logs and Pod configuration outrank more topology checks, and internal model-recovery
  warnings collapse into one concise limitation without hiding security or collection failures.
- Ask planning now pins the initial goal, detects duplicate-only no-progress plans across collection
  phases, and supplies an object-specific capability ledger so available-but-uncollected Service,
  endpoint, Pod, log, metric, and probe checks are not called unavailable. Medium/high structured
  answer gaps—and capability-matched suggested checks—can trigger one bounded typed collection phase
  and answer regeneration. Gap, graph, and recommendation prose remains non-executable.
- Grounded traversal now uses one compact resource-agnostic action-selection contract. Normal code
  offers at most twelve opaque reads derived from exact operator anchors, observed relationships,
  unresolved evidence needs, implicated logs, and bounded catalog matches. The model may select up to
  four IDs or author up to three object-only discovery/GET/LIST/search reads; Pod logs and all other
  tool classes still require server-owned candidates. Candidate rounds retain only the current
  question, six fact cards within a 5 KB aggregate target, action labels, and twelve policy-filtered
  catalog entries. Query-relevant ConfigMap/workload/CRD candidates remain visible beside generic
  owner edges, and normalized LIST/search results become exact GET candidates on the next round.
  Unknown IDs and denied/scope-invalid authored reads fail closed, and a repeated stop on
  a matching high/medium structured gap can recover one highest-priority candidate through the normal broker.
- Action selection now tolerates the constrained model's inconsistent decision label when it also
  returns exact supplied action IDs: the IDs continue the investigation, while an empty investigate
  response receives the bounded retry and can recover with the highest-priority supplied action.
  Flattened bold answer sections and Unicode bullets are restored
  to readable Markdown headings and lists. Pod logs collected during recommendation follow-up still
  pass through the dedicated bounded model log analysis before answer regeneration.
- Explicit failure investigations now keep exact healthy workload logs actionable even when the
  model omits a log recommendation. EndpointSlice/Endpoints target references ground the downstream
  Pod read, and after two model stops PodPilot can collect one remaining exact log candidate through
  the unchanged broker; successful logs still receive the separate bounded semantic analysis.
- Natural requests such as “check the Authorino Pod logs in the kuadrant-system namespace” now
  compile to a bounded namespace-scoped Pod-name search. Search evidence emits exact container-log
  candidates, enabling the unchanged broker and isolated log analyzer without model-authored Pod
  coordinates.
- Up to three remaining unread server-owned candidates may expose a **Run check** button independently
  of model recommendation wording. The CSRF-protected click creates a linked
  same-conversation run with fresh model context, revalidates the opaque candidate, and executes
  exactly that one read through the unchanged broker. Its answer receives only the original question,
  selected-check label, and bounded evidence; it does not restart planning or inherit chat prose.
  Collected capability classes are suppressed from the next button set, and the recommendation cards
  use larger high-contrast text and controls. Mutation guidance remains display-only.
- The concise answer contract now contains only `answer` and `citations`. It does not request
  certainty, gaps, capability names, coordinates, or recommendations. Provider attempts to append a
  recommendation schema are removed before Markdown rendering; suggested controls come from normal code.
- Inventory and existence questions now retain the model's concise conclusion while normal code appends
  a verified table containing every collected OpenShift cluster, resource kind, namespace, object name,
  and Ready condition within the bounded list window. This presentation no longer depends on the model
  answer failing quality validation, so a technically valid yes/no response cannot hide collected identities.
  Live catalog resolution also compiles the requested LIST deterministically on each selected cluster.
  Clusters where the API is readable but returns zero objects are distinguished from clusters where no
  matching readable API type is installed or authorized; neither case falls through to unrelated resources.
- Pod discovery now emits bounded exact log candidates. Planner-selected opaque
  IDs are bound to observed namespace/Pod/container coordinates before execution;
  invented targets receive one budget-free repair, followed by a disclosed
  server-owned fallback across at most three relevant candidates. This improves
  discover-then-log autonomy without expanding the investigator ServiceAccount.
  Direct unobserved Pod-log targets and literal future-value placeholders are now
  rejected before cluster collection. Model-authored object GETs are now permitted only through the
  compact planner schema and must pass live API resolution, namespace, sensitivity, verb, and RBAC
  validation; discovery is preferred when an exact name is not known. Model activation probes verify a
  synthetic discovery-to-exact-log-candidate sequence.
- Ask PodPilot opens the bounded conversation viewport at the newest response.
  Chat messages render safe CommonMark with readable system prose typography,
  distinct monospace code, and styled tables; raw HTML remains escaped and unsafe
  link schemes are not activated.
- The application runs as `ai-ops/podpilot-investigator`, bound to OpenShift
  `cluster-reader`. The separate `ai-observer` identity retains cluster-admin only
  as disposable-lab development and break-glass access.
- The monitoring check submits only fixed `ALERTS` and `up` instant-query shapes
  to the TLS-validated, authenticated in-cluster Thanos endpoint. Exact alert
  labels are escaped, responses are capped at 64 KiB and 20 retained series, and
  results are redacted before becoming evidence.
- SQLite/Alembic persistence on the SNO-local PVC. Schema head is
  `0013_raw_model_responses`.
- A remote Kustomize overlay composes the read-only base, explicit
  `openshift-monitoring` Alertmanager API Role, group-based OAuth GUI admission,
  default-StorageClass PVC, and single-replica workload. The accompanying runbook
  covers Docker/Podman build and push, versioned internal-registry ImageStreamTag
  selection, out-of-band Secrets, existing LDAP-synchronized elevated-role
  mapping, server dry-run, RBAC checks, rollout, and rollback. Every authenticated user receives Viewer;
  each elevated application role accepts multiple existing groups; no remote
  Group or membership is created by PodPilot.

## Last Verified State

- Deployed application version: `0.11.0`; current source version: `0.12.0`.
- OpenShift lab version: `4.22.9` on the documented Hyper-V SNO.
- Deployment: `ai-ops/podpilot`, last observed `1/1` Available.
- Local automated suite: 280 tests passing with 84% aggregate coverage.
- Live Milestone 6 exercise verified creator cancellation with no workload
  mutation, `remediation.cancel` attribution, automatic cancellation after the
  exact fixture target changed, and automatic cancellation after the source
  alert left Alertmanager. Reconciler audit events recorded `target_stale` and
  `source_alert_not_active` under `system:reconciler`.
- The disposable CrashLoop workload namespace and synthetic PrometheusRule were
  removed after validation.
- Live Milestone 7 upgraded the pre-existing `TargetDown` investigation
  `c1443ddc-cc0a-45e4-b91c-8bf2601a11cd` in place and successfully ran both
  checks under `podpilot-breakglass`, followed by a ready model interpretation.
- The independent TargetDown fixture investigation ran both checks under
  `podpilot-investigator`, found ready Service topology, rejected a second run,
  and recorded planner, execution, and reanalysis audit events. Its namespace
  and platform PrometheusRule were removed after validation.
- Live Milestone 8 chat on investigation
  `c1443ddc-cc0a-45e4-b91c-8bf2601a11cd` returned a ready evidence-based answer
  with 12 server-validated citations and no unavailable tool intent after its
  checks had completed. Audit records contain attribution and citation IDs but
  no message body.
- A fresh TargetDown fixture investigation
  `389d29c6-8801-4bed-bbcb-e856ca0fde1f` returned a ready
  `run_queued_checks` proposal and rendered the separate run control. Both checks
  remained queued after the chat turn, proving the proposal did not execute.
  The fixture namespace and PrometheusRule were removed afterward.
- Live Milestone 9 fixture investigation
  `9bdee782-bc08-418e-9922-cec6f66b3f16` ran all three checks under
  `podpilot-breakglass`. Thanos returned one matching firing `ALERTS` series and
  zero matching `up` series, so the deterministic result correctly left target
  discovery unresolved. All checks succeeded, the model status was ready, and
  three `diagnostic.execute` events recorded the exact registered tools. The
  fixture namespace and PrometheusRule were removed afterward.
- Live Milestone 10 conversation `cd23e2dd-de0e-4abd-a289-b00e57d09c19`
  used one `get_resource` intent to read the exact running PodPilot Pod, persisted
  one observation, returned one validated citation, and recorded attributed
  `adhoc.message` and `adhoc.answer` audit events. A deliberately under-scoped
  preceding question failed collection without inventing evidence or attempting a
  mutation.
- Live iterative-log conversation `108dc517-38e7-45e5-b1df-f910bfb1e49a`
  replayed the question "are there any errors in the kube api server pods logs?".
  Round 1 discovered the static Pod and its containers; round 2 collected the
  bounded current `kube-apiserver` container log. The final answer cited both
  persisted observations and reported the observed etcd warnings with explicit
  time-window and sidecar limitations.
- The conversation-management update was built as OpenShift build `podpilot-25`
  at image digest
  `sha256:e01ec69288037e394ae35053ba61cde4663b1bcc3e7bef4ac9be6b157a3fb142`.
  The `0008_conversation_management` migration ran during rollout and the live
  readiness endpoint reported a healthy database. A clean in-app browser reached
  the expected OpenShift OAuth login boundary; authenticated visual behavior is
  covered by rendered-template and interaction tests rather than transferring a
  lab credential into that browser session.
- The Alertmanager log and citation-navigation correction was deployed as
  OpenShift build `podpilot-26` at image digest
  `sha256:7b379db9e0c30f6d4b08862e8ba1ec74f882a1d9df233d89ddd273d9faf0daac`.
  Live replay of the exact previous-log read confirmed Kubernetes had no retained
  previous `alertmanager` stream; the deployed broker fell back to current logs,
  collected 1,692 bounded characters, and returned the explicit retention
  limitation. The deployment remained `1/1` Available.
- The chat presentation update was deployed as OpenShift build `podpilot-27` at
  image digest
  `sha256:5f6e96fdc3d1c32ccb19c5765955a15e87cb153426e266cef0d498c2849a08ce`.
  Live rendering of the latest stored conversation confirmed a real Markdown
  table, the structured chat container, and the newest-message scroll marker.
- The degraded Alertmanager collection state was traced to an inert RoleBinding
  that referenced `monitoring-alertmanager-view` as a ClusterRole. The corrected
  `openshift-monitoring/podpilot-alertmanager-api-view` binding references the
  existing namespaced Role. Live collection then returned a complete snapshot of
  five alerts, and the obsolete binding was removed.
- The model registry was deployed as OpenShift build `podpilot-29` at image digest
  `sha256:1244c165107ce2f545bab9e83aeafa9ea58a20041f165ac8222d817162889b62`.
  The init container upgraded the live PVC from `0008_conversation_management` to
  `0009_model_registry`, preserving the ready OpenAI profile as active with its
  existing `api_key`. A live, OAuth-attributed API exercise created a temporary
  Chat Completions profile, patched its opaque token key into the fixed credential
  Secret, deleted the profile and key, and confirmed the API container did not
  restart. The database and Secret returned to the original single-profile state.
- The Quiet Ledger Ask redesign was deployed as OpenShift build `podpilot-30` at
  image digest
  `sha256:09ba40c6039f05b6a730497a0dbee47fc199501d29c055711e9f4c7b12af2071`.
  The full 425-test suite passed at 84% coverage. Authenticated Chrome verification
  under `podpilot-breakglass` exercised the 40-item evidence drawer, raw-response
  switch, composer state, desktop transcript, and 720px responsive layout with no
  console warnings, errors, or horizontal page overflow.

These observations are a handoff snapshot, not a substitute for checking the
current repository and cluster state.

## Important Safety State

- The normal runtime is `podpilot-investigator` with `cluster-reader`. Live audit
  confirmed Pod-log and ConfigMap reads and denied Secrets, `pods/exec`, and
  Deployment patch. `ai-observer` has cluster-admin only through the explicit
  `poc-cluster-admin` overlay and is not the application identity.
- Model output, alert text, events, logs, annotations, and retrieved memory are
  untrusted evidence and cannot define executable operations.
- The browser submits only an opaque action ID. The server owns the target,
  operation, preconditions, expiry, and verifier.
- Cancellation grants no execute authority. Lifecycle closure uses an atomic
  preview-ready transition and records the actor, reason, detail, and timestamp.
- Absence from a bounded, truncated Alertmanager response is not accepted as
  proof that an alert resolved.
- The model and browser cannot submit diagnostic tool names, targets, selectors,
  query text, or commands. Normal code owns the plan, budget, and exact inputs.
- Chat receives no Kubernetes credentials or generic tool channel. Citations and
  the single available intent are validated by normal code; executing proposed
  checks always requires a separate operator request.
- Alert labels are never treated as PromQL or network destinations. The server
  owns the query shape and escapes exact-match values. No DNS, TCP, TLS, or HTTP
  connection is made to the alert `instance` or selected Service.
- The application-level Ask broker denies mutations and Secrets even though the
  runtime also has one narrowly resource-named model-credential Secret permission.
- Pod DELETE preview carries `dryRun: ["All"]` in `DeleteOptions` and the query
  parameter because live SNO testing found the query-only Python-client form was
  not sufficient on this OpenShift path.
- Never commit model tokens, kubeconfigs, cluster credentials, pull secrets, or
  private keys.

## 2026-08-27 Cluster audit Ask queries

- Added a typed `query_audit_events` read path backed by the OpenShift LokiStack audit tenant.
  Semantic classification supplies the exact username, requested time range, result limit,
  all-versus-mutation scope, and all/successful/failed outcome. Configured defaults apply only
  when the operator omits a count or period.
- Audit usernames are regex-escaped, matched exactly and case-insensitively in Loki, then verified
  again with `casefold()` before projection. Evidence retains only bounded event metadata and does
  not persist raw audit lines or request/response objects.
- The capability remains inside Ask's Investigator-or-higher authorization boundary, so
  Investigator, Approver, and Breakglass roles can query it through the runtime identity's existing
  `cluster-logging-audit-view` binding.
- Deterministic fallback and suggested-check generation now use current-turn evidence IDs, stopping
  an unrelated follow-up from recycling an earlier Node inventory as its answer or next check.
- Follow-up correction: the configured one-hour value is now an initial search window rather than a
  final default period. “Last N” expands backward to the configured audit ceiling, while a strict
  duration-only continuation inherits the previous validated audit target and performs a fresh read.
  Classification retries once after invalid JSON, and a failed unrelated classification cannot cite
  prior audit evidence.
- Explicit audit-log questions now retain a grounded deterministic semantic fallback after both
  provider classification attempts fail, and a valid single fenced JSON object is accepted from
  compatible Chat Completions endpoints. The richer semantic classifier has a 1,400-token ceiling;
  profile limits remain authoritative.
- Audit Loki queries request exactly the validated result count rather than four times that count.
  Their raw HTTP response has a separate configurable 1 MiB default ceiling, while persisted evidence
  remains the existing redacted bounded projection with no raw lines or request/response objects.
- Audit operation scope now distinguishes delete-only (`delete` and `deletecollection`) from broader
  mutations, so the original “last N delete actions” wording no longer includes creates, patches, or updates.
- Audit usernames are now optional. “Last 10 delete actions according to the audit log” compiles to
  a cluster-wide query that filters completed deletes in Loki and requests ten newest-first compact
  results; “by USER” retains the escaped exact, case-insensitive username filter.
- Added normalized model-call diagnostics for both Responses and Chat Completions. Completed Ask
  replies expose aggregate token usage and largest single-request input in a collapsed author-rail
  control. The latest model capability test retains an Approver-visible collapsed request trace with
  operation/schema labels, status, duration, usage, request ID, and bounded redacted synthetic output;
  request bodies, authorization headers, and credentials are never captured.

## 2026-08-28 Site-wide Quiet Ledger redesign

- Extended the selected Quiet Ledger direction from Ask to the complete operator UI: Cluster Health, cluster registry, cluster memory, model registry, and investigation detail pages now share one mellow slate-blue surface and divider-led hierarchy.
- Replaced floating dashboard metrics and page panels with continuous rails, subtle silver-blue separators, and flatter status treatments while preserving evidence, provenance, forms, action controls, and live cluster data.
- Removed the unused Alert Queue, Investigations, and disabled Actions entries from primary navigation. Correct active states are now present for every remaining route, including Model Settings.
- The signed-in user's recent Ask sessions remain expanded in the shared sidebar on Dashboard, management, and investigation pages, so switching sections no longer hides the active conversation list.
- Versioned the stylesheet request so an existing Chrome session receives the redesign immediately after rollout instead of retaining the earlier cached CSS.
- SNO binary build `podpilot-33` is deployed at digest `sha256:fd43b4bc680f1c99790604c005a28aa375b032b3698250280fcb3a8c8ee44630`.
- Authenticated Chrome QA covered Dashboard, Ask, Clusters, Memory, Model Settings, an investigation detail, and the 720px responsive dashboard. `design-qa.md` records the passed source/implementation comparison.
- Model-free verification remains green: 430 tests passed with 84% coverage.

## 2026-08-28 Exact Node label reads

- Ask now compiles an explicit label request for an exact named Node into a cluster-scoped
  `get_resource` read instead of treating the word “show” as a request to relist every Node.
- Semantic classification treats labels, annotations, spec, status, and taints as object-detail
  requests, and deterministic provider fallback can render matching metadata such as Node labels.
- Question-focused model fact cards retain bounded requested metadata, so the final answer receives
  labels from an exact GET instead of seeing only the Node identity and spec/status.
- Explicit labels, annotations, and owner-reference questions prefer a deterministic exact-metadata
  table over a weaker model interpretation once the named GET succeeds.
- Evidence payload ceilings remain unchanged.

## 2026-08-28 Typed semantic read descriptions

- Replaced the coarse routing-only classification contract with a backward-compatible semantic IR
  covering operation, cardinality, resource concept, grounded name/namespace, requested fields,
  explicit label selectors, log container/history/time bounds, metrics, and audit semantics.
- Normal code resolves semantic resource concepts through live safe discovery and compiles exact GET,
  bounded exact-name search, collection, related-object Event, and Pod-discovery reads without
  accepting model-authored API coordinates.
- Exact semantic coordinates must appear in the current question or recent conversation. Namespaced
  objects without a grounded namespace are searched before GET, and model-invented names are ignored.
- Pod logs now support semantic `sinceSeconds`, plus init- and ephemeral-container candidates. Event
  projection supports both core/v1 and events.k8s.io/v1 field shapes.
- Evidence payload ceilings remain unchanged.

## 2026-08-28 Configurable model reasoning effort

- Model profiles now declare their supported reasoning levels and a default selection. Provider
  default remains available for endpoints with unknown or no explicit reasoning controls.
- Ask PodPilot exposes those levels beside the raw-response switch. The user's per-model choice
  persists across conversations and is snapshotted onto each queued run.
- PodPilot sends the effective selection using the API-specific OpenAI-compatible shape on every
  Responses or Chat Completions request. Capability probes use the profile default.
- Explicit reasoning uses the profile's full maximum-output budget because hidden reasoning tokens
  count against that allowance. Migration `0017_user_reasoning_preferences` adds the supported-level
  metadata, queued-run snapshot, and per-user/per-model preference.
- Reduced-capability profiles now remain usable when their probe proves the core safe text contract;
  semantic Ask-probe failures are shown as warnings and continue through typed validation and fallback.
- The model-free suite and a fresh SQLite migration through the new head pass locally; this change
  has not yet been rolled out to the SNO workload.

## 2026-08-28 Compact server-side audit filtering

- Typed audit queries now parse and filter username, stage, verb, outcome, and object coordinates
  inside Loki, then use `line_format` to return only the safe projected fields.
- Newest-first `query_range` and the requested result limit operate on compact matching lines, so
  large audit request/response objects are not downloaded or scanned page-by-page by PodPilot.
- Last-N searches still expand the bounded time window only when too few matching records exist.
  This local change has not yet been rolled out to the SNO workload.

## 2026-08-28 Worker-node utilization routing

- Ask recognizes explicit CPU-and-memory utilization requests for worker/compute Nodes as
  node-level monitoring questions rather than pod top-consumer rankings.
- Normal code compiles the request into separate bounded CPU and memory queries, joins the
  trusted `kube_node_role{role="worker"}` membership metric, and groups results by Node.
- A deterministic guard owns this unambiguous request even if model classification returns a
  different schema-valid metric route; model-authored PromQL remains prohibited.
- The model-free suite passes locally with 509 tests and 83% aggregate coverage; this change
  has not yet been rolled out to the SNO workload.

## 2026-08-28 Cluster-wide Node utilization ranking

- Ask recognizes `top/rank + CPU/memory + Nodes` as an overall Node-utilization ranking rather
  than a Node inventory or a monitored Pod/container ranking.
- Normal code compiles the requested top-N against bounded node-exporter CPU or memory templates,
  groups by Node, and uses the five-minute default when the operator supplies no period.
- This deterministic route retains priority if model classification returns a schema-valid Node
  inventory, while typed model semantics can also request the same registered cluster ranking.
- The model-free suite passes locally with 540 tests and 83% aggregate coverage; these local
  changes have not yet been rolled out to the SNO workload.

## 2026-08-28 Composable metric requests

- Ask metric classification now has a backward-compatible typed request with up to four signals,
  exact target semantics, show/trend/rank/compare/threshold operations, requested statistic,
  grouping, threshold, period, and result limit.
- Normal code compiles registered CPU, memory, allocation, throttling, network, restart, readiness,
  PVC, ranking, and node-utilization signals for cluster, Namespace, Pod/container, Deployment,
  StatefulSet, DaemonSet, Job, Node, Node-role, and PVC targets. The model cannot author PromQL.
- Controller metrics use trusted owner joins, supported groupings become bounded PromQL aggregation,
  and metric-only results receive a deterministic current/average/peak table.
- Machine, Service/Route, OpenShift control-plane, Kafka, and arbitrary CRD telemetry remain future
  capability packs because Kubernetes API discovery does not prove that their metrics exist.
- This local change has not yet been rolled out to the SNO workload.

## 2026-08-28 Stable live-investigation phases

- The active Ask placeholder groups progress into phase sections in chronological order.
- New phases append without reordering existing headings. Each phase displays its latest three
  updates, and reloads reconstruct the same bounded phase view from persisted progress.
- This UI behavior is locally implemented and has not yet been rolled out to the SNO workload.

## Known Limitations

- Single-cluster, single-replica PoC with SNO-local storage and no production
  backup or high-availability design.
- A production action service and narrow action-specific identity are not
  implemented. Existing remediation execution is intentionally unavailable from
  the reader runtime until that boundary exists.
- Only CrashLoop-correlated workload replacement and rollout restart are
  registered remediation domains.
- Investigation chat is limited to one investigation, a 20-message history, one
  non-executing safe-check intent, and non-streaming responses. Standalone Ask
  PodPilot conversations are unlimited and use rolling context, but responses
  remain non-streaming. Curated memory can now be managed and searched, but is not
  yet retrieved into investigation or chat model context.
- The first executable plan is fixed to scoped `TargetDown` passive monitoring
  signals, Service topology, and Pod events. It does not inspect full rule
  definitions or perform an active DNS, TCP, TLS, or HTTP probe.
- Active probing requires an administrator-owned destination registry, a
  dedicated no-token identity, explicit egress policy, redirect/DNS-rebinding
  defenses, rate limits, and adversarial fixtures before it is safe to add.
- Full rule-definition inspection, ad hoc PromQL, Routes, ClusterOperators,
  networking, storage, and version-aware Service Mesh packs remain future
  capability packs.
- The lab binary build publishes `:latest`; immutable release promotion and a
  tested database rollback process remain open.

## Candidate Next Work

No next milestone is formally selected. The highest-value candidates are:

1. Add bounded answer-time memory retrieval and a server-validated knowledge
   citation contract without allowing memory to influence tool or action policy.
2. Add the next diagnostic capability pack with fixtures and release gates;
   Routes and ClusterOperators are narrower choices than Service Mesh.
3. Design an administrator-owned probe-target registry and dedicated no-token,
   egress-restricted probe identity before considering active reachability.
4. Implement the separate approval-gated action executor identity, then replace
   the lab `:latest` build flow with immutable image promotion.
5. Evaluate streaming responses against the existing citation, redaction,
   attribution, rolling-context, and tool-intent boundaries.

Before selecting work, reconcile these candidates with `docs/prd.md`, record the
decision in `docs/decisions.md`, and update this file in the same change.

## Verification Entry Points

- Repository and tests: commands in `AGENTS.md` and `docs/release.md`.
- SNO connection and deployment: `docs/cluster-lab.md` and
  `docs/operations.md`.
- System boundaries: `docs/architecture.md` and `docs/security.md`.
- Product scope and acceptance criteria: `docs/prd.md`.
- Fast file ownership map: `docs/codebase-map.md`.
