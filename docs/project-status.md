# PodPilot Project Status

Last reviewed: 2026-09-05
Update when: a milestone is completed, the deployed version changes, a release
gate changes, a material blocker is discovered, or the immediate next work is
selected.

## Resume Here

Incident response PoC is implemented on `codex/incident-response-poc`, after
merging/pushing the evidence-ledger UI branch into main at `e2e4505`. The feature is
opt-in and is now deployed on the disposable SNO. It adds fleet incidents, authenticated per-cluster
Alertmanager ingress, separate Secret-backed automation connections, Argo CD/GitHub
metadata enrichment and a bounded platform-only agent. See
[incident-response.md](incident-response.md) for configuration and current limits.
Validation: 799 model-free tests pass (78% aggregate coverage), migration upgrade/
downgrade/re-upgrade passes, the SNO incident composition passes server-side dry-run,
and live read-only platform collector probes succeed. Local synthetic incident and
connector pages were checked in the browser. SNO Alertmanager 0.31.1 now delivers
authenticated, TLS-verified webhooks. A live synthetic Prometheus rule produced
repeated deliveries, one completed model investigation with operator evidence,
and a resolved incident. Connections and webhook status have dedicated settings
pages. Corporate connectors still require end-to-end environment validation.
Incident mode now isolates Argo CD, GitHub and selected Pod-log analysis in specialist
contexts, returns their compact cited reports to a bounded coordinator context, and
retains the bounded source evidence for operators. Normal runs have a configurable
15-minute deadline, ten coordinator rounds and up to twelve specialist reports. The
SNO deployment simulates a 64,000-token total model window (45,952 effective input
tokens with its current output reserve), runs three incident coordinators concurrently,
and fans out up to three Pod-log specialists per round. A four-scenario live stress run
finished in about 11 minutes with three completed investigations and one correctly
partial result due to invalid final citations. SNO has no Argo CD Application CRD or
corporate GitHub connector, so those specialists remain model-free tested. The shared
sidebar now retains active Ask sessions on the incident configuration pages, lists the
ten most recently updated incidents with a link to the full fleet view, and nests the
connector and webhook pages under **Connections & webhooks**. Cluster Management remains
its own administration entry rather than a duplicate configuration tab.
The lab investigation reader token lasts 24 hours; rerun the documented configure
helper to renew it. The smoke-test rule is left inert.

The current SNO application image is
`sha256:40c4f78ed1a1435f213b3f0b3a21aad1e64ad6228fc79f76e6d86fd223fd75be`
with schema head `0023_fleet_incidents`; the runner remains unchanged.

The preceding PodPilot 0.12.0 delegated-sessions rollout deployed to the
disposable SNO lab at schema head `0021_user_delegated_access`. That 2026-09-01 rollout used
application image digest `sha256:02b041afb5824019941cc1e62067dd90748063992f9514106d83c4464fced061`
and runner digest `sha256:fc7c654ea5f3ea9c86b69e698f2640f038aab511d6de360edb4f1742ccaac05e`.
The deployed implementation makes Ask user-delegated for every role, uses a 24-hour local maximum,
supports per-cluster TLS policy and private user-owned registry entries, and removes stored remote
cluster credentials. Successful cluster sign-ins are reused across new conversations for the
browser session. Partial login failures remain retryable without discarding successful connections;
users can append clusters, revoke one sign-in, or clear all sign-ins independently of durable chat history, and an owned
conversation can resume after its required clusters are reconnected.
The Workspace navigation also exposes visible clusters as a sidebar tree with connected and
sign-in-required indicators. A cluster click starts a fresh preselected conversation or routes
through the existing credential form first; the tree's add control opens a dedicated **My clusters**
page for owner-scoped ad hoc entries. Shared registry administration now appears only to
configuration administrators as **Cluster Management** in the Manage section.
The Ask composer keeps the prompt and its cluster, mode, reasoning, raw-response, and submit
controls inside one frame. It starts at two text rows, grows through ten as the operator adds
lines, then scrolls internally; the desktop toolbar stays on one row and Submit matches the
32-pixel control height.
OpenRouter Chat Completions with exact model `openai/gpt-oss-120b`, and the localhost tokenless
`oc-runner` sidecar. It also adds Ask-only
multi-cluster routing, secret-backed cluster
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

- The model-facing metric catalog is reduced to 15 CPU, memory, node-utilization, application-log,
  and Kafka signals. `top_log_volume_by_namespace` again provides the dedicated cluster-level Loki
  namespace ranking, while `application_log_volume` provides scoped namespace and Pod reads from
  aggregate byte counts without reading log lines. Kafka topic disk utilization
  compares replicated topic bytes with the shared allocated broker-PVC capacity. Topic-grouped reads
  now add bounded topic-byte and partition-replica companion evidence, and Ask renders a topic-first
  ranking with expandable partition ID, replica bytes, broker ID, and broker Pod placement. Kafka
  consumer lag remains available. Legacy server-side templates remain readable for persisted evidence
  but are no longer advertised to the model.

- Dynamic answer tables now use a stricter equal-cell prompt contract and bounded display cleanup
  for strict-JSON leakage. Redundant leading `unknown` placeholders and unmatched boundary braces
  are removed while balanced `{}` and OpenShift Logging templates remain literal.

- The pending workload requests an eight-hour projected service-account token for the OAuth client
  and supervises the pinned proxy's startup-only client-secret cache. Token rotation restarts only
  `oauth-proxy`, retaining the API process, SQLite state, and stable OAuth cookie key so later fresh
  browser logins do not fail with `unauthorized_client`.

- The front-door OAuth proxy now uses a fixed eight-hour signed cookie with refresh disabled. The
  pinned OpenShift provider cannot renew access tokens, so the former one-hour refresh only
  revalidated the original token and forced relogin on clusters with a one-hour OAuth token TTL.

- Ask now redirects every authorized role through user-owned cluster connections. Investigator is
  read-only; Read-Write chooses read-only or Action at conversation creation. Configuration
  administration is orthogonal. Cluster Health is removed from active navigation.

- Cluster, model, and curated-memory configuration now share one explicit management boundary:
  only Approver and Breakglass sessions see the **Manage** navigation or may open and modify those
  sections. Investigator, Viewer, and Delegated Operator requests are rejected server-side.

- The delegated-sessions work adds explicit Delegated Operator sessions for users
  outside every configured PodPilot role group. The delegated picker uses the same enabled cluster
  registry as cluster management, including the runtime system cluster. Approvers register additional
  DEV cluster API origins and optional custom CA bundles; users multi-select clusters, complete one-time username/password
  challenge logins, and receive up to 24-hour memory-only delegated sessions. New conversations lock
  their cluster set and execution mode. All agent-selected `oc` requests traverse a random loopback API
  capability whose broker injects the user's token; the runner receives neither that token nor the
  Pod service-account token. Logout, expiry, replacement, disable, and graceful shutdown attempt
  OAuth revocation. Investigator and Action sessions use the same agent loop; Investigator receives
  the read-only proxy capability and Action receives the read-write capability.

- New Ask sessions replace fictional prompt examples with real read-only starter actions. All
  eligible users can start a failing-workload investigation against the selected clusters or open
  a namespace/resource workload troubleshooter; the broad recent-warning starter is omitted to
  avoid placing unprojected cluster-wide Event output into model context. Delegated sessions also
  expose effective-access and visible-project checks. Starters
  use the normal conversation API and stay disabled until cluster, model, and session prerequisites
  are satisfied.

- The Ask orchestration boundary now makes collectors evidence-only. Registered compilers,
  search/watch projections, catalogs, relationship graphs, findings, and
  enrichment packs can expose grounded candidates and native views but cannot force a read,
  continue/stop decision, terminal result, or replacement conclusion. The agent now terminates
  through a structured complete/blocked/budget-exhausted contract, and PodPilot accepts the agent's
  chosen stopping point without semantic deferral detection. Exact same-cluster shell commands require an explicit retry/comparison reason, while
  the evidence sequence remains model-selected. Automatic TLS retries, referenced-ConfigMap reads,
  Pod-log recovery, answer-gap collection, and style-based answer retries have been removed from
  runtime orchestration. The final agent sees bounded raw log evidence directly.
  The generic `list_resources` and `search_resources` helpers are absent from the unified agent
  schema and have no runtime feature flag. Existing resource evidence and low-level object reads
  inside purpose-built typed collectors remain supported. Both delegated modes can enumerate and
  filter with deliberately bounded read-only `oc get` commands and then fetch the exact object
  details required for comparison. The
  broker, not a reduced planner, prevents writes and Secret reads in Investigator mode.
- Agent tool schemas now enumerate selected cluster IDs. Rejected model-formatting attempts receive retry guidance and render
  as collapsed diagnostics instead of unresolved yellow limitations; genuine access, collection,
  and command failures remain visible. Loki transport normalization preserves
  `tls_verification_failed`, timeout, and transport-unavailable categories rather than reporting
  certificate failures as generic gateway downtime.
- Delegated and shared-credential unified-agent conversations expose the same purpose-built HTTP,
  metric, and audit collectors on every model turn. Delegated
  Thanos and Loki reads resolve the current memory-only user
  token per request and stop working immediately after capability revocation; read-only versus
  read-write behavior is enforced by the Kubernetes broker rather than by different tool menus.
- Delegated typed collectors initialize their Kubernetes discovery clients in the worker pool. A
  collector can therefore call the loopback token broker without deadlocking the ASGI event loop or
  starving liveness and readiness probes while an investigation is running.
- Agent prose is preserved after redaction and safe-Markdown normalization. Missing or conflicting
  citations lower evidence status and add limitations instead of erasing the response. Native
  resource tables, metric cards, and dynamic-column answer tables are additive and no longer hide
  prose. Older operator-visible conversation messages remain available through the bounded transcript
  digest after they leave the recent-message window. Recommendation sections and valid audit, access,
  or configuration conclusions are no longer removed or replaced by semantic output guards.
  Flat standalone JSON summaries are transformed into native property/value tables without changing
  their values. Deterministic conclusions remain only as provider/contract-failure fallbacks.

- The delegated agent runtime uses OpenRouter Chat Completions with
  exact model `openai/gpt-oss-120b`. The model can repeatedly call an arbitrary `execute_shell`
  function backed by a localhost `oc-runner` sidecar until it returns a final answer. This bypasses
  typed read/remediation approval inside the explicit agentic mode while retaining the durable run deadline,
  output redaction before provider reuse, progress, and command metadata audit. The SNO and remote
  agentic deployments include the command runner.
- The runner image copies a digest-pinned Linux `oc` binary into the pinned UBI Python runtime. The
  SNO overlay runs it non-root under the existing `podpilot-investigator` Pod service account. The
  deploy helper refuses to proceed if that identity can patch Deployments, builds both images,
  deploys the sidecar, and configures/probes the fixed OpenRouter profile from an environment key
  passed over stdin. The `remote-poc-agentic` overlay reuses the remote PoC,
  promotes a separate versioned runner image, and adds the same shared sidecar without adding RBAC.
  Each Action-mode shell call names one selected cluster. The API brokers only that cluster's
  in-memory delegated user token to the loopback runner, which uses and deletes a per-command
  kubeconfig. Per-cluster TLS policy is honored consistently. Runner/API logs expose redacted
  target, TLS, exit, duration, and byte-count
  metadata, periodic heartbeat logs are suppressed in both containers, failed-command summaries appear in
  Ask, and a 300-second runner deadline terminates the complete shell process group with exit code
  124. The API still publishes changing live Ask progress while the outer run retains
  its 900-second deadline in the agentic overlays. Runner stdout and stderr are now drained
  concurrently with independent 256 KiB retained prefixes, preventing verbose commands from
  exhausting the sidecar through unbounded `communicate()` buffers; completion logs expose true
  byte counts and truncation flags.
  The model-free suite passes locally with 767 tests and 80% aggregate coverage.
  Both images were built in-cluster and the profile capability probe reported `ready`. Live runner
  verification returned the exact `podpilot-investigator` identity, `yes` for reading Pods, and
  `no` for patching Deployments, creating ClusterRoleBindings, and wildcard access.
- Natural-language resource field predicates are now first-class semantic constraints. Collection
  requests such as Route hostnames containing a supplied suffix compile to bounded
  `search_resources` reads instead of whole-kind lists. Terminal completion requires the plan to
  preserve the exact field, operator, and grounded value; otherwise enrichment remains a seed for
  continued agent investigation. Empty searches report absence only with complete scan coverage.
- Cited resource lists now carry a general versioned `grouped_resource_list` presentation built
  from normalized evidence rather than model formatting. Ask renders cluster-grouped collapsible
  tables for every resource Kind, includes retained search-field values and coverage state, and
  offers CSV export while preserving Markdown as a backward-compatible fallback.
- Elliptical resource-list follow-ups now recover a typed prior query from validated evidence.
  Presentation-only requests can reuse and cluster-narrow the prior snapshot without a provider
  call, while `current`/`still`/`now` wording preserves the same filters but performs a fresh read.
  Unique selected-cluster aliases narrow one turn; the locked conversation selection is unchanged.
- Answer-authored Markdown tables now render through a bounded native dynamic-column table component
  with collapse and CSV controls while preserving surrounding prose order. They remain explicitly
  answer-derived and do not inherit the observed-evidence trust level of typed resource cards.
- Thanos remains the preferred metric trend source. Node rankings and namespace-scoped Pod CPU or
  memory rankings now fall back to a current `metrics.k8s.io/v1beta1` snapshot when Thanos fails,
  with the lost history called out explicitly. When every registered read and shell verification
  fails, normal code reports the exact failures and suppresses unsupported model explanations such
  as claiming a metrics add-on is absent.
- Recognized Kafka topic-storage questions now fail closed on the registered Strimzi JMX/Thanos
  path. If that authoritative read fails, the delegated workflow renders the collection limitation
  directly instead of attempting broker Pod exec or recommending broader `pods/exec` RBAC.
- Namespace-scoped Kafka topic-storage wording now discovers exact Strimzi Kafka CRs in the named
  namespace and fans out one registered storage query per observed CR, grouped by topic. The path
  bypasses fragile metric classification, renders successful results directly, and preserves empty,
  denied, or partially unavailable states without entering the delegated command loop.
- An empty delegated model turn now receives one tool-free finalization request. If that request
  is also empty, PodPilot reports an invalid agent response rather than mislabeling it as provider
  unavailability.
- Imperative Kafka deployment inventory wording now routes to the registered Strimzi Kafka reader.
  “Show/list all deployed Kafka clusters” runs once per selected OpenShift cluster and renders
  found, empty, and unavailable API states with complete coverage accounting instead of repeatedly
  guessing resource names through `oc-runner` on the first cluster.
- Remote Thanos and LokiStack authorization failures now preserve the literal `HTTP 403` status in
  per-cluster Ask limitations and name the relevant read-only role. Log-volume queries correctly
  identify `cluster-logging-application-view`; Thanos metrics identify `cluster-monitoring-view`.
- Successful terminal registered enrichments now render once and suppress a competing delegated
  shell call. Audit queries preserve explicit resource scope in addition to namespace, operation,
  outcome, username, and time range; an all-user Pod deletion query no longer shows an appended
  `events.audit.k8s.io` RBAC failure or the misleading phrase “the supplied user.”
- Explicit audit counts and filters are now authoritative after classification. “Last 5” no longer
  expands to the default 20 when the model omits `result_limit`; delete/mutation scope and
  successful/failed outcome wording likewise override broader model defaults before Loki access.
- Unnumbered “recent” audit requests now query only the initial bounded window instead of repeatedly
  widening toward the audit ceiling to fill a model/default limit. Explicit “last N” requests retain
  bounded backward expansion until N matches are found.
- Registered Loki audit reads now fail closed in the delegated workflow. A timeout, denial, or partial
  multi-cluster result is rendered directly instead of falling through to an invalid
  `events.audit.k8s.io`/`jq` shell attempt.
- Elliptical metric-period follow-ups now reuse the latest registered top CPU, top memory, or
  namespace log-volume ranking. The original scope and top-N are retained while only the range is
  replaced, so a three-day log-volume follow-up remains on the Loki adapter instead of attempting
  `pods/exec` or `logcli`. The shipped log-analytics range ceiling is now seven days, allowing the
  requested three-day window while retaining a bounded server-owned LogQL query.
- Delegated Chat Completions finalization tolerates one empty assistant turn after tool use. The
  API logs the anomaly, sends one corrective request using the existing tool results, and then
  either persists the recovered answer or fails explicitly after a second empty turn. It does not
  automatically repeat completed shell commands.

- Some Chat Completions providers occasionally serialize valid `finish_investigation` arguments in
  assistant content instead of returning a native tool call. The unified agent now validates that
  exact completion envelope and persists only its operator-facing Markdown `answer`; malformed
  envelopes remain rejected model output and enter the bounded finalization retry.

- Failed exploratory shell reads no longer render their raw stderr as a stack of answer
  limitations. Ask groups them by cluster and failure category in a collapsed **Exploratory
  checks** disclosure. Command bodies and diagnostic references remain in persisted activity and
  audit records, while redacted stderr remains in server logs. This also prevents delegated-proxy
  HTML error pages from leaking into the answer surface. When the agent stops blocked or exhausts
  its budget, the grouped failures also remain visible as answer limitations.

- Explicit namespace log-volume ranking questions now repair model-invented log metric names at
  the typed collector boundary and route them to `top_log_volume_by_namespace`. This preserves the
  agent-owned investigation sequence while preventing Pod-count approximations when the registered
  aggregate Loki reader is available.

- Ask PodPilot cluster registry with Approver/Breakglass management, plain-text label and key/value
  tags, connection testing, soft disable, a dedicated resourceName-restricted cluster
  credential Secret, default-on TLS verification, and an explicit visible/audited
  per-cluster insecure exception. The runtime cluster is registered automatically and its
  persisted display name and tags can be changed without modifying its deployment-managed
  identity or connection.
- New Ask conversations select one to ten clusters through a searchable picker. The
  immutable selection is retained in history; changing it starts another conversation.
  The picker defaults to a Signed-In tab and offers All for clusters that still need authentication;
  text search composes with either filter. Generic new-chat links start with an empty selection and
  keep Submit disabled until the user chooses at least one cluster; a sidebar cluster-name link
  remains an explicit single-cluster preselection.
- Delegated Ask exposes the existing policy-filtered Kubernetes discovery catalog as a
  delegated typed tool. The agent is directed to search it before guessing unfamiliar CRD names or
  after a NoMatch error; deterministic matching recognizes compound fragments such as
  `logforwarder` while returning only exact, discovered API coordinates. Discovery remains
  session-user scoped and does not imply object authorization.
- Answer-derived table cells now normalize model-authored HTML break variants, including breaks
  accidentally wrapped in inline-code spans, without enabling raw HTML. This keeps multi-line
  summaries readable while every other tag remains escaped by the Markdown trust boundary.
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
- Standalone Ask now supports a model-directed loop of ten planning rounds within 50 weighted
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
  Up to ten schema-validated planning rounds spend at most 50 weighted units on adaptive
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
- Closed-form inventory turns (explicit identifiers-only, count, existence, or prior-snapshot
  presentation) finish through the deterministic renderer without a general final-model
  answer/correction pass or unrelated suggested checks. Bare show/list requests for
  configuration-bearing resources now retain their normalized observed-resource card and continue
  into agent interpretation. The classifier records the requested answer goal, and normal code
  defaults uncertain inventory goals to non-terminal so collection completeness cannot masquerade as
  answer completeness. Multi-cluster summaries report matches as “X of Y queried clusters,” and
  absent Ready conditions display as `Unknown` rather than implying that a discovered custom resource
  is running.
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
  response rather than conversation metadata. Deletion also removes queued runs and
  cancels a running in-process investigation so a stuck session never blocks its owner.
  The content-free deletion audit records only how many active runs were cancelled.
  Questions are unlimited per
  conversation: the model receives the ten most recent messages plus a bounded
  deterministic digest of earlier messages. Per-question collection remains
  bounded to 50 weighted investigation units, and each user is throttled to ten questions per minute.
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
- The Ask composer keeps its question label above one shared prompt frame. Cluster, execution-mode,
  reasoning, raw-response, and Submit/Cancel controls occupy the frame's bottom toolbar; the former
  per-question budget and keyboard-hint row is no longer rendered.
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
- Dedicated Pod-log analysis now requires every mentioned anomaly to include a structured issue and
  an exact quoted passage from cited evidence. Validated excerpts render as visible text blocks;
  unsupported overview-only clues are withheld instead of being followed by a contradictory
  “no issue identified” message. Empty issue lists require an explicitly clean overview, so vague
  phrases such as “problem patterns” cannot bypass the excerpt requirement. Diagnostic final-answer
  guidance also treats `Ready=false` as a symptom rather than a causal explanation.
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
- Exact named-Pod failure questions now retain their operator-grounded namespace/name even when the
  capability classifier returns generic investigation semantics. They begin with one exact Pod GET,
  offer only bounded logs for observed containers and an exact `involvedObject.name` Event search,
  and never promote a diagnostic 20-object catalog sample to the 500-object inventory ceiling.
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
- Ask PodPilot opens the bounded conversation viewport at the newest response. The conversation now uses
  the same navigation width, page-title typography, spacing rhythm, elevated surfaces, and semantic form
  treatment as the cluster sign-in workflow. User prompts and assistant replies are contained in readable
  conversation surfaces instead of the previous full-width flat transcript, while the activity sidebar
  remains available for operators to hide or restore from the
  conversation header. The header actions stay anchored to the evidence divider when the rail is open and
  to the page edge when it is closed. The shared navigation has no Ask-route typography, spacing, brand,
  active-state, subtree, or identity overrides, so it remains visually identical while moving among chats,
  cluster sign-in, and management pages; that browser preference persists across conversations and reloads. The original
  blue-black PodPilot palette is the default, with persistent Dark and Light alternatives available
  from the shared sidebar on every page. Shared canvas, panel, navigation, input, menu, button, notice,
  code, dialog, evidence, resource-result, and answer-table colors resolve through the same semantic theme tokens.
  The activity rail is timeline-only, and each full operation row opens its retained details. Completed agent operations retain
  start/stop timestamps, duration, cluster, status, bounded request/result detail, and a visible filtering
  indicator whenever credential redaction or output reduction occurred.
  Chat messages render safe CommonMark with readable system prose typography,
  distinct monospace code, and styled tables; raw HTML remains escaped and unsafe
  link schemes are not activated.
- Delegated agent shell calls no longer require `repeat_reason` and are not de-duplicated by PodPilot.
  The model may poll or re-run an observation as needed within the existing action budget and deadlines;
  broker authorization and cluster RBAC remain authoritative. Ledger rows expose runner execution,
  safe failure categories, errors, and diagnostic references. A provider failure after completed agent
  work preserves the activity and reports completed, non-rolled-back writes instead of claiming that no
  cluster changes were attempted.
- The application runs as `ai-ops/podpilot-investigator`, bound only to the custom
  `podpilot-role-reader` for OpenShift Group lookup plus explicit supporting platform views.
  It has no `cluster-reader` binding. The separate `ai-observer` identity retains cluster-admin
  only as disposable-lab development and break-glass access.
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

- Deployed application version: `0.12.0`; current source version: `0.12.0`.
- OpenShift lab version: `4.22.9` on the documented Hyper-V SNO.
- Deployment: `ai-ops/podpilot`, last observed `1/1` Available with the API, OAuth proxy, and
  `oc-runner` containers ready.
- Local automated suite: 636 tests passing with 82% aggregate coverage.
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

- The normal runtime is `podpilot-investigator` with `podpilot-role-reader`, not
  `cluster-reader`. Ask Pod-log, ConfigMap, and other Kubernetes reads use delegated-user
  broker capabilities. `ai-observer` has cluster-admin only through the explicit
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
- Model connection testing treats workflow-schema checks as an informational compatibility smoke
  test rather than a synthetic quality benchmark. It no longer grades inquiry classification,
  grounded action choice, or citations, and a workflow-smoke failure does not degrade an otherwise
  ready profile or display a persistent warning in Ask. Runtime typed validation and deterministic
  fallback remain authoritative during real conversations.
- Ask no longer shows reduced-capability warnings for usable profiles; detailed connection-test
  status remains on Model settings. Operator messages now default to the supported 4,000-character
  ceiling, including the OpenShift runtime configuration.
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
- Registered domain packs now cover Strimzi Kafka topic throughput/storage/lag/replication health,
  OpenShift router traffic, MachineConfigPool rollout state, HPA/workload availability, PVC
  byte/inode pressure, ClusterOperator conditions, API server/scheduler/etcd health, Prometheus and
  Alertmanager self-health, and LokiStack ingestion/query health. Kubernetes API
  discovery still does not prove that the corresponding exporter is scraped, so empty results name
  the required telemetry profile rather than reporting a zero value.
- Elliptical metric follow-ups can select opaque recent object or relationship references. The
  server rebinds those IDs to trusted exact coordinates, rejects cross-Kind and ungrounded targets,
  and retries explicit utilization/throughput/lag questions that were misclassified as inventory.
- Unknown CRDs continue through live discovery, bounded redacted object/status reads, and opaque
  evidence-derived relationship traversal. They require an explicit reviewed metric profile before
  they can become telemetry targets; the model cannot invent a series from the CRD Kind.
- The model-free suite passes locally with 578 tests and 83% aggregate coverage. These capability
  packs have not yet been rolled out to the SNO workload or validated against its live metric-label
  profile.

## 2026-08-28 Stable live-investigation phases

- The active Ask placeholder groups progress into phase sections in chronological order.
- New phases append without reordering existing headings. Each phase displays its latest three
  updates, and reloads reconstruct the same bounded phase view from persisted progress.
- This UI behavior is locally implemented and has not yet been rolled out to the SNO workload.

## 2026-08-28 Deterministic resource health summaries

- Cluster-wide and namespace-scoped Pod health/crash questions compile to a typed
  `pod_health_summary` read even when model classification selects generic object fields.
- The read scans bounded Pod pages, evaluates current Pod plus primary/init container
  state in normal code, and retains anomaly-first compact evidence with counts by reason and
  severity. A `Running`-phase Pod with a `CrashLoopBackOff` container is detected.
- Scan coverage and returned anomaly detail have independent ceilings. Deterministic answer
  rendering confirms absence only for a complete scan and otherwise reports the result unresolved.
- Typed summaries now also cover Nodes, ClusterOperators, Machines, and Deployment/StatefulSet/
  DaemonSet controllers. Nodes and ClusterOperators are cluster-scoped; Machines and workload
  controllers support namespace filters. Each uses reviewed resource-specific conditions or
  lifecycle fields rather than a generic status rule.
- Missing OpenShift Machine or ClusterOperator APIs are unresolved coverage, not an empty healthy
  result. Combined workload scans report per-kind coverage.
- This capability is locally implemented and has not yet been rolled out to the SNO workload.

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
  remain non-streaming. Curated memory is retrieved into delegated-agent context as bounded
  untrusted guidance; it does not enter investigation-chat or
  remediation prompts.
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

1. Add a server-validated knowledge citation contract without allowing memory to authorize tools,
   actions, or current-state claims.
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
