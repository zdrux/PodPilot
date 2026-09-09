# Reliability follow-up review

Status: reviewed, 2026-09-09. The original 32-run development baseline is
preserved in `../enterprise/`. These follow-up results use explicit evaluation
kinds; component/model replay is not counted as a full chat investigation.

## Live chat investigations

| Scenario | Independent assessment |
|---|---|
| Pod name reuse (`6480978f87a6`) | Correct old/new UID separation, current HTTP 200, no current repair. Old termination cause remains unknown to the investigator. Response is overly long about hypothetical redesign, but keeps it conditional. |
| GitOps image regression (`3ef34c1d0efa`) | Correct exact commit/diff, preserved old healthy replica, and recovered source-server history. Incorrectly required a new Pod UID for rollback; prompt corrected and recovery verified in final run `61c1bc26f45d`. |
| GitOps replica drift (`84811f802021`) | Correct one-to-two drift after manual sync, healthy workload vs OutOfSync, and unknown writer/capacity intent. Proposes scoped sync without prune, with conditional capacity restoration. |
| Argo invalid-path rollback (`809dcdeef64f`) | Resolved: unrenderable source cannot prune; intended path and valid rollback state remain prerequisites. |
| Authorized readiness repair (`82b3c0945b6c`) | Actual command tests UID, resourceVersion, container name and old path atomically. HTTP 200 before/after, generation and independent replica/path checks passed. |

## Adapter and evidence-only model checks

| Scenario | Independent assessment |
|---|---|
| Denied discovery (`8d68b836f583`) | Rerun confirmed identity through SelfSubjectReview and a real 403. No absence claim. Namespace-role advice does not enable cluster-wide inventory; final run `83db1f88586d` verified explicit scope metadata. |
| Metrics unavailable (`0bf0fc1f0c21`) | Actual connection failure against isolated test adapter; no fake zero series. Sol preserved uncertainty and did not prescribe workload changes. Shared Thanos was untouched. |
| Historical Loki gap (`e759aef712f4`) | Actual successful empty query for a bounded window older than configured one-day retention and fixture creation. Sol did not infer health or prove retention caused absence. This does not simulate previously ingested records being deleted. |

## Iteration findings

- Fixed a discovery deadline path that reported an empty successful read when
  its budget expired before the first list. Added a deterministic regression.
- Discovery checks now retain API version, requested list operation, scope and
  HTTP status so missing access can be investigated precisely.
- Restricted test identity must disable the copied in-cluster token refresh hook;
  otherwise it overwrites the supplied credential. This was a fixture defect.
- Quota status must initialize before creating a direct Pod. The first name-reuse
  fixture was rejected safely and cleaned up before its rerun.
- The temporary Git server initially used the base HTTP handler and returned 501.
  It was corrected to SimpleHTTPRequestHandler; the initial comparison failure
  is preserved as historical evidence and a healthy sync was established before
  injecting the actual image fault.
- Two component fixture startup attempts failed before execution because the
  remote entrypoint extraction split at an embedded string. These are retained
  as unscored setup attempts, not investigation failures or passes.

Validation: 910 model-free tests passed, including the new Git source isolation
and discovery-deadline checks. Development approval bypass remains enabled.


Build 165 is deployed. Final reruns add independent GitOps reconciliation and
functional checks after read-only investigations, explicitly recording whether
the original healthy Pod was reused. The Action harness now compares the whole
Deployment spec to prove that only the authorized readiness path changed.


### Verified GitOps image recovery on build 165

Run `61c1bc26f45d` corrected the earlier new-Pod verification requirement. The
answer explicitly permits the existing healthy ReplicaSet/Pod. After the
read-only answer, the independent fixture harness reconciled the recorded good
Git SHA, observed Synced/Healthy and one available replica at the correct image,
and received HTTP 200 from the serving Pod. Its UID was unchanged: the healthy
Pod was reused. This recovery was performed by the fixture harness, not by the
read-only model conversation.

Final denied-discovery replay `83db1f88586d` confirmed server identity and HTTP
403 with API version, list operation and cluster/all-namespace scope. The model
kept the result inconclusive and proposed a separate scoped diagnostic snapshot.
Those permission details also rendered successfully in cluster details.

## Final build-165 results

- GitOps drift `b744c83692f8`: correct healthy/OutOfSync distinction and unresolved
  capacity intent. Independent harness reconciled the known intended replica
  count to one, Synced/Healthy and HTTP 200, reusing a healthy Pod.
- Action `d2ecc6043a21`: atomic UID/resourceVersion/old-value tests preceded the
  PATCH. Independent whole-spec comparison confirmed only the requested readiness
  path changed. Reconciled generation, one ready replica and HTTP 200 passed.
- Metrics `0ab87973e6b1` and Loki `5255038c31fd`: actual failed Pod state and
  UID-matched Events were correlated with unavailable metrics or an empty old
  logging window. Both diagnosed exit 17/CrashLoopBackOff, bounded the timeline,
  and kept ownership/intent/known-good configuration as repair prerequisites.
  These evidence-only replays record the deployed remediation-policy hash.
  Earlier generic-prompt replays remain partial, not silently upgraded to passes.

Eight new full chat runs bring the total to 40 across 28 distinct scenarios.
The three adapter failure types are additional component/model coverage; full
chat tool-selection coverage for them remains future work. The historical Loki
check does not prove retention deletion of previously ingested records.

All eight delegated broker audits were reviewed: no Secret requests and no
read-only writes or privileged operations. Each of two Action runs accepted one
PATCH to its own subject Deployment. Exec attempts returned HTTP 400; typed HTTP
probes succeeded as fallback. Broker audit coverage does not replace the retained
non-broker tool ledger. GitOps recovery writes were independent harness actions.

Final verification confirmed build 165 available, migration 0028, approval bypass
still enabled, real Thanos/Loki queries, audit pagination, ready lab dependencies,
original model profile 2 restored, and zero owned fixture namespaces/Argo objects.
Inventory remains explicitly partial, not an assertion of complete discovery.
The model-free suite passed 910 tests; the affected API suite passed 341 tests.

The new remediation rules are prompt policy, not a generalized machine-enforced
plan engine. Conditional plans deliberately leave missing intent/source access
unresolved. See `../enterprise-followup-verification.json` for final state.
