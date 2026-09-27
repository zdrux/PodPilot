# Main versus oc-tool experiment, both models at LOW

Date: 2026-09-27. Main commit: `462f10b1b4e0914b81a74e3712e816478fd99d0e`.
Main was built and deployed as `podpilot-192`; API and migrate use
`sha256:7d687afa45d8021d47bf750e43dcbbee16e87a9df27cec8057a702ab05032738`.

## Outcome

GPT-5.6 Sol on main gave the strongest results in this single nine-case sample.
The two feature-branch non-answers (inventory and API discovery) both completed
correctly on main. Main also avoided the incorrect CPU limit in Sol's broad
fixture diagnosis. Kafka presentation was less complete on main than on the
feature branch.

| Implementation | Model, LOW | Pass | Partial | Fail | Strict pass rate | Median case time | Tool operations |
|---|---|---:|---:|---:|---:|---:|---:|
| Feature branch, build 191 | OSS 120B | 2 | 2 | 5 | 22% | 86.1 s | 51 |
| Main, build 192 | OSS 120B | 3 | 2 | 4 | 33% | 56.1 s | 30 |
| Feature branch, build 191 | GPT-5.6 Sol | 6 | 1 | 2 | 67% | 76.0 s | 157 |
| Main, build 192 | GPT-5.6 Sol | 8 | 1 | 0 | 89% | 31.0 s | 38 |

Tool-operation counts are API/tool invocations, not counts of underlying cluster
requests: one shell call on main can batch multiple commands and project results
with jq. The smaller number is not directly a measure of Kubernetes API traffic.
All recorded cluster operations were reads; main used 24 shell calls for OSS and
31 for Sol, while the feature branch used no shell calls. Neither main batch made
cluster writes. Fixture Deployment generations remained 1.

## Method and limits

- Same nine scenario objectives, synthetic fixtures, delegated test identity,
  two-conversation concurrency and LOW reasoning for each model. All 18 new
  persisted run records confirm LOW. No failed case was replaced by a retry.
- Main has no oc_* tools. Five questions changed only the tool name to its CLI
  equivalent: oc_get → oc get; oc_top → oc adm top; oc_explain → oc explain;
  oc_can_i → oc auth can-i; oc_api_resources → oc api-resources. The other four
  questions are identical. Exact questions and all redacted answers are retained.
- Same configured model budgets as the feature comparison: 64k context, 16,384
  output tokens, 131,072 maximum input tokens and 180-second provider timeout.
- This compares the complete main and feature implementations, including the
  feature branch's required-tool/finalization changes. It does not isolate the
  causal effect of oc_* tools alone.
- One run per case/model, sequential batches, no randomized ordering. These
  percentages describe this suite, not production reliability or statistical
  significance. Live usage and restart counts vary; numeric answers were checked
  against their own observations. Independent stable fixture/API observations
  are in ground-truth.json.
- Pass means requested core coverage and conclusions are supported. Partial
  means useful coverage with a material error or omission. Fail includes wrong
  core diagnosis, fabricated evidence, major missing coverage, or no final answer.
  Minor wording/presentation issues are noted separately. All new runs reported
  succeeded and pages rendered HTTP 200; those statuses are not quality scores.

## Per-case review on main

| Scenario | OSS 120B LOW | GPT-5.6 Sol LOW |
|---|---|---|
| Fixture diagnosis | **Fail.** Identifies symptoms but misses selector/PVC/ConfigMap/network causes, incorrectly groups web-a and web-b under resource scarcity and infers stopping events as explanations for unscheduled Pods. | **Pass.** Finds all five distinct causes, correct 100-core request and limit, exact missing claim/ConfigMap, destination ingress denial, and proposed scoped fixes. Also recognizes WaitForFirstConsumer on the existing PVC. |
| Pod inventory | **Pass.** All five Pod phases/waiting reasons and five Deployment replica counts covered; explains omitted ready/available fields as no ready replicas. Minor presentation defect: adds an inapplicable desired-replica cell to Pod rows. | **Pass.** Two compact reads; exact five Pods and Deployments, zero-normalized replica counters, clear phase/waiting distinction. network-client had no waiting state during those samples; the answer accurately reports that transient observation. |
| Kafka | **Fail.** Invents a broker Pod name and sidecar layout, omits two topics and misstates listener details; broad installation detection is correct but the actual inventory is not. | **Partial.** Correct cluster, topology, four topics, operator availability and current Pod health. Does not name both supporting Pods exactly or report the exporter's 45 restarts, despite the request for names and observed issues. |
| Utilization | **Partial.** Node/Pod values match, but claims approximately 14:10 UTC when collection was 17:59 UTC; also converts 21792 Mi to 21.8 GiB incorrectly. | **Pass.** Values, units and 18:04:26–27 UTC collection interval match; distinguishes sampled usage from requests/limits/history. |
| Schema / scheduling | **Fail.** Claims web-a has no selector/resources and calls web-c's 100 CPUs 100 millicores, leading to wrong causal conclusions. | **Pass.** Actual specs and scheduling evidence support both causes. Recovers from one failed JSONPath command. |
| Permissions | **Pass.** Four correct yes results; no writes. | **Pass.** Four correct yes results; no writes. |
| Other Kinds | **Pass.** All requested object names and Service/EndpointSlice relationships, with explicit absent kinds and disclosed policy-rule inspection gap. Minor caveats: incorrectly suggests normal list RBAC silently hides individual objects; ready endpoints alone do not prove traffic flows. | **Pass.** Complete names, endpoints, rules and absence coverage; recovers from an invalid core-resource alias and discloses it. |
| Network | **Partial.** Correct deny-ingress cause and evidence. Incorrectly expects an ai-ops-origin HTTP probe to succeed after permitting only podpilot-test; also overstates DNS resolution as resolving to the Pod IP. | **Pass.** Correct evidence, actual HTTP timeout, probe-origin limitation and scoped namespace-plus-Pod selector proposal; no false promise about ai-ops reachability. |
| API discovery | **Fail.** Only broad output is read; does not inventory kafka.strimzi.io or the main Istio groups, mixes groups/kinds and incorrectly says cluster scope means a single instance. | **Pass.** Complete Kafka/Argo/Istio resource tables with preferred API versions and namespaced scope, including cluster-scoped Argo and Sail resources; correctly separates API availability from application health. |

Feature-branch case scores and explanations are preserved in
feature-baseline/low-comparison.md and its redacted case reports.

## Delivery and final state

The feature-branch changes, including untracked files and earlier results, were
preserved with `git stash push --include-untracked` under:
`On codex/read-only-oc-tools: Preserve read-only oc experiment and LOW model evaluations before main comparison`.
The working branch is main; the stash has not been applied or dropped. No
application source was changed for this comparison.

Build 192 completed; the image update passed server-side dry-run and rollout.
Alembic is at `0030_requester_write_approval (head)`. Live/ready health and
authorized model settings return HTTP 200. API and migrate are pinned to the same
main digest. The final active profile is GPT-5.6 Sol, ready, default LOW, with no
queued/running evaluations. See verification.json.

The main regression suite has one pre-existing failure:
`test_shell_assets_use_current_content_fingerprint` omits compact.css from its
expected hash. The corresponding correction exists in the preserved feature
changes. It was deliberately not applied to main during this comparison.

To repeat a batch after connecting with scripts/connect-sno.ps1 and selecting the
intended ready model profile, run the saved harness with --reasoning-effort low
and a new --output directory. Results remain uncommitted.
