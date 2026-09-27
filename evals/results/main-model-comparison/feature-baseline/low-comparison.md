# LOW reasoning model comparison — 2026-09-27

Build 191, branch `codex/read-only-oc-tools`. The same nine questions in
`scripts/oc-tools-live-eval.py` ran once per model against the same synthetic
fixtures, with two concurrent investigations and no application redeployment.
The active profile is now OpenRouter `openai/gpt-5.6-sol`, default reasoning LOW.

## Reasoning-setting correction

The earlier `build191/` reports used MEDIUM: the harness explicitly overrode
the OSS profile's LOW default. They are not the baseline for this comparison.
Both models were rerun explicitly at LOW. All 18 persisted AdHocRun records
confirm LOW (`low-run-settings.json`). Both profiles use a 64,000-token context
window, 16,384 output tokens, 131,072 configured maximum input tokens and a
180-second provider timeout. Public configuration snapshots are in
`low-profile-settings.json`; no credentials are captured. LOW is now the harness
default and can be selected explicitly with `--reasoning-effort low`.

## Results

Manual scoring against independent cluster observations and each run's evidence
ledger: pass means the requested core coverage and conclusions are supported;
partial means useful coverage with a material error or omission; fail means a
wrong core diagnosis, fabricated evidence, major missing coverage, or no answer.
Minor wording issues are noted without turning correct permission results into
failures. Successful execution/rendering is not answer-quality success.

| Measure | OSS 120B LOW | GPT-5.6 Sol LOW |
|---|---:|---:|
| Pass | 2/9 (22%) | 6/9 (67%) |
| Partial | 2/9 | 1/9 |
| Fail | 5/9 | 2/9 |
| Median case duration, including failed answers | 86.1 s | 76.0 s |
| Recorded tool operations | 51 | 157 |
| Shell calls / write operations | 0 / 0 | 0 / 0 |

This is a 44-percentage-point increase in strict passes on this small suite,
not an estimate of general production reliability. Live metrics, event ages and
restart counts can change between sequential batches; usage answers were checked
against their own collected samples. No retries replaced failed cases.

| Scenario | OSS LOW | Sol LOW |
|---|---|---|
| Fixture diagnosis | **Fail.** Lists all five, but assigns web-c the wrong selector cause, misses web-d's ConfigMap typo and the destination ingress policy; some Events requests use the wrong namespace `podpilot_test`. | **Partial.** Finds all five causes and proposes relevant fixes, but incorrectly reports web-c CPU limit as `100m`; the actual request and limit are both `100` cores. |
| Pod inventory | **Partial.** Includes all five Pods and Deployments with replica counts, but puts Unschedulable in the container-waiting column and describes CrashLoopBackOff as a Pod phase. | **Fail.** Repeats the same narrow reads; after 36 successful reads the answer is a provider APIConnectionError fallback, not an inventory. |
| Kafka | **Partial.** Finds installation and topology, but leaves topic/Pod names incomplete, claims a NodePool Ready condition without support and overstates empty/unread Events. | **Pass.** Names all four topics and three Pods, correctly reports topology, readiness and historical restart counts; recovers from an invalid logs call and explicitly identifies the later log-specialist analysis gap. |
| Utilization | **Pass.** All observed node/Pod values match; distinguishes snapshot usage from requests, limits and history. | **Pass.** Accurate node/Pod values, units and bounded snapshot interpretation. |
| Schema / scheduling | **Fail.** Only calls oc_explain; claims workload/event observations without reading the actual specs. | **Pass.** Reads actual specs and scheduling evidence; correctly identifies web-a's selector and web-c's 100-core request and limit. |
| Permissions | **Pass.** All four yes results match; minor prose incorrectly calls patch permission a read-only action. No patch is attempted. | **Pass.** All four checks match and the answer clearly distinguishes authorization review from writing. |
| Other Kinds | **Fail.** Skips three test2 kind reads and invents their absence, including the existing deny-ingress NetworkPolicy. | **Pass.** Covers all five kinds in both namespaces, exact Service/EndpointSlice relationships and all policies; makes justified absence statements. |
| Network | **Fail.** Wrong container name causes log failures; label-filtered empty Service/policy lists are mistaken for namespace-wide absence; cites an HTTP probe that never ran and invents DNS failure. | **Pass.** Verifies Service, endpoint, readiness, logs, policy and actual HTTP timeout; identifies the probe origin and proposes a scoped allow rule. |
| API discovery | **Fail.** Invents Argo resource names/scopes and treats a successful empty maistra.io query as proof that the group exists. | **Fail.** Finds actual Istio groups but repeats discovery reads until the input budget is exhausted; returns no complete requested API inventory. |

## Remaining issues exposed by the experiment

Sol is substantially better at gathering and interpreting the required evidence,
but switching models does not solve repeated-read loops or evidence retention.
Its API-discovery run made 35 operations, including 23 repeated namespaced Argo
and Kafka API queries. Its inventory run made 36 reads, largely alternating the
same Pod and Deployment projections. Those two cases account for 71 operations.
The connection failure's underlying cause has not been established; repeated
reads are observed behavior, not proof that they caused that connection error.

Recommended follow-up: inspect the tool-result/context handoff and repeated-call
handling, then prevent identical successful reads from consuming the entire
budget and preserve the compact results needed for finalization. Keep the
single incorrect CPU limit in the diagnosis as a factual regression case.
No prompt, runtime or tool behavior was changed during the comparison.

All seven new oc tools were exercised across both batches. Pod health and HTTP
probe remained available. Every saved page rendered HTTP 200, yet both of Sol's
fallback answers had run status `succeeded`; evaluators must inspect answer
content rather than using that status as the success metric.

Final verification: GPT-5.6 Sol profile ready and active at LOW; all 18 run settings
LOW; no queued/running evaluation remains; PodPilot Deployment 1/1 available.
The synthetic failure fixtures remain in place. Raw redacted case reports and
ledger evidence are in `oss120b-low/` and `gpt56-sol-low/`; machine-readable scores
and timings are in `low-comparison.json`.
