# Model runtime policy

Model settings is the source of truth for a profile's total context window,
maximum input, maximum output, protocol reserve, timeout and retries. Every workflow
using that profile inherits these settings. Maximum output is an allowance, not a
requested answer length; reasoning consumes the same allowance. There are no
smaller implicit Incident coordinator or specialist output caps.

Effective input is `min(maximum input, total window - maximum output - reserve)`.
For a 64,000-token endpoint, 45,952 input, 16,000 output and a 2,048-token reserve
fit the configured window. Input counts are estimates. Configure the actual deployed
window rather than the model family's advertised maximum. Both API adapters enforce
the budget before transmission, including retry requests and tool/schema overhead.

## Incident controls

Expand **Incident collection and execution limits** on the model form. Values are
validated, persisted per profile, and included in the model-save audit event.
New runs capture the active profile's policy; edits do not alter an in-flight run.
The worker checks the active profile's concurrency when claiming new work.

| Control | Default |
| --- | --- |
| Concurrent investigations / log specialists | 3 / 3 |
| Investigation / connector-enrichment deadline | 2,700 / 300 seconds |
| Coordinator turns / collectors per turn | 10 / 3 |
| Specialist calls per investigation | 100 |
| Input share reserved for evidence | 70% |
| Retained evidence per run | 16 MiB |
| Projected collection / API response per page | 8 MiB / 2 MiB |
| API page size / read deadline | 60 objects / 15 seconds |
| Namespace ceiling | 0: all discovered namespaces within other budgets |
| Kubernetes logs | 1,000 lines, 96 KiB, 2 hours |
| Loki history | 2,000 lines, 96 KiB, 6 hours |
| Loki history lead before alert | 30 minutes |
| Deployment-change lookback before alert | 2 hours |
| Metrics | 100 series, 30 minutes, 60-second steps |
| Warning-event lookback | 2 hours |

Page size is a transport setting, not a collection-count ceiling. Collectors follow
continuations, preserve allowlisted fields, and report byte/deadline/API failures.
Healthy objects are excluded from the exception survey; unhealthy objects have no
fixed count cap. Source evidence is kept separately from model context. Large
collections and log streams are partitioned for specialists with source IDs intact.
Coordinator summarization reduces accumulated input; final structural compaction
may omit records if the configured input or specialist budget still cannot fit them.
Those limitations remain explicit. Retention and deadlines still bound total work.

The API response limit applies before projection. Raise it for unusually large
individual Kubernetes objects or direct Argo CD responses. Redaction, exact-target
authorization, webhook admission limits, GET-only collection and mutation approval
requirements remain security/contract boundaries. They are not model tuning controls.
Ask retains its separate collection policy; Incident policy never changes Ask's
payload, inventory or detail-fanout limits.

## Upgrade

Apply Alembic migration `0027_model_runtime_policy` before starting the updated app.
Existing profiles retain their configured input/output values and receive a
64,000-token total window, 2,048-token reserve and default Incident policy. Review
the new form for endpoints with different windows. If an existing output allowance
leaves no input space, requests fail locally until corrected; new saves require at
least 1,024 input tokens after reserves. Older form clients which omit new fields
preserve the saved policy.

The former `PODPILOT_INCIDENT_*` token, evidence, log, turn, timeout and worker
concurrency overrides are retired. Manifests no longer supply them. Feature enablement,
worker enablement and credential Secret location remain deployment configuration.
Custom values previously supplied by environment must be entered on the model form.
No credentials are moved into profile policy or returned to the browser.

## Validation for this change

The full model-free suite passed with 77% coverage. Focused Incident, policy,
collector, migration and model-form tests also pass after the final changes.
Server-side dry-run of `deploy/openshift/overlays/sno-incident-response` passed on
2026-09-07 using the external bootstrap path documented in operations. No live
deployment or model profile was changed.
