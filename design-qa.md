# Investigation Ledger Design QA

## Visual target

- Reference: `C:\Users\zdrux\.codex\generated_images\01a07788-d19b-7191-ae43-bcbee7ba979f\exec-599a45f3-764c-48b8-b0ab-0d73c1bebf3d.png`
- Implementation capture: `C:\Users\zdrux\Desktop\projects\PodPilot\.data\incident-ledger-implementation.jpg`
- Comparison viewport: 1536 × 1024, Classic theme, Investigation 1 selected, E7 expanded

## Comparison result

The implemented report preserves the selected visual direction: a compact incident header, summary strip, model-authored findings and hypotheses, expandable evidence ledger, recommendation-only operator next steps, and investigation activity. It uses the existing PodPilot shell, typography, theme tokens, navigation, evidence dialogs, and live controls rather than introducing a parallel design system.

Intentional differences from the generated reference:

- The existing 256 px application sidebar is retained to avoid a navigation-width jump on one page.
- The evidence expansion displays the retained JSON payload instead of a shortened illustrative excerpt.
- The unsupported overflow menu and execution-state claims were omitted. The page exposes only implemented rerun, Ask continuation, evidence, recommendation, and investigation-activity capabilities.
- Narrative findings, hypotheses, and next steps remain model-authored prose because the backend does not expose them as typed dashboard records.

## Functional checks

- Overview and per-run Investigation tabs switch correctly. The redundant latest-run Activity tab
  was removed; each Investigation now owns expandable coordinator and specialist task details.
- Evidence rows expand independently and retain stable evidence anchors.
- The raw JSON dialog opens with the selected evidence and closes correctly.
- Evidence citations link only to server-validated evidence IDs.
- Desktop (1536 × 1024), tablet (768 × 900), and mobile (390 × 844) layouts were inspected in the in-app browser.
- The report reading scale was raised after wide-screen review: narrative findings, hypotheses, and
  recommendations render at 13 px, with ledger metadata held to 10–11 px for density.
- The fleet dashboard's expanded investigation row was rechecked at the reported narrow desktop
  width; its drawer spans the complete table row and no longer inherits the detail-page activity grid.
- Fleet expansion keeps current workstream state and latest evidence without repeating internal
  queued/started/completed persistence transitions in a second journal.
- On mobile, the global sidebar is suppressed on the incident detail route so the report remains the first usable surface; the incident breadcrumb provides a route back to the incident list.
- Full Python test suite passes.
- `git diff --check` passes.

## Final result

Passed.
