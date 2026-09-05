# Administration configuration design QA

- Source visual truth: Connectors at `http://127.0.0.1:8766/settings/connectors`
- Implementations: Model settings at `http://127.0.0.1:8766/settings/model`, Cluster memory at `http://127.0.0.1:8766/memory`, and Cluster Management at `http://127.0.0.1:8766/settings/clusters`
- Viewport: Codex in-app browser, 718 × 856 CSS pixels
- Capture dimensions: all source and implementation captures 718 × 856 pixels; device density 1; no density normalization required
- State: dark theme, breakglass administrator; empty model and memory directories; one system cluster; new-record editors plus focused form captures
- Browser evidence: the Connectors source and all three rendered implementation captures were placed together in one comparison input.

## Findings

No actionable P0, P1, or P2 visual differences remain.

- Fonts and typography: all four screens use the shared Inter/system stack, the same page-title scale, cyan uppercase eyebrow treatment, compact labels, muted helper copy, and matching optical weights.
- Spacing and layout rhythm: Model settings, Memory, and Cluster Management now repeat the source's bounded page frame, 11px-radius cards, directory/editor separation, 44px control height, numbered steps, section dividers, and grounded action footer. At the captured tablet-width viewport, directories stack above editors without clipping persistent controls.
- Colors and visual tokens: new surfaces, focus rings, borders, selected states, notices, and status chips use the existing theme tokens. No route-specific palette was introduced.
- Image quality and assets: these screens do not use product imagery. Existing PodPilot brand and navigation icons remain untouched; no image or icon was replaced by custom artwork.
- Copy and content: administrator tasks are grouped into endpoint identity/runtime/security, knowledge content/provenance/scope, and cluster identity/API trust/availability. Existing security warnings and exact compatibility copy remain visible.
- States and accessibility: empty directories, selected system cluster, editable forms, capability observations, validation helpers, and danger actions preserve their existing semantics. Programmatic labels, focus treatment, checkbox targets, disabled states, and responsive fallbacks remain intact.

## Full-view comparison evidence

The combined in-app-browser comparison shows the Connectors source followed by the three implementation routes at the same theme and viewport. Page hierarchy, card treatment, record-directory rhythm, control framing, and density are visibly consistent. Memory intentionally retains its retrieval-preview panel above the record editor, and Model settings retains a capability-observation column when a profile exists; both are task-specific extensions of the common configuration shell.

## Focused region comparison evidence

Focused anchor captures of `#model-settings-form`, `#knowledge-form`, and `#cluster-settings-form` confirmed the detailed controls. The captures show matching numbered step headers, field grids, helper-copy rhythm, inset inputs, bordered option groups, and footer actions. These details were legible at the captured viewport, so no additional crop was necessary.

## Comparison history

- Initial visual comparison: no P0/P1/P2 visual findings.
- Compatibility verification found two non-visual copy regressions: Cluster Management title casing and the Memory retrieval contract phrase. Both strings were restored without changing the redesign, and the affected tests passed afterward.
- Final combined comparison: no additional visual fixes required.

## Verification

- Browser-rendered routes checked: `/settings/connectors`, `/settings/model`, `/memory`, `/settings/clusters`, plus focused form anchors and the selected system-cluster state.
- Primary interactions preserved: add/edit navigation, form submission hooks, model probe/activate/delete actions, memory search/status actions, cluster test/disable/delete actions, tag editors, TLS synchronization, and connector-kind visibility.
- Automated check: `python -m pytest apps/api/tests/test_app.py -q` passed.
- Console errors: no application errors were surfaced during route rendering; the in-app browser does not expose a separate console-log surface.

## Follow-up polish

- P3: A future interaction pass could add consistent non-blocking success toasts to the remaining save flows.

final result: passed
