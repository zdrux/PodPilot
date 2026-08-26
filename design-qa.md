# Design QA: compact Ask PodPilot replies

## Sources

- Crowded-chat reference: `C:/Users/zdrux/AppData/Local/Temp/codex-clipboard-855d62a5-4259-4499-a09a-2976caa599b9.png`
- Timeline reference: `C:/Users/zdrux/AppData/Local/Temp/codex-clipboard-2119e729-c0b1-4f77-9ce6-8c2ff6f60c0b.png` (477 x 240)
- Collapsed implementation: `C:/Users/zdrux/.codex/visualizations/2026/08/25/01a039ef-54c2-73d3-8008-aeabaa416fe3/compact-chat/01-collapsed.jpg` (1585 x 1085)
- Expanded implementation: `C:/Users/zdrux/.codex/visualizations/2026/08/25/01a039ef-54c2-73d3-8008-aeabaa416fe3/compact-chat/02-expanded-timeline.jpg` (1585 x 1213)
- Status-tooltip implementation: `C:/Users/zdrux/.codex/visualizations/2026/08/25/01a039ef-54c2-73d3-8008-aeabaa416fe3/compact-chat/03-status-tooltip.jpg` (1600 x 900)

## Viewport and interaction checks

- Browser: Codex in-app browser, 1600 x 900 viewport override.
- Evidence disclosure is closed on initial render and expands to four ordered timeline entries.
- Each timeline entry remains a citation link; selecting one updates the URL fragment and focuses the exact evidence drawer source.
- `Evidence-backed` and `Not confirmed` are inline with author and reply time.
- Status explanations appear on pointer hover and keyboard focus; the inspected pseudo-element was visible with opacity `1` while focused.
- Reply and session timestamps render with the fixed `EST (-4)` suffix.
- No horizontal overflow was observed (`body.scrollWidth` did not exceed the rendered viewport width).
- Browser console contained no messages or errors.

## Comparison history

1. Compared the supplied timeline reference and the expanded implementation in the same visual pass. The implementation preserves the requested compact vertical connector, ordered tool labels, supporting summary, and provenance ID while integrating with PodPilot's existing visual language. No P0, P1, or P2 mismatch was found.
2. Checked the default collapsed state separately to verify that citations no longer consume chat height until requested.
3. Checked the focused status pill separately to verify the longer confidence explanation remains discoverable without a persistent nested card.

## Final result

passed
