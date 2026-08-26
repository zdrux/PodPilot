# Design QA: compact Ask PodPilot session header

## Sources

- Source visual truth: `C:/Users/zdrux/AppData/Local/Temp/codex-clipboard-c9d20f53-0546-4a13-a79c-52fcf3234761.png` (1806 x 993, 1x). This is the supplied pre-change conversation state.
- Browser-rendered implementation: `C:/Users/zdrux/.codex/visualizations/2026/08/26/01a03ed6-326e-7f72-9f7b-6314972d2216/ask-compact-header.png` (1806 x 993, 1x).
- Focused tooltip state: `C:/Users/zdrux/.codex/visualizations/2026/08/26/01a03ed6-326e-7f72-9f7b-6314972d2216/ask-compact-header-tooltip.png` (1806 x 993, 1x).
- Narrow implementation: `C:/Users/zdrux/.codex/visualizations/2026/08/26/01a03ed6-326e-7f72-9f7b-6314972d2216/ask-compact-header-mobile.png` (700 x 900, 1x).
- Combined full-view comparison: `C:/Users/zdrux/.codex/visualizations/2026/08/26/01a03ed6-326e-7f72-9f7b-6314972d2216/ask-header-comparison.png` (3612 x 993).

## Viewport and state

- Browser: Codex in-app browser.
- Desktop comparison viewport: 1806 x 993 CSS pixels at device scale 1. Source and implementation required no density normalization.
- State: existing conversation with collected evidence; compact boundary pill immediately precedes the evidence button.
- Narrow responsive check: 700 x 900 CSS pixels. The header controls stayed side by side, the panel remained within the viewport, and no horizontal overflow was present.

## Findings

- No actionable P0, P1, or P2 differences remain for the requested changes.
- Fonts and typography: the relocated `Read-only cluster assistant` text inherits the existing gray subtitle font, size, line height, and weight. It no longer uses the cyan uppercase eyebrow treatment.
- Spacing and layout rhythm: the full-width warning was removed. The conversation panel begins at 121.8 px in the desktop implementation instead of roughly 223 px in the supplied screenshot, reclaiming about 101 px of vertical space. Both compact header controls are 38 px tall with a 9 px gap.
- Colors and visual tokens: the boundary pill retains the existing orange warning semantics at low visual weight; the evidence control retains its cyan evidence styling.
- Image quality and assets: the affected area contains no raster imagery or custom image assets. The existing text-based information mark was preserved and no new image approximation was introduced.
- Copy and content: the complete investigation-boundary explanation remains unchanged in meaning and is available through both pointer hover and keyboard focus. The visible label is shortened to `Cluster selection locked`.

## Interaction and accessibility checks

- Keyboard focus on the boundary pill displayed the complete explanation; the tooltip pseudo-element reported opacity `1`.
- The pill exposes the complete explanation in its accessible label.
- `Collected evidence` still opens its dialog, changes `aria-expanded` to `true`, closes normally, and restores `aria-expanded` to `false`.
- Browser console warning/error check returned no entries.

## Comparison history

1. The initial browser render placed the compact warning directly to the left of `Collected evidence`, aligned both controls at 38 px high, and moved the read-only context into the subtitle line. No P0/P1/P2 issue was found.
2. The focused state verified that removing the banner did not remove its detailed safety explanation.
3. The 700 px responsive pass verified wrapping and overflow. No follow-up visual fix was required.

## Focused region comparison

The page-header and conversation-header regions were inspected at native size because the supplied screenshot is a pre-change state and contains different conversation content. The requested delta is visible and measurable: the cyan eyebrow and full-width orange banner are absent, while the gray subtitle text and compact orange pill are present in their requested locations.

## Final result

passed
