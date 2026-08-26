# Ask PodPilot pinned-session layout QA

- Source visual truth: `C:\Users\zdrux\AppData\Local\Temp\codex-clipboard-63365a39-70cb-4b62-9e14-3cfa063ef4e4.png`
- Implementation screenshot: `C:\Users\zdrux\AppData\Local\Temp\podpilot-ask-pinned-layout-final.png`
- Desktop viewport: 2101 × 1012 CSS px at device scale factor 1
- Source pixels: 2101 × 1012
- Implementation pixels: 2101 × 1012
- Density normalization: none; source and implementation were captured at identical pixel dimensions
- State: desktop dark theme. The source shows a populated conversation; the isolated QA database shows the empty-session state. The shared header, transcript region, cluster selector, and composer shell are directly comparable.

## Full-view comparison evidence

The supplied source and the final browser-rendered screenshot were opened together at the same 2101 × 1012 size. The implementation preserves the sidebar and dark blue-grey chat hue while removing the previous inset outer panel. The main session now fills the complete area to the right of the 248px sidebar. The 88px header begins at viewport top, the composer terminates exactly at viewport bottom, and the center region consumes the remaining height.

Measured final desktop geometry:

- Session surface: left 248, top 0, right 2101, bottom 1012
- Header: top 0, bottom 88
- Composer in the model-not-ready QA state: top 658, bottom 1012
- Body scroll height: 1012, equal to viewport height
- Outer panel border: 0px none
- Outer panel radius: 0px
- Outer panel shadow: none

## Focused region comparison evidence

Separate crops were not needed because the full-resolution captures keep the header and composer typography, controls, spacing, and divider lines readable. Focused inspection confirmed:

- Header: brief session summary and title remain left-aligned; status controls remain right-aligned; the bottom divider is subtle and continuous.
- Conversation: the retained dark blue-grey field has no outer card edge; message cards remain available as intentional attribution boundaries when messages exist.
- Composer: cluster selection and message input are grouped in one bottom region with a continuous top divider. Permission and model-readiness notices stay inside the same pinned region.

## Required fidelity surfaces

- Fonts and typography: existing Inter/system stack, sizes, weights, wrapping, and hierarchy are unchanged. No new type styles were introduced.
- Spacing and layout rhythm: the old page padding and panel inset are removed only for Ask PodPilot. Header, transcript, and composer form a full-height three-row grid. Existing internal 18–20px spacing remains consistent.
- Colors and visual tokens: existing dark blue-grey surfaces, cyan accents, orange boundary status, muted text, and border tokens are preserved. Divider opacity uses the existing blue-grey palette.
- Image quality and asset fidelity: the screen contains no new raster assets. Existing brand and UI marks were left unchanged.
- Copy and content: all existing product copy, evidence labels, cluster-selection guidance, composer help, and empty-state prompts are unchanged.

## Interaction and responsive verification

- Opened the cluster picker successfully.
- Filled and cleared the question textarea successfully.
- Submit was intentionally not attempted because the isolated QA model profile was not configured.
- At 700 × 900, the sidebar collapses to the top, the main area fills the remaining 765px, the header and composer remain bounded inside it, and body scroll height remains equal to viewport height.
- Browser console errors checked: none.

## Comparison history

### Pass 1

- [P2] The generic `.panel` rule appeared later in the cascade and restored a faint 1px outer border and 16px radius around the Ask session.
- Fix: increased selector specificity to `.ask-page .ask-panel`, preserving the edge-to-edge overrides against the generic panel rule.
- Post-fix evidence: the final screenshot and computed styles show no border, no radius, and no shadow; the session bounds exactly match the main viewport bounds.

### Pass 2

No actionable P0, P1, or P2 differences remain for the requested layout change.

## Findings

No blocking visual, interaction, accessibility, or responsive findings remain.

## Open questions

None.

## Implementation checklist

- [x] Remove Ask page outer card inset, border, radius, and shadow.
- [x] Pin the session summary header to the top region.
- [x] Make the transcript the only independently scrolling region when messages overflow.
- [x] Pin cluster selection and the message composer to the bottom region.
- [x] Add subtle continuous separators between all three regions.
- [x] Preserve the existing dark blue-grey chat background and sidebar contrast.
- [x] Verify desktop and responsive geometry, core controls, and browser console.

## Follow-up polish

No P3 follow-up is required for this scoped change.

final result: passed
