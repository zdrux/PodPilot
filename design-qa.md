# Ask PodPilot message-card height QA

- Source visual truth: `C:\Users\zdrux\AppData\Local\Temp\codex-clipboard-7ca933cc-6391-4f9e-9df2-5b0a0cb56a23.png`
- Browser-rendered implementation: `C:\Users\zdrux\AppData\Local\Temp\podpilot-chat-card-height-fixed-1861.png`
- Viewport: 1861 × 1001 CSS px at device scale factor 1
- Source pixels: 1861 × 1001
- Implementation pixels: 1861 × 1001
- Density normalization: none
- State: dark desktop Ask PodPilot conversation with one user message and one active investigation card containing five progress events

## Full-view comparison evidence

The source and corrected browser render were opened together at identical dimensions and state. In the source, the two automatic CSS Grid rows stretch vertically to fill the 649px transcript area, leaving large empty regions inside both cards. In the corrected render, the cards are content-sized and the unused transcript height appears below the message stack, where it belongs.

Measured corrected geometry:

- Transcript height: 649px
- User card: 126.34px rendered height, 124px scroll height
- Active investigation card: 243.95px rendered height, 242px scroll height
- Grid automatic rows: `max-content`
- Grid content alignment: `start`
- Page scroll height: 1001px, equal to the viewport height

## Focused region comparison evidence

The message region is legible at native size in the full-view pair, so a separate crop was unnecessary. Focused inspection confirmed that card widths, padding, borders, typography, progress markers, and the 12px inter-card gap are unchanged. Only the unintended vertical stretching was removed.

## Required fidelity surfaces

- Fonts and typography: unchanged; existing Inter/system stack, font sizes, weights, line heights, and wrapping are preserved.
- Spacing and layout rhythm: card padding and the inter-card gap are unchanged. Automatic rows now use intrinsic content height and the message stack is anchored to the transcript top.
- Colors and visual tokens: unchanged; dark blue-grey surfaces, cyan borders, and semantic progress colors remain intact.
- Image quality and asset fidelity: no image or icon assets were added, replaced, or altered.
- Copy and content: the user message, active investigation status, and progress entries render unchanged.

## Interaction and browser verification

- Verified the populated active-investigation state from a seeded isolated QA database.
- Confirmed the transcript remains independently scrollable when content exceeds its fixed region.
- Browser console errors checked: none.
- Model execution and form submission were intentionally not triggered; this change affects only message-row sizing.

## Comparison history

### Pass 1

- [P1] Message cards expanded to consume unused transcript height.
- Cause: the fixed-height `.ask-thread` remained a grid whose implicit auto rows participated in `align-content: normal`, allowing the rows to stretch.
- Fix: set `grid-auto-rows: max-content` and `align-content: start` on `.ask-thread`.

### Pass 2

- Post-fix browser evidence shows both cards matching their content height with unused space below the stack.
- No actionable P0, P1, or P2 findings remain.

## Findings

No blocking visual, interaction, accessibility, or responsive findings remain for this correction.

## Implementation checklist

- [x] Prevent implicit transcript rows from stretching.
- [x] Keep messages anchored at the top of the scrolling region.
- [x] Preserve card padding, width, styling, and message content.
- [x] Verify against the reported active-investigation state at the same viewport.
- [x] Check browser console and existing API UI tests.

## Follow-up polish

No P3 follow-up is required.

final result: passed
