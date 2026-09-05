# Connector form design QA

- Source visual truth: cluster sign-in screen at `http://127.0.0.1:8766/delegated/connect` and `C:/Users/zdrux/AppData/Local/Temp/codex-clipboard-b70bc70a-e678-474d-ac9a-3c1f73e7eb0a.png`
- Implementation: connector administration screen at `http://127.0.0.1:8766/settings/connectors`
- Viewport: Codex in-app browser, 718 × 856 CSS pixels
- Capture dimensions: source 718 × 856 pixels; implementation 718 × 856 pixels; device density 1; no density normalization required
- State: dark theme, breakglass administrator, one configured cluster connector, new-connection editor
- Browser evidence: both rendered captures were placed in the same comparison input in the Codex in-app browser session.

## Findings

No actionable P0, P1, or P2 differences remain.

- Fonts and typography: both screens use the shared Inter/system sans stack, matching heading weight, compact labels, muted helper copy, and cyan uppercase eyebrows. The connector page preserves the application's established scale rather than introducing route-specific typography.
- Spacing and layout rhythm: the implementation repeats the sign-in screen's bordered header, numbered setup steps, 44px framed controls, restrained radii, and section dividers. The connection directory intentionally becomes a stacked card at the captured narrow viewport; at desktop width it occupies a compact left rail beside the editor.
- Colors and visual tokens: all new surfaces, borders, focus states, and semantic status text use the existing theme tokens. The implementation matches the dark navy, cyan accent, subdued border, and inset-control balance of the source.
- Image quality and assets: neither screen depends on raster imagery. No source logo, illustration, or product image was replaced. Existing navigation brand and icons remain unchanged.
- Copy and content: labels are concise, secrets and optional values are identified consistently, helper text explains storage and TLS behavior, and configuration is grouped by operator task.
- Interaction and accessibility: every input retains its existing `name`, form id, endpoint, and dynamic connector-kind hook. Controls have programmatic labels, visible focus treatment, practical target sizing, and responsive one-column fallbacks.

## Full-view comparison evidence

The combined capture shows the source sign-in card and connector implementation at the same viewport and theme. Both use the same layered card structure, compact cyan hierarchy, numbered progression, framed input surfaces, and quiet supporting copy. The connector page adds a connection directory because selecting existing records is part of this screen's task; this is an intentional information-architecture difference.

## Focused region comparison evidence

A separate crop was not needed because the 718px-wide captures render the step headings, field labels, helper copy, frame borders, and selected navigation states legibly. The first connector setup section was directly compared with the source's credential section.

## Comparison history

- Initial implementation review: no P0/P1/P2 findings. The previous unstructured field stack was replaced before this pass with a directory, staged configuration sections, framed controls, scoped choice panels, and a grounded action footer.
- Post-build comparison: no additional visual fixes required.

## Verification

- Browser-rendered routes checked: `/delegated/connect`, `/settings/connectors`
- Primary behavior checked: existing form hooks and connector-kind visibility logic preserved; add/edit/test/save controls remain wired to the existing JavaScript and API contract.
- Automated check: `python -m pytest apps/api/tests/test_app.py -q` passed.
- Console errors: no application errors observed during route rendering; the in-app browser does not expose a separate console log surface.

## Follow-up polish

- P3: Consider adding a persisted success toast after save/test in a future interaction-focused pass.

final result: passed
