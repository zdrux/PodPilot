# PodPilot Web Design System

This file is the visual source of truth for PodPilot’s operator-facing web UI.
Read it before adding or substantially changing a page, template, component, or
responsive behavior under `apps/web/`.

Implementation authority remains `apps/web/static/styles.css` and the rendered
templates. This document defines the intent and reusable patterns; it must not
become a second, conflicting token implementation.

## 1. Visual Theme and Atmosphere

PodPilot is a restrained, operations-focused SaaS workspace with ShadCN
influence. It should feel calm, precise, trustworthy, and dense enough for
incident response without becoming crowded.

The visual hierarchy is built from:

- a persistent, quiet navigation rail;
- a clear page title and one-sentence purpose statement;
- bounded work surfaces with thin borders and very light elevation;
- inset controls for operator input;
- compact metadata, timestamps, and status labels;
- cyan/teal emphasis for navigation, focus, and primary actions;
- semantic green, amber, and red reserved for state and risk.

Avoid decorative dashboard filler, excessive nested cards, oversized type,
gratuitous gradients, glass effects, and repeated badges. Every visible boundary
must clarify ownership, state, grouping, or interaction.

## 2. Design Principles

### Evidence first

Observed facts, model interpretation, limitations, and operator actions must be
visually distinct. Never style a model hypothesis as if it were collected
evidence. Preserve provenance and timestamps near the content they qualify.

### Dense, not cramped

Use compact type and controls, but maintain a steady vertical rhythm. Prefer a
small number of clearly delineated regions over many free-floating elements.
Long technical values may wrap or truncate with a disclosure path; they must not
force the entire page wider.

### Structure over decoration

Borders, muted fills, section headings, and alignment establish hierarchy. Use
shadows sparingly. Rounded containers should feel subtly softened, not pillowy.

### One shell, many workflows

All routes inherit the same navigation width, typography, page gutters, button
geometry, and theme tokens through `base.html` and `.saas-app`. A route may add a
body class for its workflow, but must not redefine the shared shell.
Sidebar links fetch the destination and replace the main workspace while preserving
the sidebar navigation element and its scroll offset. Server-rendered navigation
entries still refresh to reflect permissions and current selections. Returning to
a visited URL restores its scroll offsets and expanded sections. Page initialization
uses `PodPilotPage` scopes so navigation cancels old requests, timers, streams and
global listeners before binding the destination. Authentication, external links and
modified clicks retain normal browser navigation.

### Security is visible

Credential storage, TLS exceptions, read-only boundaries, approval requirements,
and destructive actions must be stated where the operator makes the decision.
Never reduce a security warning to color alone.

## 3. Semantic Color System

Always consume `--theme-*` variables. Do not hard-code a dark-theme color into a
new component. The default dark palette below documents the intended roles; the
Classic, Light, Medium Light, CIBC Red, and Orange themes provide equivalent values in
`styles.css`.

Orange is an optional DemandKit-inspired comparison theme defined in `static/orange.css`.
Select it from Appearance in the sidebar; the existing browser preference persists
the choice across routes and reloads. Classic remains the default. Orange uses a
neutral light canvas, white bordered panels, orange selection fills, and a darker
orange for readable links and primary actions. Green, amber, and red retain their
operational meanings. Its shared sidebar is 292px on desktop, 252px below 1180px,
and 224px below 840px, with 48px primary navigation rows and outline icons.
Connector categories use folder icons and branch lines down to individual instances;
the add action shares the Connectors row outline while remaining a separate link.
Secondary navigation uses a quiet vertical guide rather than enclosing cards.
The shared connector overview uses the Orange layout as its baseline and offers three flat setup rows with configured counts
and direct add actions. Configured instances appear as children with subtle tree
branches, concise metadata, and Configure/Manage actions. Discovery details and
deployment relationships are nested under their own instance, avoiding duplicate
status strips or global findings blocks. OpenShift Add opens a searchable
multi-select dialog of registered shared clusters; existing enrollments are marked
and disabled. Cluster Management exposes the same enrollment setting. Discovery results
use matching expandable sections for installations, endpoints, Applications,
ApplicationSets, repository admission, and coverage. Applications expand by
namespace, project, then individual source details; repository URLs are grouped
by admission status and deduplicated. Long lists start collapsed and retain their
expansion state through live refreshes. All six themes use this same HTML and
layout CSS; only theme tokens change the connector colors.
Existing navigation and permission conditions remain
intact. Ask uses the shared edge-to-edge conversation and composer layout, with
line separators and no enclosing rounded card or outer gutter.
The composer uses the available conversation width with a 1400px maximum and
automatic side margins. As the panel narrows it moves left with its gutters,
without reserving an author column. Container-based rules stack the toolbar when
needed. Reasoning and raw-response controls live in the Response options pull-up.
Evidence has a persistent 44px folded right rail with an icon-only toggle; the
expanded rail shows the labeled toggle and evidence. On narrow screens the open
rail overlays the conversation. New sessions are started from sidebar navigation.
Other pages retain their existing theme geometry. No frontend framework is required.

Orange configuration pages use a flat directory/editor layout with a divider,
plain section headings, and unboxed option groups. Search stays prominent in
Cluster memory. Model capability results sit below the editor rather than forming
a third narrow column. Model runtime and collection limits start collapsed in
Orange; switching themes restores the expanded layout, and validation reveals
invalid fields inside disclosures. Transport security, credential notices, scope,
provenance, and save/test actions remain visible. Connector forms use the same
flat section treatment without removing field help or security boundaries.

Orange chat uses a soft neutral reading canvas, 16px body text at 1.8 line height,
and a 100-character maximum prose width. Inline code and code blocks use dark slate
text on a pale neutral fill with a visible border, rather than dark cyan highlights.
Links and citations retain orange action emphasis; semantic operational states keep
their existing meaning. Selection uses a pale peach fill with dark text.

| Role | Default dark value | Visual use |
| --- | --- | --- |
| Canvas | `--theme-canvas: #070b10` | Page background and large empty regions |
| Primary surface | `--theme-surface: #0b1118` | Main work surface |
| Raised surface | `--theme-surface-raised: #101821` | Cards, buttons, and elevated regions |
| Soft surface | `--theme-surface-soft: #151f2b` | Hover and selected-supporting fills |
| Inset surface | `--theme-surface-inset: #080e14` | Inputs, code, and recessed content |
| Navigation | `--theme-nav: #090e14` | Persistent sidebar |
| Hairline border | `--theme-border: #202c37` | Cards, rows, and section dividers |
| Strong border | `--theme-border-strong: #344252` | Inputs and emphasized boundaries |
| Primary text | `--theme-text: #f3f5f7` | Headings and operator-critical content |
| Secondary text | `--theme-muted: #9ba8b7` | Body copy and labels |
| Tertiary text | `--theme-subtle: #6f7f90` | Helper copy, timestamps, and metadata |
| Accent | `--theme-accent: #56cfe1` | Primary actions, focus, active navigation |
| Strong accent | `--theme-accent-strong: #85efff` | Small high-emphasis labels and links |
| Success | `--theme-success: #65d391` | Completed, ready, connected |
| Warning | `--theme-warning: #e9a379` | Partial, degraded, caution |
| Danger | `--theme-danger: #ff9a9a` | Failed, destructive, credential risk |

Use `color-mix()` with semantic tokens for low-emphasis backgrounds and borders.
Status must pair color with a text label or an accessible name.

## 4. Typography

- Family: `Inter`, then the system sans-serif stack defined by `.saas-app`.
- Page title: `30–38px`, weight `700`, tight negative tracking, approximately
  `1.1` line height.
- Section title: `17–20px`, weight `650–700`, slightly tightened tracking.
- Card and row title: `12–14px`, weight `600–675`.
- Body and page subtitle: `14px` with approximately `1.5` line height.
- Field label: `11px`, weight `650`.
- Helper text and table metadata: `9–11px`, regular to medium weight.
- Eyebrow: `10–11px`, uppercase, strong weight, restrained letter spacing, and
  `--theme-accent-strong`.
- Code, identifiers, and certificate content: Cascadia Code/Consolas monospace;
  prose must remain sans-serif.

Do not introduce a display font. Do not use uppercase for sentences, row titles,
or primary navigation. Long technical names should preserve readable word breaks
without shrinking the global type scale.

## 5. Geometry, Spacing, and Depth

- Shared sidebar: `260px` desktop, `224px` tablet; it becomes a top region only
  below the phone breakpoint.
- Main gutter: `40px` vertically and `clamp(28px, 4vw, 64px)` horizontally on
  desktop; `28px 18px` at tablet widths.
- Standard content frame: full width with a `1320–1420px` maximum, centered.
- Major region gap: `16–20px`.
- Section padding: `18–22px`.
- Field/grid gap: `14–17px`.
- Control height: at least `44px` for forms; compact toolbar controls may be
  `32–38px`.
- Card radius: `9–11px`; input radius: `7–8px`; small tags: `5–6px`; use pills
  only for compact counts or state labels.
- Borders: one-pixel semantic hairlines. Prefer dividers to nesting another card.
- Elevation: one subtle `0 1px 2px` shadow for work surfaces. Use deeper shadows
  only for dialogs or floating overlays.

## 6. Page Archetypes

### Standard workspace page

Use a `.topbar` with an eyebrow, `h1`, short subtitle, and at most one primary
page action. Follow it with one or more bounded work surfaces. Incidents is the
reference for tables and operational activity.

### Administration configuration page

Use the Connectors and Admin Config pattern:

1. compact boundary or security notice when necessary;
2. a record directory in the page or persistent navigation, but never both;
3. editor on the right;
4. numbered sections that follow the operator’s mental model;
5. inset, consistently framed controls and helper copy;
6. a grounded footer for save, test, activate, disable, or delete actions;
7. a separate observation panel for read-only probe or capability results.

The Connectors directory lives in the persistent Manage navigation and groups
OpenShift clusters, GitHub instances, and Argo CD instances as independent endpoint
types. Do not duplicate that directory inside the Connectors page. Its add action
opens a type chooser before showing a type-specific form; do not render unrelated
integration fields together.
Relationships between connector types are investigation evidence, not form nesting.
Below the editor, use the observed-topology surface for bounded connector discovery:
compact per-connector status cards followed by a horizontally contained Application
relationship table. Show incomplete and ambiguous matches explicitly; never style a
discovered relationship as a configured access grant.

Use `.admin-config-page`, `.admin-config-layout`, `.admin-config-directory`,
`.admin-config-editor`, `.admin-config-form`, and `.admin-form-step` before adding
new page-specific equivalents.

### Investigation and evidence page

Keep current state and source alerts visible before model interpretation. Tables
use distinct headers, aligned columns, horizontal overflow containment, and row
dividers. Details and raw evidence are collapsed when they would dominate the
primary assessment.

Completed investigation runs use the Investigation Ledger pattern: a compact
run-summary strip, model-authored assessment findings, ranked hypotheses,
retained evidence, operator recommendations, and collection activity. Keep these
provenance classes visibly separate. Evidence rows may use aligned ledger columns
because their identifiers, sources, collection timestamps, summaries, and object
references are server-owned. Findings, hypotheses, and next steps remain cited
narrative rows until their contracts become structured; do not invent per-row
scope, confidence, execution mode, or completion state. Investigation task states
describe collection work only and must not imply that a recommendation ran.

### Ask workspace

Ask is the intentional full-height exception. It retains the shared sidebar but
uses its own conversation canvas, composer, and activity rail. Do not copy Ask’s
route-specific density or full-height positioning into ordinary pages.
Readiness, role, and cluster-reconnection notices precede the chat input in the
composer so operators see blocking conditions before typing.

## 7. Components

### Cards and panels

Cards group one coherent unit of work. Use a header divider when a title belongs
to a list, table, or form body. Avoid placing every metric or paragraph in its own
card. Empty states belong inside the surface they describe.

### Forms

- Labels sit above controls; helper or validation text sits immediately below.
- Inputs use the inset surface, strong border, `44px` minimum height, and a visible
  accent focus ring.
- Group related fields in a two-column grid only when both values have equal
  importance and enough width. Collapse to one column before labels or values
  become cramped.
- Mark secrets and optional values consistently with small neutral metadata.
- Use bordered option groups for related checkboxes rather than a loose vertical
  stack.
- Keep destructive actions visually separated and explicitly labeled.
- Never return saved secrets to the browser or imply that a masked field contains
  a retrievable value.

### Buttons

Primary actions use the accent fill and dark-on-accent text. Secondary actions use
a raised neutral surface. Danger actions use danger text and a low-emphasis danger
surface. Keep labels verb-led and specific: “Save metadata,” “Test connection,”
or “Disable cluster,” not “Submit.”

### Tables and dense lists

Use a visible header band, consistent column tracks, `10–13px` table text, and
row dividers. One selected or active row may use a narrow accent inset and a very
soft accent fill. Never rely on zebra striping as the only grouping device.

### Status and notices

Status labels are compact and factual: Active, Completed, Partial, Firing,
Disabled. Notices have one title and a concise consequence or operator action.
Warnings use semantic color plus explicit wording.
On incident reports, separate PodPilot-enforced collection/policy limits from
model-reported uncertainty. Do not merge or repeat a model paraphrase of a trusted
system limit; each group needs a plain-language provenance label.

### Navigation

Preserve all workspace and Manage destinations. Active navigation uses a soft
accent background and border. Subtrees remain visibly nested. Do not hide sidebar
destinations to make an individual page feel cleaner.

## 8. Responsive Behavior

- Desktop: preserve side-by-side record directories, editors, tables, and
  observation panels when they remain readable. The Connectors page is the exception:
  its directory stays in persistent navigation and its editor uses the main width.
- Around `1180px`: reduce optional third columns and move observation panels
  below the editor.
- Around `980px`: stack administration directories and editors.
- At `840px`: retain the full `224px` workspace navigation beside the main view.
- Below `640px`: move navigation above content and use a single content column.
- Below `700–760px`: collapse field grids and footer actions to one column.

Horizontal scrolling is acceptable inside a deliberately bounded data table. It
is not acceptable for the overall page, form, navigation rail, or persistent
actions.

## 9. Content, Accessibility, and Trust

- Use semantic headings in order and real `label` elements for controls.
- Provide visible `:focus-visible` or `:focus-within` treatment.
- Keep interactive targets at least `36px`, preferably `44px` for forms.
- Do not communicate status, risk, or selection by color alone.
- Auto-escape cluster, model, log, event, and evidence text. Never render observed
  HTML as trusted markup.
- Use plain language for the operator action and technical detail for the
  consequence. Avoid promotional copy, generic “AI-powered” language, and
  anthropomorphic agent language.
- Preserve timestamps, cluster attribution, evidence identifiers, limitations,
  and uncertainty whenever they affect interpretation.
- Incident-to-Ask handoffs appear as a provenance panel at the top of the
  conversation, never as a PodPilot-authored chat reply. Keep the imported
  incident run and immutable evidence snapshot identifiable, and distinguish
  subsequent live observations from that historical context. The prepared
  continuation question may submit automatically only after the required
  delegated cluster session is active; the server-side claim must remain
  idempotent so page reloads cannot create duplicate runs.

## 10. Reference Screens

Use rendered application routes as the primary visual references:

| Pattern | Reference route |
| --- | --- |
| SaaS shell and operational table | `/incidents` |
| Directory plus staged configuration | `/settings/connectors` |
| Secure sign-in form | `/delegated/connect` |
| Extended admin configuration | `/settings/model`, `/memory`, `/settings/clusters` |
| Full-height conversation workspace | `/ask?new=1` |

## 11. New-Screen Checklist

Before merging a new or substantially redesigned screen:

1. Start from the closest reference route and existing component classes.
2. Use semantic theme tokens; verify Dark, Classic, Light, Medium Light, CIBC
   Red, and Orange themes when the change affects shared surfaces.
3. Confirm shell width, page title scale, gutters, card geometry, and control
   heights match neighboring routes.
4. Verify empty, loading, selected, error, disabled, and success states relevant
   to the workflow.
5. Verify desktop, tablet, and phone layouts without whole-page overflow.
6. Preserve field names, API hooks, permission boundaries, CSRF behavior, secret
   handling, evidence provenance, and destructive-action confirmation.
7. Run the relevant automated tests and perform a browser comparison against the
   chosen reference screen.
8. Update this file when a new reusable visual pattern is intentionally adopted.

## 12. Anti-Patterns

Memory trends can include occurrence markers and a compact, source-attributed
timeline table. Use semantic surface/text colors in every theme, dotted event
markers distinct from metric samples, visible units, and broken lines for known
sampling gaps. Charts must also render when no ranking table accompanies them.
Discovery details use a flat section with an Auto-detect action and disclosures
for endpoints, repository admission states, and collection limitations.
Development approval bypass must be visible in Action mode; approving a typed
proposal and executing it are separate controls when the bypass is disabled.

Do not introduce:

- route-specific fonts, title scales, or sidebar geometry;
- borderless fields floating in large undifferentiated panels;
- dashboards made from many identical rounded cards without hierarchy;
- decorative gradients, glows, illustrations, or icons without product meaning;
- pills for ordinary labels or long text;
- tiny controls, low-contrast helper text, or hover-only affordances;
- hidden navigation destinations or duplicated administration tabs;
- unreviewed hard-coded colors where a semantic token exists;
- model output styled as authoritative evidence;
- security exceptions presented as harmless preferences.

### Metric timeline markers

Timeline markers use explicit text-only tooltips with observation, timestamp,
message and provenance. Provide a wider transparent pointer target, keyboard
focus/Enter support, tap support and Escape dismissal. Keep the timeline table
as the persistent alternative. Do not rely on native SVG title hover behavior.

### Tool-attempt diagnostics

Use a plain-language cause in both the answer and activity sidebar. Keep raw
compiler output and diagnostic references in a closed Technical details
 disclosure with wrapped, bounded text. A blocked tool attempt is not a cluster
health finding; do not imply that a later operation recovered unless its own
record establishes that result. Unknown diagnostics retain a neutral summary.

### Lists in answer-table cells

Balanced, attribute-free `ul`, `ol` and `li` tags in model-authored table cells
render as lists, including nested lists and Markdown emphasis/code in items.
Literal code spans/blocks remain escaped. Malformed lists and tags with
attributes remain text; this does not enable arbitrary model-authored HTML.

### Navigation regression check

With Node, Playwright and Chrome available, set `PODPILOT_BROWSER_TESTS=1`
(and `NODE_PATH` if Playwright is installed outside the project) and run
`pytest apps/api/tests/test_incidents.py -k sidebar_partial_navigation`.
This uses rendered application fixtures without cluster or model access and checks
persistent sidebar navigation, history/scroll restoration and stream cleanup.
